package celeng

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
)

// Load checks a decoded, signature-verified control set against the upstream
// provider schema: the
// Compile rules, then the schema rules. The first load error rejects the
// bundle: Load returns nil, the warnings collected so far and a *LoadDiag.
// On success checked is parallel to cs and diags holds every warning
// (control_reads_unused, control_constant, control_schema_type_missing,
// control_schema_path_missing).
//
// A schema Load cannot trust (nil, an error diagnostic, a nil map for a
// control's kind, a nil schema or block) is a plain error: no bundle loads
// without the upstream schema.
//
// Load relies on two checks it cannot run itself:
//   - An effective deny control reading an Optional+Computed attribute loads
//     without a diagnostic. The control schema carries no proof, so Load
//     trusts the generator verify (E_OPTIONAL_COMPUTED) that signed
//     the bundle.
//   - A resource or deletion_guard control whose type or read path is
//     missing from the schema is kept; evaluation returns not_evaluable /
//     no_such_attribute, which the 0B severity matrix treats as
//     fail.
//
// Kind rules: a data_source
// or ephemeral control whose type or read path is missing from its schema
// is an error (control_data_source_unknown, control_ephemeral_unknown,
// control_schema_path_missing); an ephemeral control reading a Computed-only
// attribute is control_ephemeral_result for any action; a data_source
// control may read Computed-only resource.* attributes (its read result).
func Load(cs []bundle.Control, s *tfprotov5.GetProviderSchemaResponse) ([]*Checked, []LoadDiag, error) {
	return loadLint(cs, s, true)
}

func loadLint(cs []bundle.Control, s *tfprotov5.GetProviderSchemaResponse, lintPolarity bool) ([]*Checked, []LoadDiag, error) {
	if err := usable(s); err != nil {
		return nil, nil, err
	}
	checked := make([]*Checked, len(cs))
	var diags []LoadDiag
	for i := range cs {
		ch, ds, err := compile(&cs[i], lintPolarity)
		diags = append(diags, ds...)
		switch {
		case err == nil:
			ds, err = checkSchema(&cs[i], ch, s)
			diags = append(diags, ds...)
		case ch != nil:
			// Rejected either way; control_computed_only is the more
			// specific reason (Compile).
			var d *LoadDiag
			if _, serr := checkSchema(&cs[i], ch, s); errors.As(serr, &d) && d.Code == "control_computed_only" {
				err = serr
			}
		}
		var d *LoadDiag
		if errors.As(err, &d) {
			return nil, diags, err
		}
		if err != nil {
			return nil, nil, err
		}
		checked[i] = ch
	}
	return checked, diags, nil
}

func usable(s *tfprotov5.GetProviderSchemaResponse) error {
	if s == nil || s.ResourceSchemas == nil {
		return errors.New("celeng: no upstream resource schemas")
	}
	for _, d := range s.Diagnostics {
		if d != nil && d.Severity == tfprotov5.DiagnosticSeverityError {
			return fmt.Errorf("celeng: upstream schema: %s", d.Summary)
		}
	}
	return nil
}

// kindSchemas picks the schema map for a control kind.
func kindSchemas(k bundle.Kind, s *tfprotov5.GetProviderSchemaResponse) map[string]*tfprotov5.Schema {
	switch k {
	case bundle.KindDataSource:
		return s.DataSourceSchemas
	case bundle.KindEphemeral:
		return s.EphemeralResourceSchemas
	}
	return s.ResourceSchemas // resource, deletion_guard
}

// checkSchema resolves every AST read (resource, config and prior alike)
// against the schema of the control's kind and type. The Computed-only rule
// skips prior reads.
func checkSchema(c *bundle.Control, ch *Checked, s *tfprotov5.GetProviderSchemaResponse) ([]LoadDiag, error) {
	m := kindSchemas(c.Kind, s)
	if m == nil {
		return nil, fmt.Errorf("celeng: no upstream %s schemas", c.Kind)
	}
	sc, ok := m[c.ResourceType]
	switch {
	case !ok && c.Kind == bundle.KindDataSource:
		return nil, &LoadDiag{ControlID: c.ID, Code: "control_data_source_unknown",
			Detail: detailf("targets unknown data source %s", c.ResourceType)}
	case !ok && c.Kind == bundle.KindEphemeral:
		return nil, &LoadDiag{ControlID: c.ID, Code: "control_ephemeral_unknown",
			Detail: detailf("targets unknown ephemeral resource %s", c.ResourceType)}
	case !ok:
		return []LoadDiag{{ControlID: c.ID, Code: "control_schema_type_missing",
			Detail: detailf("resource type %s not in upstream %s schema", c.ResourceType, c.Kind)}}, nil
	}
	if sc == nil || sc.Block == nil {
		return nil, fmt.Errorf("celeng: upstream %s schema %s has no block", c.Kind, c.ResourceType)
	}
	// A use the schema rejects (control_dynamic_access) still lets the
	// declared reads be checked: control_computed_only is the more specific
	// reason when both apply (as in Load).
	reads, useErr := schemaReads(sc.Block, ch)
	if useErr != nil {
		var d *LoadDiag
		if errors.As(useErr, &d) {
			d.ControlID = c.ID
		}
		reads = ch.Reads
	}
	var diags []LoadDiag
	var computedOnly []string
	missing := func(name string) {
		diags = append(diags, LoadDiag{ControlID: c.ID, Code: "control_schema_path_missing",
			Detail: detailf("read %s not in schema for %s", name, c.ResourceType)})
	}
	for _, r := range reads {
		a, b, _, found, err := resolve(sc.Block, r.Path)
		if err != nil {
			return nil, fmt.Errorf("celeng: upstream %s schema %s: %w", c.Kind, c.ResourceType, err)
		}
		name := r.Var + "." + r.Path
		// prior is stored state, known at plan time: its reads are exempt
		// from the Computed-only rule. Every
		// other check (missing path, dynamic access, key presence) applies.
		// A data source's resource is its read result, known once read:
		// Computed-only resource reads are allowed there.
		flag := func(n string) {
			if r.Var != varPrior && (c.Kind != bundle.KindDataSource || r.Var != varResource) {
				computedOnly = append(computedOnly, n)
			}
		}
		switch {
		case !found:
			missing(name)
		case a != nil && computedOnlyAttr(a):
			flag(name)
		case b != nil && wholeObject(sc.Block, ch, r) && hasComputedOnly(b):
			// The block value itself flows on (e.g. through map or
			// filter), so every attribute below it is read.
			flag(name)
		case b != nil:
			// r["k"] below a block selects attribute or nested block k:
			// resolve it, and count a nested block as reading every
			// attribute in it (deeper keys and steps are not tracked).
			for _, k := range ch.Keys[r] {
				if ka := attr(b, k); ka != nil {
					if computedOnlyAttr(ka) {
						flag(name + "." + k)
					}
				} else if nb := block(b, k); nb == nil {
					missing(name + "." + k)
				} else if hasComputedOnly(nb.Block) {
					flag(name + "." + k)
				}
			}
		}
	}
	slices.Sort(computedOnly)
	switch {
	case c.Kind == bundle.KindEphemeral && len(computedOnly) > 0:
		// Ephemeral controls check the open request; a Computed-only
		// attribute is the result, whatever the action.
		return diags, &LoadDiag{ControlID: c.ID, Code: "control_ephemeral_result",
			Detail: detailf("ephemeral control reads result attribute %s", computedOnly[0])}
	case c.Action == bundle.ActionDeny && len(computedOnly) > 0:
		return diags, &LoadDiag{ControlID: c.ID, Code: "control_computed_only",
			Detail: detailf("deny control reads computed-only attributes [%s]; ship it as a warn control decided post-apply", computedOnly)}
	case useErr != nil:
		return nil, useErr
	case len(diags) > 0 && (c.Kind == bundle.KindDataSource || c.Kind == bundle.KindEphemeral):
		// The data_source and ephemeral kinds fail closed on a path the schema lacks; diags
		// holds only control_schema_path_missing here.
		return nil, &diags[0]
	}
	return diags, nil
}

// schemaReads checks the uses of ch against schema block b and returns the
// reads to resolve: ch.Reads plus, for each constant attribute key an in test
// checks on an object, the read of that attribute, so a key missing from the
// schema is no_such_attribute like a select. Every object carries every
// schema attribute, so any other use that sees an object's key set (a key
// test, key enumeration, equality or membership of a value holding objects)
// would decide on a field missing from the schema: control_dynamic_access.
// Uses whose path is not in the schema are left to the read check.
func schemaReads(b *tfprotov5.SchemaBlock, ch *Checked) ([]Read, error) {
	reads := ch.Reads
	for _, u := range ch.uses {
		t := typeAt(b.ValueType(), u.Path, u.Elem)
		_, obj := t.(tftypes.Object)
		var why string
		switch {
		case t == nil:
		case t.Is(tftypes.DynamicPseudoType) && u.Op != useWhole:
			// Its object type, if any, comes from the value, not the schema.
			why = "key test, key enumeration or comparison of a dynamic value"
		case u.Op == useCompare && mayHoldMap(t):
			why = "comparison of a value holding objects"
		case u.Op == useKeys && obj:
			why = "key enumeration of an object"
		case u.Op == useIn && obj && u.Key != "":
			reads = append(slices.Clip(reads), Read{Var: u.Var, Path: u.Path + "." + u.Key})
		case u.Op == useIn && obj:
			why = "non-constant key test of an object"
		case u.Op == useIn && mayHoldMap(elem(t)) && !isMap(t):
			why = "membership in a collection of objects"
		case u.Op == useWhole && hasObject(t):
			why = "whole use of a value holding objects"
		}
		if why != "" {
			// why is a fixed reason, not control text: part of the format,
			// so detailf does not replace it with the placeholder.
			return nil, dynamic(why+" at %s.%s; select its attributes instead", u.Var, u.Path)
		}
	}
	if len(reads) != len(ch.Reads) {
		reads = slices.Clone(reads)
		slices.SortFunc(reads, func(x, y Read) int {
			return strings.Compare(x.Var+"\x00"+x.Path, y.Var+"\x00"+y.Path)
		})
		reads = slices.Compact(reads)
	}
	return reads, nil
}

// typeAt is the type of the value at path in root type t after n element
// steps, nil when the path is not in the schema. Path steps follow typeHas
// (list and set steps implicit, a map step is a key). An element of a map
// is its key (only an iteration variable steps into a map); a tuple is
// opaque and counts as an object.
func typeAt(t tftypes.Type, path string, n int) tftypes.Type {
	for _, seg := range strings.Split(path, ".") {
		switch c := elem(elem(t)).(type) {
		case tftypes.Map:
			t = c.ElementType
		case tftypes.Object:
			t = c.AttributeTypes[seg]
		default:
			if c != nil && c.Is(tftypes.DynamicPseudoType) {
				return c
			}
			return nil
		}
		if t == nil {
			return nil
		}
	}
	for range n {
		switch t.(type) {
		case tftypes.Map, tftypes.Object:
			t = tftypes.String // iterating yields keys
		default:
			t = elem(t)
		}
	}
	if _, ok := t.(tftypes.Tuple); ok {
		return tftypes.Object{}
	}
	return t
}

// hasObject reports whether a value of type t holds an object (or a tuple).
func hasObject(t tftypes.Type) bool {
	switch c := t.(type) {
	case tftypes.Object, tftypes.Tuple:
		return true
	case tftypes.List:
		return hasObject(c.ElementType)
	case tftypes.Set:
		return hasObject(c.ElementType)
	case tftypes.Map:
		return hasObject(c.ElementType)
	}
	return false
}

// mayHoldMap is hasObject that also counts a dynamic value, which may be an
// object at runtime.
func mayHoldMap(t tftypes.Type) bool {
	switch c := t.(type) {
	case tftypes.List:
		return mayHoldMap(c.ElementType)
	case tftypes.Set:
		return mayHoldMap(c.ElementType)
	case tftypes.Map:
		return mayHoldMap(c.ElementType)
	}
	return hasObject(t) || (t != nil && t.Is(tftypes.DynamicPseudoType))
}

func isMap(t tftypes.Type) bool {
	_, ok := t.(tftypes.Map)
	return ok
}

// resolve walks a name-only read path (no index or wildcard
// segments). A nested block segment descends; an attribute segment ends the
// walk, the rest of the path being inside the attribute's value (object
// attribute or map key), so its flags apply. A path ending at a block
// returns a nil attribute and that block: a nested block path itself counts
// as non-Computed (string keys below it are checked by the caller).
// Protocol v5 attributes have no NestedType, so blocks are the only nesting.
// The segments after the attribute come back as rest.
func resolve(b *tfprotov5.SchemaBlock, path string) (a *tfprotov5.SchemaAttribute, blk *tfprotov5.SchemaBlock, rest []string, found bool, err error) {
	segs := strings.Split(path, ".")
	for i, seg := range segs {
		if a := attr(b, seg); a != nil {
			return a, nil, segs[i+1:], true, nil
		}
		nb := block(b, seg)
		if nb == nil {
			return nil, nil, nil, false, nil
		}
		if nb.Block == nil {
			return nil, nil, nil, false, fmt.Errorf("block %s has no schema", safe(seg))
		}
		b = nb.Block
	}
	return nil, b, nil, true, nil
}

// wholeObject reports whether ch uses the value at read r, or an element of
// it, as a whole where that value holds objects (the block itself, not one
// of its keys an iteration over the object yields).
func wholeObject(b *tfprotov5.SchemaBlock, ch *Checked, r Read) bool {
	return slices.ContainsFunc(ch.uses, func(u use) bool {
		return u.Op == useWhole && u.Var == r.Var && u.Path == r.Path &&
			hasObject(typeAt(b.ValueType(), u.Path, u.Elem))
	})
}

func computedOnlyAttr(a *tfprotov5.SchemaAttribute) bool {
	return a.Computed && !a.Optional && !a.Required
}

// hasComputedOnly reports whether b or any block nested in it has a
// Computed-only attribute. A nested block without a schema counts as one.
func hasComputedOnly(b *tfprotov5.SchemaBlock) bool {
	if b == nil {
		return true
	}
	for _, a := range b.Attributes {
		if a != nil && computedOnlyAttr(a) {
			return true
		}
	}
	for _, nb := range b.BlockTypes {
		if nb != nil && hasComputedOnly(nb.Block) {
			return true
		}
	}
	return false
}

func attr(b *tfprotov5.SchemaBlock, name string) *tfprotov5.SchemaAttribute {
	for _, a := range b.Attributes {
		if a != nil && a.Name == name {
			return a
		}
	}
	return nil
}

func block(b *tfprotov5.SchemaBlock, name string) *tfprotov5.SchemaNestedBlock {
	for _, nb := range b.BlockTypes {
		if nb != nil && nb.TypeName == name {
			return nb
		}
	}
	return nil
}
