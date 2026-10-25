// Package schemadiff is the schema-diff contract test: it checks generated
// control content against the pruned schema
// of a new upstream version, relative to the schema the content was
// generated against. The report names controls, types and read paths only:
// no expr text and no values.
package schemadiff

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/bundlegen"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/celeng"
)

// Results, worst last.
const (
	Pass = "pass"
	Warn = "warn"
	Fail = "fail"
)

// Checks, one per row of the section 9 table.
const (
	CheckTypeRemoved  = "type_removed"  // target type removed
	CheckReadMissing  = "read_missing"  // a reads path no longer resolves
	CheckShapeChanged = "shape_changed" // leaf type, a container kind, block nesting or max_items on the path changed
	CheckComputedOnly = "computed_only" // a config read became Computed-only, or celeng control_computed_only
	CheckExprCompile  = "expr_compile"  // the control no longer loads against the new schema
	CheckDeprecated   = "deprecated"    // a read attribute or block is newly deprecated

	// The content is not fully covered by base, so nothing could be compared.
	CheckTypeNotInBase = "type_not_in_base"
	CheckReadNotInBase = "read_not_in_base"
)

// Report is schemadiff-report.json. Findings are sorted and never null.
type Report struct {
	Result   string    `json:"result"`
	Findings []Finding `json:"findings"`
}

// Finding is one check result for one control (and read, where the check is
// per read).
type Finding struct {
	ControlID    string `json:"control_id"`
	Kind         string `json:"kind"`
	ResourceType string `json:"resource_type"`
	Read         string `json:"read,omitempty"`
	Check        string `json:"check"`
	Result       string `json:"result"`
}

// Diff checks content against next, the pruned schema of the new upstream
// version, comparing accessors with base, the schema the content was
// generated against. A type or read base lacks is a warn finding, so a
// stale base never yields a clean pass. A graph control is checked on both
// of its resource types: target_attrs as reads of resource_type and
// link_attr as a read of companion_type (findings name that type); its
// companion_expr is not compiled here (the provider never evaluates graph
// controls). An error is an unknown control kind or a graph control without
// graph (E_SCHEMA_TYPE), or a schema celeng cannot use.
func Diff(content []bundle.Control, base, next bundlegen.Schemas) (Report, error) {
	r := Report{Findings: []Finding{}}
	for i := range content {
		c := &content[i]
		add := func(typ, read, check, result string) {
			r.Findings = append(r.Findings, Finding{c.ID, string(c.Kind), typ, read, check, result})
		}
		switch c.Kind {
		case bundle.KindResource, bundle.KindDeletionGuard, bundle.KindDataSource, bundle.KindEphemeral:
			if !checkReads(add, c.Kind, c.ResourceType, c.Reads, configReads(c), base, next) {
				continue
			}
			_, _, err := celeng.Load([]bundle.Control{*c}, next.ProviderSchema())
			var d *celeng.LoadDiag
			switch {
			case errors.As(err, &d) && d.Code == "control_computed_only":
				add(c.ResourceType, "", CheckComputedOnly, Fail)
			case errors.As(err, &d):
				add(c.ResourceType, "", CheckExprCompile, Fail)
			case err != nil:
				return Report{}, err
			}
		case bundle.KindGraph:
			if c.Graph == nil {
				return Report{}, &bundlegen.Error{Code: "E_SCHEMA_TYPE", Msg: fmt.Sprintf("%s: graph control without graph", c.ID)}
			}
			none := func(string) bool { return false } // no expr reads config
			checkReads(add, bundle.KindResource, c.ResourceType, c.Graph.TargetAttrs, none, base, next)
			checkReads(add, bundle.KindResource, c.Graph.CompanionType, []string{c.Graph.LinkAttr}, none, base, next)
		default:
			return Report{}, &bundlegen.Error{Code: "E_SCHEMA_TYPE", Msg: fmt.Sprintf("%s: unknown kind %q", c.ID, c.Kind)}
		}
	}
	slices.SortFunc(r.Findings, func(a, b Finding) int {
		return cmp.Or(cmp.Compare(a.ControlID, b.ControlID), cmp.Compare(a.Kind, b.Kind),
			cmp.Compare(a.ResourceType, b.ResourceType), cmp.Compare(a.Read, b.Read), cmp.Compare(a.Check, b.Check))
	})
	r.Findings = slices.Compact(r.Findings)
	r.Result = Pass
	for _, f := range r.Findings {
		switch {
		case f.Result == Fail:
			r.Result = Fail
		case r.Result == Pass:
			r.Result = f.Result
		}
	}
	return r, nil
}

// checkReads checks type typ of kind k and its reads against next and base,
// adding findings for typ; it reports whether typ is in next.
func checkReads(add func(typ, read, check, result string), k bundle.Kind, typ string, reads []string,
	cfg func(string) bool, base, next bundlegen.Schemas,
) bool {
	ns, ok := next.Lookup(k, typ)
	if !ok {
		add(typ, "", CheckTypeRemoved, Fail)
		return false
	}
	bs, ok := base.Lookup(k, typ)
	if !ok {
		add(typ, "", CheckTypeNotInBase, Warn)
	}
	for _, read := range reads {
		nr, ok := resolve(ns.Block, read)
		if !ok {
			add(typ, read, CheckReadMissing, Fail)
			continue
		}
		if bs == nil {
			continue // reported as type_not_in_base
		}
		br, ok := resolve(bs.Block, read)
		if !ok {
			add(typ, read, CheckReadNotInBase, Warn)
			continue
		}
		for _, f := range compare(cfg, read, br, nr) {
			add(typ, read, f[0], f[1])
		}
	}
	return true
}

// Failed reports whether any check failed.
func (r Report) Failed() bool { return r.Result == Fail }

// JSON renders the report with 2-space indent and a trailing newline.
func (r Report) JSON() ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// step is one segment of a read path: a nested block or the attribute that
// ends the schema walk.
type step struct {
	block      bool
	nesting    tfprotov5.SchemaNestedBlockNestingMode
	maxItems   int64
	deprecated bool
}

// resolved is a read path resolved as celeng does: nested block segments
// descend, an attribute segment ends the walk and the rest of the path is
// inside its value (sig is then the container kind at every step plus the
// leaf cty type); a path ending at a block leaves attr nil and block set.
type resolved struct {
	steps []step
	attr  *tfprotov5.SchemaAttribute
	sig   string
	block *tfprotov5.SchemaBlock
}

func resolve(b *tfprotov5.SchemaBlock, path string) (resolved, bool) {
	var r resolved
	if b == nil {
		return r, false
	}
	segs := strings.Split(path, ".")
	for i, seg := range segs {
		if a := attr(b, seg); a != nil {
			sig, ok := typeSig(a.Type, segs[i+1:])
			r.steps = append(r.steps, step{deprecated: a.Deprecated})
			r.attr, r.sig = a, sig
			return r, ok
		}
		nb := block(b, seg)
		if nb == nil || nb.Block == nil {
			return r, false
		}
		b = nb.Block
		r.steps = append(r.steps, step{true, nb.Nesting, nb.MaxItems, b.Deprecated})
	}
	r.block = b
	return r, true
}

// typeSig walks rest inside a value of type t (list and set steps implicit,
// a map step is a key, a step into a dynamic value stays dynamic) and
// records the container kind at each step, so list/set swaps and added
// nesting on the way are visible, then the leaf type signature.
func typeSig(t tftypes.Type, rest []string) (string, bool) {
	var sig strings.Builder
	for _, seg := range rest {
		for {
			if l, ok := t.(tftypes.List); ok {
				sig.WriteString("list.")
				t = l.ElementType
			} else if st, ok := t.(tftypes.Set); ok {
				sig.WriteString("set.")
				t = st.ElementType
			} else {
				break
			}
		}
		switch c := t.(type) {
		case tftypes.Map:
			sig.WriteString("map.")
			t = c.ElementType
		case tftypes.Object:
			sig.WriteString("object.")
			t = c.AttributeTypes[seg]
		default:
			if t != nil && t.Is(tftypes.DynamicPseudoType) {
				return sig.String() + `"dynamic"`, true
			}
			return "", false
		}
		if t == nil {
			return "", false
		}
	}
	tj, err := t.MarshalJSON() //nolint:staticcheck // schema -json type signature, as schema_compat_digest
	if err != nil {
		return "", false
	}
	sig.Write(tj)
	return sig.String(), true
}

// compare returns the (check, result) pairs for one read resolved in base
// and next. A read ending at a block covers what the block holds in base:
// every attribute and nested block below it, recursively; additions in next
// are not a change.
func compare(cfg func(string) bool, read string, br, nr resolved) [][2]string {
	var out [][2]string
	if len(br.steps) != len(nr.steps) || (br.attr == nil) != (nr.attr == nil) {
		return [][2]string{{CheckShapeChanged, Fail}}
	}
	for i, b := range br.steps {
		n := nr.steps[i]
		if b.block != n.block || b.nesting != n.nesting || b.maxItems != n.maxItems {
			out = append(out, [2]string{CheckShapeChanged, Fail})
		}
		if n.deprecated && !b.deprecated {
			out = append(out, [2]string{CheckDeprecated, Warn})
		}
	}
	if br.attr != nil {
		return append(out, compareAttr(cfg(read), br.attr, nr.attr, br.sig != nr.sig)...)
	}
	return append(out, compareBlock(cfg, read, br.block, nr.block)...)
}

func compareAttr(cfg bool, b, n *tfprotov5.SchemaAttribute, changed bool) [][2]string {
	var out [][2]string
	if changed {
		out = append(out, [2]string{CheckShapeChanged, Fail})
	}
	// A configured read through config must stay config-settable (spec 9).
	// Deny controls reading resource.* are left to celeng.Load
	// (control_computed_only), which exempts prior.*, stored state.
	if cfg && computedOnly(n) && !computedOnly(b) {
		out = append(out, [2]string{CheckComputedOnly, Fail})
	}
	return out
}

// compareBlock compares block b at path with n; cfg is asked per attribute
// path, so only attributes the expr reads through config count for
// computed_only.
func compareBlock(cfg func(string) bool, path string, b, n *tfprotov5.SchemaBlock) [][2]string {
	var out [][2]string
	if n.Deprecated && !b.Deprecated {
		out = append(out, [2]string{CheckDeprecated, Warn})
	}
	for _, ba := range b.Attributes {
		if ba == nil {
			continue
		}
		na := attr(n, ba.Name)
		if na == nil {
			out = append(out, [2]string{CheckReadMissing, Fail})
			continue
		}
		if na.Deprecated && !ba.Deprecated {
			out = append(out, [2]string{CheckDeprecated, Warn})
		}
		bs, _ := typeSig(ba.Type, nil)
		ns, _ := typeSig(na.Type, nil)
		out = append(out, compareAttr(cfg(path+"."+ba.Name), ba, na, bs != ns)...)
	}
	for _, bb := range b.BlockTypes {
		if bb == nil || bb.Block == nil {
			continue // a base block without schema covers nothing
		}
		nb := block(n, bb.TypeName)
		if nb == nil || nb.Block == nil {
			out = append(out, [2]string{CheckReadMissing, Fail})
			continue
		}
		if nb.Nesting != bb.Nesting || nb.MaxItems != bb.MaxItems {
			out = append(out, [2]string{CheckShapeChanged, Fail})
		}
		out = append(out, compareBlock(cfg, path+"."+bb.TypeName, bb.Block, nb.Block)...)
	}
	return out
}

// configReads returns whether the expr of c reads an attribute path through
// config: for a configured control, an AST read (celeng.Compile) that is not
// prior.* at the path, at an ancestor (the whole value flows on) or inside
// it. prior is stored state, exempt from the Computed-only rule as in
// celeng.Load. A control that does not compile counts as reading config;
// its load failure is reported anyway.
func configReads(c *bundle.Control) func(path string) bool {
	if c.PresenceMode != bundle.PresenceConfigured {
		return func(string) bool { return false }
	}
	ch, _, err := celeng.Compile(c)
	if err != nil || ch == nil {
		return func(string) bool { return true }
	}
	return func(path string) bool {
		return slices.ContainsFunc(ch.Reads, func(r celeng.Read) bool {
			return r.Var != "prior" && (r.Path == path || strings.HasPrefix(path, r.Path+".") || strings.HasPrefix(r.Path, path+"."))
		})
	}
}

func computedOnly(a *tfprotov5.SchemaAttribute) bool {
	return a.Computed && !a.Optional && !a.Required
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
