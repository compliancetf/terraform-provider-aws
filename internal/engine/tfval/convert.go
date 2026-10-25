// Package tfval converts Terraform values (tftypes) into CEL activation
// values. An unknown object attribute or map
// entry is left out, an unknown list element becomes null, and each unknown
// path is reported for a CEL attribute pattern; a set that is not wholly
// known is one pattern on the set. Errors carry paths and type names only,
// never values: sensitive values are evaluated in plaintext but never output.
package tfval

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"slices"

	"cel.dev/cel-go/cel"
	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// Converted is one CEL variable built from a tftypes value.
type Converted struct {
	Variable string
	Value    any // map[string]any, []any, string, bool, int64, float64 or nil; only when Known
	// Known is false when the whole value is unknown: leave the variable out
	// of the activation; Unknown then holds the empty (root) path.
	Known bool
	// Unknown lists every unknown path in walk order (map keys sorted).
	Unknown []*tftypes.AttributePath
}

// Patterns returns the CEL attribute patterns for the unknown paths.
func (c Converted) Patterns() []*cel.AttributePatternType {
	out := make([]*cel.AttributePatternType, 0, len(c.Unknown))
	for _, p := range c.Unknown {
		out = append(out, Pattern(c.Variable, p))
	}
	return out
}

// Pattern maps a path to an attribute pattern: AttributeName and
// ElementKeyString become QualString, ElementKeyInt becomes QualInt.
// Converted never reports an ElementKeyValue step (sets are patterned whole).
func Pattern(variable string, p *tftypes.AttributePath) *cel.AttributePatternType {
	pat := cel.AttributePattern(variable)
	for _, st := range p.Steps() {
		switch st := st.(type) {
		case tftypes.AttributeName:
			pat = pat.QualString(string(st))
		case tftypes.ElementKeyString:
			pat = pat.QualString(string(st))
		case tftypes.ElementKeyInt:
			pat = pat.QualInt(int64(st))
		}
	}
	return pat
}

// Convert converts v into the CEL value of variable. block is the resource
// schema; it decides that an absent NestingList/NestingSet block is [] and an
// absent NestingSingle/NestingGroup block is null. block may be nil for
// values that are not resource objects.
func Convert(variable string, v tftypes.Value, block *tfprotov5.SchemaBlock) (Converted, error) {
	root := tftypes.NewAttributePath()
	if patterned(v) {
		return Converted{Variable: variable, Unknown: []*tftypes.AttributePath{root}}, nil
	}
	c := &converter{}
	val, err := c.value(v, root, block)
	if err != nil {
		return Converted{}, err
	}
	return Converted{Variable: variable, Value: val, Known: true, Unknown: c.unknown}, nil
}

type converter struct {
	unknown []*tftypes.AttributePath
}

// child converts a value inside a container. ok is false when the value is
// unknown (or a set that is not wholly known): the path is recorded and the
// caller leaves the entry out or puts null in its place.
func (c *converter) child(v tftypes.Value, path *tftypes.AttributePath, blk *tfprotov5.SchemaBlock) (any, bool, error) {
	if patterned(v) {
		c.unknown = append(c.unknown, path)
		return nil, false, nil
	}
	val, err := c.value(v, path, blk)
	return val, err == nil, err
}

// patterned reports whether v is replaced by one pattern on its own path:
// it is unknown, or it is a set that is not wholly known.
func patterned(v tftypes.Value) bool {
	_, isSet := v.Type().(tftypes.Set)
	return !v.IsKnown() || (isSet && !v.IsFullyKnown())
}

// value converts a known value. blk, when set, is the block schema that
// applies to the first object level (it passes through the list, set or map
// that a nested block is wrapped in).
func (c *converter) value(v tftypes.Value, path *tftypes.AttributePath, blk *tfprotov5.SchemaBlock) (any, error) {
	if v.IsNull() {
		return nil, nil
	}
	switch typ := v.Type().(type) {
	case tftypes.Object:
		return c.object(v, path, blk)
	case tftypes.Map:
		var m map[string]tftypes.Value
		if err := v.As(&m); err != nil {
			return nil, readErr(path, typ)
		}
		out := make(map[string]any, len(m))
		for _, k := range sortedKeys(m) {
			val, ok, err := c.child(m[k], path.WithElementKeyString(k), blk)
			if err != nil {
				return nil, err
			}
			if ok {
				out[k] = val
			}
		}
		return out, nil
	case tftypes.List, tftypes.Tuple:
		var l []tftypes.Value
		if err := v.As(&l); err != nil {
			return nil, readErr(path, typ)
		}
		out := make([]any, len(l))
		for i, e := range l {
			val, _, err := c.child(e, path.WithElementKeyInt(i), blk)
			if err != nil {
				return nil, err
			}
			out[i] = val
		}
		return out, nil
	case tftypes.Set:
		return c.set(v, path, blk)
	}
	if blk != nil {
		return nil, fmt.Errorf("tfval: %s: block schema for a %s value", path, v.Type())
	}
	return primitive(v, path)
}

func (c *converter) object(v tftypes.Value, path *tftypes.AttributePath, blk *tfprotov5.SchemaBlock) (any, error) {
	var attrs map[string]tftypes.Value
	if err := v.As(&attrs); err != nil {
		return nil, readErr(path, v.Type())
	}
	nested := map[string]*tfprotov5.SchemaNestedBlock{}
	if blk != nil {
		for _, nb := range blk.BlockTypes {
			nested[nb.TypeName] = nb
		}
	}
	out := make(map[string]any, len(attrs))
	for _, name := range sortedKeys(attrs) {
		av, p := attrs[name], path.WithAttributeName(name)
		nb := nested[name]
		if nb != nil && av.IsNull() {
			out[name] = absentBlock(nb.Nesting)
			continue
		}
		var nblk *tfprotov5.SchemaBlock
		if nb != nil {
			nblk = nb.Block
			if nblk == nil {
				nblk = &tfprotov5.SchemaBlock{}
			}
		}
		val, ok, err := c.child(av, p, nblk)
		if err != nil {
			return nil, err
		}
		if ok {
			out[name] = val
		}
	}
	return out, nil
}

// absentBlock is the value of a null nested block: an empty collection for
// repeated blocks (so "block required" is size(...) >= 1), null otherwise.
func absentBlock(mode tfprotov5.SchemaNestedBlockNestingMode) any {
	switch mode {
	case tfprotov5.SchemaNestedBlockNestingModeList, tfprotov5.SchemaNestedBlockNestingModeSet:
		return []any{}
	case tfprotov5.SchemaNestedBlockNestingModeMap:
		return map[string]any{}
	}
	return nil
}

// set converts a wholly known set into a list sorted by the canonical JSON
// of each element.
func (c *converter) set(v tftypes.Value, path *tftypes.AttributePath, blk *tfprotov5.SchemaBlock) (any, error) {
	var elems []tftypes.Value
	if err := v.As(&elems); err != nil {
		return nil, readErr(path, v.Type())
	}
	type keyed struct {
		key []byte
		v   tftypes.Value
	}
	ks := make([]keyed, len(elems))
	for i, e := range elems {
		k, err := CanonicalJSON(e)
		if err != nil {
			return nil, fmt.Errorf("tfval: %s: %w", path, err)
		}
		ks[i] = keyed{k, e}
	}
	slices.SortStableFunc(ks, func(a, b keyed) int { return bytes.Compare(a.key, b.key) })
	out := make([]any, len(ks))
	for i, k := range ks {
		val, err := c.value(k.v, path, blk)
		if err != nil {
			return nil, err
		}
		out[i] = val
	}
	return out, nil
}

func primitive(v tftypes.Value, path *tftypes.AttributePath) (any, error) {
	typ := v.Type()
	switch {
	case typ.Is(tftypes.String):
		return as[string](v, path)
	case typ.Is(tftypes.Bool):
		return as[bool](v, path)
	case typ.Is(tftypes.Number):
		f := new(big.Float)
		if err := v.As(&f); err != nil {
			return nil, readErr(path, typ)
		}
		return Number(f), nil
	}
	return nil, fmt.Errorf("tfval: %s: unsupported type %s", path, typ)
}

// Number maps a Terraform number to CEL: int when integral and exactly
// representable as int64 (decided on the big.Float, never through float64),
// else double.
func Number(f *big.Float) any {
	if f.IsInt() {
		if i, acc := f.Int64(); acc == big.Exact {
			return i
		}
	}
	d, _ := f.Float64()
	return d
}

func as[T any](v tftypes.Value, path *tftypes.AttributePath) (any, error) {
	var x T
	if err := v.As(&x); err != nil {
		return nil, readErr(path, v.Type())
	}
	return x, nil
}

func readErr(path *tftypes.AttributePath, typ tftypes.Type) error {
	return fmt.Errorf("tfval: %s: cannot read %s value", path, typ)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// CanonicalJSON renders a wholly known value as JSON with sorted object and
// map keys, set elements sorted by their own canonical JSON, and numbers as
// exact decimal text (integral: no exponent; else shortest round-trip form
// at the value's precision). It is the set ordering key and the value text
// the prefilter projection uses. It errors on any unknown.
func CanonicalJSON(v tftypes.Value) ([]byte, error) {
	if !v.IsFullyKnown() {
		return nil, fmt.Errorf("tfval: canonical JSON of a value that is not wholly known")
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, v tftypes.Value) error {
	if v.IsNull() {
		buf.WriteString("null")
		return nil
	}
	switch typ := v.Type().(type) {
	case tftypes.Object, tftypes.Map:
		var m map[string]tftypes.Value
		if err := v.As(&m); err != nil {
			return fmt.Errorf("tfval: cannot read %s value", typ)
		}
		buf.WriteByte('{')
		for i, k := range sortedKeys(m) {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeJSON(buf, k); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := writeCanonical(buf, m[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
		return nil
	case tftypes.List, tftypes.Tuple, tftypes.Set:
		var l []tftypes.Value
		if err := v.As(&l); err != nil {
			return fmt.Errorf("tfval: cannot read %s value", typ)
		}
		parts := make([][]byte, len(l))
		for i, e := range l {
			var eb bytes.Buffer
			if err := writeCanonical(&eb, e); err != nil {
				return err
			}
			parts[i] = eb.Bytes()
		}
		if _, isSet := typ.(tftypes.Set); isSet {
			slices.SortFunc(parts, bytes.Compare)
		}
		buf.WriteByte('[')
		buf.Write(bytes.Join(parts, []byte{','}))
		buf.WriteByte(']')
		return nil
	}
	if !v.Type().Is(tftypes.Number) {
		p, err := primitive(v, tftypes.NewAttributePath())
		if err != nil {
			return err
		}
		return writeJSON(buf, p)
	}
	f := new(big.Float)
	if err := v.As(&f); err != nil || f.IsInf() {
		return fmt.Errorf("tfval: number has no JSON form")
	}
	if f.IsInt() {
		buf.WriteString(f.Text('f', 0))
	} else {
		buf.WriteString(f.Text('g', -1))
	}
	return nil
}

func writeJSON(buf *bytes.Buffer, s any) error {
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return err
	}
	buf.Truncate(buf.Len() - 1) // drop Encode's trailing newline
	return nil
}
