// Package enginetest reads and writes the selector cross-check vectors in
// pkg/engine/testdata: a selector, the values it binds and the outcome the
// provider's exception tests recorded for it. A tool that imports pkg/engine
// runs the vectors to show it binds selectors as the provider does.
//
// Value encoding (typed by the vector's schema): JSON null is null,
// {"$unknown": true} is unknown, {"$repeat": n, "of": x} with n >= 1 is n
// copies of x (a list or set of n elements, or a string of x repeated n
// times), numbers parse at 512-bit precision. Keys starting with "$" are
// reserved: an object holding one is exactly one of the two forms above. The
// $repeat forms of one value expand to at most 1<<20 elements and string
// bytes in total: a list $repeat costs n times the leaf elements and string
// bytes of x, so nested forms multiply. An absent resource, config or prior
// binds null.
package enginetest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"maps"
	"math/big"
	"os"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/pkg/engine"
)

// File is one vectors file.
type File struct {
	Comment string                     `json:"_comment"`
	Schemas map[string]json.RawMessage `json:"schemas"` // type -> `terraform providers schema -json` schema object
	Vectors []Vector                   `json:"vectors"`
}

// Vector is one selector case. CompileError set: CompileSelector fails with
// that message and nothing else applies.
type Vector struct {
	Name         string          `json:"name"`
	Selector     string          `json:"selector"`
	CompileError string          `json:"compile_error,omitempty"`
	Type         string          `json:"type,omitempty"`
	Op           string          `json:"op,omitempty"`
	Env          string          `json:"env,omitempty"`
	EnvKnown     bool            `json:"env_known,omitempty"`
	Provider     Provider        `json:"provider,omitzero"`
	Resource     json.RawMessage `json:"resource,omitempty"`
	Config       json.RawMessage `json:"config,omitempty"`
	Prior        json.RawMessage `json:"prior,omitempty"`
	Want         *Want           `json:"want,omitempty"`
}

// Provider holds the known provider fields; nil is unknown.
type Provider struct {
	Region    *string `json:"region,omitempty"`
	AccountID *string `json:"account_id,omitempty"`
	Partition *string `json:"partition,omitempty"`
}

// Want is the recorded outcome.
type Want struct {
	State        engine.State    `json:"state"`
	Err          engine.ErrClass `json:"err,omitempty"`
	UnknownPaths []string        `json:"unknown_paths,omitempty"`
}

// Load reads a vectors file; unknown fields, trailing data and a vector
// without exactly one of compile_error and want are an error.
func Load(path string) (*File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var f File
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("%s: data after the document", path)
	}
	for i, v := range f.Vectors {
		if (v.CompileError == "") == (v.Want == nil) {
			return nil, fmt.Errorf("%s: vector %d: want exactly one of compile_error and want", path, i)
		}
	}
	return &f, nil
}

// Input builds the evaluation input of v.
func (f *File) Input(v *Vector) (*engine.Input, error) {
	raw, ok := f.Schemas[v.Type]
	if !ok {
		return nil, fmt.Errorf("vector %s: no schema for %q", v.Name, v.Type)
	}
	sc, err := engine.SchemaFromJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("vector %s: %w", v.Name, err)
	}
	in := &engine.Input{Type: v.Type, Schema: sc, Op: v.Op, Env: v.Env, EnvKnown: v.EnvKnown}
	typ := sc.ValueType()
	for _, x := range []struct {
		raw json.RawMessage
		out *tftypes.Value
	}{{v.Resource, &in.Resource}, {v.Config, &in.Config}, {v.Prior, &in.Prior}} {
		if x.raw == nil {
			continue
		}
		if *x.out, err = Decode(typ, x.raw); err != nil {
			return nil, fmt.Errorf("vector %s: %w", v.Name, err)
		}
	}
	p := &in.Provider
	p.Region, p.RegionKnown = deref(v.Provider.Region)
	p.AccountID, p.AccountKnown = deref(v.Provider.AccountID)
	p.Partition, p.PartitionKnown = deref(v.Provider.Partition)
	return in, nil
}

// ProviderOf is the vector form of p.
func ProviderOf(p engine.ProviderInfo) Provider {
	ref := func(s string, known bool) *string {
		if !known {
			return nil
		}
		return &s
	}
	return Provider{ref(p.Region, p.RegionKnown), ref(p.AccountID, p.AccountKnown), ref(p.Partition, p.PartitionKnown)}
}

func deref(s *string) (string, bool) {
	if s == nil {
		return "", false
	}
	return *s, true
}

// repeatMin is the run length from which Encode writes $repeat.
const repeatMin = 64

// Encode writes v in the vector encoding. A zero Value is nil (absent).
func Encode(v tftypes.Value) (json.RawMessage, error) {
	if v.Type() == nil {
		return nil, nil
	}
	left := int64(maxRepeat)
	x, err := encode(v, &left)
	if err != nil {
		return nil, err
	}
	return json.Marshal(x)
}

// encode writes $repeat only while the decode budget left allows it, so
// Decode reads back everything Encode writes.
func encode(v tftypes.Value, left *int64) (any, error) {
	switch {
	case !v.IsKnown():
		return map[string]bool{"$unknown": true}, nil
	case v.IsNull():
		return nil, nil
	}
	switch t := v.Type().(type) {
	case tftypes.List, tftypes.Set:
		var elems []tftypes.Value
		if err := v.As(&elems); err != nil {
			return nil, err
		}
		if c := int64(len(elems)); c >= repeatMin && weight(elems[0]) <= *left/c &&
			!slices.ContainsFunc(elems, func(e tftypes.Value) bool { return !e.Equal(elems[0]) }) {
			scratch := *left
			x, err := encode(elems[0], &scratch)
			*left -= c * weight(elems[0])
			return map[string]any{"$repeat": len(elems), "of": x}, err
		}
		out := make([]any, len(elems))
		for i, e := range elems {
			var err error
			if out[i], err = encode(e, left); err != nil {
				return nil, err
			}
		}
		return out, nil
	case tftypes.Map, tftypes.Object:
		var m map[string]tftypes.Value
		if err := v.As(&m); err != nil {
			return nil, err
		}
		out := map[string]any{}
		for k, e := range m {
			if strings.HasPrefix(k, "$") {
				return nil, errors.New("map key uses the reserved $ prefix")
			}
			var err error
			if out[k], err = encode(e, left); err != nil {
				return nil, err
			}
		}
		return out, nil
	default:
		switch {
		case t.Is(tftypes.String):
			var s string
			if err := v.As(&s); err != nil {
				return nil, err
			}
			if len(s) >= repeatMin && int64(len(s)) <= *left && s[0] < 0x80 && strings.Count(s, s[:1]) == len(s) {
				*left -= int64(len(s))
				return map[string]any{"$repeat": len(s), "of": s[:1]}, nil
			}
			return s, nil
		case t.Is(tftypes.Number):
			f := new(big.Float)
			if err := v.As(&f); err != nil {
				return nil, err
			}
			return json.Number(f.Text('g', -1)), nil
		case t.Is(tftypes.Bool):
			var b bool
			err := v.As(&b)
			return b, err
		}
	}
	return nil, fmt.Errorf("type %s is not supported", v.Type())
}

// Decode reads raw, in the vector encoding, as a value of typ.
func Decode(typ tftypes.Type, raw json.RawMessage) (tftypes.Value, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var x any
	if err := dec.Decode(&x); err != nil {
		return tftypes.Value{}, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return tftypes.Value{}, errors.New("data after the value")
	}
	left := int64(maxRepeat)
	v, _, err := decode(typ, x, &left)
	return v, err
}

// decode reads x as typ and returns its weight; left is the $repeat
// expansion budget of the value.
func decode(typ tftypes.Type, x any, left *int64) (tftypes.Value, int64, error) {
	if x == nil {
		return tftypes.NewValue(typ, nil), 1, nil
	}
	if m, ok := x.(map[string]any); ok && hasReserved(m) {
		of, hasOf := m["of"]
		switch n, isN := m["$repeat"].(json.Number); {
		case m["$unknown"] == true && len(m) == 1:
			return tftypes.NewValue(typ, tftypes.UnknownValue), 1, nil
		case isN && hasOf && len(m) == 2:
			return repeat(typ, n, of, left)
		}
		return tftypes.Value{}, 0, errors.New("malformed reserved $ form")
	}
	switch t := typ.(type) {
	case tftypes.List, tftypes.Set:
		l, ok := x.([]any)
		if !ok {
			return tftypes.Value{}, 0, fmt.Errorf("want a list for %s", typ)
		}
		et := elemType(t)
		elems := make([]tftypes.Value, len(l))
		var sum int64
		for i, e := range l {
			var w int64
			var err error
			if elems[i], w, err = decode(et, e, left); err != nil {
				return tftypes.Value{}, 0, err
			}
			sum = addWeight(sum, w)
		}
		return tftypes.NewValue(typ, elems), max(1, sum), nil
	case tftypes.Object:
		m, ok := x.(map[string]any)
		if !ok {
			return tftypes.Value{}, 0, fmt.Errorf("want an object for %s", typ)
		}
		for _, k := range slices.Sorted(maps.Keys(m)) {
			if _, ok := t.AttributeTypes[k]; !ok {
				return tftypes.Value{}, 0, fmt.Errorf("object key not an attribute of %s", typ)
			}
		}
		return decodeMap(typ, maps.Keys(t.AttributeTypes), func(k string) tftypes.Type { return t.AttributeTypes[k] }, m, left)
	case tftypes.Map:
		m, ok := x.(map[string]any)
		if !ok {
			return tftypes.Value{}, 0, fmt.Errorf("want an object for %s", typ)
		}
		return decodeMap(typ, maps.Keys(m), func(string) tftypes.Type { return t.ElementType }, m, left)
	}
	switch {
	case typ.Is(tftypes.Number):
		n, ok := x.(json.Number)
		if !ok {
			return tftypes.Value{}, 0, fmt.Errorf("want a number for %s", typ)
		}
		f, _, err := big.ParseFloat(string(n), 10, 512, big.ToNearestEven)
		if err != nil {
			return tftypes.Value{}, 0, err
		}
		return tftypes.NewValue(typ, f), 1, nil
	case typ.Is(tftypes.String), typ.Is(tftypes.Bool):
		if err := tftypes.ValidateValue(typ, x); err != nil {
			return tftypes.Value{}, 0, err
		}
		if s, ok := x.(string); ok {
			return tftypes.NewValue(typ, x), max(1, int64(len(s))), nil
		}
		return tftypes.NewValue(typ, x), 1, nil
	}
	return tftypes.Value{}, 0, fmt.Errorf("type %s is not supported", typ)
}

// decodeMap decodes the keys of an object or map; a key absent from m is null.
func decodeMap(typ tftypes.Type, keys iter.Seq[string], at func(string) tftypes.Type, m map[string]any, left *int64) (tftypes.Value, int64, error) {
	vals := map[string]tftypes.Value{}
	var sum int64
	for k := range keys {
		var w int64
		var err error
		if vals[k], w, err = decode(at(k), m[k], left); err != nil {
			return tftypes.Value{}, 0, err
		}
		sum = addWeight(sum, w)
	}
	return tftypes.NewValue(typ, vals), max(1, sum), nil
}

func hasReserved(m map[string]any) bool {
	for k := range m {
		if strings.HasPrefix(k, "$") {
			return true
		}
	}
	return false
}

// maxRepeat bounds the $repeat expansion (elements and string bytes) of one
// value, nested forms included, so a malformed file errors before it
// allocates; the vectors stay far below it.
const maxRepeat = 1 << 20

// weight is what one copy of v costs in a $repeat: its string bytes and
// leaf elements, at least 1, capped just past maxRepeat. A value whose
// elements cannot be read weighs past the cap, so the repeat is rejected.
// Decode returns the same weight with each value instead of walking it.
func weight(v tftypes.Value) int64 {
	if !v.IsKnown() || v.IsNull() {
		return 1
	}
	var kids []tftypes.Value
	switch v.Type().(type) {
	case tftypes.List, tftypes.Set:
		if v.As(&kids) != nil {
			return maxRepeat + 1
		}
	case tftypes.Map, tftypes.Object:
		var m map[string]tftypes.Value
		if v.As(&m) != nil {
			return maxRepeat + 1
		}
		kids = slices.Collect(maps.Values(m))
	default:
		var s string
		if v.Type().Is(tftypes.String) && v.As(&s) == nil {
			return max(1, int64(len(s)))
		}
		return 1
	}
	var n int64
	for _, k := range kids {
		if n = addWeight(n, weight(k)); n > maxRepeat {
			return n
		}
	}
	return max(1, n)
}

func repeat(typ tftypes.Type, n json.Number, of any, left *int64) (tftypes.Value, int64, error) {
	c, err := n.Int64()
	if err != nil || c < 1 || c > *left {
		return tftypes.Value{}, 0, errors.New("$repeat count out of range")
	}
	if s, ok := of.(string); ok && typ.Is(tftypes.String) {
		if int64(len(s))*c > *left {
			return tftypes.Value{}, 0, errors.New("$repeat string too long")
		}
		*left -= int64(len(s)) * c
		return tftypes.NewValue(typ, strings.Repeat(s, int(c))), max(1, int64(len(s))*c), nil
	}
	switch typ.(type) {
	case tftypes.List, tftypes.Set:
		// The element decodes once against a scratch budget, then its c
		// copies are charged c times its weight. As c >= 1 and nothing
		// decoded is dropped, that covers what decoding the element spent.
		scratch := *left
		e, w, err := decode(elemType(typ), of, &scratch)
		if err != nil {
			return tftypes.Value{}, 0, err
		}
		if w > *left/c {
			return tftypes.Value{}, 0, errors.New("$repeat expands past the budget")
		}
		*left -= c * w
		return tftypes.NewValue(typ, slices.Repeat([]tftypes.Value{e}, int(c))), c * w, nil
	}
	return tftypes.Value{}, 0, fmt.Errorf("$repeat for %s", typ)
}

// addWeight sums weights, saturating just past maxRepeat.
func addWeight(a, b int64) int64 {
	return min(a+b, maxRepeat+1)
}

func elemType(t tftypes.Type) tftypes.Type {
	switch t := t.(type) {
	case tftypes.List:
		return t.ElementType
	case tftypes.Set:
		return t.ElementType
	}
	return nil
}
