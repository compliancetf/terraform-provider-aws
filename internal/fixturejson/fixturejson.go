// Package fixturejson reads crosscheck fixture JSON (the cross-check case
// format) into tftypes values: absent, null or missing
// attributes are null and {"$unknown": true} is unknown. The engine tests
// (internal/engine/enginetest) and the generator's verify (internal/bundlegen)
// share it, so a fixture means the same in both.
package fixturejson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// Value builds a value of typ from fixture JSON. A key the schema type does
// not have is an error, naming its path: a typo would otherwise be null.
func Value(typ tftypes.Type, raw json.RawMessage) (tftypes.Value, error) {
	var v any
	if len(raw) > 0 {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&v); err != nil {
			return tftypes.Value{}, err
		}
		if _, err := dec.Token(); err != io.EOF {
			return tftypes.Value{}, errors.New("data after the fixture value")
		}
	}
	return build(typ, v, "")
}

func build(typ tftypes.Type, v any, path string) (tftypes.Value, error) {
	if IsUnknown(v) {
		return tftypes.NewValue(typ, tftypes.UnknownValue), nil
	}
	if v == nil {
		return tftypes.NewValue(typ, nil), nil
	}
	m, isMap := v.(map[string]any)
	l, isList := v.([]any)
	bad := func(want string) (tftypes.Value, error) {
		return tftypes.Value{}, fmt.Errorf("%s: want %s for %s", path, want, typ)
	}
	switch typ := typ.(type) {
	case tftypes.Object:
		if !isMap {
			return bad("an object")
		}
		for k := range m {
			if _, ok := typ.AttributeTypes[k]; !ok {
				return tftypes.Value{}, fmt.Errorf("fixture key %q at %q is not in the schema", k, path)
			}
		}
		out := map[string]tftypes.Value{}
		for k, at := range typ.AttributeTypes {
			x, err := build(at, m[k], path+"."+k)
			if err != nil {
				return tftypes.Value{}, err
			}
			out[k] = x
		}
		return tftypes.NewValue(typ, out), nil
	case tftypes.Map:
		if !isMap {
			return bad("an object")
		}
		out := map[string]tftypes.Value{}
		for k, e := range m {
			x, err := build(typ.ElementType, e, path+"["+k+"]")
			if err != nil {
				return tftypes.Value{}, err
			}
			out[k] = x
		}
		return tftypes.NewValue(typ, out), nil
	case tftypes.List:
		return elems(typ, typ.ElementType, l, isList, path)
	case tftypes.Set:
		return elems(typ, typ.ElementType, l, isList, path)
	}
	switch {
	case typ.Is(tftypes.Number):
		n, ok := v.(json.Number)
		if !ok {
			return bad("a number")
		}
		f, _, err := big.ParseFloat(string(n), 10, 512, big.ToNearestEven)
		if err != nil {
			return tftypes.Value{}, fmt.Errorf("%s: %w", path, err)
		}
		return tftypes.NewValue(typ, f), nil
	case typ.Is(tftypes.String):
		if _, ok := v.(string); !ok {
			return bad("a string")
		}
	case typ.Is(tftypes.Bool):
		if _, ok := v.(bool); !ok {
			return bad("a bool")
		}
	}
	return tftypes.NewValue(typ, v), nil
}

func elems(typ, et tftypes.Type, l []any, ok bool, path string) (tftypes.Value, error) {
	if !ok {
		return tftypes.Value{}, fmt.Errorf("%s: want an array for %s", path, typ)
	}
	var out []tftypes.Value
	for i, e := range l {
		x, err := build(et, e, fmt.Sprintf("%s[%d]", path, i))
		if err != nil {
			return tftypes.Value{}, err
		}
		out = append(out, x)
	}
	return tftypes.NewValue(typ, out), nil
}

// IsUnknown reports the {"$unknown": true} marker in decoded JSON.
func IsUnknown(v any) bool {
	m, ok := v.(map[string]any)
	return ok && len(m) == 1 && m["$unknown"] == true
}

// String reads a fixture string: absent or {"$unknown": true} is unknown
// (known false); a JSON null or any other value is an error that names the
// expected type only, never the value.
func String(raw json.RawMessage) (s string, known bool, err error) {
	if len(raw) == 0 {
		return "", false, nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", false, errors.New("not JSON")
	}
	if IsUnknown(v) {
		return "", false, nil
	}
	s, ok := v.(string)
	if !ok {
		return "", false, errors.New(`want a string or {"$unknown": true}`)
	}
	return s, true, nil
}
