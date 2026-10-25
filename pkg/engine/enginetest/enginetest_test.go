package enginetest

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// TestDecodeRejects: malformed reserved forms and oversized repeats error
// instead of decoding as data or allocating.
func TestDecodeRejects(t *testing.T) {
	str, list := tftypes.String, tftypes.List{ElementType: tftypes.String}
	m := tftypes.Map{ElementType: tftypes.Bool}
	for _, c := range []struct {
		typ tftypes.Type
		raw string
	}{
		{list, `{"$repeat": 2, "typo": "x"}`},
		{list, `{"$repeat": 2}`},
		{m, `{"$unknown": false}`},
		{m, `{"$x": true}`},
		{str, `{"$unknown": true, "of": "a"}`},
		{list, `{"$repeat": 1048577, "of": "a"}`},
		{str, `{"$repeat": 9223372036854775807, "of": "aa"}`},
		{str, `{"$repeat": 524289, "of": "aa"}`},
		{str, `{"$repeat": -1, "of": "a"}`},
		{str, `{"$repeat": 0, "of": "a"}`},
		{list, `{"$repeat": 0, "of": "a"}`},
		{tftypes.List{ElementType: list}, `{"$repeat": 0, "of": {"$repeat": 1048576, "of": "a"}}`},
		{tftypes.List{ElementType: list}, `{"$repeat": 1024, "of": {"$repeat": 1048576, "of": "a"}}`},
		{tftypes.List{ElementType: list}, `{"$repeat": 65536, "of": {"$repeat": 65536, "of": "a"}}`},
		{tftypes.List{ElementType: list}, `{"$repeat": 1024, "of": {"$repeat": 1025, "of": "a"}}`},
		{tftypes.List{ElementType: list}, `{"$repeat": 1025, "of": {"$repeat": 1024, "of": "a"}}`},
		{tftypes.List{ElementType: list}, `{"$repeat": 524289, "of": ["a", "b"]}`},
		{list, `{"$repeat": 2, "of": {"$repeat": 524289, "of": "a"}}`},
		{tftypes.List{ElementType: tftypes.List{ElementType: list}}, `[{"$repeat": 0, "of": {"$repeat": 1048576, "of": "a"}}, {"$repeat": 0, "of": {"$repeat": 1, "of": "a"}}]`},
		{tftypes.List{ElementType: tftypes.List{ElementType: tftypes.List{ElementType: list}}}, `{"$repeat": 0, "of": {"$repeat": 1048576, "of": {"$repeat": 0, "of": {"$repeat": 1048576, "of": "a"}}}}`},
		{tftypes.Object{AttributeTypes: map[string]tftypes.Type{}}, `{"secret-key": "x"}`},
	} {
		if _, err := Decode(c.typ, []byte(c.raw)); err == nil || strings.Contains(err.Error(), "secret") {
			t.Errorf("%s as %s: %v", c.raw, c.typ, err)
		}
	}
	for _, raw := range []string{
		`{"$repeat": 1048576, "of": "a"}`,
	} {
		if v, err := Decode(str, []byte(raw)); err != nil || v.IsNull() {
			t.Fatalf("%s: %v", raw, err)
		}
	}
	// Nested repeats multiply: 1024 x 1024 is the whole budget, 1023 x 1024 under it.
	for _, raw := range []string{
		`{"$repeat": 1024, "of": {"$repeat": 1024, "of": "a"}}`,
		`{"$repeat": 1023, "of": {"$repeat": 1024, "of": "a"}}`,
	} {
		if v, err := Decode(tftypes.List{ElementType: list}, []byte(raw)); err != nil || v.IsNull() {
			t.Fatalf("%s: %v", raw, err)
		}
	}
}

// TestDecodeWeight: decode returns the weight a $repeat charges, equal to
// walking the value, and deep unary repeats do not re-walk their subtree.
func TestDecodeWeight(t *testing.T) {
	list := tftypes.List{ElementType: tftypes.String}
	obj := tftypes.Object{AttributeTypes: map[string]tftypes.Type{"l": list, "n": tftypes.Number, "s": tftypes.String}}
	for _, c := range []struct {
		typ tftypes.Type
		raw string
	}{
		{tftypes.String, `"abc"`},
		{tftypes.String, `""`},
		{list, `[]`},
		{list, `["ab", null, {"$unknown": true}, {"$repeat": 3, "of": "x"}]`},
		{tftypes.List{ElementType: list}, `{"$repeat": 70, "of": ["a", "bb"]}`},
		{obj, `{"l": {"$repeat": 2, "of": "abc"}, "s": "xy"}`},
		{tftypes.Map{ElementType: list}, `{"k": [], "j": ["q"]}`},
	} {
		left := int64(maxRepeat)
		x, err := Decode(c.typ, []byte(c.raw))
		if err != nil {
			t.Fatalf("%s: %v", c.raw, err)
		}
		var raw any
		dec := json.NewDecoder(strings.NewReader(c.raw))
		dec.UseNumber()
		if err := dec.Decode(&raw); err != nil {
			t.Fatal(err)
		}
		_, w, err := decode(c.typ, raw, &left)
		if err != nil || w != weight(x) {
			t.Errorf("%s: decode weight %d, walked %d (%v)", c.raw, w, weight(x), err)
		}
	}
	// 1000 unary repeats around a full-budget inner list once walked about
	// 2e9 leaves.
	typ, raw := tftypes.Type(list), `{"$repeat": 1048576, "of": "a"}`
	for range 1000 {
		typ, raw = tftypes.List{ElementType: typ}, `{"$repeat": 1, "of": `+raw+`}`
	}
	if _, err := Decode(typ, []byte(raw)); err != nil {
		t.Fatalf("deep unary repeats: %v", err)
	}
}

// TestEncodeNestedBudget: Encode charges a nested repeat as Decode does, so a
// value at the budget round-trips through $repeat and one past it does not
// need the budget to decode.
func TestEncodeNestedBudget(t *testing.T) {
	typ := tftypes.List{ElementType: tftypes.List{ElementType: tftypes.String}}
	for _, n := range []int{1024, 1025} {
		inner := tftypes.NewValue(typ.ElementType, slices.Repeat([]tftypes.Value{tftypes.NewValue(tftypes.String, "a")}, 1024))
		v := tftypes.NewValue(typ, slices.Repeat([]tftypes.Value{inner}, n))
		raw, err := Encode(v)
		if err != nil {
			t.Fatal(err)
		}
		if outer := bytes.HasPrefix(raw, []byte(`{"$repeat":`)); outer != (n == 1024) {
			t.Fatalf("n=%d: outer $repeat %v", n, outer)
		}
		got, err := Decode(typ, raw)
		if err != nil || !got.Equal(v) {
			t.Fatalf("n=%d round trip: %v", n, err)
		}
	}
}

// TestEncodeDecodeBudget: past the budget Encode writes plain values, which
// Decode reads back.
func TestEncodeDecodeBudget(t *testing.T) {
	typ := tftypes.List{ElementType: tftypes.String}
	v := tftypes.NewValue(typ, []tftypes.Value{
		tftypes.NewValue(tftypes.String, strings.Repeat("a", maxRepeat)),
		tftypes.NewValue(tftypes.String, strings.Repeat("a", maxRepeat+1)),
	})
	raw, err := Encode(v)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(typ, raw)
	if err != nil || !got.Equal(v) {
		t.Fatalf("round trip: %v", err)
	}
}

func TestEncodeReservedKeyValueFree(t *testing.T) {
	v := tftypes.NewValue(tftypes.Map{ElementType: tftypes.String}, map[string]tftypes.Value{
		"$secret-key": tftypes.NewValue(tftypes.String, "x"),
	})
	_, err := Encode(v)
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("got %v", err)
	}
}

func TestLoadRejects(t *testing.T) {
	for _, doc := range []string{
		`{"vectors": []} {}`,
		`{"vectors": [{"name": "a", "selector": "true"}]}`,
		`{"vectors": [{"name": "a", "selector": "x", "compile_error": "e", "want": {"state": "pass"}}]}`,
	} {
		p := filepath.Join(t.TempDir(), "v.json")
		if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil {
			t.Errorf("%s: loaded", doc)
		}
	}
}
