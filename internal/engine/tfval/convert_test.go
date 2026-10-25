package tfval

import (
	"math/big"
	"reflect"
	"slices"
	"strings"
	"testing"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

var (
	strT  = tftypes.String
	numT  = tftypes.Number
	objA  = tftypes.Object{AttributeTypes: map[string]tftypes.Type{"a": strT}}
	objV  = tftypes.Object{AttributeTypes: map[string]tftypes.Type{"v": strT}}
	objIn = tftypes.Object{AttributeTypes: map[string]tftypes.Type{"inner": objV}}
)

// testSchema is a small aws-like resource schema covering every collection
// kind and every nested block mode the converter distinguishes.
var testSchema = &tfprotov5.SchemaBlock{
	Attributes: []*tfprotov5.SchemaAttribute{
		{Name: "name", Type: strT},
		{Name: "kms_key_id", Type: strT},
		{Name: "policy", Type: strT},
		{Name: "password", Type: strT, Sensitive: true},
		{Name: "count", Type: numT},
		{Name: "tags", Type: tftypes.Map{ElementType: strT}},
		{Name: "mobj", Type: tftypes.Map{ElementType: objA}},
		{Name: "cidrs", Type: tftypes.List{ElementType: strT}},
		{Name: "ports", Type: tftypes.Set{ElementType: numT}},
		{Name: "obj", Type: objIn},
		{Name: "lso", Type: tftypes.List{ElementType: objA}},
		{Name: "sso", Type: tftypes.Set{ElementType: objA}},
		{Name: "lis", Type: tftypes.List{ElementType: tftypes.Set{ElementType: strT}}},
		{Name: "sil", Type: tftypes.Set{ElementType: tftypes.List{ElementType: strT}}},
		{Name: "tup", Type: tftypes.Tuple{ElementTypes: []tftypes.Type{strT, numT}}},
		{Name: "dyn", Type: tftypes.DynamicPseudoType},
	},
	BlockTypes: []*tfprotov5.SchemaNestedBlock{
		{TypeName: "ingress", Nesting: tfprotov5.SchemaNestedBlockNestingModeList, Block: &tfprotov5.SchemaBlock{
			Attributes: []*tfprotov5.SchemaAttribute{
				{Name: "from_port", Type: numT},
				{Name: "cidr_blocks", Type: tftypes.List{ElementType: strT}},
			},
		}},
		{TypeName: "rule", Nesting: tfprotov5.SchemaNestedBlockNestingModeSet, Block: &tfprotov5.SchemaBlock{
			Attributes: []*tfprotov5.SchemaAttribute{{Name: "id", Type: strT}},
		}},
		{TypeName: "logging", Nesting: tfprotov5.SchemaNestedBlockNestingModeSingle, Block: &tfprotov5.SchemaBlock{
			Attributes: []*tfprotov5.SchemaAttribute{
				{Name: "bucket", Type: strT},
				{Name: "secret", Type: strT, Sensitive: true},
			},
		}},
	},
}

var rootT = testSchema.ValueType().(tftypes.Object)

func unk(t tftypes.Type) tftypes.Value { return tftypes.NewValue(t, tftypes.UnknownValue) }
func s(v string) tftypes.Value         { return tftypes.NewValue(strT, v) }
func n(v int64) tftypes.Value          { return tftypes.NewValue(numT, big.NewFloat(float64(v))) }
func oa(v tftypes.Value) tftypes.Value {
	return tftypes.NewValue(objA, map[string]tftypes.Value{"a": v})
}

// res builds a resource object; attributes not given are null.
func res(attrs map[string]tftypes.Value) tftypes.Value {
	vals := map[string]tftypes.Value{}
	tys := map[string]tftypes.Type{}
	for k, t := range rootT.AttributeTypes {
		tys[k] = t
		vals[k] = tftypes.NewValue(t, nil)
	}
	for k, v := range attrs {
		vals[k] = v
		if rootT.AttributeTypes[k].Is(tftypes.DynamicPseudoType) {
			tys[k] = v.Type()
		}
	}
	return tftypes.NewValue(tftypes.Object{AttributeTypes: tys}, vals)
}

func evalState(t *testing.T, c Converted, expr string) string {
	t.Helper()
	env, err := cel.NewEnv(cel.Variable("resource", cel.MapType(cel.StringType, cel.DynType)))
	if err != nil {
		t.Fatal(err)
	}
	ast, iss := env.Compile(expr)
	if iss.Err() != nil {
		t.Fatalf("compile %q: %v", expr, iss.Err())
	}
	prg, err := env.Program(ast, cel.EvalOptions(cel.OptPartialEval))
	if err != nil {
		t.Fatal(err)
	}
	vars := map[string]any{}
	if c.Known {
		vars["resource"] = c.Value
	}
	act, err := cel.PartialVars(vars, c.Patterns()...)
	if err != nil {
		t.Fatal(err)
	}
	val, _, err := prg.Eval(act)
	switch {
	case val != nil && types.IsUnknown(val):
		return "unknown"
	case err != nil:
		return "not_evaluable"
	case val == types.True:
		return "pass"
	case val == types.False:
		return "fail"
	}
	return "not_evaluable"
}

type convCase struct {
	name    string
	in      map[string]tftypes.Value
	attr    string // attribute whose converted value is checked
	want    any    // expected converted value of attr; absentAttr = left out
	unknown []string
	expr    string
	state   string
}

func tagsOwnerUnknown() map[string]tftypes.Value {
	return map[string]tftypes.Value{"tags": tftypes.NewValue(tftypes.Map{ElementType: strT}, map[string]tftypes.Value{
		"Owner": unk(strT), "Env": s("prod"),
	})}
}

var absentAttr = struct{ absent bool }{true}

func runCases(t *testing.T, cases []convCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := Convert("resource", res(tc.in), testSchema)
			if err != nil {
				t.Fatalf("Convert: %v", err)
			}
			got, ok := c.Value.(map[string]any)[tc.attr]
			if tc.want == absentAttr && ok {
				t.Fatalf("%s = %#v, want left out", tc.attr, got)
			} else if tc.want != absentAttr && (!ok || !reflect.DeepEqual(got, tc.want)) {
				t.Fatalf("%s = %#v (present %v), want %#v", tc.attr, got, ok, tc.want)
			}
			var paths []string
			for _, p := range c.Unknown {
				paths = append(paths, p.String())
			}
			if !slices.Equal(paths, tc.unknown) {
				t.Fatalf("unknown paths = %q, want %q", paths, tc.unknown)
			}
			if st := evalState(t, c, tc.expr); st != tc.state {
				t.Fatalf("%s: state %s, want %s", tc.expr, st, tc.state)
			}
		})
	}
}

// TestConvertNested is the "nested 8" oracle group plus set ordering.
func TestConvertNested(t *testing.T) {
	runCases(t, []convCase{
		{name: "N1 unknown in list of objects", in: map[string]tftypes.Value{"lso": tftypes.NewValue(tftypes.List{ElementType: objA}, []tftypes.Value{oa(s("x")), oa(unk(strT))})},
			attr: "lso", want: []any{map[string]any{"a": "x"}, map[string]any{}},
			unknown: []string{`AttributeName("lso").ElementKeyInt(1).AttributeName("a")`}, expr: `resource.lso.all(e, e.a == "x")`, state: "unknown",
		},
		{name: "N2 unknown in set of objects", in: map[string]tftypes.Value{"sso": tftypes.NewValue(tftypes.Set{ElementType: objA}, []tftypes.Value{oa(s("y")), oa(unk(strT))})},
			attr: "sso", want: absentAttr,
			unknown: []string{`AttributeName("sso")`}, expr: `size(resource.sso) > 0`, state: "unknown",
		},
		{name: "N3 unknown in map of objects", in: map[string]tftypes.Value{"mobj": tftypes.NewValue(tftypes.Map{ElementType: objA}, map[string]tftypes.Value{
			"k": oa(unk(strT)), "j": oa(s("ok")),
		})},
			attr: "mobj", want: map[string]any{"k": map[string]any{}, "j": map[string]any{"a": "ok"}},
			unknown: []string{`AttributeName("mobj").ElementKeyString("k").AttributeName("a")`}, expr: `resource.mobj["k"].a == "ok"`, state: "unknown",
		},
		{name: "N4 unknown in object in object", in: map[string]tftypes.Value{"obj": tftypes.NewValue(objIn, map[string]tftypes.Value{
			"inner": tftypes.NewValue(objV, map[string]tftypes.Value{"v": unk(strT)}),
		})},
			attr: "obj", want: map[string]any{"inner": map[string]any{}},
			unknown: []string{`AttributeName("obj").AttributeName("inner").AttributeName("v")`}, expr: `resource.obj.inner.v == "z"`, state: "unknown",
		},
		{name: "N5 unknown in list in set", in: map[string]tftypes.Value{"sil": tftypes.NewValue(tftypes.Set{ElementType: tftypes.List{ElementType: strT}}, []tftypes.Value{
			tftypes.NewValue(tftypes.List{ElementType: strT}, []tftypes.Value{unk(strT)}),
		})},
			attr: "sil", want: absentAttr,
			unknown: []string{`AttributeName("sil")`}, expr: `resource.sil.all(l, l.all(x, x != "*"))`, state: "unknown",
		},
		{name: "N6 unknown in set in list", in: map[string]tftypes.Value{"lis": tftypes.NewValue(tftypes.List{ElementType: tftypes.Set{ElementType: strT}}, []tftypes.Value{
			tftypes.NewValue(tftypes.Set{ElementType: strT}, []tftypes.Value{s("b"), s("a")}),
			tftypes.NewValue(tftypes.Set{ElementType: strT}, []tftypes.Value{unk(strT)}),
		})},
			attr: "lis", want: []any{[]any{"a", "b"}, nil},
			unknown: []string{`AttributeName("lis").ElementKeyInt(1)`}, expr: `size(resource.lis[1]) == 1`, state: "unknown",
		},
		{name: "N7 unknown whole collection", in: map[string]tftypes.Value{"cidrs": unk(tftypes.List{ElementType: strT}), "name": s("n")},
			attr: "cidrs", want: absentAttr,
			unknown: []string{`AttributeName("cidrs")`}, expr: `size(resource.cidrs) == 0`, state: "unknown",
		},
		{name: "N8 unknown map key value", in: tagsOwnerUnknown(), attr: "tags", want: map[string]any{"Env": "prod"},
			unknown: []string{`AttributeName("tags").ElementKeyString("Owner")`}, expr: `resource.tags["Owner"] != ""`, state: "unknown",
		},
		// Safety: a container holding an unknown never decides size(), has() or all().
		{name: "map with unknown value: size is unknown", in: tagsOwnerUnknown(), attr: "tags", want: map[string]any{"Env": "prod"},
			unknown: []string{`AttributeName("tags").ElementKeyString("Owner")`}, expr: `size(resource.tags) == 1`, state: "unknown"},
		{name: "map with unknown value: has on the unknown key is unknown", in: tagsOwnerUnknown(), attr: "tags", want: map[string]any{"Env": "prod"},
			unknown: []string{`AttributeName("tags").ElementKeyString("Owner")`}, expr: `!has(resource.tags.Owner)`, state: "unknown"},
		{name: "map with unknown value: all() is unknown", in: tagsOwnerUnknown(), attr: "tags", want: map[string]any{"Env": "prod"},
			unknown: []string{`AttributeName("tags").ElementKeyString("Owner")`}, expr: `resource.tags.all(k, k != "Owner")`, state: "unknown"},
		{name: "list with null slot: size is unknown", in: map[string]tftypes.Value{"lso": tftypes.NewValue(tftypes.List{ElementType: objA}, []tftypes.Value{unk(objA)})}, attr: "lso", want: []any{nil},
			unknown: []string{`AttributeName("lso").ElementKeyInt(0)`}, expr: `size(resource.lso) == 1`, state: "unknown"},
		{name: "list with null slot: all() is unknown, not a null error", in: map[string]tftypes.Value{"lso": tftypes.NewValue(tftypes.List{ElementType: objA}, []tftypes.Value{unk(objA)})}, attr: "lso", want: []any{nil},
			unknown: []string{`AttributeName("lso").ElementKeyInt(0)`}, expr: `resource.lso.all(x, x.a == "bar")`, state: "unknown"},
		{name: "known map decides size, has and all", in: map[string]tftypes.Value{"tags": tftypes.NewValue(tftypes.Map{ElementType: strT}, map[string]tftypes.Value{"Env": s("prod")})},
			attr: "tags", want: map[string]any{"Env": "prod"}, expr: `size(resource.tags) == 1 && has(resource.tags.Env) && resource.tags.all(k, k == "Env")`, state: "pass"},
		{name: "list with null slot for unknown: null check is unknown", in: map[string]tftypes.Value{"lso": tftypes.NewValue(tftypes.List{ElementType: objA}, []tftypes.Value{unk(objA)})},
			attr: "lso", want: []any{nil}, unknown: []string{`AttributeName("lso").ElementKeyInt(0)`}, expr: `resource.lso[0] == null`, state: "unknown"},
		{name: "known sibling of an unknown stays decided", in: map[string]tftypes.Value{"cidrs": unk(tftypes.List{ElementType: strT}), "name": s("n")},
			attr: "name", want: "n",
			unknown: []string{`AttributeName("cidrs")`}, expr: `resource.name == "n"`, state: "pass",
		},
		{name: "set of objects sorted by canonical JSON", in: map[string]tftypes.Value{"sso": tftypes.NewValue(tftypes.Set{ElementType: objA}, []tftypes.Value{
			oa(s("b")), oa(tftypes.NewValue(strT, nil)), oa(s("a")),
		})},
			attr: "sso", want: []any{map[string]any{"a": "a"}, map[string]any{"a": "b"}, map[string]any{"a": nil}},
			expr: `resource.sso[0].a == "a"`, state: "pass",
		},
		{name: "set of numbers sorted by canonical JSON bytes", in: map[string]tftypes.Value{"ports": tftypes.NewValue(tftypes.Set{ElementType: numT}, []tftypes.Value{n(443), n(3), n(22)})},
			attr: "ports", want: []any{int64(22), int64(3), int64(443)},
			expr: `22 in resource.ports`, state: "pass",
		},
		{name: "absent NestingSet block is an empty list", attr: "rule", want: []any{},
			expr: `size(resource.rule) == 0`, state: "pass",
		},
		{name: "tuple keeps order", in: map[string]tftypes.Value{"tup": tftypes.NewValue(tftypes.Tuple{ElementTypes: []tftypes.Type{strT, numT}}, []tftypes.Value{s("x"), n(7)})},
			attr: "tup", want: []any{"x", int64(7)},
			expr: `resource.tup[1] >= 7`, state: "pass",
		},
		{name: "dynamic converted by concrete type", in: map[string]tftypes.Value{"dyn": tftypes.NewValue(tftypes.List{ElementType: strT}, []tftypes.Value{s("d")})},
			attr: "dyn", want: []any{"d"},
			expr: `resource.dyn[0] == "d"`, state: "pass",
		},
	})
}

// TestConvertNullEmpty is the null/empty 8 oracle group.
func TestConvertNullEmpty(t *testing.T) {
	ingressT := rootT.AttributeTypes["ingress"]
	runCases(t, []convCase{
		{name: "E1 null attribute", attr: "kms_key_id", want: nil, expr: `resource.kms_key_id != null`, state: "fail"},
		{name: "E2 empty string", in: map[string]tftypes.Value{"name": s("")}, attr: "name", want: "", expr: `resource.name != ""`, state: "fail"},
		{
			name: "E3 empty list", in: map[string]tftypes.Value{"cidrs": tftypes.NewValue(tftypes.List{ElementType: strT}, []tftypes.Value{})},
			attr: "cidrs", want: []any{}, expr: `size(resource.cidrs) == 0`, state: "pass",
		},
		{
			name: "E4 absent NestingList block", in: map[string]tftypes.Value{"ingress": tftypes.NewValue(ingressT, nil)},
			attr: "ingress", want: []any{}, expr: `size(resource.ingress) >= 1`, state: "fail",
		},
		{name: "E5 absent NestingSingle block", attr: "logging", want: nil, expr: `resource.logging == null`, state: "pass"},
		{
			name: "E6 index 0 on empty list", in: map[string]tftypes.Value{"cidrs": tftypes.NewValue(tftypes.List{ElementType: strT}, []tftypes.Value{})},
			attr: "cidrs", want: []any{}, expr: `resource.cidrs[0] == "x"`, state: "not_evaluable",
		},
		// cel-go v0.32.0: has() on a null map is false, not an error.
		{name: "E7 null map in tags.has", attr: "tags", want: nil, expr: `has(resource.tags.Owner)`, state: "fail"},
		{name: "E8 null policy", attr: "policy", want: nil, expr: `resource.policy != null && resource.policy.contains("*")`, state: "fail"},
	})
}

// TestConvertNumbers parses each input from its decimal text at 512 bits,
// the precision tftypes decodes numbers with.
func TestConvertNumbers(t *testing.T) {
	for _, tc := range []struct {
		json string
		want any
	}{
		{"7", int64(7)},
		{"9223372036854775807", int64(1<<63 - 1)},
		{"-9223372036854775808", int64(-1 << 63)},
		{"9007199254740993", int64(9007199254740993)}, // 2^53+1, not exact in float64
		{"9223372036854775808", float64(1 << 63)},     // 2^63 overflows int64
		{"0.1", 0.1},
		{"1.5", 1.5},
	} {
		f, _, err := big.ParseFloat(tc.json, 10, 512, big.ToNearestEven)
		if err != nil {
			t.Fatal(err)
		}
		v := tftypes.NewValue(numT, f)
		c, err := Convert("n", v, nil)
		j, jerr := CanonicalJSON(v)
		if err != nil || jerr != nil || c.Value != tc.want || string(j) != tc.json {
			t.Errorf("%s: value %#v (want %#v), json %s, errs %v %v", tc.json, c.Value, tc.want, j, err, jerr)
		}
	}
}

func TestConvertWholeUnknownAndNull(t *testing.T) {
	c, err := Convert("resource", unk(rootT), testSchema)
	if err != nil || c.Known || len(c.Unknown) != 1 || len(c.Unknown[0].Steps()) != 0 {
		t.Fatalf("whole unknown: %+v %v", c, err)
	}
	if st := evalState(t, c, `resource.name == "x"`); st != "unknown" {
		t.Fatalf("U-10 state %s", st)
	}
	setT := tftypes.Set{ElementType: strT}
	c, err = Convert("s", tftypes.NewValue(setT, []tftypes.Value{s("a"), unk(strT)}), nil)
	if err != nil || c.Known || len(c.Unknown) != 1 {
		t.Fatalf("root set with unknown element: %+v %v", c, err)
	}
	c, err = Convert("prior", tftypes.NewValue(rootT, nil), testSchema)
	if err != nil || !c.Known || c.Value != nil || len(c.Unknown) != 0 {
		t.Fatalf("null root: %+v %v", c, err)
	}
}

func TestCanonicalJSONSorted(t *testing.T) {
	v := tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{"b": strT, "a": tftypes.Set{ElementType: strT}}},
		map[string]tftypes.Value{"b": s("q\"<"), "a": tftypes.NewValue(tftypes.Set{ElementType: strT}, []tftypes.Value{s("z"), s("y")})})
	j, err := CanonicalJSON(v)
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"a":["y","z"],"b":"q\"<"}`; string(j) != want {
		t.Fatalf("got %s, want %s", j, want)
	}
	if _, err := CanonicalJSON(unk(strT)); err == nil {
		t.Fatal("unknown must not have canonical JSON")
	}
}

func TestSensitivePaths(t *testing.T) {
	sp := NewSensitivePaths(testSchema)
	for read, want := range map[string]bool{
		"password": true, "logging": true, "logging.secret": true,
		"name": false, "logging.bucket": false, "passwordx": false, "": true,
	} {
		if got := sp.Overlaps(read); got != want {
			t.Errorf("Overlaps(%q) = %v, want %v", read, got, want)
		}
	}
	if !slices.Equal(sp.Paths(), []string{"logging.secret", "password"}) {
		t.Errorf("Paths = %q", sp.Paths())
	}
}

// TestConvertErrorsValueFree: a schema/value mismatch reports the path and
// type, never the value.
func TestConvertErrorsValueFree(t *testing.T) {
	const marker = "bobthecorp-SECRET-marker"
	bad := &tfprotov5.SchemaBlock{BlockTypes: []*tfprotov5.SchemaNestedBlock{
		{TypeName: "password", Nesting: tfprotov5.SchemaNestedBlockNestingModeList, Block: &tfprotov5.SchemaBlock{}},
	}}
	v := tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{"password": strT}},
		map[string]tftypes.Value{"password": s(marker)})
	_, err := Convert("resource", v, bad)
	if err == nil {
		t.Fatal("want error for block/value mismatch")
	}
	if strings.Contains(err.Error(), marker) {
		t.Fatalf("error leaks value: %v", err)
	}
}
