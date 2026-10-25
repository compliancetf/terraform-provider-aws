package celeng

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
)

// TestReads is the oracle: one row per AST shape of the reads analysis,
// plus the fork picks recorded in the PR (no cel.bind,
// no whole-variable use incl. null tests).
func TestReads(t *testing.T) {
	cases := []struct {
		name, expr string
		want       []string // "var:path", sorted
		code       string   // load error id; want ignored when set
	}{
		{"select chain", "resource.a.b == 1", []string{"resource:a.b"}, ""},
		{"const int index", "resource.a[0].b == 1", []string{"resource:a.b"}, ""},
		{"const string index is a step", `resource.a["k"].b == 1`, []string{"resource:a.k.b"}, ""},
		{"non-attribute key ends the path", `resource.tags["aws:x"] == "1"`, []string{"resource:tags"}, ""},
		{"select below a non-attribute key", `!has(resource.a["aws:x"].b)`, nil, "control_dynamic_access"},
		{"computed list equality", `resource.a.filter(x, x.b == 1) != [{"b": 1}]`, nil, "control_dynamic_access"},
		{"computed element membership", `resource.a.filter(x, true).exists(y, y in [{"b": 1}])`, nil, "control_dynamic_access"},
		{"computed list membership of a map", `!({"b": 1} in resource.a.filter(x, true))`, nil, "control_dynamic_access"},
		{"map key", `resource.tags["Owner"] != ""`, []string{"resource:tags"}, ""},
		{"root string index is a field", `resource["kms_key_id"] != null`, []string{"resource:kms_key_id"}, ""},
		{"comprehension binds range", "resource.a.exists(x, x.b == 1)", []string{"resource:a.b"}, ""},
		{"comprehension U-04", `resource.ingress.all(r, !("0.0.0.0/0" in r.cidr_blocks))`, []string{"resource:ingress.cidr_blocks"}, ""},
		{"nested comprehension", "resource.a.all(x, x.c.exists(y, y.d == 1))", []string{"resource:a.c.d"}, ""},
		{"iter var used whole", `resource.a.exists(x, x == "v")`, []string{"resource:a"}, ""},
		{"iter var unused reads range", "resource.a.exists(x, true)", []string{"resource:a"}, ""},
		{"map macro", "resource.a.map(x, x.b).exists(y, y == 1)", []string{"resource:a.b"}, ""},
		{"has", "has(resource.a.b)", []string{"resource:a.b"}, ""},
		{"function whole subtree", "size(resource.a) >= 1", []string{"resource:a"}, ""},
		{"type name is not a variable", "type(resource.a) == string", []string{"resource:a"}, ""},
		{"in operator", `"x" in resource.tags`, []string{"resource:tags"}, ""},
		{"prior and op", `op == "create" || prior.tags == resource.tags`, []string{"prior:tags", "resource:tags"}, ""},
		{"shadowing a variable", "[1].all(resource, resource > 0) && resource.a", nil, "control_dynamic_access"},
		{"absolute name under shadowing", "[1].all(resource, .resource.a == 1)", nil, "control_dynamic_access"},
		{"absolute name", ".resource.a == 1", []string{"resource:a"}, ""},
		// A field below a computed value has no path: reject.
		{"filter then select", "resource.a.filter(x, x.b).all(y, y.c)", nil, "control_dynamic_access"},
		{"map then select", "resource.a.map(x, x.b).all(y, y.c)", nil, "control_dynamic_access"},
		{"filter then index", "resource.a.filter(x, x.b)[0].c == 1", nil, "control_dynamic_access"},
		{"has through dyn", "resource.ingress.all(r, !has(dyn(r).no_such_field))", nil, "control_dynamic_access"},
		{"index through dyn", `dyn(resource.a)["b"] == 1`, nil, "control_dynamic_access"},
		{"erasure inside a comprehension range", "resource.a.filter(x, x.b).map(y, y.c).all(z, z == 1)", nil, "control_dynamic_access"},
		{"erasure inside size", "size(dyn(resource.a).b) > 0", nil, "control_dynamic_access"},
		{"erasure then later select", "resource.a.filter(x, x.b).all(y, y.c) && resource.d == 1", nil, "control_dynamic_access"},
		{"filter then whole element", "resource.a.filter(x, x.b).all(y, y == 1)", []string{"resource:a", "resource:a.b"}, ""},
		{"nested same-name iter var", "resource.a.all(x, x.b.all(x, x.c == 1) && x.d == 2)", []string{"resource:a.b.c", "resource:a.d"}, ""},
		{"iter var as inner range", "resource.a.all(x, x.exists(y, true))", []string{"resource:a"}, ""},
		{"same path, same name", "resource.a.all(x, resource.a.all(x, x.c == 1))", []string{"resource:a", "resource:a.c"}, ""},
		{"dynamic index on iter var", "resource.a.exists(x, x[op] == 1)", nil, "control_dynamic_access"},
		{"range used only via outer name", "resource.a.exists(x, resource.a.b == 1)", []string{"resource:a", "resource:a.b"}, ""},
		{"root key not an attribute name", `resource["a.b"] == 1`, nil, "control_dynamic_access"},
		{"member function target", `resource.name.startsWith("x")`, []string{"resource:name"}, ""},
		// iam.parse results have a fixed shape: selects below them are allowed.
		{"iam.parse statements", `iam.parse(resource.policy).statements.all(s, s.effect == "Deny")`, []string{"resource:policy"}, ""},
		{"iam.parse nested comprehension", `iam.parse(resource.policy).statements.exists(s, s.conditions.exists(c, c.key == "k") && iam.grants(s, "s3:getobject"))`, []string{"resource:policy"}, ""},
		{"iam.parse index, size, in", `size(iam.parse(resource.policy).statements[0].actions) > 0 && "*" in iam.parse(resource.policy).statements[0].actions`, []string{"resource:policy"}, ""},
		{"iam.parse argument still checked", `iam.parse(resource.a.filter(x, true)[0].b).version == ""`, nil, "control_dynamic_access"},
		{"json.path result stays computed", `json.path(resource.policy, "").Statement == null`, nil, "control_dynamic_access"},
		{"ternary hides the shape", `(op == "create" ? iam.parse(resource.policy) : resource.obj).version == ""`, nil, "control_dynamic_access"},
		{"member size", "resource.tags.size() > 0", []string{"resource:tags"}, ""},
		{"ternary", "(op == 'create' ? resource.a : resource.b).c == 1", nil, "control_dynamic_access"},
		{"select on a literal", `{"c": 1}.c == 1 && resource.a`, []string{"resource:a"}, ""},
		{"dynamic index", "resource.a[resource.k] == 1", nil, "control_dynamic_access"},
		{"dynamic root index", `["a"].all(k, resource[k] == 1)`, nil, "control_dynamic_access"},
		{"whole variable", "size(resource) > 0", nil, "control_dynamic_access"},
		{"whole variable null test via dyn", "dyn(prior) == null", nil, "control_dynamic_access"},
		{"whole variable null test", "prior == null", nil, "control_expr"}, // map == null has no overload
		{"iter over whole variable", "resource.exists(k, k == 'a')", nil, "control_dynamic_access"},
		{"cel.bind not in env", "cel.bind(x, resource.a, x.b == 1)", nil, "control_expr"},
		{"optional syntax off", "resource.?a.hasValue()", nil, "control_expr"},
		// Key tests and key enumeration on a computed value of data have no
		// path the schema check could type: reject.
		{"key in dyn", `!("x" in dyn(resource.a))`, nil, "control_dynamic_access"},
		{"key in erased element", `[resource.a].all(x, !("k" in x))`, nil, "control_dynamic_access"},
		{"iterate keys of dyn", `!dyn(resource.a).exists(k, k == "x")`, nil, "control_dynamic_access"},
		{"size of dyn", "size(dyn(resource.a)) == 0", nil, "control_dynamic_access"},
		{"iterate keys of ternary", `(op == "create" ? resource.a : resource.b).all(k, k != "x")`, nil, "control_dynamic_access"},
		{"key in computed list", `"x" in resource.a.map(y, y.b)`, []string{"resource:a.b"}, ""},
		{"size of computed string", `size(resource.a.lowerAscii()) > 0`, []string{"resource:a"}, ""},
		{"dyn output allowed", "resource.a.b", []string{"resource:a.b"}, ""},
		{"int output", "size(resource.a)", nil, "control_expr"},
		{"string output", `"x"`, nil, "control_expr"},
		{"parse error", "resource.a ==", nil, "control_expr"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, err := check(tc.expr)
			if tc.code != "" {
				if code := diagCode(err); code != tc.code {
					t.Fatalf("want %s, got %v", tc.code, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, r := range a.Reads {
				got = append(got, r.Var+":"+r.Path)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("reads = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestReadsVars pins the variable-by-mode table (control_vars).
func TestReadsVars(t *testing.T) {
	type mode struct {
		kind bundle.Kind
		pm   bundle.PresenceMode
	}
	allowed := map[mode][]string{
		{bundle.KindResource, bundle.PresenceEffective}:    {"resource", "prior", "op", "env", "provider"},
		{bundle.KindResource, bundle.PresenceConfigured}:   {"config", "prior", "op", "env", "provider"},
		{bundle.KindDeletionGuard, ""}:                     {"prior", "op", "env", "provider"},
		{bundle.KindDataSource, bundle.PresenceEffective}:  {"resource", "env", "provider"},
		{bundle.KindDataSource, bundle.PresenceConfigured}: {"config", "env", "provider"},
		{bundle.KindEphemeral, ""}:                         {"config", "env", "provider"},
	}
	exprs := map[string]string{
		"resource": "resource.a == 1", "config": "config.a == 1", "prior": "prior.a == 1",
		"op": `op == "create"`, "env": `env == "prod"`, "provider": `provider.region == "eu-west-1"`,
	}
	for m, ok := range allowed {
		for v, expr := range exprs {
			c := testControl(m.kind, m.pm, expr, "a")
			_, _, err := Compile(c)
			want := slices.Contains(ok, v)
			if (err == nil) != want {
				t.Errorf("%s/%s using %s: err = %v, want allowed=%v", m.kind, m.pm, v, err, want)
			}
			if err != nil && diagCode(err) != "control_vars" {
				t.Errorf("%s/%s using %s: code %s, want control_vars", m.kind, m.pm, v, diagCode(err))
			}
		}
	}
}

// TestReadsIAMDynamicIndex: the fixed-shape exemption covers
// constant indexes into an iam.parse result only. A data-derived index is
// rejected by the reads analysis itself, without the identity lint, which
// check() runs first and which rejects these forms too.
func TestReadsIAMDynamicIndex(t *testing.T) {
	env, err := newEnv()
	if err != nil {
		t.Fatal(err)
	}
	const st = `iam.parse(resource.policy).statements`
	for _, expr := range []string{
		`iam.parse(resource.policy)[resource.k] == 1`,
		`iam.parse(resource.policy)["statements"][resource.i].effect == "Deny"`,
		st + `[resource.i].effect == "Deny"`,
		st + `[0].actions[resource.i] == "x"`,
		st + `.all(s, s[resource.k] == 1)`,
		st + `.all(s, s.conditions[resource.i].key == "k")`,
		// A non-literal, non-data key earlier in the chain keeps it fixed;
		// an index taken from a range over data is data.
		`["conditions"].all(f, ` + st + `.all(s, s[f][resource.k].key == "k"))`,
		`resource.xs.all(i, ` + st + `[i].effect == "Deny")`,
		// Wrapped results lose the fixed shape and are erased (erases).
		`dyn(iam.parse(resource.policy))[resource.k] == 1`,
		`[iam.parse(resource.policy)][0][resource.k] == 1`,
	} {
		a, iss := env.Compile(expr)
		if iss.Err() != nil {
			t.Fatalf("%s: %v", expr, iss.Err())
		}
		if _, err := analyze(a); diagCode(err) != "control_dynamic_access" {
			t.Errorf("%s: %v, want control_dynamic_access", expr, err)
		}
	}
	// Constant and non-data indexes keep the exemption.
	for _, expr := range []string{
		st + `[0].effect == "Deny"`,
		`iam.parse(resource.policy)["statements"][0]["effect"] == "Deny"`,
		`[0, 1].all(i, ` + st + `[i].effect == "Deny")`,
	} {
		a, iss := env.Compile(expr)
		if iss.Err() != nil {
			t.Fatalf("%s: %v", expr, iss.Err())
		}
		if _, err := analyze(a); err != nil {
			t.Errorf("%s: %v, want accepted", expr, err)
		}
	}
}

// TestCompileReadsCoverage pins the coverage direction (declared path is a
// segment prefix of the AST path) and the unused-read warning.
func TestCompileReadsCoverage(t *testing.T) {
	cases := []struct {
		expr    string
		reads   []string
		code    string
		warning string
	}{
		{`resource.ingress.all(r, !("0.0.0.0/0" in r.cidr_blocks))`, []string{"ingress"}, "", ""},
		{`resource.ingress.all(r, !("0.0.0.0/0" in r.cidr_blocks))`, []string{"ingress.cidr_blocks"}, "", ""},
		{"size(resource.a) >= 1", []string{"a.b"}, "control_reads_missing", ""},
		{"resource.ab == 1", []string{"a"}, "control_reads_missing", ""},
		{"resource.a == 1 && prior.b == 2", []string{"a"}, "control_reads_missing", ""},
		{"resource.a == 1 && prior.b == 2", []string{"a", "b"}, "", ""},
		{"resource.a == 1", []string{"a", "z"}, "", "control_reads_unused"},
		{"type(resource.a) == string", []string{"a"}, "", ""}, // type names are not variables
	}
	for _, tc := range cases {
		_, diags, err := Compile(testControl(bundle.KindResource, bundle.PresenceEffective, tc.expr, tc.reads...))
		if diagCode(err) != tc.code {
			t.Errorf("%q reads %v: err = %v, want %q", tc.expr, tc.reads, err, tc.code)
		}
		var warn string
		if len(diags) > 0 {
			warn = diags[0].Code
		}
		if warn != tc.warning {
			t.Errorf("%q reads %v: warnings %v, want %q", tc.expr, tc.reads, diags, tc.warning)
		}
	}
}

// TestCompileASTCache: one checked AST per distinct expression.
func TestCompileASTCache(t *testing.T) {
	c1 := testControl(bundle.KindResource, bundle.PresenceEffective, "resource.cache_probe == true", "cache_probe")
	c2 := testControl(bundle.KindResource, bundle.PresenceEffective, "resource.cache_probe == true", "cache_probe")
	a, _, err := Compile(c1)
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := Compile(c2)
	if err != nil {
		t.Fatal(err)
	}
	if a.Ast != b.Ast {
		t.Error("same expr must reuse the cached *cel.Ast")
	}
	if _, _, err := Compile(&bundle.Control{ID: "p"}); diagCode(err) != "control_expr" {
		t.Errorf("control without expr: %v", err)
	}
}

// compileWant lists the celeng load error id for every fixture in
// testdata/bundles/invalid that strict decode accepts (decodeWant code "").
// Schema-aware ids (control_computed_only) compile cleanly here; Load
// rejects them.
var compileWant = map[string]string{
	"control_vars":                       "control_vars",
	"control_reads_missing":              "control_reads_missing",
	"control_dynamic_access":             "control_dynamic_access",
	"control_iam_unconditional_polarity": "control_iam_unconditional_polarity",
	"iam_identity_direct":                "control_iam_identity_direct",
	"control_computed_only":              "",
	"computed_only":                      "",
	"computed_only_effective":            "",
	"optional_computed":                  "",
}

func TestCompileFixtures(t *testing.T) {
	root := filepath.Join("..", "..", "..", "testdata", "bundles")
	for name, want := range compileWant {
		t.Run(name, func(t *testing.T) {
			cs := decodeFixture(t, filepath.Join(root, "invalid", name+".json"))
			var err error
			for i := range cs {
				if _, _, err = Compile(&cs[i]); err != nil {
					break
				}
			}
			if diagCode(err) != want {
				t.Fatalf("want %q, got %v", want, err)
			}
		})
	}
	valid, _ := filepath.Glob(filepath.Join(root, "valid", "*.json"))
	for _, f := range valid {
		for _, c := range decodeFixture(t, f) {
			if _, _, err := Compile(&c); err != nil {
				t.Errorf("%s %s: %v", filepath.Base(f), c.ID, err)
			}
		}
	}
}

func decodeFixture(t *testing.T, f string) []bundle.Control {
	t.Helper()
	data, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := bundle.DecodeControls(data)
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

func testControl(k bundle.Kind, pm bundle.PresenceMode, expr string, reads ...string) *bundle.Control {
	return &bundle.Control{ID: "test_control", Kind: k, PresenceMode: pm, Expr: &expr, Reads: reads}
}

func diagCode(err error) string {
	var d *LoadDiag
	if errors.As(err, &d) {
		return d.Code
	}
	if err != nil {
		return "unexpected: " + strings.TrimSpace(err.Error())
	}
	return ""
}

// TestReadsErasureNotCached: a rejected expression is never cached, so a
// second check of it is rejected again.
func TestReadsErasureNotCached(t *testing.T) {
	const expr = "resource.a.filter(x, x.b).all(y, y.c)"
	for i := range 2 {
		if _, err := check(expr); diagCode(err) != "control_dynamic_access" {
			t.Fatalf("check %d: want control_dynamic_access, got %v", i, err)
		}
	}
}
