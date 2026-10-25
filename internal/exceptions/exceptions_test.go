package exceptions

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/celeng"
	"github.com/compliancetf/terraform-provider-aws/internal/evidence"
)

// selType is the resource the selector tests evaluate: the v0.1 truth table
// columns (s, n, b, l, blk) plus set and map shapes (ss, so, m, mo).
var selType = tftypes.Object{AttributeTypes: map[string]tftypes.Type{
	"s": tftypes.String, "n": tftypes.Number, "b": tftypes.Bool,
	"l":   tftypes.List{ElementType: tftypes.String},
	"blk": tftypes.List{ElementType: tftypes.Object{AttributeTypes: map[string]tftypes.Type{"s": tftypes.String, "n": tftypes.Number, "l": tftypes.List{ElementType: tftypes.String}}}},
	"ss":  tftypes.Set{ElementType: tftypes.String},
	"so":  tftypes.Set{ElementType: tftypes.Object{AttributeTypes: map[string]tftypes.Type{"s": tftypes.String}}},
	"m":   tftypes.Map{ElementType: tftypes.String},
	"mo":  tftypes.Map{ElementType: tftypes.Object{AttributeTypes: map[string]tftypes.Type{"s": tftypes.String}}},
}}

var (
	selSchemas = testSchemas{"aws_test_thing": schemaOf(selType)}
	selCtl     = &bundle.Control{ID: "test_control", Kind: bundle.KindResource, ResourceType: "aws_test_thing"}
	selExpires = time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
)

// verdictCtx is a one-minute deadline for tests that check verdicts: a
// context without a deadline gets the 50 ms per-resource budget, which a
// loaded machine can spend. Budget tests build their own.
func verdictCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	t.Cleanup(cancel)
	return ctx
}

// decide runs expr as one applicable sidecar entry through lookup, the path
// grants and the sidecar share.
func decide(t *testing.T, ctx context.Context, expr string, a *engine.Activation) Decision {
	t.Helper()
	sel, err := compileSelector(expr)
	if err != nil {
		t.Fatalf("compile %q: %v", expr, err)
	}
	r := rule{label: "sel", source: "self_service", sel: sel, expires: selExpires, status: StatusApplied}
	return lookup(ctx, []rule{r}, Clock{}, selCtl, selSchemas, a, now)
}

// verdict is the exception outcome: apply, pending (unknown, retried at the
// next stage), rejected (the selector errored) or none (false).
func verdict(d Decision) string {
	switch {
	case d.Applied:
		return "apply"
	case d.Unresolved:
		return "pending"
	case d.Exception != nil && d.Exception.Status == StatusRejected:
		return "rejected"
	}
	return "none"
}

// TestExceptionSelector pins the CEL exception match selector: variables, true
// applies, false does not, unknown is
// pending and logged, an error is rejected and logged with its class, and a
// spent per-resource budget never applies.
func TestExceptionSelector(t *testing.T) {
	base := func() *engine.Activation { return selectorBase(t) }
	for _, tc := range selectorCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			a := base()
			if tc.act != nil {
				tc.act(a)
			}
			d := decide(t, verdictCtx(t), tc.expr, a)
			status := ""
			if d.Exception != nil {
				status = d.Exception.Status
			}
			if got := verdict(d); got != tc.want || status != tc.status || strings.Join(d.Log, "\n") != tc.log {
				t.Fatalf("got %s status %q log %q, want %s status %q log %q", got, status, d.Log, tc.want, tc.status, tc.log)
			}
		})
	}

	t.Run("no schema", func(t *testing.T) {
		sel, _ := compileSelector("true")
		r := rule{label: "sel", sel: sel, expires: selExpires, status: StatusApplied}
		d := lookup(verdictCtx(t), []rule{r}, Clock{}, ctl(rdsEnc), selSchemas, base(), now)
		if d.Applied || d.Exception == nil || d.Exception.Status != StatusRejected {
			t.Fatalf("type outside the upstream schema: %+v", d)
		}
	})
	t.Run("budget spent", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if d := decide(t, ctx, "true", base()); d.Applied || !slices.Equal(d.Log, []string{"exception sel: exception_rejected: selector timeout"}) {
			t.Fatalf("expired deadline: %+v", d)
		}
	})
	t.Run("non-applicable entry", func(t *testing.T) {
		// Errors and unknowns are logged only for entries that could apply.
		sel, _ := compileSelector("resource.s > 1")
		r := rule{label: "sel", sel: sel, expires: selExpires, status: StatusWrongWorkspace}
		if d := lookup(verdictCtx(t), []rule{r}, Clock{}, selCtl, selSchemas, base(), now); d.Exception != nil || len(d.Log) != 0 {
			t.Fatalf("wrong-workspace entry: %+v", d)
		}
	})
	t.Run("pending then applied", func(t *testing.T) {
		pending, _ := compileSelector("provider.account_id == '1'")
		good, _ := compileSelector("true")
		rules := []rule{{label: "pending", sel: pending, expires: selExpires, status: StatusApplied},
			{label: "good", sel: good, expires: selExpires, status: StatusApplied}}
		d := lookup(verdictCtx(t), rules, Clock{}, selCtl, selSchemas, base(), now)
		if !d.Applied || d.Unresolved || len(d.Log) != 0 {
			t.Fatalf("an applied decision is not pending and drops pending lines: %+v", d)
		}
	})
	t.Run("past the control deadline", func(t *testing.T) {
		// The lifecycle passes the control's per-resource deadline (plan.go
		// Evaluate WithTimeout) to the lookups; past it a selector times out.
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		defer cancel()
		if d := decide(t, ctx, "true", base()); d.Applied || !slices.Equal(d.Log, []string{"exception sel: exception_rejected: selector timeout"}) {
			t.Fatalf("selector after the deadline: %+v", d)
		}
	})
	t.Run("applicable rules first", func(t *testing.T) {
		yes, _ := compileSelector("true")
		bad, _ := compileSelector("resource.s > 1")
		expired := rule{label: "old", sel: yes, expires: selExpires, status: StatusExpired}
		// A non-applicable match ahead of an applicable one never blocks it.
		d := lookup(verdictCtx(t), []rule{expired, {label: "good", sel: yes, expires: selExpires, status: StatusApplied}}, Clock{}, selCtl, selSchemas, base(), now)
		if !d.Applied || d.Exception.ID != "good" {
			t.Fatalf("applicable after non-applicable: %+v", d)
		}
		// None applies: an applicable entry's rejection is recorded before a
		// non-applicable match.
		d = lookup(verdictCtx(t), []rule{expired, {label: "bad", sel: bad, expires: selExpires, status: StatusApplied}}, Clock{}, selCtl, selSchemas, base(), now)
		if d.Applied || d.Exception.ID != "bad" || d.Exception.Status != StatusRejected {
			t.Fatalf("rejected applicable vs expired match: %+v", d.Exception)
		}
		// Only non-applicable entries: the first matching one is recorded.
		d = lookup(verdictCtx(t), []rule{expired}, Clock{}, selCtl, selSchemas, base(), now)
		if d.Applied || d.Exception.ID != "old" || d.Exception.Status != StatusExpired {
			t.Fatalf("expired match: %+v", d.Exception)
		}
	})
	t.Run("rejected then applied", func(t *testing.T) {
		bad, _ := compileSelector("resource.s > 1")
		good, _ := compileSelector("true")
		rules := []rule{{label: "bad", sel: bad, expires: selExpires, status: StatusApplied},
			{label: "good", sel: good, expires: selExpires, status: StatusApplied}}
		d := lookup(verdictCtx(t), rules, Clock{}, selCtl, selSchemas, base(), now)
		if !d.Applied || d.Exception.ID != "good" || !slices.Equal(d.Log, []string{"exception bad: exception_rejected: selector type_error"}) {
			t.Fatalf("a later entry applies and keeps the earlier log: %+v", d)
		}
	})
}

// selectorBase is the activation the selector cases start from.
func selectorBase(t *testing.T) *engine.Activation {
	res := selValue(t, map[string]any{"s": "legacy-a", "n": json.Number("3"), "b": true, "l": []any{"x", "y"}})
	return &engine.Activation{Resource: res, Config: res, Op: engine.OpUpdate,
		Prior: selValue(t, map[string]any{"s": "old"}),
		Env:   "prod", EnvKnown: true,
		Provider: engine.ProviderInfo{Region: "eu-west-1", RegionKnown: true}}
}

// selectorCase is one TestExceptionSelector row; the cross-check vectors
// (vectors_test.go) are generated from the same rows.
type selectorCase struct {
	name, expr string
	act        func(*engine.Activation)
	want       string
	status     string // evidence status; "" none
	log        string
}

func selectorCases(t *testing.T) []selectorCase {
	return []selectorCase{
		{name: "type", expr: "type == 'aws_test_thing'", want: "apply", status: StatusApplied},
		{name: "other type", expr: "type == 'aws_db_instance'", want: "none"},
		{name: "resource", expr: "resource.s.startsWith('legacy-') && resource.n >= 3 && resource.b", want: "apply", status: StatusApplied},
		{name: "config", expr: "config.l.exists(e, e == 'y')", want: "apply", status: StatusApplied},
		{name: "prior", expr: "prior.s == 'old'", want: "apply", status: StatusApplied},
		{name: "op", expr: "op == 'update'", want: "apply", status: StatusApplied},
		{name: "env", expr: "env == 'prod'", want: "apply", status: StatusApplied},
		{name: "provider", expr: "provider.region == 'eu-west-1'", want: "apply", status: StatusApplied},
		{name: "false", expr: "resource.s == 'other'", want: "none"},
		{name: "unknown", expr: "resource.s == 'legacy-a'", act: func(a *engine.Activation) {
			a.Resource = selValue(t, map[string]any{"s": "<unknown>"})
		}, want: "pending", log: "exception sel pending: selector unknown"},
		{name: "unknown absorbed by false", expr: "resource.s == 'legacy-a' && resource.b", act: func(a *engine.Activation) {
			a.Resource = selValue(t, map[string]any{"s": "<unknown>", "b": false})
		}, want: "none"},
		{name: "unknown provider", expr: "provider.account_id == '123'", want: "pending", log: "exception sel pending: selector unknown"},
		{name: "untrusted env", expr: "env == 'prod'", act: func(a *engine.Activation) { a.Env, a.EnvKnown = "", false },
			want: "rejected", status: StatusRejected, log: "exception sel: exception_rejected: selector scope_untrusted"},
		{name: "untrusted env with unknown resource", expr: "env != 'prod' && resource.s == 'legacy-a'", act: func(a *engine.Activation) {
			a.Env, a.EnvKnown = "", false
			a.Resource = selValue(t, map[string]any{"s": "<unknown>"})
		}, want: "rejected", status: StatusRejected, log: "exception sel: exception_rejected: selector scope_untrusted"},
		{name: "untrusted env absorbed", expr: "resource.b || env == 'dev'", act: func(a *engine.Activation) { a.Env, a.EnvKnown = "", false },
			want: "apply", status: StatusApplied},
		{name: "type error", expr: "resource.s > 1", want: "rejected", status: StatusRejected,
			log: "exception sel: exception_rejected: selector type_error"},
		{name: "non-bool result", expr: "resource.s", want: "rejected", status: StatusRejected,
			log: "exception sel: exception_rejected: selector type_error"},
		{name: "missing attribute", expr: "resource.nope == 'x'", want: "rejected", status: StatusRejected,
			log: "exception sel: exception_rejected: selector no_such_attribute"},
	}
}

// selectorCompileErrors maps a selector that does not compile to its error.
var selectorCompileErrors = map[string]string{
	"type == ":                           "match: does not compile at 1:9",
	"resource.s == 'secret-value' +":     "match: does not compile at 1:31",
	"nope == 1":                          "match: does not compile at 1:1",
	"1":                                  "match: output type is not bool",
	"":                                   "match: does not compile at 1:1",
	"iam.grants(resource, 's3:Get*')":    "match: iam.* is not allowed in a selector",
	"iam.grants_all(resource, 's3:Get')": "match: iam.* is not allowed in a selector",
	"true && !iam.grants(resource, 'x')": "match: iam.* is not allowed in a selector",
}

// TestExceptionSelectorCompile: a selector that does not compile rejects
// its grant or sidecar file, naming a position, never the expression.
func TestExceptionSelectorCompile(t *testing.T) {
	for expr, want := range selectorCompileErrors {
		_, err := compileSelector(expr)
		if err == nil || err.Error() != want {
			t.Errorf("%q: %v, want %q", expr, err, want)
		}
		src := fmt.Sprintf("exception \"x\" {\n  controls  = [%q]\n  match     = %q\n  workspace = \"w\"\n  reason    = \"r\"\n  expires   = \"2027-01-01\"\n}\n", rdsEnc, expr)
		_, _, err = parseSidecar([]byte(src), "exceptions.hcl", scopeInput())
		if err == nil || err.Error() != `exceptions_file: exception "x": `+want {
			t.Errorf("sidecar %q: %v", expr, err)
		}
		if err != nil && strings.Contains(err.Error(), "secret-value") {
			t.Errorf("error quotes the expression: %v", err)
		}
	}
	if _, err := parse(payload(selector("type =="))); err == nil || err.Error() != "exception bobthecorp-legacy-db: match: does not compile at 1:8" {
		t.Errorf("grant: %v", err)
	}
}

// TestExceptionSetMapShapes covers set and map attributes (which
// asked for these rows on the v0.1 table): sets are ordered lists, maps are
// maps; an unknown element keeps the selector pending unless a known
// element decides it, and a missing key is an error, never a match.
func TestExceptionSetMapShapes(t *testing.T) {
	for _, tc := range setMapCases() {
		t.Run(tc.name, func(t *testing.T) {
			if got := verdict(decide(t, verdictCtx(t), tc.expr, &engine.Activation{Resource: selValue(t, tc.res)})); got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
	// v0.1 map wildcards read values; CEL reads a value by a computed key
	// only through a path, as controls do: an index by the iteration
	// variable does not compile (an unknown value under it has no path).
	if _, err := compileSelector("resource.m.all(k, resource.m[k] != 'off')"); err == nil || err.Error() != "match: non-constant index into resource.m" {
		t.Errorf("map value by computed key: %v", err)
	}
}

// setMapCase is one TestExceptionSetMapShapes row.
type setMapCase struct {
	name, expr string
	res        map[string]any
	want       string
}

func setMapCases() []setMapCase {
	obj := func(s any) map[string]any { return map[string]any{"s": s} }
	return []setMapCase{
		{"set exists", "resource.ss.exists(e, e == 'x')", map[string]any{"ss": []any{"y", "x"}}, "apply"},
		{"set exists none", "resource.ss.exists(e, e == 'x')", map[string]any{"ss": []any{"y"}}, "none"},
		{"set all", "resource.ss.all(e, e != 'off')", map[string]any{"ss": []any{"a", "b"}}, "apply"},
		{"set all violated", "resource.ss.all(e, e != 'off')", map[string]any{"ss": []any{"a", "off"}}, "none"},
		{"set empty all", "resource.ss.all(e, e != 'off')", map[string]any{"ss": []any{}}, "apply"},
		{"set required", "size(resource.ss) > 0", map[string]any{"ss": []any{}}, "none"},
		{"set null", "resource.ss.exists(e, e == 'x')", map[string]any{}, "rejected"},
		{"set unknown element", "resource.ss.exists(e, e == 'x')", map[string]any{"ss": []any{"y", "<unknown>"}}, "pending"},
		{"set unknown element, known match", "resource.ss.exists(e, e == 'x')", map[string]any{"ss": []any{"x", "<unknown>"}}, "pending"},
		{"set unknown", "resource.ss.exists(e, e == 'x')", map[string]any{"ss": "<unknown>"}, "pending"},
		{"set of objects", "resource.so.all(o, o.s.startsWith('a'))", map[string]any{"so": []any{obj("ab"), obj("ac")}}, "apply"},
		{"set of objects, unknown field", "resource.so.all(o, o.s.startsWith('a'))", map[string]any{"so": []any{obj("ab"), obj("<unknown>")}}, "pending"},
		{"map keys all", "resource.m.all(k, k.startsWith('a'))", map[string]any{"m": map[string]any{"a1": "on", "a2": "x"}}, "apply"},
		{"map keys violated", "resource.m.all(k, k.startsWith('a'))", map[string]any{"m": map[string]any{"a1": "on", "b": "x"}}, "none"},
		{"map keys exists", "resource.m.exists(k, k == 'env')", map[string]any{"m": map[string]any{"env": "dev"}}, "apply"},
		{"map key", "resource.m['env'] == 'dev'", map[string]any{"m": map[string]any{"env": "dev"}}, "apply"},
		{"map missing key", "resource.m['env'] == 'dev'", map[string]any{"m": map[string]any{"x": "dev"}}, "rejected"},
		{"map missing key guarded", "'env' in resource.m && resource.m['env'] == 'dev'", map[string]any{"m": map[string]any{"x": "dev"}}, "none"},
		{"map unknown value", "resource.m['b'] != 'off'", map[string]any{"m": map[string]any{"a": "on", "b": "<unknown>"}}, "pending"},
		{"map unknown value, known violation", "resource.m['a'] != 'off' && resource.m['b'] != 'off'", map[string]any{"m": map[string]any{"a": "off", "b": "<unknown>"}}, "none"},
		{"map unknown value, keys known", "resource.m.exists(k, k == 'b')", map[string]any{"m": map[string]any{"a": "on", "b": "<unknown>"}}, "pending"},
		{"map of objects", "resource.mo['x'].s == 'a'", map[string]any{"mo": map[string]any{"x": obj("a")}}, "apply"},
		{"map null", "resource.m.exists(k, k == 'env')", map[string]any{}, "rejected"},
	}
}

// v01Row is one row of testdata/selector/v01_truth_table.json, the v0.1
// match truth table of the removed v0.1 matcher.
type v01Row struct {
	Case  string `json:"case"`
	Name  string `json:"name"`
	Check struct {
		Path  string          `json:"path"`
		Op    string          `json:"op"`
		Value json.RawMessage `json:"value"`
	} `json:"check"`
	Resource         map[string]any  `json:"resource"`
	Want             engine.State    `json:"want"`
	WantErr          engine.ErrClass `json:"want_err"`
	WantUnknownPaths []string        `json:"want_unknown_paths"`
}

// Why a row's verdict changes under the CEL selector.
const (
	// celeng marks a list holding an unknown element unknown as a whole, so
	// a known element no longer decides it: pending at this stage, decided
	// at apply. Never applies now.
	whyUnknownList = "list with an unknown element is unknown"
	// CEL numbers are int64 and double: 1e309 is not a finite double, so
	// the comparison errors. Never applies.
	whyDouble = "1e309 is not a CEL double"
)

// v01FailRejected are the rows v0.1 decided false whose CEL selector errors
// (rejected, still not applied), by index.
var v01FailRejected = map[int]string{12: whyDouble, 13: whyDouble}

// v01Changed are the rows whose exception verdict changes, by index: the
// transition and why. Every other row keeps its v0.1 verdict.
var v01Changed = map[int]string{
	7:  "none -> pending: " + whyUnknownList,
	11: "apply -> none: " + whyDouble,
	47: "apply -> pending: " + whyUnknownList,
	56: "none -> pending: " + whyUnknownList,
	88: "apply -> pending: " + whyUnknownList,
}

// TestExceptionV01Verdicts proves the CEL selector keeps the v0.1 match
// verdicts: each truth-table row, translated into the CEL selector a v0.1
// match block means, gives the same exception outcome (pass applies, unknown
// is pending, fail and not_evaluable do not apply), except the rows listed
// in v01Changed.
func TestExceptionV01Verdicts(t *testing.T) {
	changed := 0
	for i, r := range v01Rows(t) {
		expr := v01CEL(t, r)
		// v0.1 had no rejected outcome: fail and not_evaluable both did not
		// apply, so the verdicts compare with rejected folded into none.
		old := map[engine.State]string{engine.Pass: "apply", engine.Unknown: "pending"}[r.Want]
		if old == "" {
			old = "none"
		}
		// No wall-clock budget: the verdict is the engine's, not the
		// machine's (the 50 ms per-resource budget only removes waivers).
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		full := verdict(decide(t, ctx, expr, &engine.Activation{Resource: selValue(t, r.Resource)}))
		cancel()
		got := strings.Replace(full, "rejected", "none", 1)
		// A row v0.1 decided false must evaluate to false, not error: the
		// translation is exercised, never hidden behind a rejection.
		if r.Want == engine.Fail && full == "rejected" && v01FailRejected[i] == "" || r.Want != engine.Fail && v01FailRejected[i] != "" ||
			full != "rejected" && v01FailRejected[i] != "" {
			t.Errorf("row %03d %s/%s %s: v0.1 fail, CEL %s, listed %q\n  %s", i, r.Check.Op, r.Case, r.Name, full, v01FailRejected[i], expr)
		}
		want, listed := v01Changed[i]
		if got != old || listed {
			changed++
			if tr := old + " -> " + got; !strings.HasPrefix(want, tr+": ") {
				t.Errorf("row %03d %s/%s %s: %s, listed %q\n  %s", i, r.Check.Op, r.Case, r.Name, tr, want, expr)
			}
			if got == "apply" {
				t.Errorf("row %03d newly applies", i)
			}
		}
	}
	if changed != len(v01Changed) {
		t.Errorf("%d changed rows, %d listed", changed, len(v01Changed))
	}
}

// v01Rows reads testdata/selector/v01_truth_table.json.
func v01Rows(t *testing.T) []v01Row {
	t.Helper()
	data, err := os.ReadFile("testdata/selector/v01_truth_table.json")
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	dec.DisallowUnknownFields()
	var tt struct {
		Comment string   `json:"_comment"`
		Rows    []v01Row `json:"rows"`
	}
	if err := dec.Decode(&tt); err != nil {
		t.Fatal(err)
	}
	if len(tt.Rows) != 112 {
		t.Fatalf("%d rows, want 112", len(tt.Rows))
	}
	return tt.Rows
}

// v01CEL is the CEL selector a v0.1 match block means: a wildcard is all()
// over the elements (a known empty collection passes, except for required),
// a null on the way stops the walk and decides as the operator decides a
// null leaf (negated operators pass, the others fail).
func v01CEL(t *testing.T, r v01Row) string {
	t.Helper()
	var v any
	if len(r.Check.Value) > 0 {
		d := json.NewDecoder(bytes.NewReader(r.Check.Value))
		d.UseNumber()
		if err := d.Decode(&v); err != nil {
			t.Fatal(err)
		}
	}
	negated := slices.Contains([]string{"not_equals", "not_in", "not_contains", "not_contains_cidr", "regex_not_match"}, r.Check.Op)
	var walk func(x string, typ tftypes.Type, parts []string, depth int) string
	walk = func(x string, typ tftypes.Type, parts []string, depth int) string {
		if len(parts) == 0 {
			return v01Leaf(t, x, typ, r.Check.Op, v)
		}
		if parts[0] != "*" {
			var at tftypes.Type
			if o, ok := typ.(tftypes.Object); ok {
				at = o.AttributeTypes[parts[0]]
			}
			return walk(x+"."+parts[0], at, parts[1:], depth)
		}
		var et tftypes.Type
		if l, ok := typ.(tftypes.List); ok {
			et = l.ElementType
		}
		e := fmt.Sprintf("e%d", depth)
		all := fmt.Sprintf("%s.all(%s, %s)", x, e, walk(e, et, parts[1:], depth+1))
		if r.Check.Op == "required" {
			all = fmt.Sprintf("size(%s) > 0 && %s", x, all)
		}
		return fmt.Sprintf("(%s == null ? %t : %s)", x, negated, all)
	}
	return walk("resource", selType, strings.Split(r.Check.Path, "."), 0)
}

func v01Leaf(t *testing.T, x string, typ tftypes.Type, op string, v any) string {
	lit := func(v any) string {
		switch v := v.(type) {
		case string:
			b, _ := json.Marshal(v)
			return string(b)
		case json.Number:
			if _, err := v.Int64(); err == nil {
				return v.String()
			}
			return "double('" + v.String() + "')"
		}
		return fmt.Sprint(v)
	}
	list := func(v any) string {
		l, _ := v.([]any)
		s := make([]string, len(l))
		for i, e := range l {
			s[i] = lit(e)
		}
		return "[" + strings.Join(s, ", ") + "]"
	}
	switch op {
	case "equals":
		return fmt.Sprintf("%s == %s", x, lit(v))
	case "not_equals":
		return fmt.Sprintf("(%s == null || %s != %s)", x, x, lit(v))
	case "in":
		return fmt.Sprintf("%s in %s", x, list(v))
	case "not_in":
		return fmt.Sprintf("(%s == null || !(%s in %s))", x, x, list(v))
	case "contains":
		return fmt.Sprintf("(%s != null && %s.exists(c, c == %s))", x, x, lit(v))
	case "not_contains":
		return fmt.Sprintf("(%s == null || !%s.exists(c, c == %s))", x, x, lit(v))
	case "not_contains_cidr":
		return fmt.Sprintf("(%s == null || !%s.exists(c, c != null && cidr.contains(c, %s)))", x, x, lit(v))
	case "min_int":
		return fmt.Sprintf("(%s != null && %s >= %s)", x, x, lit(v))
	case "max_int":
		return fmt.Sprintf("(%s != null && %s <= %s)", x, x, lit(v))
	case "required":
		switch typ.(type) {
		case tftypes.List, tftypes.Set, tftypes.Map:
			return fmt.Sprintf("(%s != null && size(%s) > 0)", x, x)
		}
		return fmt.Sprintf("%s != null", x)
	case "regex_match":
		return fmt.Sprintf("(%s != null && %s.matches(%s))", x, x, lit(v))
	case "regex_not_match":
		return fmt.Sprintf("(%s == null || !%s.matches(%s))", x, x, lit(v))
	}
	t.Fatalf("op %s", op)
	return ""
}

// v0.1 element and string caps the truth table's markers are built from.
const (
	v01MaxElements = 10000
	v01MaxString   = 256 << 10
)

// selValue builds a selType value: an attribute left out is null,
// "<unknown>" is unknown; <big-string>, <max-string>, <big-list> and
// <max-list> are the v0.1 cap markers.
func selValue(t *testing.T, raw map[string]any) tftypes.Value {
	t.Helper()
	return build(t, selType, raw)
}

func build(t *testing.T, typ tftypes.Type, raw any) tftypes.Value {
	t.Helper()
	switch raw {
	case nil:
		return tftypes.NewValue(typ, nil)
	case "<unknown>":
		return tftypes.NewValue(typ, tftypes.UnknownValue)
	case "<big-string>", "<max-string>":
		n := v01MaxString
		if raw == "<big-string>" {
			n++
		}
		return tftypes.NewValue(typ, strings.Repeat("a", n))
	case "<big-list>", "<max-list>":
		lt := typ.(tftypes.List)
		n := v01MaxElements
		if raw == "<big-list>" {
			n++
		}
		elems := make([]tftypes.Value, n)
		for i := range elems {
			if lt.ElementType.Is(tftypes.String) {
				elems[i] = tftypes.NewValue(tftypes.String, "a")
			} else {
				elems[i] = build(t, lt.ElementType, map[string]any{"s": "a", "n": json.Number("1")})
			}
		}
		return tftypes.NewValue(typ, elems)
	}
	switch tt := typ.(type) {
	case tftypes.Object:
		m := raw.(map[string]any)
		vals := map[string]tftypes.Value{}
		for k, at := range tt.AttributeTypes {
			vals[k] = build(t, at, m[k])
		}
		return tftypes.NewValue(typ, vals)
	case tftypes.List, tftypes.Set:
		et := tftypes.Type(nil)
		if l, ok := tt.(tftypes.List); ok {
			et = l.ElementType
		} else {
			et = tt.(tftypes.Set).ElementType
		}
		elems := []tftypes.Value{}
		for _, e := range raw.([]any) {
			elems = append(elems, build(t, et, e))
		}
		return tftypes.NewValue(typ, elems)
	case tftypes.Map:
		vals := map[string]tftypes.Value{}
		for k, e := range raw.(map[string]any) {
			vals[k] = build(t, tt.ElementType, e)
		}
		return tftypes.NewValue(typ, vals)
	}
	if n, ok := raw.(json.Number); ok {
		f, _, err := big.ParseFloat(string(n), 10, 512, big.ToNearestEven)
		if err != nil {
			t.Fatal(err)
		}
		return tftypes.NewValue(typ, f)
	}
	return tftypes.NewValue(typ, raw)
}

var _ celeng.SchemaSource = testSchemas{}

// TestExceptionCombine: the lifecycle merges the grant and sidecar decisions
// so a pending marker and both log trails survive.
func TestExceptionCombine(t *testing.T) {
	gPending := Decision{Unresolved: true, Log: []string{"exception g pending: selector unknown"}}
	gRejected := Decision{Exception: &evidence.Exception{ID: "g", Status: StatusRejected},
		Log: []string{"exception g: exception_rejected: selector type_error"}}
	sPending := Decision{Unresolved: true, Log: []string{"exception s pending: selector unknown"}}
	sApplied := Decision{Exception: &evidence.Exception{ID: "s", Status: StatusApplied}, Applied: true}
	for _, tc := range []struct {
		name    string
		g, s    Decision
		want    string // exception id, "" none
		applied bool
		pending bool
		log     []string
	}{
		{"grant pending, sidecar no match", gPending, Decision{}, "", false, true, gPending.Log},
		{"grant rejected, sidecar pending", gRejected, sPending, "g", false, true, append(slices.Clone(gRejected.Log), sPending.Log...)},
		{"grant pending, sidecar applied", gPending, sApplied, "s", true, false, nil},
		{"grant rejected, sidecar applied", gRejected, sApplied, "s", true, false, gRejected.Log},
		{"grant none, sidecar rejected", Decision{}, Decision{Exception: &evidence.Exception{ID: "s"}}, "s", false, false, nil},
	} {
		d := Combine(tc.g, tc.s)
		id := ""
		if d.Exception != nil {
			id = d.Exception.ID
		}
		if id != tc.want || d.Applied != tc.applied || d.Unresolved != tc.pending || !slices.Equal(d.Log, tc.log) {
			t.Errorf("%s: %+v", tc.name, d)
		}
	}
}
