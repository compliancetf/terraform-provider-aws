package celeng

// TestCELSemantics pins the raw cel-go behavior the CEL engine relies on:
// partial evaluation with unknown attribute patterns,
// logical absorption, comprehensions over values containing unknowns,
// function calls with unknown arguments, and error-vs-unknown precedence.
//
// Unknowns are modeled the way engine/tfval will build them: the unknown
// entry is left out of the activation and declared by an attribute pattern.
//
// Safety rows (want == pass is never allowed when an unknown could change
// the outcome) are frozen. Precision rows (U-05, U-07) record the observed
// cel-go behavior; changing them needs review.

import (
	"context"
	"errors"
	"slices"
	"sort"
	"sync/atomic"
	"testing"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/ext"
	"cel.dev/cel-go/interpreter"
)

type state string

const (
	statePass         state = "pass"
	stateFail         state = "fail"
	stateUnknown      state = "unknown"
	stateNotEvaluable state = "not_evaluable"
)

// errIAMCalled marks that the iam.parse stub ran; U-09 requires that it does not.
// iamCalls counts invocations independently of how the error propagates.
var (
	errIAMCalled = errors.New("iam.parse stub called")
	iamCalls     atomic.Int32
)

func newSemanticsEnv(t *testing.T) *cel.Env {
	t.Helper()
	env, err := cel.NewEnv(
		cel.Variable("resource", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("provider", cel.MapType(cel.StringType, cel.StringType)),
		cel.Variable("env", cel.StringType),
		ext.Strings(),
		cel.ParserRecursionLimit(64),
		// iam.parse stub, not the real binding. The stub fails
		// loudly so U-09 proves it is never invoked with an unknown argument.
		cel.Function("iam.parse",
			cel.Overload("iam_parse_dyn", []*cel.Type{cel.DynType}, cel.MapType(cel.StringType, cel.DynType),
				cel.UnaryBinding(func(ref.Val) ref.Val { iamCalls.Add(1); return types.WrapErr(errIAMCalled) }))),
	)
	if err != nil {
		t.Fatalf("NewEnv: %v", err)
	}
	return env
}

// toState is the spike's result mapping: bool -> pass/fail, unknown ->
// unknown, anything else (error, non-bool) -> not_evaluable.
func toState(val ref.Val, err error) state {
	switch {
	case val != nil && types.IsUnknown(val):
		return stateUnknown
	case err != nil:
		return stateNotEvaluable
	}
	if b, ok := val.(types.Bool); ok {
		if b {
			return statePass
		}
		return stateFail
	}
	return stateNotEvaluable
}

func evalExpr(t *testing.T, env *cel.Env, expr string, vars map[string]any, unknown []*cel.AttributePatternType) (ref.Val, error) {
	t.Helper()
	ast, iss := env.Compile(expr)
	if iss.Err() != nil {
		t.Fatalf("compile %q: %v", expr, iss.Err())
	}
	prg, err := env.Program(ast,
		cel.EvalOptions(cel.OptPartialEval, cel.OptTrackState),
		cel.CostLimit(1_000_000),
		cel.InterruptCheckFrequency(100),
	)
	if err != nil {
		t.Fatalf("program %q: %v", expr, err)
	}
	act, err := cel.PartialVars(vars, unknown...)
	if err != nil {
		t.Fatalf("PartialVars: %v", err)
	}
	val, _, err := prg.Eval(act)
	return val, err
}

func pat(v string) *cel.AttributePatternType { return cel.AttributePattern(v) }

type semCase struct {
	id      string
	expr    string
	vars    map[string]any
	unknown []*cel.AttributePatternType
	want    state
	// neverPass marks the safety property; it holds even if want changes.
	neverPass bool
	// trails, when set, are the expected unknown attribute trails: what
	// UnknownPaths will be built from.
	trails []string
	// stubCalled: the iam.parse stub must run (control row for U-09).
	stubCalled bool
}

func unknownTrails(val ref.Val) []string {
	u, ok := val.(*types.Unknown)
	if !ok {
		return nil
	}
	var out []string
	for _, id := range u.IDs() {
		ts, _ := u.GetAttributeTrails(id)
		for _, tr := range ts {
			out = append(out, tr.String())
		}
	}
	sort.Strings(out)
	return out
}

func clean(cidrs ...string) map[string]any { return map[string]any{"cidr_blocks": cidrs} }

func TestCELSemantics(t *testing.T) {
	env := newSemanticsEnv(t)
	const ingressAll = `resource.ingress.all(r, !("0.0.0.0/0" in r.cidr_blocks))`
	provider := map[string]any{"region": "eu-west-1"}

	cases := []semCase{
		{
			id: "U-01", expr: `resource.kms_key_id != null`,
			vars:    map[string]any{"resource": map[string]any{}, "provider": provider},
			unknown: []*cel.AttributePatternType{pat("resource").QualString("kms_key_id")},
			want:    stateUnknown, neverPass: true,
			trails: []string{"resource.kms_key_id"},
		},
		{
			id: "U-02", expr: `resource.storage_encrypted == true && resource.kms_key_id != null`,
			vars:    map[string]any{"resource": map[string]any{"storage_encrypted": false}, "provider": provider},
			unknown: []*cel.AttributePatternType{pat("resource").QualString("kms_key_id")},
			want:    stateFail, neverPass: true,
		},
		{
			id: "U-03", expr: `resource.a || resource.b`,
			vars:    map[string]any{"resource": map[string]any{"a": true}, "provider": provider},
			unknown: []*cel.AttributePatternType{pat("resource").QualString("b")},
			want:    statePass,
		},
		{
			id: "U-04", expr: ingressAll,
			vars: map[string]any{"resource": map[string]any{"ingress": []any{
				clean("10.0.0.0/8"), map[string]any{}, clean("192.168.0.0/16"),
			}}, "provider": provider},
			unknown: []*cel.AttributePatternType{pat("resource").QualString("ingress").QualInt(1).QualString("cidr_blocks")},
			want:    stateUnknown, neverPass: true,
			trails: []string{"resource.ingress"},
		},
		{
			// Precision: fail would be decidable; cel-go treats the whole
			// list as unknown once a pattern sits below it, so unknown.
			id: "U-05", expr: ingressAll,
			vars: map[string]any{"resource": map[string]any{"ingress": []any{
				clean("0.0.0.0/0"), map[string]any{},
			}}, "provider": provider},
			unknown: []*cel.AttributePatternType{pat("resource").QualString("ingress").QualInt(1).QualString("cidr_blocks")},
			want:    stateUnknown, neverPass: true,
			trails: []string{"resource.ingress"},
		},
		{
			// Set with a not wholly known element: one pattern on the set.
			id: "U-06", expr: ingressAll,
			vars:    map[string]any{"resource": map[string]any{}, "provider": provider},
			unknown: []*cel.AttributePatternType{pat("resource").QualString("ingress")},
			want:    stateUnknown, neverPass: true,
		},
		{
			// Precision: pass preferred, unknown accepted. Observed: unknown,
			// the list is unknown as a whole once a leaf below it is.
			id: "U-07", expr: `size(resource.ebs_block_device) >= 1`,
			vars: map[string]any{"resource": map[string]any{"ebs_block_device": []any{
				map[string]any{"device_name": "/dev/sdb"},
			}}, "provider": provider},
			unknown: []*cel.AttributePatternType{pat("resource").QualString("ebs_block_device").QualInt(0).QualString("volume_size")},
			want:    stateUnknown,
			trails:  []string{"resource.ebs_block_device"},
		},
		{
			id: "U-08", expr: `resource.tags["Owner"] != ""`,
			vars:    map[string]any{"resource": map[string]any{"tags": map[string]any{"Name": "bobthecorp"}}, "provider": provider},
			unknown: []*cel.AttributePatternType{pat("resource").QualString("tags").QualString("Owner")},
			want:    stateUnknown, neverPass: true,
			trails: []string{"resource.tags.Owner"},
		},
		{
			id: "U-09", expr: `iam.parse(resource.policy).statements.all(s, s.effect == "Deny")`,
			vars:    map[string]any{"resource": map[string]any{}, "provider": provider},
			unknown: []*cel.AttributePatternType{pat("resource").QualString("policy")},
			want:    stateUnknown, neverPass: true,
			trails: []string{"resource.policy"},
		},
		{
			id: "U-10", expr: `resource.storage_encrypted == true`,
			vars:    map[string]any{"provider": provider},
			unknown: []*cel.AttributePatternType{pat("resource")},
			want:    stateUnknown, neverPass: true,
			trails: []string{"resource"},
		},
		{
			id: "U-10/has", expr: `!has(resource.kms_key_id) || resource.kms_key_id != ""`,
			vars:    map[string]any{"provider": provider},
			unknown: []*cel.AttributePatternType{pat("resource")},
			want:    stateUnknown, neverPass: true,
		},
		{
			id: "U-11", expr: `provider.account_id == "111111111111"`,
			vars:    map[string]any{"resource": map[string]any{}, "provider": provider},
			unknown: []*cel.AttributePatternType{pat("provider").QualString("account_id")},
			want:    stateUnknown, neverPass: true,
			trails: []string{"provider.account_id"},
		},
		{
			// Presence of a nested patterned key; the parent map is present.
			id: "U-08/has", expr: `!has(resource.tags.Owner)`,
			vars:    map[string]any{"resource": map[string]any{"tags": map[string]any{"Name": "bobthecorp"}}, "provider": provider},
			unknown: []*cel.AttributePatternType{pat("resource").QualString("tags").QualString("Owner")},
			want:    stateUnknown, neverPass: true,
		},
		{
			// A container with a patterned entry is unknown as a whole:
			// size and quantifiers never decide from the present entries.
			id: "U-08/size", expr: `size(resource.tags) == 1 && resource.tags.all(k, k != "Owner")`,
			vars:    map[string]any{"resource": map[string]any{"tags": map[string]any{"Name": "bobthecorp"}}, "provider": provider},
			unknown: []*cel.AttributePatternType{pat("resource").QualString("tags").QualString("Owner")},
			want:    stateUnknown, neverPass: true, trails: []string{"resource.tags", "resource.tags"},
		},
		{
			id: "U-08/in", expr: `!("Owner" in resource.tags)`,
			vars:    map[string]any{"resource": map[string]any{"tags": map[string]any{"Name": "bobthecorp"}}, "provider": provider},
			unknown: []*cel.AttributePatternType{pat("resource").QualString("tags").QualString("Owner")},
			want:    stateUnknown, neverPass: true,
		},
		{
			// Dual of U-05 with exists: a matching known element does not
			// short-circuit past a container-level unknown.
			id: "U-05/exists", expr: `!resource.ingress.exists(r, "0.0.0.0/0" in r.cidr_blocks)`,
			vars: map[string]any{"resource": map[string]any{"ingress": []any{
				clean("0.0.0.0/0"), map[string]any{},
			}}, "provider": provider},
			unknown: []*cel.AttributePatternType{pat("resource").QualString("ingress").QualInt(1).QualString("cidr_blocks")},
			want:    stateUnknown, neverPass: true,
		},
		{
			// Control for U-09: with a known argument the stub does run.
			id: "U-09/known", expr: `iam.parse(resource.policy).statements.all(s, s.effect == "Deny")`,
			vars: map[string]any{"resource": map[string]any{"policy": "{}"}, "provider": provider},
			want: stateNotEvaluable, stubCalled: true,
		},
		{
			// Direct index into a known sibling stays decided.
			id: "P-sibling-index", expr: `!("0.0.0.0/0" in resource.ingress[0].cidr_blocks)`,
			vars: map[string]any{"resource": map[string]any{"ingress": []any{
				clean("0.0.0.0/0"), map[string]any{},
			}}, "provider": provider},
			unknown: []*cel.AttributePatternType{pat("resource").QualString("ingress").QualInt(1).QualString("cidr_blocks")},
			want:    stateFail,
		},
	}
	cases = append(cases, absorptionCases(provider)...)

	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			iamCalls.Store(0)
			val, err := evalExpr(t, env, tc.expr, tc.vars, tc.unknown)
			got := toState(val, err)
			if called := iamCalls.Load() > 0; called != tc.stubCalled || errors.Is(err, errIAMCalled) != tc.stubCalled {
				t.Fatalf("%s: iam.parse stub called = %v, want %v", tc.id, called, tc.stubCalled)
			}
			if tc.neverPass && got == statePass {
				t.Fatalf("%s: SAFETY: %q returned pass with an outcome-changing unknown", tc.id, tc.expr)
			}
			if got != tc.want {
				t.Fatalf("%s: %q = %s (val %v, err %v), want %s", tc.id, tc.expr, got, val, err, tc.want)
			}
			if tc.trails != nil && !slices.Equal(unknownTrails(val), tc.trails) {
				t.Fatalf("%s: unknown trails = %v, want %v", tc.id, unknownTrails(val), tc.trails)
			}
		})
	}
}

// TestCELSemanticsLimits pins abort behavior under partial evaluation. A
// tripped cost limit aborts the whole evaluation (not_evaluable) even next to
// an unknown. A canceled context is an error that, like any error, is
// absorbed by an unknown on the other side of ||. Engine rule: check
// ctx.Err() before reading the value and map it to timeout.
func TestCELSemanticsLimits(t *testing.T) {
	env := newSemanticsEnv(t)
	const heavy = `[1,2,3,4,5,6,7,8,9,10].map(x, [1,2,3,4,5,6,7,8,9,10].map(y, x*y)).size() > 0`
	unk := []*cel.AttributePatternType{pat("resource").QualString("x")}
	vars := map[string]any{"resource": map[string]any{}, "provider": map[string]any{}}
	act, err := cel.PartialVars(vars, unk...)
	if err != nil {
		t.Fatalf("PartialVars: %v", err)
	}
	program := func(expr string, extra ...cel.ProgramOption) cel.Program {
		t.Helper()
		ast, iss := env.Compile(expr)
		if iss.Err() != nil {
			t.Fatalf("compile: %v", iss.Err())
		}
		opts := append([]cel.ProgramOption{cel.EvalOptions(cel.OptPartialEval, cel.OptTrackState), cel.InterruptCheckFrequency(1)}, extra...)
		prg, err := env.Program(ast, opts...)
		if err != nil {
			t.Fatalf("program: %v", err)
		}
		return prg
	}
	cancelCause := func(err error) (interpreter.CancellationCause, bool) {
		var ce interpreter.EvalCancelledError
		if errors.As(err, &ce) {
			return ce.Cause, true
		}
		return 0, false
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	for _, tc := range []struct {
		expr                  string
		control, cost, ctxCan state
	}{
		{heavy, statePass, stateNotEvaluable, stateNotEvaluable},
		{`resource.x || (` + heavy + `)`, statePass, stateNotEvaluable, stateUnknown},
	} {
		// Control: no limit, live context.
		val, _, err := program(tc.expr).ContextEval(context.Background(), act)
		if got := toState(val, err); got != tc.control {
			t.Fatalf("control %q = %s (err %v), want %s", tc.expr, got, err, tc.control)
		}

		val, _, err = program(tc.expr, cel.CostLimit(10)).ContextEval(context.Background(), act)
		if got := toState(val, err); got != tc.cost {
			t.Errorf("cost limit %q = %s (val %v, err %v), want %s", tc.expr, got, val, err, tc.cost)
		}
		if cause, ok := cancelCause(err); !ok || cause != interpreter.CostLimitExceeded {
			t.Errorf("cost limit %q: err %v is not EvalCancelledError{CostLimitExceeded}", tc.expr, err)
		}

		val, _, err = program(tc.expr).ContextEval(canceled, act)
		if got := toState(val, err); got != tc.ctxCan {
			t.Errorf("canceled %q = %s (val %v, err %v), want %s", tc.expr, got, val, err, tc.ctxCan)
		}
		if tc.ctxCan == stateNotEvaluable {
			if !errors.Is(err, context.Canceled) {
				t.Errorf("canceled %q: err %v does not wrap context.Canceled", tc.expr, err)
			}
		}
	}
}

// absorptionCases pin &&, ||, ternary and error-vs-unknown precedence.
// x is unknown, resource.missing is a no-such-key error.
func absorptionCases(provider map[string]any) []semCase {
	unk := []*cel.AttributePatternType{pat("resource").QualString("x")}
	vars := map[string]any{"resource": map[string]any{"t": true, "f": false}, "provider": provider}
	rows := []struct {
		id, expr string
		want     state
	}{
		{"A-and-false-unk", `resource.f && resource.x`, stateFail},
		{"A-and-unk-false", `resource.x && resource.f`, stateFail},
		{"A-and-true-unk", `resource.t && resource.x`, stateUnknown},
		{"A-or-true-unk", `resource.x || resource.t`, statePass},
		{"A-or-false-unk", `resource.f || resource.x`, stateUnknown},
		{"A-not-unk", `!resource.x`, stateUnknown},
		{"A-ternary-cond-unk", `resource.x ? true : false`, stateUnknown},
		{"A-ternary-branch-skipped", `resource.t ? true : resource.x`, statePass},
		{"A-ternary-branch-taken", `resource.f ? true : resource.x`, stateUnknown},
		{"A-eq-unk", `resource.x == "a"`, stateUnknown},
		{"A-in-unk", `"a" in resource.x`, stateUnknown},
		{"A-exists-unk", `resource.x.exists(e, e == "a")`, stateUnknown},
		// Error vs unknown: a decided side still absorbs an error; with no
		// decided side the unknown wins over the error.
		{"E-and-false-err", `resource.f && resource.missing`, stateFail},
		{"E-or-true-err", `resource.missing || resource.t`, statePass},
		{"E-and-unk-err", `resource.x && resource.missing`, stateUnknown},
		{"E-and-err-unk", `resource.missing && resource.x`, stateUnknown},
		{"E-or-unk-err", `resource.x || resource.missing`, stateUnknown},
		{"E-err", `resource.missing`, stateNotEvaluable},
		{"E-non-bool", `resource.t ? "yes" : "no"`, stateNotEvaluable},
		{"E-ternary-err-untaken", `resource.t ? true : resource.missing`, statePass},
		{"E-ternary-err-untaken-else", `resource.f ? resource.missing : true`, statePass},
		// Presence under omit+pattern: an omitted, patterned key is never
		// decided absent or present.
		{"H-has-unk", `has(resource.x)`, stateUnknown},
		{"H-not-has-unk", `!has(resource.x)`, stateUnknown},
		{"H-in-unk", `"x" in resource`, stateUnknown},
		{"H-not-in-unk", `!("x" in resource)`, stateUnknown},
		{"H-has-known-sibling", `has(resource.t)`, statePass},
		// ext.Strings functions do not run on unknown arguments.
		{"S-ext-unk", `resource.x.lowerAscii() == "a"`, stateUnknown},
	}
	out := make([]semCase, 0, len(rows))
	for _, r := range rows {
		out = append(out, semCase{id: r.id, expr: r.expr, vars: vars, unknown: unk, want: r.want, neverPass: r.want != statePass})
	}
	return out
}
