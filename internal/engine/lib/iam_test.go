package lib

import (
	"context"
	"errors"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"

	"github.com/compliancetf/terraform-provider-aws/internal/iampolicy"
)

// TestPrincipalsInAccountPrecedence pins the argument handling of
// iam.principals_in_account: an error argument passes through in
// order, an unknown or invalid partition is ErrUnresolved even when the
// statement is unknown, and an unknown statement stays unknown only when
// account and partition are known and valid.
func TestPrincipalsInAccountPrecedence(t *testing.T) {
	unk := types.NewUnknown(1, nil)
	errS, errA, errP := types.NewErr("s"), types.NewErr("a"), types.NewErr("p")
	acct, aws := types.String("111111111111"), types.String("aws")
	isUnres := func(v ref.Val) bool { e, ok := v.(*types.Err); return ok && errors.Is(e, ErrUnresolved) }
	for _, tc := range []struct {
		name    string
		s, a, p ref.Val
		want    func(ref.Val) bool
	}{
		{"stmt error first", errS, errA, errP, func(v ref.Val) bool { return v == errS }},
		{"account error before partition", unk, errA, errP, func(v ref.Val) bool { return v == errA }},
		{"partition error", unk, acct, errP, func(v ref.Val) bool { return v == errP }},
		{"unknown partition", unk, acct, unk, isUnres},
		{"unknown account", unk, unk, aws, isUnres},
		{"invalid partition, unknown stmt", unk, acct, types.String("aws-mars"), isUnres},
		{"empty partition, unknown stmt", unk, acct, types.String(""), isUnres},
		{"unknown stmt", unk, acct, aws, types.IsUnknown},
	} {
		if got := principalsInAccount(tc.s, tc.a, tc.p); !tc.want(got) {
			t.Errorf("%s: got %v", tc.name, got)
		}
	}
}

func iamCatalog(t *testing.T, services string) *iampolicy.Catalog {
	t.Helper()
	c, err := iampolicy.LoadCatalog([]byte(`{"format":"compliancetf.iam-actions/v1","retrieved":"2026-10-01","services":{` + services +
		`},"snapshot":"sha256:` + strings.Repeat("0", 64) + `","source":"aws-service-reference"}`))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func expanded(t *testing.T, v ref.Val) []string {
	t.Helper()
	st := v.(traits.Mapper).Get(types.String("statements")).(traits.Lister).Get(types.Int(0))
	l, err := st.(traits.Mapper).Get(types.String("actions_expanded")).ConvertToNative(reflect.TypeOf([]string{}))
	if err != nil {
		t.Fatal(err)
	}
	return l.([]string)
}

// TestIAMCacheKey: one document parsed under two catalogs is two cache
// entries with different actions_expanded; the same catalog under another
// content digest is a third; a repeat is a hit.
func TestIAMCacheKey(t *testing.T) {
	a := iamCatalog(t, `"kms":["decrypt","encrypt"]`)
	b := iamCatalog(t, `"kms":["createkey","decrypt","encrypt"]`)
	c := newDocCache(DefaultDocCacheBytes)
	doc := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"kms:*","Resource":"*"}}`
	va, err := c.iam(doc, a, "sha256:content-1", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	vb, err := c.iam(doc, b, "sha256:content-1", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.m) != 2 || c.decodes != 2 {
		t.Fatalf("two catalogs: %d entries, %d decodes, want 2, 2", len(c.m), c.decodes)
	}
	if ea, eb := expanded(t, va), expanded(t, vb); slices.Equal(ea, eb) {
		t.Fatalf("actions_expanded equal under two catalogs: %v", ea)
	}
	if _, err := c.iam(doc, a, "sha256:content-2", time.Second); err != nil || len(c.m) != 3 {
		t.Fatalf("content digest change: %d entries, err %v, want 3", len(c.m), err)
	}
	if _, err := c.iam(doc, a, "sha256:content-1", time.Second); err != nil || c.decodes != 3 {
		t.Fatalf("repeat: %d decodes, err %v, want a hit", c.decodes, err)
	}
	// A spent budget is limit even on a hit: never depends on cache state.
	for _, spent := range []time.Duration{0, -time.Second} {
		if _, err := c.iam(doc, a, "sha256:content-1", spent); !errors.Is(err, ErrLimit) {
			t.Fatalf("hit with budget %v: %v, want limit", spent, err)
		}
	}
	// Admission depends on the live budget: a limit is never cached.
	other := doc + " "
	if _, err := c.iam(other, a, "sha256:content-1", time.Nanosecond); !errors.Is(err, ErrLimit) {
		t.Fatalf("no budget: %v, want ErrLimit", err)
	}
	if _, err := c.iam(other, a, "sha256:content-1", time.Second); err != nil {
		t.Fatalf("budget restored: %v", err)
	}
	if _, err := c.iam(doc, nil, "sha256:content-1", time.Second); !errors.Is(err, ErrUnresolved) {
		t.Fatalf("nil catalog: %v, want ErrUnresolved", err)
	}
}

func TestIAMBindings(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/iam/actions-fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	cat, err := iampolicy.LoadCatalog(data)
	if err != nil {
		t.Fatal(err)
	}
	env, err := cel.NewEnv(cel.Variable("v", cel.StringType), IAM())
	if err != nil {
		t.Fatal(err)
	}
	bound, err := IAMProgram(cat, "sha256:content")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := IAMProgram(nil, "sha256:content"); err == nil {
		t.Fatal("IAMProgram(nil catalog): want an error")
	}
	doc := `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","NotAction":["kms:*","s3:Delete*"],"Resource":"*"},
		{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"NumericGreaterThan":{"s3:max-keys":"3600"}}},
		{"Effect":"Allow","Action":"bobthecorp:Get*","Resource":"*"}]}`
	deadline := time.Now().Add(time.Minute)
	for _, tc := range []struct {
		expr    string
		opts    []cel.ProgramOption
		vars    map[string]any
		want    any
		wantErr error
	}{
		// Allow+NotAction: grants everything outside the NotAction patterns.
		{`iam.grants(iam.parse(v).statements[0], "s3:GetObject")`, nil, nil, true, nil},
		{`iam.grants(iam.parse(v).statements[0], "s3:deletebucket")`, nil, nil, false, nil},
		{`iam.grants(iam.parse(v).statements[0], "KMS:Decrypt")`, nil, nil, false, nil},
		{`iam.grants_all(iam.parse(v).statements[0], "ec2")`, nil, nil, true, nil},
		{`iam.grants_all(iam.parse(v).statements[0], "kms")`, nil, nil, false, nil},
		{`iam.grants(iam.parse(v).statements[0], "ec2:NoSuchAction")`, nil, nil, nil, ErrUnresolved},
		{`iam.grants_all(iam.parse(v).statements[0], "bobthecorp")`, nil, nil, nil, ErrUnresolved},
		{`iam.grants(iam.parse(v).statements[2], "s3:GetObject")`, nil, nil, nil, ErrUnresolved},
		// Numeric comparison over condition text is plain CEL.
		{`iam.parse(v).statements[1].conditions.all(c, c.values.all(x, int(x) > 3000))`, nil, nil, true, nil},
		{`iam.parse(v).statements.size() == 3 && iam.parse(v).catalog.startsWith("sha256:")`, nil, nil, true, nil},
		// The deadline resolves inside a comprehension.
		{`[v].all(d, iam.parse(d).statements[0].action_any)`, nil, nil, true, nil},
		// A forged statement is a type error, never a grant.
		{`iam.grants({"actions": ["*"], "action_all": true}, "s3:GetObject")`, nil, nil, nil, ErrInvalid},
		{`iam.parse(v + "x").version`, nil, nil, nil, ErrInvalid},
		// Without the program binding or the deadline the call fails closed
		// (a cache hit needs no budget, so these documents are new).
		{`iam.parse(v).version`, []cel.ProgramOption{}, nil, nil, ErrUnresolved},
		{`iam.parse(v).version`, nil, map[string]any{"v": doc + "\n"}, nil, ErrLimit},
		{`iam.parse(v).version`, nil, map[string]any{"v": doc + "\n\n", DeadlineVar: time.Now().Add(-time.Second)}, nil, ErrLimit},
	} {
		t.Run(tc.expr, func(t *testing.T) {
			ast, iss := env.Compile(tc.expr)
			if iss.Err() != nil {
				t.Fatal(iss.Err())
			}
			opts := tc.opts
			if opts == nil {
				opts = []cel.ProgramOption{bound}
			}
			prg, err := env.Program(ast, opts...)
			if err != nil {
				t.Fatal(err)
			}
			vars := tc.vars
			if vars == nil {
				vars = map[string]any{"v": doc, DeadlineVar: deadline}
			}
			out, _, err := prg.Eval(vars)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil || out.Value() != tc.want {
				t.Fatalf("got %v, %v, want %v", out, err, tc.want)
			}
		})
	}
}

// TestIAMFlagsNeedSink: a program with IAMFlags evaluated without
// the UnresolvedVar entry fails loudly instead of losing an absorbed
// unresolved answer (err || true would pass).
func TestIAMFlagsNeedSink(t *testing.T) {
	env, err := cel.NewEnv(cel.Variable("v", cel.StringType), IAM())
	if err != nil {
		t.Fatal(err)
	}
	ast, iss := env.Compile(`iam.parse(v).version == "" || true`)
	if iss.Err() != nil {
		t.Fatal(iss.Err())
	}
	// The engine's path: ContextEval, partial evaluation, a partial activation.
	prg, err := env.Program(ast, IAMFlags(), cel.EvalOptions(cel.OptPartialEval, cel.OptTrackState))
	if err != nil {
		t.Fatal(err)
	}
	for name, vars := range map[string]map[string]any{
		"missing":   {"v": "{}"},
		"not *bool": {"v": "{}", UnresolvedVar: true},
	} {
		if out, _, err := prg.Eval(vars); err == nil || !strings.Contains(err.Error(), UnresolvedVar) {
			t.Errorf("%s sink: got %v, %v, want an error naming %s", name, out, err, UnresolvedVar)
		}
		act, err := cel.PartialVars(vars)
		if err != nil {
			t.Fatal(err)
		}
		if out, _, err := prg.ContextEval(context.Background(), act); err == nil || !strings.Contains(err.Error(), UnresolvedVar) {
			t.Errorf("%s sink, ContextEval: got %v, %v, want an error naming %s", name, out, err, UnresolvedVar)
		}
	}
	hit := new(bool)
	if out, _, err := prg.Eval(map[string]any{"v": "{}", UnresolvedVar: hit}); err != nil || out != types.True || !*hit {
		t.Fatalf("with sink: got %v, %v, flag %v, want true and the flag set", out, err, *hit)
	}
}
