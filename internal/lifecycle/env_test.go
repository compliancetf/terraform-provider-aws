package lifecycle

import (
	"bytes"
	"context"
	"log"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/celeng"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
)

// trustedEnvGolden is the trusted_env object of stages/env_*.json.
type trustedEnvGolden struct {
	ScopeEnvironment string `json:"scope_environment"` // signed profile scope; "" = none
	HCLEnvironment   string `json:"hcl_environment"`   // compliance { environment }
	EnvEnvironment   string `json:"env_environment"`   // COMPLIANCETF_ENVIRONMENT
	WantEnv          string `json:"want_env"`
	WantEnvKnown     bool   `json:"want_env_known"`
}

// envDependentID is the control the test compiler turns env-dependent.
const envDependentID = "rds_db_instance_encryption_at_rest_enabled"

// envExpr is the real CEL env-dependent control expression (U-12).
const envExpr = `env != "prod" || resource.storage_encrypted == true`

// envCompiler compiles envDependentID with envExpr in place of its stage
// expr (which reads no env) through real celeng, and records each
// activation it sees. Every other control is plain celeng.
type envCompiler struct{ seen *[]engine.Activation }

func (envCompiler) ID() string { return "env-test" }

func (c envCompiler) Compile(ctl *bundle.Control, schema tftypes.Type) (engine.Program, error) {
	if ctl.ID != envDependentID {
		return celeng.NewCompiler(dbSchemas{}).Compile(ctl, schema)
	}
	env := *ctl
	expr := envExpr
	env.Expr = &expr
	p, err := celeng.NewCompiler(dbSchemas{}).Compile(&env, schema)
	if err != nil {
		return nil, err
	}
	return envProgram{inner: p, seen: c.seen}, nil
}

type envProgram struct {
	inner engine.Program
	seen  *[]engine.Activation
}

func (p envProgram) Eval(ctx context.Context, a *engine.Activation) engine.Outcome {
	*p.seen = append(*p.seen, *a)
	return p.inner.Eval(ctx, a)
}

// TestTrustedEnv runs stages/env_*.json: the mode table comes from the real
// profile.ComputeModeTable, so a local environment (HCL or
// COMPLIANCETF_ENVIRONMENT) is offered exactly as Configure offers it, and
// the goldens assert control results.
func TestTrustedEnv(t *testing.T) {
	runStages(t, "env_*.json", func(t *testing.T, g *stageGolden, l *Lifecycle) {
		te := g.TrustedEnv
		if te == nil {
			t.Fatal("env golden without trusted_env")
		}
		l.cfg.Table = envTable(t, g.Mode, te)
		var seen []engine.Activation
		l.compiler = envCompiler{seen: &seen}
		t.Cleanup(func() {
			if len(seen) == 0 {
				t.Error("env-dependent control never evaluated")
			}
			for _, a := range seen {
				if a.Env != te.WantEnv || a.EnvKnown != te.WantEnvKnown {
					t.Errorf("activation env %q known %v, want %q known %v", a.Env, a.EnvKnown, te.WantEnv, te.WantEnvKnown)
				}
			}
		})
	})
}

// envTable is the mode table Configure computes from the real
// profile.ComputeModeTable when te's local environments (HCL and
// COMPLIANCETF_ENVIRONMENT) are offered next to its signed profile scope.
func envTable(t *testing.T, mode profile.Mode, te *trustedEnvGolden) profile.ModeTable {
	t.Helper()
	p := &profile.Profile{OrgID: "bobthecorp", ModeFloor: profile.ModeFloor{Default: profile.SoftFail,
		Environments: map[string]profile.Mode{"dev": profile.SoftFail, "prod": profile.HardFail}}}
	if te.ScopeEnvironment != "" {
		p.Scope = &profile.Scope{Environment: te.ScopeEnvironment}
	}
	table, err := profile.ComputeModeTable(profile.TableInput{
		Resolution: profile.Resolution{OrgID: "bobthecorp", Fallback: profile.ProfileApplied, Profile: p},
		HCLMode:    mode.String(), HCLEnvironment: te.HCLEnvironment, EnvEnvironment: te.EnvEnvironment})
	if err != nil {
		t.Fatal(err)
	}
	return table
}

// envSelector is the fail-open-prone selector of the envsel_*.json grant:
// true for every environment but prod, so an untrusted env must never make
// it true.
const envSelector = "env != 'prod'"

// TestTrustedEnvSelector runs stages/envsel_*.json: a grant selector is
// bound like its control. The verified grant on the failing
// env-independent rds_db_instance_encryption_at_rest_enabled waives it only
// under a trusted env other than prod; a signed scope prod is not widened by
// a local dev; without trusted scope, even with a local environment offered,
// the selector is not_evaluable scope_untrusted, the grant is recorded
// rejected and the control stays blocking.
func TestTrustedEnvSelector(t *testing.T) {
	now := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	runStages(t, "envsel_*.json", func(t *testing.T, g *stageGolden, l *Lifecycle) {
		te := g.TrustedEnv
		if te == nil {
			t.Fatal("envsel golden without trusted_env")
		}
		l.cfg.Table = envTable(t, g.Mode, te)
		if env, known := trustedEnv(l.cfg.Table.Environment); env != te.WantEnv || known != te.WantEnvKnown {
			t.Fatalf("trusted env %q known %v, want %q known %v", env, known, te.WantEnv, te.WantEnvKnown)
		}
		withGrant(t, l, envSelector, now)
		var logs bytes.Buffer
		prev := log.Writer()
		log.SetOutput(&logs)
		t.Cleanup(func() {
			log.SetOutput(prev)
			if got := strings.Contains(logs.String(), "selector scope_untrusted"); got == te.WantEnvKnown {
				t.Errorf("selector scope_untrusted logged %v with env known %v:\n%s", got, te.WantEnvKnown, logs.String())
			}
		})
	})
}

// TestCheckBindsSelectorEnv: a caller-set Env on the activation (always the
// value that flips the expected result) never
// reaches an exception selector, a signed grant's or a sidecar entry's;
// check binds the selector to the trusted env only, so without one the
// exception cannot waive. The whole result is asserted: an untrusted env
// rejects the exception (selector scope_untrusted), a trusted prod leaves it
// unmatched and recorded nowhere, a trusted dev applies it.
func TestCheckBindsSelectorEnv(t *testing.T) {
	now := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	for _, kind := range []struct {
		name    string
		install func(*testing.T, *Lifecycle)
		id      string
		source  string
	}{
		{"grant", func(t *testing.T, l *Lifecycle) { withGrant(t, l, envSelector, now) }, "bobthecorp-pg-encryption", "grant"},
		{"sidecar", func(t *testing.T, l *Lifecycle) { withSidecar(t, l, envDependentID, envSelector, now) }, "bobthecorp-op", "self_service"},
	} {
		for _, c := range []struct {
			name      string
			env       profile.Dim
			callerEnv string // the caller's Env: the opposite of what waives, so a leak flips the result
			decision  string
			exception string // "" = no exception recorded; else "applied" or "rejected"
		}{
			{"untrusted", profile.Dim{}, "dev", "blocked", "rejected"},
			{"local dev", profile.Dim{Value: "dev", Source: "local"}, "dev", "blocked", "rejected"},
			{"trusted prod", profile.Dim{Value: "prod", Source: "profile"}, "dev", "blocked", ""},
			{"trusted dev", profile.Dim{Value: "dev", Source: "profile"}, "prod", "excepted", "applied"},
		} {
			t.Run(kind.name+"/"+c.name, func(t *testing.T) {
				l := New(Options{})
				l.testPerResource = 10 * time.Second
				l.cfg = &Configured{Table: profile.ModeTable{RunMode: profile.HardFail, Environment: c.env},
					Controls: stageControlSet(t), Schemas: dbSchemas{}}
				kind.install(t, l)
				ctl := l.cfg.Controls.For("aws_db_instance", bundle.OnCreate)[0]
				if ctl.ID != envDependentID {
					t.Fatalf("first control %s", ctl.ID)
				}
				v := tftypes.NewValue(dbType, map[string]tftypes.Value{
					"storage_encrypted": tftypes.NewValue(tftypes.Bool, false), "kms_key_id": tftypes.NewValue(tftypes.String, nil),
					"engine": tftypes.NewValue(tftypes.String, nil), "deletion_protection": tftypes.NewValue(tftypes.Bool, nil),
					"id": tftypes.NewValue(tftypes.String, nil)})
				a := &engine.Activation{Resource: v, Config: v, Op: engine.OpCreate, Env: c.callerEnv, EnvKnown: true}
				var logs bytes.Buffer
				prev := log.Writer()
				log.SetOutput(&logs)
				t.Cleanup(func() { log.SetOutput(prev) })
				var col collected
				l.check(context.Background(), l.cfg, StagePlan, &ctl, a, "", "", &col)
				if len(col.results) != 1 {
					t.Fatalf("results %+v", col.results)
				}
				r := col.results[0]
				if r.Control != envDependentID || r.State != "fail" || r.Decision != c.decision || r.Err != "" ||
					!slices.Equal(r.Paths, []string{"storage_encrypted"}) {
					t.Errorf("result %+v, want fail %s on storage_encrypted", r, c.decision)
				}
				switch e := r.Exception; {
				case c.exception == "" && e != nil:
					t.Errorf("exception %+v, want none", e)
				case c.exception != "" && (e == nil || e.ID != kind.id || e.Source != kind.source || e.Status != c.exception):
					t.Errorf("exception %+v, want %s %s %s", e, kind.id, kind.source, c.exception)
				}
				if rejected := strings.Contains(logs.String(), "selector scope_untrusted"); rejected != (c.exception == "rejected") {
					t.Errorf("selector scope_untrusted logged %v:\n%s", rejected, logs.String())
				}
				if want := map[string]int{"blocked": 1, "excepted": 0}[c.decision]; len(col.diags) != want {
					t.Errorf("diagnostics %+v, want %d", col.diags, want)
				}
			})
		}
	}
}

func TestTrustedEnvSource(t *testing.T) {
	for _, c := range []struct {
		dim   profile.Dim
		env   string
		known bool
	}{
		{profile.Dim{Value: "prod", Source: "profile"}, "prod", true},
		{profile.Dim{Value: "Prod", Source: "profile"}, "Prod", true}, // exact, never normalized
		{profile.Dim{}, "", false},
		{profile.Dim{Value: "prod"}, "", false},
		{profile.Dim{Value: "prod", Source: "verdict"}, "prod", true}, // the verified verdict scope
		{profile.Dim{Value: " prod", Source: "verdict"}, "", false},
		{profile.Dim{Value: "prod", Source: "local"}, "", false},
		{profile.Dim{Source: "profile"}, "", false},
		{profile.Dim{Value: " prod", Source: "profile"}, "", false},
		{profile.Dim{Value: "prod\n", Source: "profile"}, "", false},
	} {
		env, known := trustedEnv(c.dim)
		if env != c.env || known != c.known {
			t.Errorf("trustedEnv(%+v) = %q, %v; want %q, %v", c.dim, env, known, c.env, c.known)
		}
	}
}

// TestEvalOverwritesEnv: a caller-set Env never reaches the program.
func TestEvalOverwritesEnv(t *testing.T) {
	var seen []engine.Activation
	l := New(Options{})
	l.testPerResource = 10 * time.Second // verdicts, not the 50 ms budget under load
	l.compiler = envCompiler{seen: &seen}
	ctl := stageControlSet(t).For("aws_db_instance", bundle.OnCreate)[0]
	if ctl.ID != envDependentID {
		t.Fatalf("first control %s", ctl.ID)
	}
	v := tftypes.NewValue(dbType, map[string]tftypes.Value{
		"storage_encrypted": tftypes.NewValue(tftypes.Bool, false), "kms_key_id": tftypes.NewValue(tftypes.String, nil),
		"engine": tftypes.NewValue(tftypes.String, nil), "deletion_protection": tftypes.NewValue(tftypes.Bool, nil),
		"id": tftypes.NewValue(tftypes.String, nil)})
	a := &engine.Activation{Resource: v, Config: v, Op: engine.OpCreate, Env: "dev", EnvKnown: true}
	out := l.eval(context.Background(), nil, profile.Dim{}, &ctl, a)
	if out.State != engine.NotEvaluable || out.Err != engine.ErrScopeUntrusted {
		t.Errorf("outcome %+v, want not_evaluable scope_untrusted", out)
	}
	if len(seen) != 1 || seen[0].EnvKnown || seen[0].Env != "" {
		t.Errorf("program saw %+v", seen)
	}
	if a.Env != "dev" || !a.EnvKnown {
		t.Error("eval mutated the caller's activation")
	}
}
