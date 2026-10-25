package lifecycle

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/celeng"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
)

// notEvaluableGolden is the not_evaluable object of
// stages/{plan,apply}_not_evaluable_*.json: the profile fixture the mode
// table comes from and the control the engine reports not_evaluable.
type notEvaluableGolden struct {
	Profile  string `json:"profile"`
	Control  string `json:"control"`
	Blocking bool   `json:"blocking"` // the control's mode under the profile is hard_fail
}

// notEvaluableClasses are every engine ErrClass (the oracle names
// scope_untrusted, limit and no_such_attribute); every golden runs once per
// class with <err_class> replaced in the wanted summaries.
var notEvaluableClasses = []engine.ErrClass{engine.ErrScopeUntrusted, engine.ErrLimit, engine.ErrNoSuchAttribute,
	engine.ErrTypeError, engine.ErrTimeout, engine.ErrUnresolved}

// forceCompiler is celeng except for one control, whose program reports
// not_evaluable with err. The engine tasks produce these classes; this test
// covers what lifecycle does with them.
type forceCompiler struct {
	control string
	err     engine.ErrClass
}

func (forceCompiler) ID() string { return "force-not-evaluable" }

func (c forceCompiler) Compile(ctl *bundle.Control, schema tftypes.Type) (engine.Program, error) {
	if ctl.ID == c.control {
		return forcedProgram(c.err), nil
	}
	return celeng.NewCompiler(dbSchemas{}).Compile(ctl, schema)
}

type forcedProgram engine.ErrClass

func (p forcedProgram) Eval(context.Context, *engine.Activation) engine.Outcome {
	return engine.Outcome{State: engine.NotEvaluable, Err: engine.ErrClass(p)}
}

// profileFixture parses testdata/profiles/<name>.dsse.json. The signature is
// checked by TestNotEvaluableProfileVerifies (ctftest keyring); here the
// payload is only an input to the mode table.
func profileFixture(t *testing.T, name string) *profile.Profile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("../../testdata/profiles", name+".dsse.json"))
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	p, _, err := profile.Parse(payload)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestNotEvaluableAsFail runs stages/*_not_evaluable_*.json under the
// bobthecorp-permissive profile (run mode soft_fail, one control_floors entry
// hard_fail): a blocking not_evaluable control errors at plan and apply_pre
// (an apply_pre error is never forwarded), a non-blocking one warns like
// fail, and no not_evaluable result is a pending diagnostic.
func TestNotEvaluableAsFail(t *testing.T) {
	const pattern = "*_not_evaluable_*.json"
	claimed, _ := filepath.Glob(filepath.Join("testdata/stages", pattern))
	// One golden per not_evaluable cell of the State table; an error at
	// apply_pre is never forwarded (proxy TestRouteApplyBlocked).
	for _, n := range []string{"plan_not_evaluable_blocking", "plan_not_evaluable_non_blocking",
		"apply_not_evaluable_blocking", "apply_not_evaluable_non_blocking", "apply_post_not_evaluable_update_blocking",
		"apply_post_not_evaluable_create_blocking", "refresh_not_evaluable_blocking"} {
		if !slices.Contains(claimed, filepath.Join("testdata/stages", n+".json")) {
			t.Errorf("golden %s missing", n)
		}
	}
	all, _ := filepath.Glob("testdata/stages/*.json")
	for _, f := range all {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		// runStages skips goldens with the not_evaluable setup key without a
		// setup: each must be ours. A not_evaluable result state is not the key.
		if strings.Contains(string(raw), `"not_evaluable":`) && !slices.Contains(claimed, f) {
			t.Errorf("%s has not_evaluable but does not match %s", f, pattern)
		}
	}
	for _, class := range notEvaluableClasses {
		t.Run(string(class), func(t *testing.T) {
			ran := 0
			t.Cleanup(func() {
				if ran != len(claimed) {
					t.Errorf("setup ran for %d of %d goldens", ran, len(claimed))
				}
			})
			runStages(t, pattern, func(t *testing.T, g *stageGolden, l *Lifecycle) {
				ran++
				ne := g.NotEvaluable
				if ne == nil {
					t.Fatal("golden without not_evaluable")
				}
				p := profileFixture(t, ne.Profile)
				table, err := profile.ComputeModeTable(profile.TableInput{Resolution: profile.Resolution{
					OrgID: p.OrgID, Fallback: profile.ProfileApplied, Profile: p}})
				if err != nil {
					t.Fatal(err)
				}
				want := profile.SoftFail // the run mode
				if ne.Blocking {
					want = profile.HardFail // the control_floors entry
				}
				if got := table.ControlMode(ne.Control, true); table.RunMode != profile.SoftFail || got != want {
					t.Fatalf("permissive table: run mode %s, want soft_fail; %s mode %s, want %s", table.RunMode, ne.Control, got, want)
				}
				l.cfg.Table = table
				l.compiler = forceCompiler{control: ne.Control, err: class}
				for i := range g.Want.Diagnostics {
					d := &g.Want.Diagnostics[i]
					if strings.Contains(d.Summary, "pending") {
						t.Fatalf("golden wants a pending diagnostic for not_evaluable: %s", d.Summary)
					}
					d.Summary = strings.ReplaceAll(d.Summary, "<err_class>", string(class))
				}
				if g.Want.Evidence == nil {
					t.Fatal("golden without want.evidence")
				}
				for _, r := range g.Want.Evidence.Results {
					if r.State == "not_evaluable" && r.Decision == "pending" {
						t.Fatalf("golden wants a pending decision for not_evaluable %s", r.Control)
					}
				}
			})
		})
	}
}

// TestNotEvaluableNeverPending: across the matrix, grandfathered or not, a
// not_evaluable result takes the fail cell and the fail evidence decision,
// is never a pending diagnostic or decision, and gets the not_evaluable text
// whenever it has a diagnostic.
func TestNotEvaluableNeverPending(t *testing.T) {
	ctl := &bundle.Control{ID: "c", Message: "m"}
	for stage, ops := range stageOps {
		for _, op := range ops {
			for _, m := range []profile.Mode{profile.Advisory, profile.SoftFail, profile.Grandfather, profile.HardFail} {
				for _, a := range []bundle.Action{bundle.ActionDeny, bundle.ActionWarn} {
					for _, gf := range []bool{false, true} {
						if ne, f := Classify(m, a, engine.NotEvaluable, stage, op, gf), Classify(m, a, engine.Fail, stage, op, gf); ne != f {
							t.Errorf("%s/%s/%s/%s grandfathered=%v: not_evaluable %+v, fail %+v", stage, op, m, a, gf, ne, f)
						}
					}
					v := Classify(m, a, engine.NotEvaluable, stage, op, false)
					if dec := decision(stage, engine.NotEvaluable, v.Severity); dec == "pending" || dec != decision(stage, engine.Fail, v.Severity) {
						t.Errorf("%s/%s/%s/%s: not_evaluable decision %q, fail %q", stage, op, m, a, dec, decision(stage, engine.Fail, v.Severity))
					}
					if v.Severity == SeverityNone {
						continue
					}
					for _, class := range notEvaluableClasses {
						out := engine.Outcome{State: engine.NotEvaluable, Err: class}
						s, d := diagText(ctl, out, m, v.Severity, stage, "")
						if stage == StageEphemeralOpen && v.Severity == SeverityError {
							// A block names the control message; the class is a detail line.
							if s != "[c] m" || !strings.Contains(d, "\nNot evaluable ("+string(class)+"): treated as a failure of this control.\n") {
								t.Errorf("%s/%s/%s/%s/%s: %q %q", stage, op, m, a, class, s, d)
							}
							continue
						}
						if s != "[c] not evaluable ("+string(class)+")" || d != "Treated as a failure of this control." {
							t.Errorf("%s/%s/%s/%s/%s: %q %q", stage, op, m, a, class, s, d)
						}
					}
				}
			}
		}
	}
}
