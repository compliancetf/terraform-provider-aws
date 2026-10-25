//go:build unix

package lifecycle

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/exceptions"
	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
	"github.com/compliancetf/terraform-provider-aws/internal/verdict"
	"github.com/compliancetf/terraform-provider-aws/internal/verdict/verdicttest"
)

// scopeLifecycle is verdictLifecycle under a profile with scope (nil: none)
// and mode_floor dev soft_fail, production hard_fail, with a self-service
// entry on opEncryption scoped to workspace bobthecorp-reporting-prod, the
// local inputs hclEnv and COMPLIANCETF_WORKSPACE localWS, and the
// Configure-time table input, table and sidecar a real Configure builds.
func scopeLifecycle(t *testing.T, k verdicttest.Key, scope *profile.Scope, hclEnv, localWS string) *Lifecycle {
	t.Helper()
	l := verdictLifecycle(t, k)
	now := verdictIssued.Add(time.Hour)
	p := l.cfg.Resolution.Profile
	p.Scope = scope
	p.ModeFloor = profile.ModeFloor{Default: profile.SoftFail, Environments: map[string]profile.Mode{"dev": profile.SoftFail, "production": profile.HardFail}}
	p.Exceptions = profile.Exceptions{SelfService: []string{opEncryption}, MaxLifetimeDays: 180, Coverable: map[string][]string{opEncryption: {"self_service"}}}
	in := profile.TableInput{Resolution: profile.Resolution{OrgID: "bobthecorp", Governed: true, Profile: p, Fallback: profile.ProfileApplied},
		HCLEnvironment: hclEnv, Workspace: localWS, SidecarConfigured: true}
	table, err := profile.ComputeModeTable(in)
	if err != nil {
		t.Fatal(err)
	}
	side := filepath.Join(t.TempDir(), "exceptions.hcl")
	if err := os.WriteFile(side, []byte(`exception "bobthecorp-op" {
  controls  = ["`+opEncryption+`"]
  match     = "true"
  workspace = "bobthecorp-reporting-prod"
  reason    = "OPS-4411"
  expires   = "2026-12-01"
}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	c := l.cfg
	c.Block, c.Resolution, c.Table, c.tableIn = Block{ExceptionsFile: side, HCLEnvironment: hclEnv, Workspace: localWS}, in.Resolution, table, in
	cov, warns := exceptions.NewCoverability(c.Controls.Coverable(), table.Exceptions)
	if len(warns) != 0 {
		t.Fatalf("coverability: %v", warns)
	}
	if c.Sidecar, _, err = loadSidecar(c.Block, table, c.Controls, cov, now, exceptions.Clock{}); err != nil {
		t.Fatal(err)
	}
	return l
}

// TestVerdictScopeApply: at apply a verdict scope is trusted only
// on a dimension the signed profile scope fixes:
// there its environment selects the floor (local values only
// raise it) and a workspace-scoped exemption applies only when it names
// that workspace. Over an unscoped profile, or without a verdict, the
// strongest floor applies and the scoped exemption is rejected.
// COMPLIANCETF_WORKSPACE and the HCL environment never unlock it or lower
// the floor.
func TestVerdictScopeApply(t *testing.T) {
	k := verdicttest.NewKey(t, verdictIssued.Add(-24*time.Hour))
	const rp = "bobthecorp-reporting-prod"
	for _, c := range []struct {
		name                                   string
		scope                                  *profile.Scope // signed profile scope
		verdictWS, verdictEnv, hclEnv, localWS string
		noVerdict, excepted                    bool
		want                                   hook.Severity
	}{
		{name: "no verdict: strongest floor, scoped entry rejected", noVerdict: true, localWS: rp, want: hook.SeverityError},
		{name: "profile-fixed workspace matched by the verdict unlocks the entry", scope: &profile.Scope{Workspace: rp},
			verdictWS: rp, verdictEnv: "production", excepted: true},
		{name: "verdict workspace over an unscoped profile never unlocks", verdictWS: rp, verdictEnv: "production", want: hook.SeverityError},
		{name: "local workspace spoof never unlocks", scope: &profile.Scope{Workspace: "bobthecorp-other"},
			verdictWS: "bobthecorp-other", verdictEnv: "production", localWS: rp, want: hook.SeverityError},
		{name: "verdict environment over an unscoped profile keeps the strongest floor", verdictWS: "bobthecorp-other", verdictEnv: "dev", want: hook.SeverityError},
		{name: "profile-fixed environment matched by the verdict selects the lower floor", scope: &profile.Scope{Environment: "dev"},
			verdictWS: "bobthecorp-other", verdictEnv: "dev", want: hook.SeverityWarning},
		{name: "hcl environment spoof never lowers", scope: &profile.Scope{Environment: "production"},
			verdictWS: "bobthecorp-other", verdictEnv: "production", hclEnv: "dev", want: hook.SeverityError},
		{name: "hcl environment raises", scope: &profile.Scope{Environment: "dev"},
			verdictWS: "bobthecorp-other", verdictEnv: "dev", hclEnv: "production", want: hook.SeverityError},
	} {
		t.Run(c.name, func(t *testing.T) {
			l := scopeLifecycle(t, k, c.scope, c.hclEnv, c.localWS)
			if c.noVerdict {
				if err := os.Unsetenv(verdict.EnvVerdict); err != nil {
					t.Fatal(err)
				}
			} else {
				b := verdictBinding(l)
				b.Workspace, b.Environment = c.verdictWS, c.verdictEnv
				vpath, kpath := verdicttest.Write(t, t.TempDir(), k, b)
				t.Setenv(verdict.EnvVerdict, vpath)
				t.Setenv(verdict.EnvKeyFile, kpath)
			}
			res, err := l.Evaluate(context.Background(), &hook.Request{Stage: hook.StageApplyPre, Kind: hook.KindResource, TypeName: "aws_db_instance",
				Op: hook.OpCreate, Config: dynValue(t, opBad), Prior: dynValue(t, opNull), Planned: dynValue(t, opBad)})
			if err != nil {
				t.Fatal(err)
			}
			d := diagnosed(res, opEncryption)
			switch {
			case c.excepted && d != nil:
				t.Fatalf("excepted control diagnosed: %+v", *d)
			case !c.excepted && (d == nil || d.Severity != c.want):
				t.Fatalf("diagnostic %+v, want severity %d (all: %+v)", d, c.want, res.Diagnostics)
			}
			if c.excepted { // no gate, scope or other block either
				for _, d := range res.Diagnostics {
					if d.Severity == hook.SeverityError {
						t.Fatalf("error diagnostic on an excepted apply: %+v", d)
					}
				}
			}
			// The apply view trusts the profile-fixed dimension from the verdict.
			if sc, err := l.scopedToVerdict(l.cfg); !c.noVerdict && (err != nil || c.scope != nil && c.scope.Workspace != "" && sc.Table.Workspace != (profile.Dim{Value: c.verdictWS, Source: "verdict"})) {
				t.Fatalf("apply view %+v, %v", sc.Table.Workspace, err)
			}
		})
	}
}

// TestVerdictScopeRebuildFails: when the mode table cannot be rebuilt under
// the verdict scope every apply blocks with the fixed diagnostic.
func TestVerdictScopeRebuildFails(t *testing.T) {
	k := verdicttest.NewKey(t, verdictIssued.Add(-24*time.Hour))
	l := scopeLifecycle(t, k, nil, "", "")
	l.cfg.tableIn.Resolution.OrgID = "" // an inconsistent resolution: the table refuses it
	vpath, kpath := verdicttest.Write(t, t.TempDir(), k, verdictBinding(l))
	t.Setenv(verdict.EnvVerdict, vpath)
	t.Setenv(verdict.EnvKeyFile, kpath)
	for range 2 {
		d := evalZeroControl(t, l, hook.StageApplyPre)
		if len(d) != 1 || d[0] != [2]string{scopeSummary, scopeDetail} {
			t.Fatalf("diagnostics %v", d)
		}
	}
}
