//go:build unix

package verdict

import (
	"bytes"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/profile"
)

// scopeTable is testdata/scope/table.json.
type scopeTable struct {
	Description string            `json:"description"`
	ModeFloor   profile.ModeFloor `json:"mode_floor"`
	Cases       []struct {
		Name           string         `json:"name"`
		ProfileScope   *profile.Scope `json:"profile_scope"`
		VerdictScope   *profile.Scope `json:"verdict_scope"`
		HCLEnvironment string         `json:"hcl_environment"`
		EnvEnvironment string         `json:"env_environment"`
		LocalWorkspace string         `json:"local_workspace"`
		Want           struct {
			RunMode     string      `json:"run_mode"`
			Environment profile.Dim `json:"environment"`
			Workspace   profile.Dim `json:"workspace"`
			Untrusted   []string    `json:"untrusted"`
		} `json:"want"`
	} `json:"cases"`
}

// TestScopeTable: HCL environment, COMPLIANCETF_ENVIRONMENT and
// COMPLIANCETF_WORKSPACE never lower the floor or supply a trusted scope;
// without trusted context the strongest floor applies and scoped
// exemptions are rejected (also when only the verdict asserts a scope the
// profile leaves open); a verdict matching the
// profile-fixed scope is honored and selects the floor.
func TestScopeTable(t *testing.T) {
	raw, err := os.ReadFile("testdata/scope/table.json")
	if err != nil {
		t.Fatal(err)
	}
	var tbl scopeTable
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&tbl); err != nil || len(tbl.Cases) == 0 {
		t.Fatalf("table: %v", err)
	}
	for _, c := range tbl.Cases {
		t.Run(c.Name, func(t *testing.T) {
			p := &profile.Profile{OrgID: tOrg, ModeFloor: tbl.ModeFloor, Scope: c.ProfileScope}
			tab, err := profile.ComputeModeTable(profile.TableInput{
				Resolution: profile.Resolution{OrgID: tOrg, Governed: true, Profile: p, Fallback: profile.ProfileApplied},
				Verdict:    c.VerdictScope, HCLEnvironment: c.HCLEnvironment, EnvEnvironment: c.EnvEnvironment, Workspace: c.LocalWorkspace})
			if err != nil {
				t.Fatal(err)
			}
			if got := tab.RunMode.String(); got != c.Want.RunMode {
				t.Errorf("run mode %s, want %s", got, c.Want.RunMode)
			}
			if tab.Environment != c.Want.Environment || tab.Workspace != c.Want.Workspace {
				t.Errorf("scope %+v %+v, want %+v %+v", tab.Environment, tab.Workspace, c.Want.Environment, c.Want.Workspace)
			}
			var untrusted []string
			for _, chk := range []struct {
				name     string
				ws, envs []string
				sidecar  bool
			}{{"workspace", []string{"bobthecorp-dev"}, nil, false}, {"environment", nil, []string{"dev"}, false}, {"sidecar", nil, nil, true}} {
				if err := tab.CheckScope(chk.ws, chk.envs, chk.sidecar); err != nil {
					untrusted = append(untrusted, chk.name)
				}
			}
			if !slices.Equal(untrusted, c.Want.Untrusted) {
				t.Errorf("untrusted %v, want %v", untrusted, c.Want.Untrusted)
			}
			// Local values never name the trusted scope in a warning.
			for _, w := range tab.Warnings {
				for _, local := range []string{c.HCLEnvironment, c.EnvEnvironment, c.LocalWorkspace} {
					if local != "" && strings.Contains(w, local) {
						t.Errorf("warning %q echoes a local value", w)
					}
				}
			}
		})
	}
	// A verdict scope without an applied profile is a table error.
	if _, err := profile.ComputeModeTable(profile.TableInput{Resolution: profile.Resolution{Fallback: profile.FreeTier},
		Verdict: &profile.Scope{Environment: "dev"}}); err == nil {
		t.Error("verdict scope accepted without a profile")
	}
}

// TestScopeLoad: Load accepts a verdict scope only where it equals
// a workspace or environment the signed profile scope fixes (an empty
// verdict member included); the diagnostic names the dimension, never a
// value. Scope returns the verdict's members as signed.
func TestScopeLoad(t *testing.T) {
	signer := newKey(t)
	const wsErr = "Verdict workspace does not match the signed profile scope: re-run plan and gate"
	const envErr = "Verdict environment does not match the signed profile scope: re-run plan and gate"
	for _, c := range []struct {
		name  string
		set   map[string]json.RawMessage
		scope *profile.Scope
		want  string
	}{
		{"profile-unscoped", map[string]json.RawMessage{"workspace": json.RawMessage(`"bobthecorp-anything"`)}, nil, ""},
		{"profile-scope-equal", nil, &profile.Scope{Workspace: "prod", Environment: "production"}, ""},
		{"profile-fixes-workspace-only", map[string]json.RawMessage{"environment": json.RawMessage(`"dev"`)}, &profile.Scope{Workspace: "prod"}, ""},
		{"workspace-differs", map[string]json.RawMessage{"workspace": json.RawMessage(`"bobthecorp-spoof"`)}, &profile.Scope{Workspace: "prod"}, wsErr},
		{"workspace-empty", map[string]json.RawMessage{"workspace": json.RawMessage(`""`)}, &profile.Scope{Workspace: "prod", Environment: "production"}, wsErr},
		{"environment-differs", map[string]json.RawMessage{"environment": json.RawMessage(`"dev"`)}, &profile.Scope{Environment: "production"}, envErr},
		{"environment-empty", map[string]json.RawMessage{"environment": json.RawMessage(`""`)}, &profile.Scope{Environment: "production"}, envErr},
	} {
		t.Run(c.name, func(t *testing.T) {
			in := run(t, signer, &fixture{Set: c.set})
			in.Profile.Scope = c.scope
			v, err := Load(in)
			if c.want == "" {
				if err != nil {
					t.Fatalf("Load: %v", err)
				}
				want := &profile.Scope{Workspace: v.Doc.Workspace, Environment: v.Doc.Environment}
				if got := v.Scope(); *got != *want {
					t.Errorf("Scope %+v, want %+v", got, want)
				}
				return
			}
			// The fixed summary and detail carry no workspace or environment value.
			e, ok := err.(*Error)
			if !ok || v != nil || e.Summary != c.want || e.Detail != detailReRun {
				t.Fatalf("Load = %v, %v; want %q", v, err, c.want)
			}
		})
	}
}
