package profile

import (
	"bytes"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// Golden format: testdata/modetable/*.json, each {"profile": <default
// profile>, "cases": [{name, input, want}]}. Every case is also run against
// the full cross product of local inputs (TestModeTable/local).

type mtInput struct {
	Fallback          string   `json:"fallback"` // free_tier | profile | hard_fail_floor | <anything else>
	OrgID             string   `json:"org_id,omitempty"`
	Governed          bool     `json:"governed,omitempty"`
	NoProfile         bool     `json:"no_profile,omitempty"` // with fallback profile: Profile nil
	Profile           *Profile `json:"profile,omitempty"`    // overrides the file profile
	HCLMode           string   `json:"hcl_mode,omitempty"`
	EnvMode           string   `json:"env_mode,omitempty"`
	HCLEnvironment    string   `json:"hcl_environment,omitempty"`
	EnvEnvironment    string   `json:"env_environment,omitempty"`
	Workspace         string   `json:"workspace,omitempty"`
	SidecarConfigured bool     `json:"sidecar_configured,omitempty"`
	HCLDataSources    string   `json:"hcl_data_sources,omitempty"`
	EnvDataSources    string   `json:"env_data_sources,omitempty"`
}

type mtWant struct {
	Error             string                     `json:"error,omitempty"`
	RunMode           string                     `json:"run_mode,omitempty"`
	ControlModes      map[string]map[string]Mode `json:"control_modes,omitempty"` // id -> deny|warn -> mode
	DenyFloor         string                     `json:"deny_floor,omitempty"`
	VerdictRequired   bool                       `json:"verdict_required,omitempty"`
	DataSourcesDeny   bool                       `json:"data_sources_deny,omitempty"`
	GraphNotEnforced  bool                       `json:"graph_not_enforced,omitempty"`
	ProfileExceptions bool                       `json:"profile_exceptions,omitempty"`
	SidecarControls   []string                   `json:"sidecar_controls,omitempty"`
	Environment       Dim                        `json:"environment"`
	Workspace         Dim                        `json:"workspace"`
	LocalEnvironment  []string                   `json:"local_environment,omitempty"`
	ScopeChecks       map[string]string          `json:"scope_checks,omitempty"`
	Warnings          []string                   `json:"warnings,omitempty"`
}

type mtCase struct {
	Name  string  `json:"name"`
	Input mtInput `json:"input"`
	Want  mtWant  `json:"want"`
}

type mtFile struct {
	Profile *Profile `json:"profile"`
	Cases   []mtCase `json:"cases"`
}

// scopeChecks are the CheckScope probes recorded in every golden.
var scopeChecks = []struct {
	name     string
	ws, envs []string
	sidecar  bool
}{
	{"unscoped", nil, nil, false},
	{"workspace", []string{"bobthecorp-prod"}, nil, false},
	{"environment", nil, []string{"prod"}, false},
	{"both", []string{"bobthecorp-prod"}, []string{"prod"}, false},
	{"sidecar", nil, nil, true},
	{"sidecar_environment", nil, []string{"prod"}, true},
}

func (in mtInput) table(fileProfile *Profile) TableInput {
	r := Resolution{OrgID: in.OrgID, Governed: in.Governed}
	switch in.Fallback {
	case "free_tier":
		r.Fallback = FreeTier
	case "profile":
		r.Fallback = ProfileApplied
	case "hard_fail_floor":
		r.Fallback = HardFailFloor
	default:
		r.Fallback = Fallback(99)
	}
	p := cmpOr(in.Profile, fileProfile)
	if in.Fallback == "profile" && !in.NoProfile || in.Fallback != "profile" && in.Profile != nil {
		r.Profile = p
	}
	return TableInput{
		Resolution: r, HCLMode: in.HCLMode, EnvMode: in.EnvMode,
		HCLEnvironment: in.HCLEnvironment, EnvEnvironment: in.EnvEnvironment,
		Workspace: in.Workspace, SidecarConfigured: in.SidecarConfigured,
		HCLDataSources: in.HCLDataSources, EnvDataSources: in.EnvDataSources,
	}
}

func cmpOr(a, b *Profile) *Profile {
	if a != nil {
		return a
	}
	return b
}

// probeIDs are the control ids a golden reports: every control_floors id plus
// one id no profile names.
func probeIDs(p *Profile) []string {
	ids := []string{"UNKNOWN-1"}
	if p != nil {
		ids = append(ids, slices.Sorted(maps.Keys(p.ControlFloors))...)
	}
	return ids
}

func observe(t ModeTable, err error, ids []string) mtWant {
	if err != nil {
		return mtWant{Error: err.Error()}
	}
	w := mtWant{
		RunMode: t.RunMode.String(), DenyFloor: t.DenyFloor.String(),
		VerdictRequired: t.VerdictRequired, DataSourcesDeny: t.DataSourcesDeny, GraphNotEnforced: t.GraphNotEnforced,
		ProfileExceptions: t.Exceptions != nil, SidecarControls: t.SidecarControls,
		Environment: t.Environment, Workspace: t.Workspace, LocalEnvironment: t.LocalEnvironment,
		Warnings: t.Warnings, ControlModes: map[string]map[string]Mode{}, ScopeChecks: map[string]string{},
	}
	for _, id := range ids {
		w.ControlModes[id] = map[string]Mode{"deny": t.ControlMode(id, true), "warn": t.ControlMode(id, false)}
	}
	for _, c := range scopeChecks {
		w.ScopeChecks[c.name] = ""
		if err := t.CheckScope(c.ws, c.envs, c.sidecar); err != nil {
			if !errors.Is(err, ErrScopeUntrusted) {
				panic("CheckScope error does not wrap ErrScopeUntrusted: " + err.Error())
			}
			w.ScopeChecks[c.name] = err.Error()
		}
	}
	return w
}

func loadModeTableGoldens(t *testing.T) map[string]mtFile {
	t.Helper()
	paths, err := filepath.Glob("testdata/modetable/*.json")
	if err != nil || len(paths) == 0 {
		t.Fatalf("no mode table goldens: %v", err)
	}
	out := map[string]mtFile{}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var f mtFile
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&f); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		out[filepath.Base(p)] = f
	}
	for _, prefix := range []string{"spoof-environment-", "spoof-workspace-", "no-trusted-context-"} {
		if !slices.ContainsFunc(slices.Collect(maps.Keys(out)), func(n string) bool { return strings.HasPrefix(n, prefix) }) {
			t.Errorf("no golden named %s*", prefix)
		}
	}
	return out
}

func TestModeTable(t *testing.T) {
	files := loadModeTableGoldens(t)
	for _, fname := range slices.Sorted(maps.Keys(files)) {
		f := files[fname]
		for _, c := range f.Cases {
			t.Run(strings.TrimSuffix(fname, ".json")+"/"+c.Name, func(t *testing.T) {
				in := c.Input.table(f.Profile)
				mt, err := ComputeModeTable(in)
				got := observe(mt, err, probeIDs(in.Resolution.Profile))
				gb, _ := json.Marshal(got)
				wb, _ := json.Marshal(c.Want)
				if !bytes.Equal(gb, wb) {
					t.Errorf("\n got %s\nwant %s", gb, wb)
				}
				if c.Want.Error == "" {
					checkLocalInputs(t, in)
				}
			})
		}
	}
}

// checkLocalInputs runs every combination of local inputs against the context
// of in and asserts that none lowers an output or widens exceptions compared
// with the same context without local inputs.
func checkLocalInputs(t *testing.T, in TableInput) {
	t.Helper()
	ctx := TableInput{Resolution: in.Resolution}
	base, err := ComputeModeTable(ctx)
	if err != nil {
		t.Fatalf("context without local inputs: %v", err)
	}
	modes := append([]string{"", "bogus"}, modeNames[:]...)
	envs := []string{"", "unknown-env"}
	if p := in.Resolution.Profile; p != nil {
		envs = append(envs, slices.Sorted(maps.Keys(p.ModeFloor.Environments))...)
		if p.Scope != nil && p.Scope.Environment != "" {
			envs = append(envs, p.Scope.Environment, strings.ToUpper(p.Scope.Environment))
		}
	}
	workspaces := []string{"", "spoofed-ws", base.Workspace.Value}
	ids := probeIDs(in.Resolution.Profile)
	n := 0
	for _, hm := range modes {
		for _, em := range modes {
			for _, he := range envs {
				for _, ee := range envs {
					for _, ws := range workspaces {
						for _, sc := range []bool{false, true} {
							n++
							li := TableInput{Resolution: in.Resolution, HCLMode: hm, EnvMode: em,
								HCLEnvironment: he, EnvEnvironment: ee, Workspace: ws, SidecarConfigured: sc}
							got, err := ComputeModeTable(li)
							if bad := firstInvalid(hm, em); bad != "" {
								_, want := ParseMode(bad)
								if err == nil || err.Error() != want.Error() {
									t.Fatalf("%+v: err %v, want %v", li, err, want)
								}
								continue
							}
							if err != nil {
								t.Fatalf("%+v: %v", li, err)
							}
							if msg := lowered(base, got, ids); msg != "" {
								t.Fatalf("local inputs %+v lowered an output: %s", li, msg)
							}
						}
					}
				}
			}
		}
	}
	if n == 0 {
		t.Fatal("empty cross product")
	}
	// data_sources is its own switch: every local pair, other inputs unset.
	ds := []string{"", "advisory", "deny", "bogus"}
	for _, h := range ds {
		for _, e := range ds {
			li := TableInput{Resolution: in.Resolution, HCLDataSources: h, EnvDataSources: e}
			got, err := ComputeModeTable(li)
			if h == "bogus" || e == "bogus" {
				if err == nil || err.Error() != `data_sources "bogus": want advisory or deny` {
					t.Fatalf("%+v: err %v", li, err)
				}
				continue
			}
			if err != nil {
				t.Fatalf("%+v: %v", li, err)
			}
			if msg := lowered(base, got, ids); msg != "" {
				t.Fatalf("local inputs %+v lowered an output: %s", li, msg)
			}
			if want := base.DataSourcesDeny || h == "deny" || e == "deny"; got.DataSourcesDeny != want {
				t.Fatalf("%+v: data_sources deny %v, want %v", li, got.DataSourcesDeny, want)
			}
		}
	}
}

func firstInvalid(ms ...string) string {
	for _, m := range ms {
		if _, err := ParseMode(m); m != "" && err != nil {
			return m
		}
	}
	return ""
}

func lowered(base, got ModeTable, ids []string) string {
	switch {
	case got.RunMode < base.RunMode:
		return "run mode"
	case got.DenyFloor < base.DenyFloor:
		return "deny floor"
	case base.VerdictRequired && !got.VerdictRequired:
		return "verdict_required"
	case base.DataSourcesDeny && !got.DataSourcesDeny:
		return "data_sources"
	case base.GraphNotEnforced && !got.GraphNotEnforced:
		return "graph_not_enforced"
	case !reflect.DeepEqual(base.Exceptions, got.Exceptions):
		return "exceptions policy"
	case !reflect.DeepEqual(base.SidecarControls, got.SidecarControls):
		return "sidecar controls"
	case base.Environment != got.Environment || base.Workspace != got.Workspace:
		return "trusted scope"
	}
	for _, id := range ids {
		for _, d := range []bool{true, false} {
			if got.ControlMode(id, d) < base.ControlMode(id, d) {
				return "control mode " + id
			}
		}
	}
	for _, c := range scopeChecks {
		for _, sc := range []bool{false, true} {
			if (base.CheckScope(c.ws, c.envs, sc) == nil) != (got.CheckScope(c.ws, c.envs, sc) == nil) {
				return "scope check " + c.name
			}
		}
	}
	return ""
}

// TestModeTableWarningsValueFree: no table warning echoes an environment or
// workspace string, local or from the profile scope.
func TestModeTableWarningsValueFree(t *testing.T) {
	const tEnv, tWS, lEnv1, lEnv2, lWS = "trusted-env-x9", "trusted-ws-x9", "local-env-x9\x1b[31m", "local-env2-x9", "local-ws-x9\n"
	p := &Profile{OrgID: "bobthecorp", Scope: &Scope{Environment: tEnv, Workspace: tWS},
		ModeFloor: ModeFloor{Default: SoftFail, Environments: map[string]Mode{"prod": HardFail}}}
	mt, err := ComputeModeTable(TableInput{Resolution: Resolution{OrgID: "bobthecorp", Fallback: ProfileApplied, Profile: p},
		HCLEnvironment: lEnv1, EnvEnvironment: lEnv2, Workspace: lWS})
	if err != nil {
		t.Fatal(err)
	}
	if len(mt.Warnings) < 4 {
		t.Fatalf("want the scope, two environment and the workspace warnings, got %q", mt.Warnings)
	}
	for _, w := range mt.Warnings {
		for _, v := range []string{tEnv, tWS, lEnv1, lEnv2, lWS, "x9"} {
			if strings.Contains(w, v) {
				t.Errorf("warning %q echoes %q", w, v)
			}
		}
	}
}

func TestModeTableCopies(t *testing.T) {
	p := &Profile{OrgID: "bobthecorp", ControlFloors: map[string]Mode{"C1": HardFail},
		Exceptions: Exceptions{SelfService: []string{"C1"}, Coverable: map[string][]string{"C1": {"self_service"}},
			ForbidControls: []string{"C2"}, ForbidEnvironmentScoped: []string{"C3"}, GrantKeys: []GrantKey{{KID: "k"}}}}
	snap, _ := json.Marshal(p)
	mt, err := ComputeModeTable(TableInput{Resolution: Resolution{OrgID: "bobthecorp", Fallback: ProfileApplied, Profile: p}})
	if err != nil {
		t.Fatal(err)
	}
	mt.ControlFloors["C1"] = Advisory
	mt.SidecarControls[0] = "X"
	mt.Exceptions.Coverable["C1"][0] = "grant"
	mt.Exceptions.SelfService[0] = "X"
	mt.Exceptions.ForbidControls[0] = "X"
	mt.Exceptions.ForbidEnvironmentScoped[0] = "X"
	mt.Exceptions.GrantKeys[0].KID = "X"
	if after, _ := json.Marshal(p); !bytes.Equal(snap, after) {
		t.Errorf("mode table aliases the profile:\n%s\n%s", snap, after)
	}
}
