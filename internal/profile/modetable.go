package profile

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
)

// The normative mode table. This file is the only
// place that computes the effective modes, exception policy, verdict_required
// and trusted scope; lifecycle code reads the ModeTable. Every local input
// (HCL, env, sidecar, environment, COMPLIANCETF_WORKSPACE) can only raise a
// mode or narrow exceptions; testdata/modetable proves it.

// ErrScopeUntrusted is wrapped by CheckScope: an exception scoped on a
// dimension that has no trusted value.
var ErrScopeUntrusted = errors.New("exception_scope_untrusted")

// Dim is one trusted scope dimension. The zero Dim is untrusted. Source is
// "profile" (the signed profile scope) or "verdict" (the verified verdict's
// gate-asserted scope), trusted only on a dimension the profile
// scope fixes and with the same value.
type Dim struct {
	Value  string `json:"value,omitempty"`
	Source string `json:"source,omitempty"`
}

// TableInput is everything the table reads. Resolution comes from Resolve
// and Verdict from a verified verdict; every other field is local and
// untrusted. "" means unset.
type TableInput struct {
	Resolution Resolution
	// Verdict is the verified verdict's scope (apply only, nil before a
	// verdict loads). It needs an applied profile and is trusted only where
	// the profile scope fixes the same value.
	Verdict           *Scope
	HCLMode, EnvMode  string // enforcement_mode, COMPLIANCETF_ENFORCEMENT_MODE
	HCLEnvironment    string // compliance block environment
	EnvEnvironment    string // COMPLIANCETF_ENVIRONMENT
	Workspace         string // COMPLIANCETF_WORKSPACE
	SidecarConfigured bool   // exceptions_file or COMPLIANCETF_EXCEPTIONS_FILE set
	// HCLDataSources and EnvDataSources are compliance data_sources and
	// COMPLIANCETF_DATA_SOURCES: advisory or deny, raise only.
	HCLDataSources, EnvDataSources string
}

// ModeTable is the table output. Maps, slices and Exceptions are copies.
type ModeTable struct {
	RunMode          Mode
	ControlFloors    map[string]Mode // profile control_floors
	DenyFloor        Mode            // hard_fail without an acceptable profile (not governed)
	VerdictRequired  bool
	DataSourcesDeny  bool        // data_sources deny: deny data source controls keep action deny (else warn)
	GraphNotEnforced bool        // graph controls warn "not enforced"
	Exceptions       *Exceptions // profile exception policy; nil = grants signed by the keyring exception key only
	SidecarControls  []string    // controls the sidecar may cover; nil = sidecar ignored
	Environment      Dim
	Workspace        Dim
	LocalEnvironment []string // untrusted, for evidence
	LocalWorkspace   string   // untrusted, for evidence
	Warnings         []string // table warnings only; the caller merges Resolution.Warnings
}

// ComputeModeTable applies the normative table.
func ComputeModeTable(in TableInput) (ModeTable, error) {
	var modes []Mode
	for _, s := range []string{in.HCLMode, in.EnvMode} {
		if s == "" {
			continue
		}
		m, err := ParseMode(s)
		if err != nil {
			return ModeTable{}, err
		}
		modes = append(modes, m)
	}
	var localDSDeny, localDSAdvisory bool
	for _, s := range []string{in.HCLDataSources, in.EnvDataSources} {
		deny, err := ParseDataSources(s)
		if err != nil {
			return ModeTable{}, err
		}
		localDSDeny = localDSDeny || deny
		localDSAdvisory = localDSAdvisory || s == "advisory"
	}
	r := in.Resolution
	if err := checkResolution(r); err != nil {
		return ModeTable{}, err
	}
	if in.Verdict != nil && r.Fallback != ProfileApplied {
		return ModeTable{}, errors.New("mode table: a verdict scope needs an applied profile")
	}

	t := ModeTable{RunMode: SoftFail, LocalWorkspace: in.Workspace}
	if slices.Contains(modes, Advisory) {
		t.Warnings = append(t.Warnings, "enforcement_mode advisory is below the default soft_fail and has no effect")
	}
	for _, m := range modes {
		t.RunMode = max(t.RunMode, m)
	}
	for _, e := range []string{in.HCLEnvironment, in.EnvEnvironment} {
		if e != "" && !slices.Contains(t.LocalEnvironment, e) {
			t.LocalEnvironment = append(t.LocalEnvironment, e)
		}
	}

	switch r.Fallback {
	case HardFailFloor:
		t.DenyFloor, t.GraphNotEnforced = HardFail, true
	case ProfileApplied:
		t.applyProfile(r.Profile, in.Verdict)
	}

	t.DataSourcesDeny = t.DataSourcesDeny || localDSDeny
	if localDSAdvisory && t.DataSourcesDeny {
		t.Warnings = append(t.Warnings, "data_sources advisory is below the effective deny and has no effect")
	}

	// Warnings name the input, never an environment or workspace string:
	// local values are unvalidated, scope values unconstrained.
	if e := t.Environment.Value; e != "" {
		for _, l := range []struct{ name, value string }{
			{"compliance block environment", in.HCLEnvironment}, {"COMPLIANCETF_ENVIRONMENT", in.EnvEnvironment}} {
			if l.value != "" && l.value != e {
				t.Warnings = append(t.Warnings, l.name+" differs from the trusted environment: it can only raise the floor")
			}
		}
	}
	if w := t.Workspace.Value; w != "" && in.Workspace != "" && in.Workspace != w {
		t.Warnings = append(t.Warnings, "COMPLIANCETF_WORKSPACE differs from the trusted workspace: ignored")
	}
	if in.SidecarConfigured && len(t.SidecarControls) == 0 {
		t.Warnings = append(t.Warnings, "exceptions file ignored: no org profile enables self-service exceptions")
	}
	return t, nil
}

func checkResolution(r Resolution) error {
	if r.Governed && r.Profile == nil {
		return fmt.Errorf("mode table: governed org %s has no acceptable profile", r.OrgID)
	}
	var bad string
	switch r.Fallback {
	case FreeTier:
		switch {
		case r.OrgID != "":
			bad = "free tier with org_id " + r.OrgID
		case r.Profile != nil:
			bad = "free tier with a profile"
		}
	case ProfileApplied:
		switch {
		case r.Profile == nil:
			bad = "profile applied without a profile"
		case r.OrgID == "":
			bad = "profile applied without org_id"
		case r.Profile.OrgID != r.OrgID:
			bad = fmt.Sprintf("profile org %s, run org %s", r.Profile.OrgID, r.OrgID)
		}
	case HardFailFloor:
		switch {
		case r.Profile != nil:
			bad = "hard_fail floor with a profile"
		case r.OrgID == "":
			bad = "hard_fail floor without org_id"
		}
	default:
		bad = fmt.Sprintf("unknown fallback %d", r.Fallback)
	}
	if bad != "" {
		return errors.New("mode table: inconsistent resolution: " + bad)
	}
	return nil
}

// scopeDim is one trusted dimension: only a value the signed profile scope
// fixes, and under a verdict only when the verdict asserts the same value
// (a verdict never adds a dimension the profile
// leaves open; a mismatch stays untrusted, fail closed).
func scopeDim(fixed string, verdict *Scope, get func(*Scope) string, src string) Dim {
	if fixed == "" || verdict != nil && get(verdict) != fixed {
		return Dim{}
	}
	return Dim{fixed, src}
}

// applyProfile is row 3: mode_floor with scope binding, control floors,
// profile exception policy and verdict_required.
func (t *ModeTable) applyProfile(p *Profile, verdict *Scope) {
	src := "profile"
	if verdict != nil {
		src = "verdict"
	}
	if s := p.Scope; s != nil {
		t.Environment = scopeDim(s.Environment, verdict, func(v *Scope) string { return v.Environment }, src)
		t.Workspace = scopeDim(s.Workspace, verdict, func(v *Scope) string { return v.Workspace }, src)
	}
	envs := p.ModeFloor.Environments
	floor, ok := envs[t.Environment.Value]
	if !ok || t.Environment.Value == "" {
		// No trusted environment, or one the profile does not list: the
		// strongest environment floor applies (never below the literal rule).
		floor = Advisory
		for _, m := range envs {
			floor = max(floor, m)
		}
		switch {
		case len(envs) == 0:
		case t.Environment.Value != "":
			t.Warnings = append(t.Warnings, fmt.Sprintf("the trusted environment (%s scope) has no mode_floor entry: strongest environment floor %s applied", src, floor))
		default:
			t.Warnings = append(t.Warnings, fmt.Sprintf("no trusted environment: strongest environment floor %s applied", floor))
		}
	}
	for _, l := range t.LocalEnvironment {
		floor = max(floor, envs[l]) // a local name only selects a stricter floor
	}
	t.RunMode = max(t.RunMode, p.ModeFloor.Default, floor)
	t.ControlFloors = maps.Clone(p.ControlFloors)
	t.VerdictRequired = p.VerdictRequired
	t.DataSourcesDeny = p.DataSources == "deny" // Parse validated the value
	ex := p.Exceptions.clone()
	t.Exceptions = &ex
	t.SidecarControls = slices.Clone(p.Exceptions.SelfService)
}

func (e Exceptions) clone() Exceptions {
	c := e
	if e.Coverable != nil {
		c.Coverable = make(map[string][]string, len(e.Coverable))
		for id, kinds := range e.Coverable {
			c.Coverable[id] = slices.Clone(kinds)
		}
	}
	c.SelfService = slices.Clone(e.SelfService)
	c.ForbidControls = slices.Clone(e.ForbidControls)
	c.ForbidEnvironmentScoped = slices.Clone(e.ForbidEnvironmentScoped)
	c.GrantKeys = slices.Clone(e.GrantKeys)
	return c
}

// ControlMode is the per-control mode: max(run mode, control_floors[id], and
// the deny floor when deny). deny is the control action; whether a result
// blocks is decided by the severity matrix from this mode.
func (t ModeTable) ControlMode(id string, deny bool) Mode {
	m := max(t.RunMode, t.ControlFloors[id])
	if deny {
		m = max(m, t.DenyFloor)
	}
	return m
}

// CheckScope rejects an exception scoped on a dimension without a trusted
// value. workspaces and environments are the entry's own scope lists; every
// sidecar entry is workspace-scoped. Unscoped grants pass.
func (t ModeTable) CheckScope(workspaces, environments []string, sidecar bool) error {
	var dims []string
	if (sidecar || len(workspaces) > 0) && t.Workspace.Value == "" {
		dims = append(dims, "workspace")
	}
	if len(environments) > 0 && t.Environment.Value == "" {
		dims = append(dims, "environment")
	}
	if dims == nil {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrScopeUntrusted, strings.Join(dims, ", "))
}
