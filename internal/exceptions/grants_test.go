package exceptions

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
	"github.com/compliancetf/terraform-provider-aws/internal/trust/testkeys"
)

// grantDir writes signed grant envelopes named <name>.dsse.json.
func grantDir(t *testing.T, envs map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	for name, env := range envs {
		if err := os.WriteFile(filepath.Join(dir, name+".dsse.json"), env, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func grantInput(t *testing.T, dir string, cov map[string][]bundle.ExemptionKind, clock Clock, now time.Time) GrantsInput {
	t.Helper()
	mt := table(t, &profile.Scope{Workspace: ws}, profile.Exceptions{}, "", "")
	v, err := NewVerifier(VerifierInput{Compiled: compiled(t), Revocations: trust.NoRevocations(), Table: mt, OrgID: org, Now: now, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	c, _ := NewCoverability(cov, nil)
	return GrantsInput{Dir: dir, Verifier: v, Coverable: c, Resolve: func(ref string) []string { return sidecarAliases[ref] }, Table: mt,
		ContentDigest: "sha256:" + strings.Repeat("ab", 32), Revoked: func(string) bool { return false }} // payload()'s binding
}

// TestForbidUnmatched: an entry that resolves to nothing warns by position,
// never by value.
func TestForbidUnmatched(t *testing.T) {
	mt := profile.ModeTable{Exceptions: &profile.Exceptions{ForbidEnvironmentScoped: []string{"ckv_aws_16", "bobthecorp_secret_name", rdsEnc}}}
	got := ForbidUnmatched(mt, foldAliases)
	if want := []string{"forbid_environment_scoped entry 2 matches no loaded control id or tool_ref; it forbids nothing"}; !slices.Equal(got, want) {
		t.Fatalf("warnings %q, want %q", got, want)
	}
	if ForbidUnmatched(profile.ModeTable{}, foldAliases) != nil {
		t.Fatal("no exceptions policy warns")
	}
}

var legacy = resourceValue(map[string]any{"identifier": "legacy-reporting", "storage_encrypted": false})

// TestGrantHonor: a verified grant whose every target is
// coverable for grant waives its controls with source grant; otherwise the
// whole grant is not applied, with one warning per unresolved reference
// (exception_unresolved_id) and one per id not coverable for grant
// (exception_not_coverable). Expiry is re-checked at honor time.
func TestGrantHonor(t *testing.T) {
	exc := testkeys.Exception()
	good := sign(t, payload(nil), exc)
	ctx := verdictCtx(t)
	grant := []bundle.ExemptionKind{bundle.CoverGrant}

	gs, n, err := LoadGrants(grantInput(t, grantDir(t, map[string][]byte{"good": good}), map[string][]bundle.ExemptionKind{rdsEnc: grant}, Clock{}, now))
	if err != nil || len(n.Warnings) != 0 || len(n.Events) != 0 {
		t.Fatalf("load: %v %+v", err, n)
	}
	d := gs.Lookup(ctx, ctl(rdsEnc), dbSchemas, act(legacy), now)
	if !d.Applied || d.Exception.Source != "grant" || d.Exception.ID != "bobthecorp-legacy-db" || d.Exception.Status != StatusApplied ||
		d.Exception.Digest != digest(good) || d.Exception.Workspace == nil || *d.Exception.Workspace != ws || d.Exception.Expires != "2027-03-31T00:00:00Z" {
		t.Fatalf("applied: %+v %+v", d, d.Exception)
	}
	if !slices.Equal(gs.Digests(), []string{digest(good)}) {
		t.Fatalf("digests %v", gs.Digests())
	}
	// one envelope under two file names is one digest.
	twice, _, err := LoadGrants(grantInput(t, grantDir(t, map[string][]byte{"good": good, "copy": good}), map[string][]bundle.ExemptionKind{rdsEnc: grant}, Clock{}, now))
	if err != nil || !slices.Equal(twice.Digests(), []string{digest(good)}) {
		t.Fatalf("same envelope twice: %v %v", err, twice.Digests())
	}
	if d := gs.Lookup(ctx, ctl(rdsEnc), dbSchemas, act(legacy), time.Date(2027, 3, 31, 0, 0, 0, 0, time.UTC)); d.Applied || d.Exception.Status != StatusExpired {
		t.Fatalf("honor-time expiry: %+v", d)
	}
	if d := gs.Lookup(ctx, ctl(rdsEnc), dbSchemas, act(resourceValue(map[string]any{"identifier": "new", "storage_encrypted": false})), now); d.Applied || d.Exception != nil {
		t.Fatalf("selector: %+v", d)
	}

	const gid = "exception bobthecorp-legacy-db: "
	for name, tc := range map[string]struct {
		controls []string
		cov      map[string][]bundle.ExemptionKind
		warnings []string
		events   []string
	}{
		"not coverable": {[]string{rdsEnc}, map[string][]bundle.ExemptionKind{rdsEnc: {bundle.CoverBaseline}},
			[]string{gid + rdsEnc + " is not exemption-coverable for grant; enforced"}, []string{"exception_not_coverable"}},
		"unresolved only": {[]string{rdsEnc, "nope"}, map[string][]bundle.ExemptionKind{rdsEnc: grant},
			[]string{gid + "nope is not a known control id or alias; grant not applied"}, []string{"exception_unresolved_id"}},
		"both": {[]string{"nope", "CKV_AWS_16"}, map[string][]bundle.ExemptionKind{rdsEnc: {bundle.CoverSelfService}},
			[]string{gid + "nope is not a known control id or alias; grant not applied",
				gid + rdsEnc + " is not exemption-coverable for grant; enforced"},
			[]string{"exception_unresolved_id", "exception_not_coverable"}},
	} {
		env := sign(t, payload(func(p map[string]any) { p["controls"] = tc.controls }), exc)
		gs, n, err := LoadGrants(grantInput(t, grantDir(t, map[string][]byte{"g": env}), tc.cov, Clock{}, now))
		if err != nil || !slices.Equal(n.Warnings, tc.warnings) || !slices.Equal(n.Events, tc.events) {
			t.Errorf("%s: %v %q %q", name, err, n.Warnings, n.Events)
			continue
		}
		d := gs.Lookup(ctx, ctl(rdsEnc), dbSchemas, act(legacy), now)
		if d.Applied || d.Exception == nil || d.Exception.Status != StatusNotCoverable || len(gs.Digests()) != 0 {
			t.Errorf("%s: %+v", name, d)
		}
	}

	// A rejected file warns and applies nothing; no dir applies nothing.
	expired := sign(t, payload(func(p map[string]any) { p["expires_at"] = "2026-10-05T00:00:00Z" }), exc)
	gs, n, err = LoadGrants(grantInput(t, grantDir(t, map[string][]byte{"old": expired}), map[string][]bundle.ExemptionKind{rdsEnc: grant}, Clock{}, now))
	if err != nil || len(n.Warnings) != 1 || gs.Lookup(ctx, ctl(rdsEnc), dbSchemas, act(legacy), now).Exception != nil {
		t.Fatalf("rejected: %v %+v", err, n)
	}
	if gs, n, err := LoadGrants(GrantsInput{}); gs != nil || err != nil || len(n.Warnings) != 0 {
		t.Fatal("no grants dir")
	}
	var none *Grants
	if none.Lookup(ctx, ctl(rdsEnc), dbSchemas, act(legacy), now).Exception != nil || none.Digests() != nil {
		t.Fatal("nil Grants")
	}
}

// TestGrantAirgapClock: under floor_mode airgap a grant's key
// window, expiry and the honor-time re-check use the stored floor
// issued_at, never the process clock; an unknown air-gap time applies none.
func TestGrantAirgapClock(t *testing.T) {
	exc := testkeys.Exception()
	floorAt := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	st := trust.State{Floors: map[string]trust.FloorMark{org: {Generation: 1, Epoch: 1, IssuedAt: floorAt}}}
	env := sign(t, payload(func(p map[string]any) { p["expires_at"] = "2026-10-06T00:00:00Z" }), exc)
	cov := map[string][]bundle.ExemptionKind{rdsEnc: {bundle.CoverGrant}}
	late := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) // past expiry and the key window
	gs, n, err := LoadGrants(grantInput(t, grantDir(t, map[string][]byte{"g": env}), cov, NewClock(st, org, trust.FloorAirgap), late))
	if err != nil || len(n.Warnings) != 0 {
		t.Fatalf("airgap load: %v %+v", err, n)
	}
	for _, local := range []time.Time{time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), late} {
		if d := gs.Lookup(verdictCtx(t), ctl(rdsEnc), dbSchemas, act(legacy), local); !d.Applied {
			t.Errorf("process clock %s: %+v", local, d)
		}
	}
	gs, n, err = LoadGrants(grantInput(t, grantDir(t, map[string][]byte{"g": env}), cov, NewClock(trust.State{}, org, trust.FloorAirgap), late))
	if err != nil || len(n.Warnings) != 1 || gs.Lookup(verdictCtx(t), ctl(rdsEnc), dbSchemas, act(legacy), late).Exception != nil {
		t.Fatalf("unknown air-gap time: %v %+v", err, n)
	}
}

// TestGrantScopeOnResolvedIDs: forbid_environment_scoped
// is checked on the resolved control ids, so an alias cannot reach a
// forbidden control and an alias in the profile list forbids its canonical
// control; a trusted workspace outside the evidence scope grammar
// rejects the grant instead of invalidating the eval record.
func TestGrantScopeOnResolvedIDs(t *testing.T) {
	exc := testkeys.Exception()
	cov := map[string][]bundle.ExemptionKind{rdsEnc: {bundle.CoverGrant}}
	load := func(sc *profile.Scope, ex profile.Exceptions, mut func(map[string]any)) (*Grants, Notices) {
		t.Helper()
		mt := table(t, sc, ex, "", "")
		v, err := NewVerifier(VerifierInput{Compiled: compiled(t), Revocations: trust.NoRevocations(), Table: mt, OrgID: org, Now: now})
		if err != nil {
			t.Fatal(err)
		}
		c, _ := NewCoverability(cov, nil)
		gs, n, err := LoadGrants(GrantsInput{Dir: grantDir(t, map[string][]byte{"g": sign(t, payload(mut), exc)}), Verifier: v, Coverable: c,
			Resolve: func(ref string) []string { return sidecarAliases[ref] }, ResolveFold: foldAliases, Table: mt})
		if err != nil {
			t.Fatal(err)
		}
		return gs, n
	}
	gs, n := load(&profile.Scope{Workspace: ws, Environment: "prod"}, profile.Exceptions{ForbidEnvironmentScoped: []string{rdsEnc}},
		func(p map[string]any) { p["controls"] = []string{"CKV_AWS_16"}; p["environments"] = []string{"prod"} })
	if d := gs.Lookup(verdictCtx(t), ctl(rdsEnc), dbSchemas, act(legacy), now); d.Applied || d.Exception == nil ||
		d.Exception.Status != StatusRejected || len(gs.Digests()) != 0 || len(n.Warnings) != 1 {
		t.Fatalf("alias to forbidden env-scoped control: %+v %q", d, n.Warnings)
	}
	gs, n = load(&profile.Scope{Workspace: ws, Environment: "prod"}, profile.Exceptions{ForbidEnvironmentScoped: []string{"CKV_AWS_16"}},
		func(p map[string]any) { p["controls"] = []string{rdsEnc}; p["environments"] = []string{"prod"} }) // profile lists the alias, grant the id
	if d := gs.Lookup(verdictCtx(t), ctl(rdsEnc), dbSchemas, act(legacy), now); d.Applied || d.Exception == nil ||
		d.Exception.Status != StatusRejected || len(gs.Digests()) != 0 || len(n.Warnings) != 1 {
		t.Fatalf("forbidden alias, env-scoped canonical control: %+v %q", d, n.Warnings)
	}
	for _, entry := range []string{"ckv_aws_16", "Ckv_Aws_16"} { // alias in another case
		gs, n = load(&profile.Scope{Workspace: ws, Environment: "prod"}, profile.Exceptions{ForbidEnvironmentScoped: []string{entry}},
			func(p map[string]any) { p["controls"] = []string{rdsEnc}; p["environments"] = []string{"prod"} })
		if d := gs.Lookup(verdictCtx(t), ctl(rdsEnc), dbSchemas, act(legacy), now); d.Applied || d.Exception == nil ||
			d.Exception.Status != StatusRejected || len(gs.Digests()) != 0 || len(n.Warnings) != 1 {
			t.Fatalf("forbidden %s, env-scoped canonical control: %+v %q", entry, d, n.Warnings)
		}
	}
	gs, n = load(&profile.Scope{Workspace: "prod@eu"}, profile.Exceptions{},
		func(p map[string]any) { p["workspaces"] = []string{"prod@eu"} })
	if d := gs.Lookup(verdictCtx(t), ctl(rdsEnc), dbSchemas, act(legacy), now); d.Applied || d.Exception == nil ||
		d.Exception.Workspace != nil || d.Exception.Status != StatusRejected || len(gs.Digests()) != 0 || len(n.Warnings) != 1 {
		t.Fatalf("workspace outside evidence grammar: %+v %q", d, n.Warnings)
	}
	gs, n = load(&profile.Scope{Workspace: "prod@eu"}, profile.Exceptions{},
		func(p map[string]any) {
			p["workspaces"] = []string{"prod@eu"}
			p["controls"] = []string{rdsEnc, "nope"}
		})
	if d := gs.Lookup(verdictCtx(t), ctl(rdsEnc), dbSchemas, act(legacy), now); d.Applied || d.Exception == nil ||
		d.Exception.Workspace != nil || len(gs.Digests()) != 0 || len(n.Warnings) != 2 {
		t.Fatalf("non-coverable grant, workspace outside evidence grammar: %+v %q", d, n.Warnings)
	}
}
