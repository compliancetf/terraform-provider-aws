package exceptions

import (
	"slices"
	"strings"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
	"github.com/compliancetf/terraform-provider-aws/internal/trust/testkeys"
)

// rescanForbidden is the earlier envForbidden: it resolves every
// forbid entry again for each id. forbidSet must decide exactly the same.
func rescanForbidden(t profile.ModeTable, resolve func(string) []string, id string) bool {
	if t.Exceptions == nil {
		return false
	}
	return slices.ContainsFunc(t.Exceptions.ForbidEnvironmentScoped, func(f string) bool {
		return strings.EqualFold(f, id) ||
			(resolve != nil && slices.ContainsFunc(resolve(f), func(r string) bool { return strings.EqualFold(r, id) }))
	})
}

// TestForbidSetMatchesRescan: resolving each entry once per
// load keeps the per-id rescan's decisions.
func TestForbidSetMatchesRescan(t *testing.T) {
	lists := [][]string{nil, {}, {rdsEnc}, {"ckv_aws_16"}, {"CKV_AWS_16"}, {"bobthecorp_secret_name"}, {"RDS_DB_INSTANCE_ENCRYPTION_AT_REST_ENABLED", "rds_instance_kms_key_configured"}}
	ids := []string{rdsEnc, strings.ToUpper(rdsEnc), "rds_instance_kms_key_configured", "CKV_AWS_16", "ckv_aws_16", "bobthecorp_secret_name", "other"}
	for _, l := range lists {
		mt := profile.ModeTable{Exceptions: &profile.Exceptions{ForbidEnvironmentScoped: l}}
		fs := newForbidSet(mt, foldAliases)
		for _, id := range ids {
			if got, want := fs.has(id), rescanForbidden(mt, foldAliases, id); got != want {
				t.Errorf("list %q id %q: has %v, rescan %v", l, id, got, want)
			}
		}
	}
	if newForbidSet(profile.ModeTable{}, foldAliases).has(rdsEnc) {
		t.Error("no exceptions policy forbids")
	}
}

// TestForbidSetResolvesOncePerEntry: the resolver runs once
// per forbid entry per load, however many grants and ids are checked.
func TestForbidSetResolvesOncePerEntry(t *testing.T) {
	calls := 0
	counting := func(ref string) []string { calls++; return foldAliases(ref) }
	mt := profile.ModeTable{Exceptions: &profile.Exceptions{ForbidEnvironmentScoped: []string{"ckv_aws_16", "bobthecorp_secret_name"}}}
	fs := newForbidSet(mt, counting)
	for range 100 {
		fs.has(rdsEnc)
		fs.has("other")
	}
	if calls != 2 {
		t.Fatalf("resolver calls %d, want 2 (one per entry)", calls)
	}

	// End to end: two env-scoped grants naming a control the profile
	// forbids through its alias (past the Verifier's raw-reference check)
	// still resolve each entry once.
	calls = 0
	exc := testkeys.Exception()
	env := func(p map[string]any) { p["controls"] = []string{rdsEnc}; p["environments"] = []string{"prod"} }
	gs, n := loadForbidGrants(t, mt.Exceptions.ForbidEnvironmentScoped, counting, map[string][]byte{
		"g1": sign(t, payload(env), exc),
		"g2": sign(t, payload(func(p map[string]any) { env(p); p["grant_id"] = "bobthecorp-g2" }), exc),
	})
	if calls != 2 {
		t.Fatalf("LoadGrants resolver calls %d, want 2 (one per entry)", calls)
	}
	if d := gs.Lookup(verdictCtx(t), ctl(rdsEnc), dbSchemas, act(legacy), now); d.Applied || d.Exception == nil || d.Exception.Status != StatusRejected || len(n.Warnings) != 2 {
		t.Fatalf("forbidden control applied: %+v %q", d, n.Warnings)
	}
}

// TestForbidNilResolverFailsClosed: without a case-folding
// resolver no forbid entry can be matched to its control, so every
// environment-scoped grant is rejected instead of falling back to the
// exact-case resolver (which would miss "ckv_aws_16" and fail open).
func TestForbidNilResolverFailsClosed(t *testing.T) {
	if !newForbidSet(profile.ModeTable{Exceptions: &profile.Exceptions{ForbidEnvironmentScoped: []string{"ckv_aws_16"}}}, nil).has("anything") {
		t.Fatal("nil resolver with a forbid list must forbid every id")
	}
	if newForbidSet(profile.ModeTable{Exceptions: &profile.Exceptions{}}, nil).has(rdsEnc) {
		t.Fatal("nil resolver with no forbid list forbids nothing")
	}
	gs, n := loadForbidGrants(t, []string{"ckv_aws_16"}, nil, map[string][]byte{"g": sign(t, payload(func(p map[string]any) {
		p["controls"] = []string{rdsEnc}
		p["environments"] = []string{"prod"}
	}), testkeys.Exception())})
	if d := gs.Lookup(verdictCtx(t), ctl(rdsEnc), dbSchemas, act(legacy), now); d.Applied || d.Exception == nil ||
		d.Exception.Status != StatusRejected || len(gs.Digests()) != 0 || len(n.Warnings) != 1 {
		t.Fatalf("nil ResolveFold: %+v %q", d, n.Warnings)
	}
}

// TestForbidUnmatchedNilResolver: a nil resolver does not
// panic, and its one warning says everything is rejected, matching
// newForbidSet, never that an entry forbids nothing.
func TestForbidUnmatchedNilResolver(t *testing.T) {
	mt := profile.ModeTable{Exceptions: &profile.Exceptions{ForbidEnvironmentScoped: []string{"ckv_aws_16", rdsEnc}}}
	got := ForbidUnmatched(mt, nil)
	if len(got) != 1 || !strings.Contains(got[0], "every environment-scoped exception is rejected") || strings.Contains(got[0], "forbids nothing") {
		t.Fatalf("warnings %q, want one 'every ... rejected' warning", got)
	}
	if got := ForbidUnmatched(profile.ModeTable{Exceptions: &profile.Exceptions{}}, nil); got != nil {
		t.Fatalf("empty list warnings %q, want none", got)
	}
}

// loadForbidGrants loads envs in the prod environment of the trusted
// workspace under forbid, resolving the forbid list with resolveFold.
func loadForbidGrants(t *testing.T, forbid []string, resolveFold func(string) []string, envs map[string][]byte) (*Grants, Notices) {
	t.Helper()
	mt := table(t, &profile.Scope{Workspace: ws, Environment: "prod"}, profile.Exceptions{ForbidEnvironmentScoped: forbid}, "", "")
	v, err := NewVerifier(VerifierInput{Compiled: compiled(t), Revocations: trust.NoRevocations(), Table: mt, OrgID: org, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	c, _ := NewCoverability(map[string][]bundle.ExemptionKind{rdsEnc: {bundle.CoverGrant}}, nil)
	gs, n, err := LoadGrants(GrantsInput{Dir: grantDir(t, envs), Verifier: v, Coverable: c,
		Resolve: func(ref string) []string { return sidecarAliases[ref] }, ResolveFold: resolveFold, Table: mt})
	if err != nil {
		t.Fatal(err)
	}
	return gs, n
}
