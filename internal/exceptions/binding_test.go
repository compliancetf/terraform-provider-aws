package exceptions

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
	"github.com/compliancetf/terraform-provider-aws/internal/trust/testkeys"
)

// loadedContent is the content digest the binding tests load; payload()
// signs "sha256:ab...", so a default grant is bound to other content.
var loadedContent = "sha256:" + strings.Repeat("cd", 32)

// bindingFixture writes (with -update) and reads testdata/grants/<name>.dsse.json
// into a fresh grants dir.
func bindingFixture(t *testing.T, name string, env []byte) string {
	t.Helper()
	path := filepath.Join("testdata", "grants", name+".dsse.json")
	if *update {
		if err := os.WriteFile(path, append(env, '\n'), 0o644); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(path) //nolint:gosec // test fixture
	if err != nil {
		t.Fatal(err)
	}
	return grantDir(t, map[string][]byte{name: b})
}

// TestGrantBinding: a grant applies only with the loaded content
// digest, a floor_epoch at or below the accepted floor epoch high-water and
// no revocation naming a listed control at its loaded version; otherwise it
// is stale_binding (event exception_stale_binding) and the control is
// enforced.
func TestGrantBinding(t *testing.T) {
	exc := testkeys.Exception()
	bound := func(epoch int) func(map[string]any) {
		return func(p map[string]any) { p["content_digest"], p["floor_epoch"] = loadedContent, epoch }
	}
	gen := map[string][]byte{
		"bound-current":     sign(t, payload(bound(2)), exc),
		"stale-content":     sign(t, payload(func(p map[string]any) { p["floor_epoch"] = 2 }), exc),
		"stale-floor-epoch": sign(t, payload(bound(4)), exc),
	}
	cov := map[string][]bundle.ExemptionKind{rdsEnc: {bundle.CoverGrant}}
	for _, tc := range []struct {
		name, fixture string
		highWater     int64
		revoked       []string
		warning       string
	}{
		{"bound, older epoch", "bound-current", 3, nil, ""},
		{"bound, equal epoch", "bound-current", 2, nil, ""},
		{"revoked control", "bound-current", 3, []string{rdsEnc},
			"exception bobthecorp-legacy-db: approved for content " + loadedContent + " at floor epoch 2, provider loaded " + loadedContent + " at 3; re-approve"},
		{"stale content", "stale-content", 3, nil,
			"exception bobthecorp-legacy-db: approved for content sha256:" + strings.Repeat("ab", 32) + " at floor epoch 2, provider loaded " + loadedContent + " at 3; re-approve"},
		{"future floor epoch", "stale-floor-epoch", 3, nil,
			"exception bobthecorp-legacy-db: approved for content " + loadedContent + " at floor epoch 4, provider loaded " + loadedContent + " at 3; re-approve"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := grantInput(t, bindingFixture(t, tc.fixture, gen[tc.fixture]), cov, Clock{}, now)
			in.ContentDigest, in.FloorEpoch = loadedContent, tc.highWater
			in.Revoked = func(id string) bool { return slices.Contains(tc.revoked, id) }
			gs, n, err := LoadGrants(in)
			if err != nil {
				t.Fatal(err)
			}
			d := gs.Lookup(verdictCtx(t), ctl(rdsEnc), dbSchemas, act(legacy), now)
			if tc.warning == "" {
				if !d.Applied || len(n.Warnings) != 0 || len(gs.Digests()) != 1 {
					t.Fatalf("want applied: %+v %q", d, n.Warnings)
				}
				return
			}
			if d.Applied || d.Exception == nil || d.Exception.Status != StatusStaleBinding || len(gs.Digests()) != 0 ||
				!slices.Equal(n.Warnings, []string{tc.warning}) || !slices.Equal(n.Events, []string{"exception_stale_binding"}) {
				t.Fatalf("want stale_binding: %+v %q %q", d, n.Warnings, n.Events)
			}
		})
	}
}

// TestCoverableSource: coverability comes only from
// compliance.tf-signed bundle or profile content. A coverable list inside a
// grant, here signed by a customer KMS grant key, adds no coverability: the
// grant is rejected and the control stays enforced.
func TestCoverableSource(t *testing.T) {
	kms := testkeys.CustomerKMS()
	env := sign(t, payload(func(p map[string]any) {
		p["content_digest"] = loadedContent
		p["coverable"] = map[string][]string{rdsEnc: {"grant"}}
	}), kms)
	dir := bindingFixture(t, "coverable-in-grant", env)
	fixture, err := os.ReadFile(filepath.Join(dir, "coverable-in-grant.dsse.json")) //nolint:gosec // test fixture
	if err != nil {
		t.Fatal(err)
	}
	mt := table(t, &profile.Scope{Workspace: ws}, profile.Exceptions{GrantKeys: []profile.GrantKey{grantKey(t, kms)}}, "", "")
	v, err := NewVerifier(VerifierInput{Compiled: compiled(t), Revocations: trust.NoRevocations(), Table: mt, OrgID: org, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.VerifyGrant(fixture); code(err) != CodeInvalid { // strict decode: the coverable member rejects the grant
		t.Fatalf("coverable member: %v", err)
	}
	c, _ := NewCoverability(map[string][]bundle.ExemptionKind{rdsEnc: {bundle.CoverBaseline}}, mt.Exceptions)
	gs, n, err := LoadGrants(GrantsInput{Dir: dir, Verifier: v, Coverable: c, Resolve: func(ref string) []string { return sidecarAliases[ref] },
		Table: mt, ContentDigest: loadedContent, Revoked: func(string) bool { return false }})
	if err != nil {
		t.Fatal(err)
	}
	if d := gs.Lookup(verdictCtx(t), ctl(rdsEnc), dbSchemas, act(legacy), now); d.Applied || len(n.Warnings) != 1 || len(gs.Digests()) != 0 {
		t.Fatalf("coverable list in a grant: %+v %q", d, n.Warnings)
	}
	if c.Coverable(rdsEnc, string(bundle.CoverGrant)) {
		t.Fatal("grant coverability from outside signed content")
	}
}
