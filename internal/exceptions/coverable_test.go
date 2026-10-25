package exceptions

import (
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
)

const (
	rdsEnc = "rds_db_instance_encryption_at_rest_enabled"
	rdsKMS = "rds_instance_kms_key_configured"
)

// TestCoverableResolve: per-kind resolution of the effective map.
func TestCoverableResolve(t *testing.T) {
	k := func(ks ...bundle.ExemptionKind) []bundle.ExemptionKind { return ks }
	declared := map[string][]bundle.ExemptionKind{
		"baseline_only": k(bundle.CoverBaseline),
		"grant_only":    k(bundle.CoverGrant),
		"empty":         k(),
		"forbidden":     k(bundle.CoverGrant, bundle.CoverSelfService),
	}
	ex := &profile.Exceptions{
		Coverable:      map[string][]string{"baseline_only": {"self_service", "grant", "grant"}, "profile_only": {"break_glass"}, "Empty": {"grant"}},
		ForbidControls: []string{"FORBIDDEN"},
	}
	c, _ := NewCoverability(declared, ex)
	cases := []struct {
		id, kind string
		want     bool
	}{
		{"baseline_only", "baseline", true},     // bundle_declared
		{"baseline_only", "grant", true},        // profile_listed merges per kind
		{"baseline_only", "break_glass", false}, // neither lists it
		{"profile_only", "break_glass", true},   // profile id not in a bundle
		{"forbidden", "grant", false},           // forbid_controls empties, case-insensitively
		{"forbidden", "self_service", false},
		{"empty", "grant", false}, // profile keys are exact: "Empty" adds nothing
		{"unknown", "grant", false},
		{"grant_only", "waiver", false},
	}
	for _, kind := range []string{"grant", "baseline", "break_glass", "self_service"} {
		cases = append(cases, struct {
			id, kind string
			want     bool
		}{"empty", kind, false}) // an empty list rejects every kind
	}
	for _, tc := range cases {
		if got := c.Coverable(tc.id, tc.kind); got != tc.want {
			t.Errorf("Coverable(%s, %s) = %v", tc.id, tc.kind, got)
		}
	}
	// Kinds is the ContentDigest input: the bundle-declared lists alone, the
	// profile merge and forbid_controls ignored.
	want := map[string][]string{"baseline_only": {"baseline"}, "grant_only": {"grant"}, "empty": {}, "forbidden": {"grant", "self_service"}}
	if k := c.Kinds(); !reflect.DeepEqual(k, want) {
		t.Errorf("Kinds %v, want %v", k, want)
	}
	// Without a signed profile only bundle-declared coverability counts.
	if b, _ := NewCoverability(declared, nil); b.Coverable("profile_only", "break_glass") || !b.Coverable("forbidden", "grant") {
		t.Error("bundle-only map")
	}
	var zero Coverability
	if zero.Coverable("grant_only", "grant") {
		t.Error("zero Coverability covers")
	}
}

// TestCoverableGrant: a verified grant applies only when every target
// control is coverable for grant (whole grant); a baseline-only control
// rejects it.
func TestCoverableGrant(t *testing.T) {
	c, _ := NewCoverability(map[string][]bundle.ExemptionKind{
		rdsEnc: {bundle.CoverBaseline}, rdsKMS: {bundle.CoverGrant},
	}, nil)
	resolve := func(ref string) []string { return sidecarAliases[ref] }
	for name, tc := range map[string]struct {
		controls   []string
		ok         bool
		notCovered []string
	}{
		"baseline_only_rejects_grant":   {[]string{rdsEnc}, false, []string{rdsEnc}},
		"not_coverable_hard_fail_grant": {[]string{"CKV_AWS_16"}, false, []string{rdsEnc}},
		"whole_grant":                   {[]string{rdsKMS, rdsEnc}, false, []string{rdsEnc}},
		"unresolvable":                  {[]string{rdsKMS, "nope"}, false, []string{"nope"}},
		"empty":                         {nil, false, nil},
		"grant_coverable":               {[]string{rdsKMS}, true, nil},
	} {
		ok, nc := c.GrantCoverable(Grant{Controls: tc.controls}, resolve)
		if ok != tc.ok || !slices.Equal(nc, tc.notCovered) {
			t.Errorf("%s: %v %v", name, ok, nc)
		}
	}
}

// TestCoverableSidecar: a sidecar entry on a self-service control whose
// effective list lacks self_service (grant-only) is not_coverable and never
// waives the result, so a hard_fail control fails closed.
func TestCoverableSidecar(t *testing.T) {
	now := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	tbl := profile.ModeTable{
		Workspace:       profile.Dim{Value: "bobthecorp-reporting-prod", Source: "profile"},
		Environment:     profile.Dim{Value: "prod", Source: "profile"},
		Exceptions:      &profile.Exceptions{MaxLifetimeDays: 180, SelfService: []string{rdsEnc}},
		SidecarControls: []string{rdsEnc},
	}
	path := filepath.Join("testdata", "applied.hcl")
	res := resourceValue(map[string]any{"identifier": "legacy-reporting", "storage_encrypted": false})
	for name, kinds := range map[string][]bundle.ExemptionKind{
		"grant_only_rejects_sidecar":      {bundle.CoverGrant},
		"not_coverable_hard_fail_sidecar": {},
		"self_service":                    {bundle.CoverSelfService},
	} {
		cov, _ := NewCoverability(map[string][]bundle.ExemptionKind{rdsEnc: kinds}, tbl.Exceptions)
		sc, n, err := LoadSidecar(path, SidecarInput{Table: tbl, Now: now, Coverable: cov,
			Resolve: func(ref string) []string { return sidecarAliases[ref] }})
		if err != nil {
			t.Fatal(err)
		}
		d := sc.Lookup(verdictCtx(t), ctl(rdsEnc), dbSchemas, act(res), now)
		if name == "self_service" {
			if !d.Applied || len(n.Events) != 0 {
				t.Errorf("%s: %+v %v", name, d, n)
			}
			continue
		}
		want := "exception legacy-reporting-db: " + rdsEnc + " is not exemption-coverable for self_service; enforced"
		if d.Applied || d.Exception == nil || d.Exception.Status != "not_coverable" ||
			!slices.Equal(n.Events, []string{"exception_not_coverable"}) || !slices.Contains(n.Warnings, want) {
			t.Errorf("%s: %+v %+v", name, d, n)
		}
	}
}
