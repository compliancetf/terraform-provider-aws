//go:build ctftest

package exceptions

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
	"github.com/compliancetf/terraform-provider-aws/internal/trust/testkeys"
)

func day(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 0, 0, 0, 0, time.UTC) }

// floorAt is the issued_at of the accepted floor statement; processClocks
// are the fake process clocks the air-gap results must not depend on.
var (
	floorAt       = day(2027, 3, 1)
	processClocks = []time.Time{day(2026, 1, 1), day(2030, 1, 1)}
)

func floorState(issued time.Time) trust.State {
	return resetState(issued, time.Time{})
}

func resetState(issued, reset time.Time) trust.State {
	return trust.State{Floors: map[string]trust.FloorMark{org: {Generation: 1, Epoch: 1, IssuedAt: issued, ResetIssuedAt: reset}}}
}

// airgapSidecar: max_lifetime_days 90 from the run clock; each entry has its
// own identifier prefix so Lookup can address it.
const airgapSidecar = `
exception "old" {
  controls      = ["rds_db_instance_encryption_at_rest_enabled"]
  match         = "type == 'aws_db_instance' && resource.identifier.matches('^old-')"
  workspace = "bobthecorp-reporting-prod"
  reason    = "r"
  expires   = "2027-02-28"
}
exception "edge" {
  controls      = ["rds_db_instance_encryption_at_rest_enabled"]
  match         = "type == 'aws_db_instance' && resource.identifier.matches('^edge-')"
  workspace = "bobthecorp-reporting-prod"
  reason    = "r"
  expires   = "2027-03-01"
}
exception "live" {
  controls      = ["rds_db_instance_encryption_at_rest_enabled"]
  match         = "type == 'aws_db_instance' && resource.identifier.matches('^live-')"
  workspace = "bobthecorp-reporting-prod"
  reason    = "r"
  expires   = "2027-03-02"
}
exception "mid" {
  controls      = ["rds_db_instance_encryption_at_rest_enabled"]
  match         = "type == 'aws_db_instance' && resource.identifier.matches('^mid-')"
  workspace = "bobthecorp-reporting-prod"
  reason    = "r"
  expires   = "2027-05-15"
}
exception "far" {
  controls      = ["rds_db_instance_encryption_at_rest_enabled"]
  match         = "type == 'aws_db_instance' && resource.identifier.matches('^far-')"
  workspace = "bobthecorp-reporting-prod"
  reason    = "r"
  expires   = "2027-07-01"
}
`

// sidecarStatuses loads airgapSidecar under clock and process clock local
// and returns the Lookup status of each entry ("" when none) and the
// warnings.
func sidecarStatuses(t *testing.T, clock Clock, local time.Time) (map[string]string, []string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "exceptions.hcl")
	if err := os.WriteFile(path, []byte(airgapSidecar), 0o600); err != nil {
		t.Fatal(err)
	}
	tbl := profile.ModeTable{
		Workspace:   profile.Dim{Value: ws, Source: "profile"},
		Environment: profile.Dim{Value: "prod", Source: "profile"},
		Exceptions: &profile.Exceptions{MaxLifetimeDays: 90,
			SelfService: []string{"rds_db_instance_encryption_at_rest_enabled"}},
		SidecarControls: []string{"rds_db_instance_encryption_at_rest_enabled"},
	}
	cov, _ := NewCoverability(map[string][]bundle.ExemptionKind{
		"rds_db_instance_encryption_at_rest_enabled": {bundle.CoverSelfService}}, nil)
	sc, n, err := LoadSidecar(path, SidecarInput{Table: tbl, Coverable: cov, Now: local, Clock: clock,
		Resolve: func(ref string) []string { return []string{ref} }})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, l := range []string{"old", "edge", "live", "mid", "far"} {
		res := resourceValue(map[string]any{"identifier": l + "-db", "storage_encrypted": false})
		if d := sc.Lookup(verdictCtx(t), ctl("rds_db_instance_encryption_at_rest_enabled"), dbSchemas, act(res), local); d.Exception != nil {
			got[l] = d.Exception.Status
		}
	}
	return got, n.Warnings
}

func grantVerifier(t *testing.T, clock Clock, local time.Time, keys ...profile.GrantKey) *Verifier {
	t.Helper()
	v, err := NewVerifier(VerifierInput{Compiled: compiled(t), Revocations: trust.NoRevocations(), OrgID: org, Now: local, Clock: clock,
		Table: table(t, &profile.Scope{Workspace: ws}, profile.Exceptions{GrantKeys: keys}, "", "")})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func grantDates(issued, expires string) func(map[string]any) {
	return func(p map[string]any) { p["issued_at"], p["expires_at"] = issued, expires }
}

// TestAirgapExpiry is the oracle: under floor_mode airgap grant and
// sidecar expiry use the stored floor issued_at, never the process clock.
func TestAirgapExpiry(t *testing.T) {
	exc, kms := testkeys.Exception(), testkeys.CustomerKMS()
	late := grantKey(t, kms) // a profile grant key valid only after the floor
	late.NotBefore, late.NotAfter = day(2027, 4, 1), day(2031, 1, 1)
	grants := []struct {
		name string
		env  []byte
		want string
	}{
		{"expired before the floor", sign(t, payload(grantDates("2027-02-20T00:00:00Z", "2027-02-28T00:00:00Z")), exc), CodeExpired},
		{"expires at the floor", sign(t, payload(grantDates("2027-02-20T00:00:00Z", "2027-03-01T00:00:00Z")), exc), CodeExpired},
		{"expires after the floor", sign(t, payload(grantDates("2027-02-20T00:00:00Z", "2027-03-02T00:00:00Z")), exc), ""},
		{"issued after the floor", sign(t, payload(grantDates("2027-06-01T00:00:00Z", "2027-07-01T00:00:00Z")), exc), CodeInvalid},
		{"key not yet valid at the floor", sign(t, payload(grantDates("2027-04-15T00:00:00Z", "2027-12-01T00:00:00Z")), kms), CodeKeyNotValid},
	}
	wantSidecar := map[string]string{"old": StatusExpired, "edge": StatusExpired, "live": StatusApplied, "mid": StatusApplied, "far": StatusRejected}
	modes := [][]string{{trust.FloorAirgap, trust.FloorAirgap}, {"", trust.FloorAirgap}, {trust.FloorAirgap, ""},
		{trust.FloorOnline, trust.FloorAirgap}, {trust.FloorAirgap, trust.FloorOnline}}
	for _, mode := range modes {
		// A later reset_issued_at never moves the air-gap time.
		clock := NewClock(resetState(floorAt, day(2027, 6, 1)), org, mode...)
		for _, local := range processClocks {
			t.Run(strings.Join(mode, "+")+"/"+local.Format(time.DateOnly), func(t *testing.T) {
				v := grantVerifier(t, clock, local, late)
				for _, g := range grants {
					_, err := v.VerifyGrant(g.env)
					if code(err) != g.want {
						t.Errorf("grant %s: %v, want %q", g.name, err, g.want)
					}
					if err != nil && !strings.Contains(err.Error(), "air-gap time 2027-03-01T00:00:00Z") {
						t.Errorf("grant %s: error %q does not name the air-gap time", g.name, err)
					}
				}
				got, _ := sidecarStatuses(t, clock, local)
				for l, w := range wantSidecar {
					if got[l] != w {
						t.Errorf("sidecar %s: %q, want %q", l, got[l], w)
					}
				}
			})
		}
	}
}

// TestAirgapClockUnknown: airgap without a usable floor mark, or an invalid
// floor_mode, applies no grant and no sidecar entry under any process clock.
func TestAirgapClockUnknown(t *testing.T) {
	good := sign(t, payload(grantDates("2027-02-20T00:00:00Z", "2027-03-02T00:00:00Z")), testkeys.Exception())
	for _, tc := range []struct {
		name, why string
		clock     Clock
	}{
		{"no mark", "import a floor statement", NewClock(trust.State{}, org, trust.FloorAirgap)},
		{"zero issued_at", "import a floor statement", NewClock(floorState(time.Time{}), org, trust.FloorAirgap)},
		{"reset only", "import a floor statement", NewClock(resetState(time.Time{}, floorAt), org, trust.FloorAirgap)},
		{"other org", "import a floor statement", NewClock(floorState(floorAt), "otherorg", trust.FloorAirgap)},
		{"empty org", "import a floor statement", NewClock(floorState(floorAt), "", trust.FloorAirgap)},
		{"invalid mode", `floor_mode "bogus"`, NewClock(floorState(floorAt), org, trust.FloorAirgap, "bogus")},
	} {
		for _, local := range processClocks {
			t.Run(tc.name+"/"+local.Format(time.DateOnly), func(t *testing.T) {
				_, err := grantVerifier(t, tc.clock, local).VerifyGrant(good)
				if code(err) != CodeAirgapTimeUnknown || !strings.Contains(err.Error(), tc.why) {
					t.Errorf("grant: %v", err)
				}
				got, warns := sidecarStatuses(t, tc.clock, local)
				for l, s := range got {
					if s == StatusApplied {
						t.Errorf("sidecar %s applied", l)
					}
				}
				if got["live"] != StatusRejected || !strings.Contains(strings.Join(warns, "\n"), tc.why) {
					t.Errorf("sidecar live %q, warnings %q", got["live"], warns)
				}
			})
		}
	}
}

// TestAirgapZeroNow: under airgap NewVerifier does not need a process clock;
// online it still does.
func TestAirgapZeroNow(t *testing.T) {
	for _, tc := range []struct {
		name    string
		clock   Clock
		wantErr bool
	}{
		{"airgap", NewClock(floorState(floorAt), org, trust.FloorAirgap), false},
		{"unknown", NewClock(trust.State{}, org, trust.FloorAirgap), false},
		{"online", Clock{}, true},
	} {
		_, err := NewVerifier(VerifierInput{Compiled: compiled(t), Revocations: trust.NoRevocations(), OrgID: org, Clock: tc.clock})
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: %v, want error %v", tc.name, err, tc.wantErr)
		}
	}
}

// TestOnlineClock: outside airgap the process clock decides.
func TestOnlineClock(t *testing.T) {
	kms := testkeys.CustomerKMS()
	wide := grantKey(t, kms)
	wide.NotBefore, wide.NotAfter = day(2025, 1, 1), day(2031, 1, 1)
	env := sign(t, payload(grantDates("2025-12-01T00:00:00Z", "2028-01-01T00:00:00Z")), kms)
	for _, tc := range []struct {
		local       time.Time
		grant, live string
	}{
		{day(2026, 1, 1), "", StatusRejected}, // live is beyond 2026-01-01 + 90 days
		{day(2027, 2, 1), "", StatusApplied},
		{day(2030, 1, 1), CodeExpired, StatusExpired},
	} {
		clock := NewClock(floorState(floorAt), org, trust.FloorOnline, trust.FloorOnline)
		if _, err := grantVerifier(t, clock, tc.local, wide).VerifyGrant(env); code(err) != tc.grant {
			t.Errorf("%s grant: %v, want %q", tc.local, err, tc.grant)
		}
		if got, _ := sidecarStatuses(t, clock, tc.local); got["live"] != tc.live {
			t.Errorf("%s sidecar live: %q, want %q", tc.local, got["live"], tc.live)
		}
	}
}
