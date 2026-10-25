//go:build ctftest

package fetch

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/profile"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

var floorNow = time.Date(2026, 10, 6, 6, 0, 0, 0, time.UTC)

func offlineClientAt(t *testing.T, at time.Time) *Client {
	t.Helper()
	dir := t.TempDir()
	seedCache(t, dir)
	c, err := New(Config{CacheDir: dir, Offline: true, Now: func() time.Time { return at }})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestFloorEmptyStateDir: with an empty COMPLIANCETF_STATE_DIR the signed
// floor statement (min_profile_version 7, bobthecorp-soc2 13) rejects the
// cached bundle v12 and the profile v6, both signature-valid and unexpired.
func TestFloorEmptyStateDir(t *testing.T) {
	s, err := trust.LoadState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	env, err := os.ReadFile("../trust/testdata/floor/good.dsse.json")
	if err != nil {
		t.Fatal(err)
	}
	fl, _, err := trust.VerifyFloor(env, trust.FloorInput{OrgID: org, Mode: trust.FloorOnline, ProviderVersion: "2.0.0", Now: floorNow, Revs: noRevs, State: s})
	if err != nil {
		t.Fatal(err)
	}
	floors := trust.Floors{OrgID: org, Mode: trust.FloorOnline, Governed: true, Statement: fl}

	bmin, err := s.EffectiveBundleMin(bundleID, floors)
	if err != nil || bmin != 13 {
		t.Fatal(bmin, err)
	}
	c := offlineClientAt(t, floorNow)
	if _, _, err := c.Bundle(context.Background(), org, bundleID, bmin, 7, noRevs); err == nil || !strings.Contains(err.Error(), "at or above v13") {
		t.Fatalf("older still-valid bundle: %v", err)
	}
	if _, _, err := c.Bundle(context.Background(), org, bundleID, 0, 7, noRevs); err != nil {
		t.Fatalf("control: the same cached bundle loads without the floor: %v", err)
	}

	pmin, err := s.EffectiveProfileMin(floors)
	if err != nil || pmin != 7 {
		t.Fatal(pmin, err)
	}
	cands := profile.LoadCandidates(profile.Sources{EnvPath: "../../testdata/profiles/bobthecorp-v6.dsse.json"}, org, noRevs)
	_, err = profile.Resolve(profile.Input{Org: profile.Org{ID: org, Governed: true}, Candidates: cands, MinVersion: pmin,
		FloorMode: trust.FloorOnline, ProviderVersion: "2.0.0", Now: floorNow})
	if err == nil || !strings.Contains(err.Error(), "v6 is below the floor v7") {
		t.Fatalf("older still-valid profile: %v", err)
	}
}

// TestFloorManifestMinimums: a cached manifest's min_bundle_version raises the
// run minimum even when that copy itself no longer loads, and its
// min_profile_version gates the load on the run's profile version.
func TestFloorManifestMinimums(t *testing.T) {
	c := offlineClientAt(t, floorNow)
	if _, _, err := c.Bundle(context.Background(), org, bundleID, 0, 5, noRevs); err == nil {
		t.Fatal("profile v5 run loaded a bundle needing v6")
	}
	if _, _, err := c.Bundle(context.Background(), org, bundleID, 0, 6, noRevs); err != nil {
		t.Fatal(err)
	}
	c = offlineClientAt(t, time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC)) // past expiry and grace
	if _, _, err := c.Bundle(context.Background(), org, bundleID, 0, 6, noRevs); err == nil || !strings.Contains(err.Error(), "at or above v10") {
		t.Fatalf("expired cached manifest did not raise the minimum: %v", err)
	}
}

// TestGovernedWithoutFloor: an org pin or COMPLIANCETF_GOVERNED=true governs
// the run, "false" cannot undo a pin, and a governed run without a verified
// floor fails Configure.
func TestGovernedWithoutFloor(t *testing.T) {
	pin := &trust.Pin{OrgID: org}
	o, err := profile.ResolveOrg("", "", pin, "false")
	if err != nil || !o.Governed || o.ID != org {
		t.Fatal(o, err)
	}
	if _, err := profile.ResolveOrg("alicecorp", "", pin, ""); err == nil {
		t.Fatal("org_id other than the pin accepted")
	}
	s, err := trust.LoadState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range []string{"true", ""} {
		var p *trust.Pin
		if g == "" {
			p = pin
		}
		o, err := profile.ResolveOrg(org, "", p, g)
		if err != nil {
			t.Fatal(err)
		}
		_, err = s.EffectiveProfileMin(trust.Floors{OrgID: o.ID, Mode: trust.FloorOnline, Governed: o.Governed})
		want := "Org floor for bobthecorp unavailable: governed runs need a signed floor statement (floor_mode online)."
		if err == nil || err.Error() != want {
			t.Fatalf("governed=%q pin=%v: %v", g, p != nil, err)
		}
		_, err = profile.Resolve(profile.Input{Org: o, Candidates: profile.LoadCandidates(profile.Sources{}, org, noRevs), Now: floorNow})
		if err == nil || err.Error() != want {
			t.Fatalf("Resolve without floor: %v", err)
		}
	}
}
