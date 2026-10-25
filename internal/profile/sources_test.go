package profile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

var now = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

// cacheWith writes fixtures into a cache dir as profiles/bobthecorp/v<n>.dsse.json.
func cacheWith(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	d := filepath.Join(dir, "profiles", "bobthecorp")
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, fx := range files {
		if err := os.WriteFile(filepath.Join(d, name), fixture(t, fx), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func resolve(t *testing.T, org Org, src Sources, minV int64, floor string) (Resolution, error) {
	t.Helper()
	c := LoadCandidates(src, org.ID, trust.NoRevocations())
	return Resolve(Input{Org: org, Candidates: c, MinVersion: minV, FloorMode: floor, ProviderVersion: "0.3.0", Now: now})
}

var bob = Org{ID: "bobthecorp"}

func TestSourceSelection(t *testing.T) {
	dir := t.TempDir()
	v6 := filepath.Join(dir, "v6.json")
	_ = os.WriteFile(v6, fixture(t, "v6"), 0o600)
	cache := cacheWith(t, map[string]string{"v7.dsse.json": "v7", "v8.dsse.json": "expired", "v9.dsse.json": "wrong-org"})

	// Highest valid version wins across sources; v6 from HCL loses to cached v7.
	r, err := resolve(t, bob, Sources{HCLPath: v6, CacheDir: cache}, 0, "online")
	if err != nil || r.Profile == nil || r.Profile.ProfileVersion != 7 || r.Source != SourceCache || !r.Governed {
		t.Fatalf("got %+v, %v", r, err)
	}
	reasons := strings.Join(rejectionReasons(r.Rejected), "|")
	for _, want := range []string{"expired", "wrong org"} {
		if !strings.Contains(reasons, want) {
			t.Errorf("rejections %q lack %q", reasons, want)
		}
	}

	// Rollback: only v6 present but the floor is 7 -> v6 rejected; v6 is not
	// governed, but no profile means hard_fail floor for a non-governed org.
	r, err = resolve(t, bob, Sources{HCLPath: v6}, 7, "online")
	if err != nil || r.Profile != nil || r.Fallback != HardFailFloor || !strings.Contains(r.Warnings[0], "hard_fail floor applied") {
		t.Fatalf("rollback: %+v, %v", r, err)
	}

	// A governed v7 at or above the selected version cannot be bypassed by
	// raising the floor past it: governed + no acceptable profile = error.
	_, err = resolve(t, bob, Sources{CacheDir: cache}, 8, "online")
	if err == nil || !strings.Contains(err.Error(), "No acceptable org profile for governed org bobthecorp") {
		t.Fatalf("governed no profile: %v", err)
	}

	// Bad signature from the runner path is named and skipped.
	bad := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(bad, fixture(t, "bad-sig"), 0o600)
	r, err = resolve(t, bob, Sources{EnvPath: bad, HCLPath: v6}, 0, "online")
	if err != nil || r.Profile.ProfileVersion != 6 || !strings.Contains(strings.Join(rejectionReasons(r.Rejected), "|"), "signature invalid") {
		t.Fatalf("bad-sig: %+v %v", r, err)
	}
}

func rejectionReasons(rs []Rejection) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.Reason)
	}
	return out
}

func TestCachedFallbackComplete(t *testing.T) {
	cache := cacheWith(t, map[string]string{"v7.dsse.json": "v7"})
	r, err := resolve(t, bob, Sources{ServiceExpected: true, CacheDir: cache}, 0, "online")
	if err != nil || r.Warnings[0] != "Org profile for bobthecorp unavailable from the service: using cached v7." {
		t.Fatalf("%+v %v", r, err)
	}
	v, _ := verifyEnvelope(fixture(t, "v7"), trust.NoRevocations())
	want, _, _ := Parse(v.Payload)
	got, _ := json.Marshal(r.Profile)
	exp, _ := json.Marshal(want)
	if string(got) != string(exp) || r.Profile.Digest != want.Digest {
		t.Fatal("cached profile not applied complete")
	}
	// The cache file name must match the payload version.
	cache = cacheWith(t, map[string]string{"v9.dsse.json": "v7"})
	r, _ = resolve(t, bob, Sources{CacheDir: cache}, 0, "online")
	if r.Profile != nil {
		t.Fatal("misnamed cache file accepted")
	}
}

func TestMissingProfile(t *testing.T) {
	// Free tier.
	r, err := Resolve(Input{Now: now})
	if err != nil || r.Fallback != FreeTier {
		t.Fatalf("free tier: %+v %v", r, err)
	}
	// Org set, not governed, nothing found.
	r, err = resolve(t, bob, Sources{}, 0, "")
	if err != nil || r.Fallback != HardFailFloor {
		t.Fatalf("hard_fail: %+v %v", r, err)
	}
	// Governed by pin or env, nothing found: floor error first (online needed).
	for _, org := range []Org{{ID: "bobthecorp", Governed: true}} {
		_, err = resolve(t, org, Sources{}, 0, "")
		if err == nil || !strings.Contains(err.Error(), "Org floor for bobthecorp unavailable") || !strings.Contains(err.Error(), "floor_mode online") {
			t.Fatalf("governed no floor: %v", err)
		}
		_, err = resolve(t, org, Sources{}, 0, "online")
		if err == nil || !strings.Contains(err.Error(), "No acceptable org profile for governed org bobthecorp") {
			t.Fatalf("governed no profile: %v", err)
		}
	}
}

func TestFloorModeBinding(t *testing.T) {
	cache := cacheWith(t, map[string]string{"v7.dsse.json": "v7"})
	for _, fm := range []string{"", "airgap"} {
		if _, err := resolve(t, bob, Sources{CacheDir: cache}, 0, fm); err == nil {
			t.Fatalf("floor mode %q accepted for an online profile", fm)
		}
	}
	// Non-governed v6 with bundles still needs the floor.
	dir := t.TempDir()
	p := filepath.Join(dir, "p.json")
	_ = os.WriteFile(p, fixture(t, "v6"), 0o600)
	if _, err := resolve(t, bob, Sources{EnvPath: p}, 0, ""); err == nil {
		t.Fatal("bundles without floor accepted")
	}
}

func TestDigestConflict(t *testing.T) {
	dir := t.TempDir()
	alt := filepath.Join(dir, "alt.json")
	_ = os.WriteFile(alt, signProfile(basePayload(7, func(m map[string]any) { m["governed"] = true; m["verdict_required"] = true })), 0o600)
	cache := cacheWith(t, map[string]string{"v7.dsse.json": "v7", "v6.dsse.json": "v6"})
	_, err := resolve(t, bob, Sources{EnvPath: alt, CacheDir: cache}, 0, "online")
	if err == nil || !strings.Contains(err.Error(), "conflicting digests at v7") {
		t.Fatalf("conflict: %v", err)
	}
}

func TestOrgAndGoverned(t *testing.T) {
	pin := &Pin{OrgID: "bobthecorp"}
	cases := []struct {
		hcl, env, gov string
		pin           *Pin
		want          Org
		err           string
	}{
		{want: Org{}},
		{hcl: "bobthecorp", want: bob},
		{hcl: "bobthecorp", env: "bobthecorp-eu", err: "differ"},
		{pin: pin, want: Org{ID: "bobthecorp", Governed: true}},
		{hcl: "bobthecorp-eu", pin: pin, err: "org pin"},
		{gov: "true", err: "needs an org_id"},
		{hcl: "bobthecorp", gov: "true", want: Org{ID: "bobthecorp", Governed: true}},
		{hcl: "bobthecorp", gov: "false", want: bob},
		{hcl: "bobthecorp", gov: "yes", err: "COMPLIANCETF_GOVERNED"},
		{hcl: "../x", err: "org_id"},
	}
	for i, c := range cases {
		got, err := ResolveOrg(c.hcl, c.env, c.pin, c.gov)
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%d: err %v, want %q", i, err, c.err)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%d: %+v %v, want %+v", i, got, err, c.want)
		}
	}
	// No local input can clear governed from a governed profile.
	cache := cacheWith(t, map[string]string{"v7.dsse.json": "v7", "v6.dsse.json": "v6"})
	org, _ := ResolveOrg("bobthecorp", "", nil, "false")
	r, err := resolve(t, org, Sources{CacheDir: cache}, 0, "online")
	if err != nil || !r.Governed {
		t.Fatalf("governed cleared: %+v %v", r, err)
	}
}

func TestWrapperResolve(t *testing.T) {
	cache := cacheWith(t, map[string]string{"v7.dsse.json": "v7"})
	c := LoadCandidates(Sources{CacheDir: cache}, "bobthecorp", trust.NoRevocations())
	_, err := Resolve(Input{Org: bob, Candidates: c, FloorMode: "online", ProviderVersion: "0.1.0", Now: now})
	if err == nil || err.Error() != "provider 0.1.0 is below the org minimum 0.2.0" {
		t.Fatalf("wrapper: %v", err)
	}
}

func TestCacheLimit(t *testing.T) {
	files := map[string]string{}
	for i := 1; i <= maxCacheFiles+1; i++ {
		files["v"+itoa(i)+".dsse.json"] = "v7"
	}
	r, _ := resolve(t, bob, Sources{CacheDir: cacheWith(t, files)}, 0, "online")
	if r.Profile != nil || !strings.Contains(strings.Join(rejectionReasons(r.Rejected), "|"), "too many") {
		t.Fatalf("%+v", r)
	}
}

func itoa(i int) string { b, _ := json.Marshal(i); return string(b) }

// TestAirgapBreakGlass: a signed profile with floor_mode airgap and
// break_glass.enabled true is rejected at load, never selected, so a governed
// org has no acceptable profile.
func TestAirgapBreakGlass(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.json")
	_ = os.WriteFile(path, fixture(t, "airgap-breakglass"), 0o600)
	c := LoadCandidates(Sources{EnvPath: path}, bob.ID, trust.NoRevocations())
	if len(c.list) != 0 || len(c.rejected) != 1 || !strings.Contains(c.rejected[0].Reason, "break_glass is unavailable with floor_mode airgap") {
		t.Fatalf("candidates %+v rejected %+v", c.list, c.rejected)
	}
	_, err := Resolve(Input{Org: Org{ID: bob.ID, Governed: true}, Candidates: c, FloorMode: FloorOnline, ProviderVersion: "0.3.0", Now: now})
	if err == nil || !strings.Contains(err.Error(), "No acceptable org profile for governed org bobthecorp") {
		t.Fatal(err)
	}
}

func TestFloorModeTopOnly(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json")
	_ = os.WriteFile(a, fixture(t, "v6"), 0o600)
	_ = os.WriteFile(b, signProfile(basePayload(6, func(m map[string]any) { m["floor_mode"] = "airgap" })), 0o600)
	cache := cacheWith(t, map[string]string{"v7.dsse.json": "v7"})
	// A disagreement below the top version does not matter.
	c := LoadCandidates(Sources{EnvPath: a, HCLPath: b, CacheDir: cache}, "bobthecorp", trust.NoRevocations())
	if m, err := c.FloorMode(false); err != nil || m != FloorOnline {
		t.Fatalf("%q %v", m, err)
	}
	// At the top version it is an error.
	c = LoadCandidates(Sources{EnvPath: a, HCLPath: b}, "bobthecorp", trust.NoRevocations())
	if _, err := c.FloorMode(false); err == nil {
		t.Fatal("disagreement at top accepted")
	}
}

// ResolveOrg and Resolve errors never echo an unvalidated org id or
// the COMPLIANCETF_GOVERNED value; a valid org id is still named.
func TestOrgDiagnosticsValueFree(t *testing.T) {
	const bad = "Leak\x1b[31m\nsecret"
	pin := &Pin{OrgID: "bobthecorp"}
	cases := []struct {
		hcl, env, gov string
		pin           *Pin
		named         []string
	}{
		{hcl: "bobthecorp", gov: bad},
		{hcl: bad, env: "bobthecorp-eu", named: []string{"bobthecorp-eu"}},
		{hcl: "bobthecorp-eu", env: bad, named: []string{"bobthecorp-eu"}},
		{hcl: bad, pin: pin, named: []string{"bobthecorp"}},
		{hcl: "bobthecorp-eu", pin: pin, named: []string{"bobthecorp-eu", "bobthecorp"}},
		{hcl: bad},
		{env: bad},
	}
	for i, c := range cases {
		_, err := ResolveOrg(c.hcl, c.env, c.pin, c.gov)
		if err == nil {
			t.Fatalf("%d: no error", i)
		}
		if strings.Contains(err.Error(), "Leak") || strings.Contains(err.Error(), "secret") {
			t.Errorf("%d: value echoed: %q", i, err)
		}
		for _, n := range c.named {
			if !strings.Contains(err.Error(), n) {
				t.Errorf("%d: %q does not name %s", i, err, n)
			}
		}
	}
	_, err := Resolve(Input{Org: bob, Candidates: LoadCandidates(Sources{}, bad, trust.Revocations{})})
	if err == nil || strings.Contains(err.Error(), "Leak") || !strings.Contains(err.Error(), "bobthecorp") {
		t.Errorf("Resolve org mismatch: %v", err)
	}
}
