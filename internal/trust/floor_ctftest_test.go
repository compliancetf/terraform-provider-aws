//go:build ctftest

package trust

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCtftestKeyringDigestFormula(t *testing.T) {
	if got := ctftestKeyringDigest(t); got != KeyringDigest() {
		t.Fatalf("%s != %s: regenerate with -tags ctftest -update", got, KeyringDigest())
	}
}

// TestFloorFixtures runs the testdata/floor oracle against the compiled
// ctftest keyring.
func TestFloorFixtures(t *testing.T) {
	stored := map[string]FloorMark{"bobthecorp": {Generation: 1, Epoch: 7, IssuedAt: time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)}}
	cases := []struct {
		file, mode string
		marks      map[string]FloorMark
		want       string
	}{
		{"good", FloorOnline, nil, ""},
		{"good", FloorAirgap, stored, ""},
		{"expired", FloorOnline, nil, "expired 2026-10-05T00:00:00Z"},
		{"wrong-keyring", FloorOnline, nil, "org floor names another keyring than the " + KeyringDigest() + " this provider embeds: upgrade the provider"},
		{"old-epoch", FloorOnline, stored, "floor epoch 6 is below the accepted high-water 7 for bobthecorp"},
		{"airgap-8d", FloorAirgap, nil, "lifetime 192h0m0s exceeds 168h0m0s for floor_mode airgap"},
		{"airgap-8d", FloorOnline, nil, "exceeds 24h0m0s for floor_mode online"},
		{"below-wrapper", FloorOnline, nil, "provider 2.0.0 is below the org minimum 9.0.0"},
	}
	for _, c := range cases {
		t.Run(c.file+"/"+c.mode, func(t *testing.T) {
			env, err := os.ReadFile(filepath.Join("testdata", "floor", c.file+".dsse.json"))
			if err != nil {
				t.Fatal(err)
			}
			f, delta, err := VerifyFloor(env, FloorInput{OrgID: "bobthecorp", Mode: c.mode, ProviderVersion: "2.0.0",
				Now: floorNow, Revs: NoRevocations(), State: loadedState(t, c.marks)})
			if c.want == "" {
				if err != nil || f.Generation != 1 || delta.Floors["bobthecorp"].Epoch != 7 {
					t.Fatal(f, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}

// TestFloorEmptyStateDir: with no trust-state.json the floor statement alone
// rejects older artifacts whose signature and expiry are still valid, and
// the accepted floor persists its minimums.
func TestFloorEmptyStateDir(t *testing.T) {
	dir := t.TempDir()
	s, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	env, err := os.ReadFile(filepath.Join("testdata", "floor", "good.dsse.json"))
	if err != nil {
		t.Fatal(err)
	}
	f, delta, err := VerifyFloor(env, FloorInput{OrgID: "bobthecorp", Mode: FloorOnline, ProviderVersion: "2.0.0", Now: floorNow, Revs: NoRevocations(), State: s})
	if err != nil {
		t.Fatal(err)
	}
	floors := Floors{OrgID: "bobthecorp", Mode: FloorOnline, Governed: true, Statement: f}
	if v, err := s.EffectiveProfileMin(floors); err != nil || v != 7 {
		t.Fatal("profile min", v, err)
	}
	if v, err := s.EffectiveBundleMin("cis-aws", floors); err != nil || v != 5 {
		t.Fatal("bundle min", v, err)
	}
	if _, err := UpdateState(dir, delta); err != nil {
		t.Fatal(err)
	}
	s, err = LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := s.MinBundleVersion("cis-aws"); err != nil || v != 5 || s.Profiles["bobthecorp"] != 7 || s.Floors["bobthecorp"].Epoch != 7 {
		t.Fatal("persisted", v, err, s.Floors)
	}
}
