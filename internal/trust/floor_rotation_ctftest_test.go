//go:build ctftest

package trust

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/trust/testkeys"
)

// revokeKeys is a revocation set (as merged from a verified bundle) with the
// given epoch revoking kids.
func revokeKeys(t *testing.T, epoch int64, kids ...string) Revocations {
	t.Helper()
	keys := []map[string]string{}
	for _, k := range kids {
		keys = append(keys, map[string]string{"kid": k, "revoked_at": "2026-10-05T00:00:00Z"})
	}
	raw, _ := json.Marshal(map[string]any{"format": revocationsFormat, "epoch": epoch,
		"revoked_keys": keys, "revoked_bundles": []any{}, "revoked_controls": []any{}})
	r, err := ParseRevocations(raw)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestCtftestFloorKeyCollision: dropping release floor keys under ctftest
// still rejects a release floor kid that is also a test kid.
func TestCtftestFloorKeyCollision(t *testing.T) {
	saved := keyringJSON
	t.Cleanup(func() { keyringJSON = saved })
	keyringJSON = keyringBytes(floorEntry(t, testkeys.FloorNext(), 2, nb, na))
	if _, err := loadEmbedded(); err == nil || !strings.Contains(err.Error(), "duplicate kid") {
		t.Fatal(err)
	}
}

// TestFloorRotation is the floor keys oracle: the compiled keyring holds the
// current (generation 1) and next (generation 2) floor key; the next key
// takes over with a newer epoch; a revoked floor kid is rejected once the
// revocation bundle is merged and the floor fails closed before that.
func TestFloorRotation(t *testing.T) {
	kr, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	if err := kr.checkFloorKeys(); err != nil {
		t.Fatal("ctftest keyring:", err)
	}
	cur, next := KIDFromSPKI(spki(t, testkeys.Floor())), KIDFromSPKI(spki(t, testkeys.FloorNext()))
	gen1 := map[string]FloorMark{"bobthecorp": {Generation: 1, Epoch: 7, IssuedAt: time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)}}
	cases := []struct {
		name, file string
		marks      map[string]FloorMark
		revs       Revocations
		wantGen    int64
		want       string // error substring; "" accepts
	}{
		{name: "next key after current", file: "next-key", marks: gen1, wantGen: 2},
		{name: "next key on empty state", file: "next-key", wantGen: 2},
		{name: "planned rotation needs the new release", file: "below-wrapper", want: "provider 2.0.0 is below the org minimum 9.0.0"},
		{name: "revocation bundle not loaded", file: "revoked-epoch-missing", marks: gen1,
			want: "needs revocation epoch 4, provider has 0: fail closed"},
		{name: "revocation bundle loaded", file: "revoked-epoch-missing", marks: gen1, revs: revokeKeys(t, 4, cur), wantGen: 2},
		{name: "revoked current key", file: "revoked-current-key", revs: revokeKeys(t, 4, cur), want: "key revoked"},
		{name: "revoked next key", file: "next-key", marks: gen1, revs: revokeKeys(t, 4, next), want: "key revoked"},
		{name: "current key after next revoked", file: "good", marks: gen1, revs: revokeKeys(t, 4, next), wantGen: 1},
		{name: "current key retires the next", file: "retires-successor", marks: gen1, want: "retires a key of generation 2"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env, err := os.ReadFile(filepath.Join("testdata", "floor", c.file+".dsse.json"))
			if err != nil {
				t.Fatal(err)
			}
			if !c.revs.valid {
				c.revs = NoRevocations()
			}
			f, delta, err := VerifyFloor(env, FloorInput{OrgID: "bobthecorp", Mode: FloorOnline, ProviderVersion: "2.0.0",
				Now: floorNow, Revs: c.revs, State: loadedState(t, c.marks)})
			if c.want != "" {
				if err == nil || !strings.Contains(err.Error(), c.want) {
					t.Fatalf("err = %v, want %q", err, c.want)
				}
				// A pending statement keeps only its high-water.
				if f != nil || delta.Bundles != nil || delta.Profiles != nil ||
					delta.Floors != nil && !errors.Is(err, ErrFloorRevocationPending) {
					t.Fatal("rejected floor returned a floor or state delta")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if f.Generation != c.wantGen || delta.Floors["bobthecorp"].Generation != c.wantGen {
				t.Fatalf("generation %d, stored %d, want %d", f.Generation, delta.Floors["bobthecorp"].Generation, c.wantGen)
			}
		})
	}
	t.Run("pending is the sentinel", func(t *testing.T) {
		env, err := os.ReadFile(filepath.Join("testdata", "floor", "revoked-epoch-missing.dsse.json"))
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = VerifyFloor(env, FloorInput{OrgID: "bobthecorp", Mode: FloorAirgap, ProviderVersion: "2.0.0",
			Now: floorNow, Revs: revokeKeys(t, 3, cur), State: loadedState(t, nil)})
		if !errors.Is(err, ErrFloorRevocationPending) {
			t.Fatal(err)
		}
	})
}
