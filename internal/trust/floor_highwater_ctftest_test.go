//go:build ctftest

package trust

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/trust/testkeys"
)

func floorFixture(t *testing.T, name string) []byte {
	t.Helper()
	env, err := os.ReadFile(filepath.Join("testdata", "floor", name+".dsse.json"))
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// verifyAndStore runs VerifyFloor against the state in dir and persists the
// returned delta, as Configure does (also on ErrFloorRevocationPending).
func verifyAndStore(t *testing.T, dir string, env []byte, revs Revocations) (*Floor, error) {
	t.Helper()
	s, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	f, delta, err := VerifyFloor(env, FloorInput{OrgID: "bobthecorp", Mode: FloorAirgap, ProviderVersion: "2.0.0",
		Now: floorNow, Revs: revs, State: s})
	if delta.Floors != nil {
		if _, uerr := UpdateState(dir, delta); uerr != nil {
			t.Fatal(uerr)
		}
	}
	return f, err
}

func assertMode0600(t *testing.T, dir string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	fi, err := os.Stat(filepath.Join(dir, stateFileName))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("trust-state.json mode %v, want 0600", fi.Mode().Perm())
	}
}

func storedMark(t *testing.T, dir string) FloorMark {
	t.Helper()
	s, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	return s.Floors["bobthecorp"]
}

// TestFloorHighWater is the epoch high-water oracle: after epoch 7 an
// unexpired epoch-6 air-gap floor file is refused; a higher-epoch revocation
// floor file is accepted into the high-water and fails closed until its
// revocation bundle loads, and the older file stays refused meanwhile.
func TestFloorHighWater(t *testing.T) {
	dir := t.TempDir()
	if _, err := verifyAndStore(t, dir, floorFixture(t, "epoch-7"), NoRevocations()); err != nil {
		t.Fatal(err)
	}
	assertMode0600(t, dir)
	if _, err := verifyAndStore(t, dir, floorFixture(t, "airgap-epoch-6-valid"), NoRevocations()); err == nil ||
		!strings.Contains(err.Error(), "floor epoch 6 is below the accepted high-water 7 for bobthecorp") {
		t.Fatalf("epoch 6 after 7: %v", err)
	}

	// Emergency revocation, bundle not loaded yet: fail closed, but the
	// higher (generation, epoch) is kept.
	f, err := verifyAndStore(t, dir, floorFixture(t, "airgap-epoch-8-revocation"), NoRevocations())
	if !errors.Is(err, ErrFloorRevocationPending) || f != nil {
		t.Fatalf("pending: %v %v", f, err)
	}
	if m := storedMark(t, dir); m.Generation != 2 || m.Epoch != 8 || m.RevocationEpoch != 0 {
		t.Fatalf("pending mark %+v: want generation 2, epoch 8, revocation epoch not pinned", m)
	}
	// The old gen-1 file is refused even while the bundle is withheld.
	if _, err := verifyAndStore(t, dir, floorFixture(t, "epoch-7"), NoRevocations()); err == nil ||
		!strings.Contains(err.Error(), "(generation 1) is retired for bobthecorp") {
		t.Fatalf("old file after revocation floor: %v", err)
	}

	cur := KIDFromSPKI(spki(t, testkeys.Floor()))
	f, err = verifyAndStore(t, dir, floorFixture(t, "airgap-epoch-8-revocation"), revokeKeys(t, 4, cur))
	if err != nil || f.Generation != 2 || f.Epoch != 8 {
		t.Fatalf("revocation floor with its bundle: %v %v", f, err)
	}
	if m := storedMark(t, dir); m.RevocationEpoch != 4 {
		t.Fatalf("mark %+v: want revocation epoch 4", m)
	}
	assertMode0600(t, dir)
}

func applyReset(t *testing.T, dir string, revs Revocations) (State, bool, error) {
	t.Helper()
	s, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	return ApplyFloorReset(dir, FloorInput{OrgID: "bobthecorp", Mode: FloorOnline, ProviderVersion: "2.0.0",
		Now: floorNow, Revs: revs, State: s})
}

func writeReset(t *testing.T, dir string, env []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, floorResetFile), env, 0o600); err != nil {
		t.Fatal(err)
	}
}

// epoch7Dir is a state dir holding the epoch-7 (generation 1) high-water.
func epoch7Dir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if _, err := verifyAndStore(t, dir, floorFixture(t, "epoch-7"), NoRevocations()); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestFloorReset: a floor-signed reset with a matching from_epoch lowers the
// high-water once; its replay, the pre-reset statement and a stale merge
// cannot raise it back; resets signed by another purpose, for another org or
// keyring, or otherwise invalid are ignored with a warning.
func TestFloorReset(t *testing.T) {
	dir := epoch7Dir(t)
	if _, applied, err := applyReset(t, dir, NoRevocations()); applied || err != nil {
		t.Fatal("no reset file:", applied, err)
	}
	writeReset(t, dir, floorFixture(t, "reset-7-to-2"))
	s, applied, err := applyReset(t, dir, NoRevocations())
	if !applied || err != nil {
		t.Fatal("reset:", applied, err)
	}
	resetAt := time.Date(2026, 10, 6, 2, 0, 0, 0, time.UTC)
	m := storedMark(t, dir)
	want := FloorMark{Generation: 1, Epoch: 2, IssuedAt: time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC), ResetIssuedAt: resetAt}
	if m.Generation != want.Generation || m.Epoch != want.Epoch || !m.IssuedAt.Equal(want.IssuedAt) ||
		!m.ResetIssuedAt.Equal(resetAt) || s.Floors["bobthecorp"].Epoch != 2 {
		t.Fatalf("after reset %+v, want %+v", m, want)
	}
	assertMode0600(t, dir)

	// The pre-reset epoch-7 statement cannot raise it back.
	if _, err := verifyAndStore(t, dir, floorFixture(t, "epoch-7"), NoRevocations()); err == nil ||
		!strings.Contains(err.Error(), "is not after the floor reset") {
		t.Fatalf("pre-reset statement: %v", err)
	}
	// Nor can a stale delta verified before the reset by another process.
	if _, err := UpdateState(dir, State{Floors: map[string]FloorMark{"bobthecorp": {Generation: 1, Epoch: 7,
		IssuedAt: time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)}}}); err != nil {
		t.Fatal(err)
	}
	if m := storedMark(t, dir); m.Epoch != 2 {
		t.Fatalf("stale merge raised the epoch to %d", m.Epoch)
	}
	// The replayed reset is a silent no-op.
	writeReset(t, dir, floorFixture(t, "reset-replay"))
	if _, applied, err := applyReset(t, dir, NoRevocations()); applied || err != nil {
		t.Fatal("replay:", applied, err)
	}
	// After the epoch climbs back to 7 with post-reset statements, the same
	// reset still does not apply again.
	post := sign(t, PayloadFloor, floorStatement(KeyringDigest(), func(p map[string]any) {
		p["issued_at"], p["expires_at"] = "2026-10-06T03:00:00Z", "2026-10-07T03:00:00Z"
	}), testkeys.Floor())
	if _, err := verifyAndStore(t, dir, post, NoRevocations()); err != nil {
		t.Fatal("post-reset statement:", err)
	}
	if _, applied, err := applyReset(t, dir, NoRevocations()); applied || err != nil || storedMark(t, dir).Epoch != 7 {
		t.Fatal("replay after climb-back:", applied, err, storedMark(t, dir))
	}
}

// TestFloorResetKeepsCallerState: the returned state keeps minimums the
// caller merged but did not persist, applied or not, and the epoch stays
// lowered.
func TestFloorResetKeepsCallerState(t *testing.T) {
	for _, file := range []string{"reset-7-to-2", "reset-wrong-org"} {
		t.Run(file, func(t *testing.T) {
			dir := epoch7Dir(t)
			writeReset(t, dir, floorFixture(t, file))
			s, err := LoadState(dir)
			if err != nil {
				t.Fatal(err)
			}
			if s, err = MergeState(s, State{Bundles: map[string]int64{"cis-aws": 99}}); err != nil {
				t.Fatal(err)
			}
			got, applied, err := ApplyFloorReset(dir, FloorInput{OrgID: "bobthecorp", Now: floorNow, Revs: NoRevocations(), State: s})
			wantEpoch := int64(7)
			if file == "reset-7-to-2" {
				wantEpoch = 2
				if !applied || err != nil {
					t.Fatal(applied, err)
				}
			}
			if got.Bundles["cis-aws"] != 99 || got.Floors["bobthecorp"].Epoch != wantEpoch {
				t.Fatalf("bundles %v, epoch %d, want 99 and %d", got.Bundles, got.Floors["bobthecorp"].Epoch, wantEpoch)
			}
		})
	}
}

// TestFloorResetChecksCallerState: the reset is checked against the on-disk
// state merged with the caller state, so a floor mark the caller accepted but
// could not persist (epoch 8) still makes a from_epoch 7 reset stale.
func TestFloorResetChecksCallerState(t *testing.T) {
	dir := epoch7Dir(t)
	writeReset(t, dir, floorFixture(t, "reset-7-to-2"))
	s, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	unsaved := State{Floors: map[string]FloorMark{"bobthecorp": {Generation: 1, Epoch: 8,
		IssuedAt: time.Date(2026, 10, 6, 1, 0, 0, 0, time.UTC)}}}
	if s, err = MergeState(s, unsaved); err != nil {
		t.Fatal(err)
	}
	got, applied, err := ApplyFloorReset(dir, FloorInput{OrgID: "bobthecorp", Now: floorNow, Revs: NoRevocations(), State: s})
	if applied || !errors.Is(err, ErrFloorResetIgnored) || !strings.Contains(err.Error(), "from_epoch 7 does not match the stored epoch 8") {
		t.Fatalf("applied %v, err %v: want ignored, from_epoch mismatch", applied, err)
	}
	if m := storedMark(t, dir); m.Epoch != 7 || !m.ResetIssuedAt.IsZero() {
		t.Fatalf("stored mark %+v: want epoch 7, no reset", m)
	}
	if got.Floors["bobthecorp"].Epoch != 8 {
		t.Fatalf("returned epoch %d, want 8", got.Floors["bobthecorp"].Epoch)
	}
}

func TestFloorResetIgnored(t *testing.T) {
	digest := KeyringDigest()
	reset := func(mut func(map[string]any)) []byte {
		return sign(t, PayloadFloorReset, floorResetPayload(digest, mut), testkeys.Floor())
	}
	set := func(k string, v any) func(map[string]any) { return func(p map[string]any) { p[k] = v } }
	cur := KIDFromSPKI(spki(t, testkeys.Floor()))
	cases := []struct {
		name string
		env  []byte
		revs Revocations
		want string
	}{
		{name: "profile key", env: floorFixture(t, "reset-profile-key"), want: "purpose"},
		{name: "wrong org", env: floorFixture(t, "reset-wrong-org"), want: `another org, not "bobthecorp"`},
		{name: "floor statement type", env: floorFixture(t, "epoch-7"), want: "payload"},
		{name: "wrong keyring", env: reset(set("keyring_digest", "sha256:"+strings.Repeat("0", 64))), want: "keyring"},
		{name: "from epoch mismatch", env: reset(set("from_epoch", 6)), want: "from_epoch 6 does not match the stored epoch 7"},
		{name: "raises", env: reset(set("to_epoch", 7)), want: "to_epoch"},
		{name: "expired", env: reset(func(p map[string]any) {
			p["issued_at"], p["expires_at"] = "2026-10-05T00:00:00Z", "2026-10-06T00:00:00Z"
		}), want: "expired"},
		{name: "lifetime", env: reset(set("expires_at", "2026-10-07T03:00:00Z")), want: "lifetime"},
		{name: "future", env: reset(func(p map[string]any) {
			p["issued_at"], p["expires_at"] = "2026-10-06T07:00:00Z", "2026-10-07T07:00:00Z"
		}), want: "future"},
		{name: "issued before the accepted statement", env: reset(func(p map[string]any) {
			p["issued_at"], p["expires_at"] = "2026-10-05T23:00:00Z", "2026-10-06T23:00:00Z"
		}), want: "is not after the accepted floor statement"},
		{name: "unknown field", env: reset(set("epoch", 2)), want: "wrong shape"},
		{name: "missing field", env: reset(func(p map[string]any) { delete(p, "to_epoch") }), want: "required"},
		{name: "missing revocation epoch", env: reset(func(p map[string]any) { delete(p, "revocation_epoch") }), want: "required"},
		{name: "negative revocation epoch", env: reset(set("revocation_epoch", -1)), want: "revocation_epoch"},
		{name: "revoked key", env: reset(nil), revs: revokeKeys(t, 4, cur), want: "key revoked"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := epoch7Dir(t)
			writeReset(t, dir, c.env)
			if !c.revs.valid {
				c.revs = NoRevocations()
			}
			_, applied, err := applyReset(t, dir, c.revs)
			if applied || !errors.Is(err, ErrFloorResetIgnored) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("applied %v, err %v, want ignored with %q", applied, err, c.want)
			}
			if m := storedMark(t, dir); m.Epoch != 7 || !m.ResetIssuedAt.IsZero() {
				t.Fatalf("ignored reset changed the mark: %+v", m)
			}
		})
	}
	t.Run("no high-water", func(t *testing.T) {
		dir := t.TempDir()
		writeReset(t, dir, reset(nil))
		if _, applied, err := applyReset(t, dir, NoRevocations()); applied || !errors.Is(err, ErrFloorResetIgnored) {
			t.Fatal(applied, err)
		}
	})
	t.Run("retired key", func(t *testing.T) {
		dir := t.TempDir()
		if _, err := verifyAndStore(t, dir, floorFixture(t, "airgap-epoch-8-revocation"), revokeKeys(t, 4, cur)); err != nil {
			t.Fatal(err)
		}
		writeReset(t, dir, reset(set("from_epoch", 8)))
		if _, applied, err := applyReset(t, dir, NoRevocations()); applied || !errors.Is(err, ErrFloorResetIgnored) ||
			!strings.Contains(err.Error(), "retired") {
			t.Fatal(applied, err)
		}
	})
	// A pending statement issued after the reset could raise the epoch back
	// once its revocations load, so the reset must be issued after it too.
	t.Run("issued before a pending statement", func(t *testing.T) {
		dir := epoch7Dir(t)
		pending := State{Floors: map[string]FloorMark{"bobthecorp": {Generation: 1, Epoch: 7,
			PendingIssuedAt: time.Date(2026, 10, 6, 3, 0, 0, 0, time.UTC)}}}
		if _, err := UpdateState(dir, pending); err != nil {
			t.Fatal(err)
		}
		writeReset(t, dir, reset(nil))
		if _, applied, err := applyReset(t, dir, NoRevocations()); applied || !errors.Is(err, ErrFloorResetIgnored) ||
			!strings.Contains(err.Error(), "is not after the accepted floor statement 2026-10-06T03:00:00Z") {
			t.Fatal(applied, err)
		}
	})
}

// TestFloorResetRevocationPending: a reset naming a revocation epoch above
// the merged revocations (state plus FloorInput.Revs) fails closed with
// ErrFloorRevocationPending and leaves the state alone; once the revocations
// catch up, from the caller or from the state, it applies.
func TestFloorResetRevocationPending(t *testing.T) {
	env := sign(t, PayloadFloorReset, floorResetPayload(KeyringDigest(), func(p map[string]any) {
		p["revocation_epoch"] = 4
	}), testkeys.Floor())
	for _, behind := range []Revocations{NoRevocations(), revokeKeys(t, 3)} {
		dir := epoch7Dir(t)
		writeReset(t, dir, env)
		s, applied, err := applyReset(t, dir, behind)
		if applied || !errors.Is(err, ErrFloorRevocationPending) || errors.Is(err, ErrFloorResetIgnored) {
			t.Fatalf("revocations at %d: applied %v, err %v: want ErrFloorRevocationPending", behind.Epoch(), applied, err)
		}
		if m := storedMark(t, dir); m.Epoch != 7 || !m.ResetIssuedAt.IsZero() || s.Floors["bobthecorp"].Epoch != 7 {
			t.Fatalf("pending reset changed the mark: %+v", m)
		}
	}
	t.Run("caller revocations catch up", func(t *testing.T) {
		dir := epoch7Dir(t)
		writeReset(t, dir, env)
		if _, applied, err := applyReset(t, dir, revokeKeys(t, 4)); !applied || err != nil || storedMark(t, dir).Epoch != 2 {
			t.Fatal(applied, err, storedMark(t, dir))
		}
	})
	t.Run("state revocations catch up", func(t *testing.T) {
		dir := epoch7Dir(t)
		if _, err := UpdateState(dir, State{Revocations: revokeKeys(t, 5)}); err != nil {
			t.Fatal(err)
		}
		writeReset(t, dir, env)
		if _, applied, err := applyReset(t, dir, NoRevocations()); !applied || err != nil || storedMark(t, dir).Epoch != 2 {
			t.Fatal(applied, err, storedMark(t, dir))
		}
	})
}

// TestFloorWrapperMinimumHighWater: the floor wrapper minimum is a high-water.
// A later, higher-epoch signed floor with a lower min_wrapper_version does
// not lower it, and a reset (which lowers only the epoch) does not either.
func TestFloorWrapperMinimumHighWater(t *testing.T) {
	dir := t.TempDir()
	floor := func(epoch int, issued, expires, minWrapper string) []byte {
		return sign(t, PayloadFloor, floorStatement(KeyringDigest(), func(p map[string]any) {
			p["epoch"], p["issued_at"], p["expires_at"], p["min_wrapper_version"] = epoch, issued, expires, minWrapper
		}), testkeys.Floor())
	}
	verify := func(env []byte, provider string) error {
		s, err := LoadState(dir)
		if err != nil {
			t.Fatal(err)
		}
		_, delta, err := VerifyFloor(env, FloorInput{OrgID: "bobthecorp", Mode: FloorAirgap, ProviderVersion: provider,
			Now: floorNow, Revs: NoRevocations(), State: s})
		if err == nil {
			if _, err := UpdateState(dir, delta); err != nil {
				t.Fatal(err)
			}
		}
		return err
	}
	if err := verify(floor(7, "2026-10-06T00:00:00Z", "2026-10-07T00:00:00Z", "1.5.0"), "2.0.0"); err != nil {
		t.Fatal(err)
	}
	if got := storedMark(t, dir).MinWrapperVersion; got != "1.5.0" {
		t.Fatalf("stored wrapper minimum %q, want 1.5.0", got)
	}
	lower := floor(8, "2026-10-06T01:00:00Z", "2026-10-07T01:00:00Z", "1.0.0")
	if err := verify(lower, "1.2.0"); err == nil || !strings.Contains(err.Error(), "below the org minimum 1.5.0") {
		t.Fatalf("provider 1.2.0 after a 1.5.0 floor: %v", err)
	}
	if err := verify(lower, "2.0.0"); err != nil {
		t.Fatal(err)
	}
	if m := storedMark(t, dir); m.Epoch != 8 || m.MinWrapperVersion != "1.5.0" {
		t.Fatalf("after the lower floor: epoch %d, wrapper minimum %q, want 8 and 1.5.0", m.Epoch, m.MinWrapperVersion)
	}
}
