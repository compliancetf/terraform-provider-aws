//go:build ctftest

package trust

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/trust/testkeys"
)

// Retired kids of floor keys no longer compiled in (generations below 1).
var (
	oldKidA = "sha256:" + strings.Repeat("1", 64)
	oldKidB = "sha256:" + strings.Repeat("2", 64)
)

// floorAcceptanceVectors are the Floor acceptance (F11) fixtures, signed by
// the generation 1 ctftest floor key.
func floorAcceptanceVectors() map[string]func(map[string]any) {
	at := func(epoch int64, issued, expires string, retired ...string) func(map[string]any) {
		return func(p map[string]any) {
			p["epoch"], p["issued_at"], p["expires_at"], p["retired_keys"] = epoch, issued, expires, retired
		}
	}
	return map[string]func(map[string]any){
		"retired-set-superset":       at(7, "2026-10-06T01:00:00Z", "2026-10-07T01:00:00Z", oldKidA, oldKidB),
		"retired-set-dropped":        at(8, "2026-10-06T01:00:00Z", "2026-10-07T01:00:00Z", oldKidB),
		"retired-kid-current-gen":    at(8, "2026-10-06T01:00:00Z", "2026-10-07T01:00:00Z", oldKidA),
		"issued-earlier-same-epoch":  at(7, "2026-10-05T23:00:00Z", "2026-10-06T23:00:00Z", oldKidA),
		"issued-earlier-newer-epoch": at(8, "2026-10-05T23:00:00Z", "2026-10-06T23:00:00Z", oldKidA),
		"airgap-time-monotonic":      at(7, "2027-03-01T00:00:00Z", "2027-03-08T00:00:00Z", oldKidA),
	}
}

// TestGenerateFloorAcceptanceVectors writes only the F11 fixtures, so the
// other floor vectors keep their bytes. Run with
// -tags ctftest -run TestGenerateFloorAcceptanceVectors -update.
func TestGenerateFloorAcceptanceVectors(t *testing.T) {
	if !*update {
		t.Skip("run with -tags ctftest -update to regenerate")
	}
	digest := ctftestKeyringDigest(t)
	for name, mut := range floorAcceptanceVectors() {
		env := sign(t, PayloadFloor, floorStatement(digest, mut), testkeys.Floor())
		if err := os.WriteFile(filepath.Join("testdata", "floor", name+".dsse.json"), append(env, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// f11Dir is a state dir holding the generation 1, epoch 7 high-water issued
// 2026-10-06T00:00Z with the given retired kids.
func f11Dir(t *testing.T, retired ...string) string {
	t.Helper()
	dir := t.TempDir()
	if _, err := UpdateState(dir, State{Floors: map[string]FloorMark{"bobthecorp": {Generation: 1, Epoch: 7,
		IssuedAt: time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC), RetiredKeys: retired}}}); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestFloorAcceptanceFixtures is the Floor acceptance (F11) oracle: a
// statement dropping a stored retired kid, or issued earlier than the stored
// issued_at (same or newer epoch), is refused with its error; a kid in the
// stored retired_keys is refused at the current generation; a superset is
// accepted. A refused statement leaves the high-water unchanged.
func TestFloorAcceptanceFixtures(t *testing.T) {
	cur := KIDFromSPKI(spki(t, testkeys.Floor()))
	cases := []struct {
		file    string
		retired []string
		want    string
	}{
		{"retired-set-superset", []string{oldKidA}, ""},
		{"retired-set-dropped", []string{oldKidA}, "floor statement for bobthecorp drops retired key " + oldKidA},
		{"retired-kid-current-gen", []string{oldKidA, cur}, "floor key " + cur + " (generation 1) is retired for bobthecorp: accepted generation 1"},
		{"issued-earlier-same-epoch", []string{oldKidA}, "floor statement for bobthecorp issued 2026-10-05T23:00:00Z is earlier than the accepted 2026-10-06T00:00:00Z"},
		{"issued-earlier-newer-epoch", []string{oldKidA}, "floor statement for bobthecorp issued 2026-10-05T23:00:00Z is earlier than the accepted 2026-10-06T00:00:00Z"},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			dir := f11Dir(t, c.retired...)
			before := storedMark(t, dir)
			_, err := verifyAndStore(t, dir, floorFixture(t, c.file), NoRevocations())
			after := storedMark(t, dir)
			if c.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				if !slices.Equal(after.RetiredKeys, []string{oldKidA, oldKidB}) || after.Epoch != 7 ||
					!after.IssuedAt.Equal(time.Date(2026, 10, 6, 1, 0, 0, 0, time.UTC)) {
					t.Fatalf("accepted mark %+v", after)
				}
				return
			}
			if err == nil || err.Error() != c.want {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
			if after.Epoch != before.Epoch || !after.IssuedAt.Equal(before.IssuedAt) || !slices.Equal(after.RetiredKeys, before.RetiredKeys) {
				t.Fatalf("refused statement moved the mark: %+v -> %+v", before, after)
			}
		})
	}
}

// TestAirgapTime: the air-gap time (stored issued_at) is the maximum
// accepted issued_at and never moves back: not through an earlier file, a
// stale merge from another process, nor a floor reset.
func TestAirgapTime(t *testing.T) {
	now := time.Date(2027, 3, 1, 18, 0, 0, 0, time.UTC)
	t0 := time.Date(2027, 3, 1, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(12 * time.Hour)
	dir := t.TempDir()
	store := func(env []byte) error {
		t.Helper()
		s, err := LoadState(dir)
		if err != nil {
			t.Fatal(err)
		}
		_, delta, err := VerifyFloor(env, FloorInput{OrgID: "bobthecorp", Mode: FloorAirgap, ProviderVersion: "2.0.0",
			Now: now, Revs: NoRevocations(), State: s})
		if delta.Floors != nil {
			if _, uerr := UpdateState(dir, delta); uerr != nil {
				t.Fatal(uerr)
			}
		}
		return err
	}
	airgapTime := func(want time.Time, step string) {
		t.Helper()
		if got := storedMark(t, dir).IssuedAt; !got.Equal(want) {
			t.Fatalf("%s: air-gap time %s, want %s", step, got, want)
		}
	}
	if err := store(floorFixture(t, "airgap-time-monotonic")); err != nil {
		t.Fatal(err)
	}
	airgapTime(t0, "first file")

	// An accepted re-issue (same epoch, later issued_at) advances it.
	reissue := sign(t, PayloadFloor, floorStatement(KeyringDigest(), func(p map[string]any) {
		p["issued_at"], p["expires_at"], p["retired_keys"] = "2027-03-01T12:00:00Z", "2027-03-08T12:00:00Z", []string{oldKidA}
	}), testkeys.Floor())
	if err := store(reissue); err != nil {
		t.Fatal(err)
	}
	airgapTime(t1, "re-issue")

	// The first file again is refused and does not move it back.
	if err := store(floorFixture(t, "airgap-time-monotonic")); err == nil || !strings.Contains(err.Error(), "is earlier than the accepted 2027-03-01T12:00:00Z") {
		t.Fatalf("earlier file: %v", err)
	}
	airgapTime(t1, "earlier file")

	// A stale delta merged by another process does not move it back.
	if _, err := UpdateState(dir, State{Floors: map[string]FloorMark{"bobthecorp": {Generation: 1, Epoch: 7, IssuedAt: t0}}}); err != nil {
		t.Fatal(err)
	}
	airgapTime(t1, "stale merge")

	// A reset lowers the epoch only.
	writeReset(t, dir, sign(t, PayloadFloorReset, floorResetPayload(KeyringDigest(), func(p map[string]any) {
		p["issued_at"], p["expires_at"] = "2027-03-01T13:00:00Z", "2027-03-02T13:00:00Z"
	}), testkeys.Floor()))
	s, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, applied, err := ApplyFloorReset(dir, FloorInput{OrgID: "bobthecorp", Mode: FloorAirgap, ProviderVersion: "2.0.0",
		Now: now, Revs: NoRevocations(), State: s}); !applied || err != nil {
		t.Fatal("reset:", applied, err)
	}
	if m := storedMark(t, dir); m.Epoch != 2 {
		t.Fatalf("reset epoch %d", m.Epoch)
	}
	airgapTime(t1, "reset")
}

// TestFloorResetKeepsIssuedAndRetired: a reset sets the epoch only; the
// stored issued_at (air-gap time) and retired_keys stay.
func TestFloorResetKeepsIssuedAndRetired(t *testing.T) {
	dir := f11Dir(t, oldKidA)
	if _, err := verifyAndStore(t, dir, floorFixture(t, "retired-set-superset"), NoRevocations()); err != nil {
		t.Fatal(err)
	}
	before := storedMark(t, dir)
	writeReset(t, dir, floorFixture(t, "reset-7-to-2"))
	if _, applied, err := applyReset(t, dir, NoRevocations()); !applied || err != nil {
		t.Fatal("reset:", applied, err)
	}
	after := storedMark(t, dir)
	if after.Epoch != 2 || after.Generation != before.Generation || !after.IssuedAt.Equal(before.IssuedAt) ||
		!slices.Equal(after.RetiredKeys, []string{oldKidA, oldKidB}) {
		t.Fatalf("reset changed more than the epoch: %+v -> %+v", before, after)
	}
}
