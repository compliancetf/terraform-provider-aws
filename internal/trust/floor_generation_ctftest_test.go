//go:build ctftest

package trust

import (
	"errors"
	"strings"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/trust/testkeys"
)

// TestFloorGeneration is the floor generation high-water oracle:
// after gen1/epoch 7 the same statement and a gen1 epoch-7 re-issue are
// accepted; gen2/epoch 8 is accepted and stores generation 2; afterwards
// gen2/epoch 7 is refused. Errors are the ones Configure surfaces.
func TestFloorGeneration(t *testing.T) {
	dir := t.TempDir()
	steps := []struct {
		file          string
		gen, epoch    int64
		want          string // error substring; "" accepts
		markGen, mark int64  // stored (generation, epoch) afterwards
	}{
		{file: "gen1-epoch7", gen: 1, epoch: 7, markGen: 1, mark: 7},
		{file: "gen1-epoch7", gen: 1, epoch: 7, markGen: 1, mark: 7}, // read again by another process
		{file: "gen1-epoch7-reissue", gen: 1, epoch: 7, markGen: 1, mark: 7},
		{file: "gen2-epoch8", gen: 2, epoch: 8, markGen: 2, mark: 8},
		{file: "gen2-epoch7", want: "floor epoch 7 is below the accepted high-water 8 for bobthecorp", markGen: 2, mark: 8},
		{file: "gen2-epoch8", gen: 2, epoch: 8, markGen: 2, mark: 8},
	}
	for i, s := range steps {
		f, err := verifyAndStore(t, dir, floorFixture(t, s.file), NoRevocations())
		switch {
		case s.want != "" && (err == nil || !strings.Contains(err.Error(), s.want) || f != nil):
			t.Fatalf("step %d %s: floor %v, err %v, want %q", i, s.file, f, err, s.want)
		case s.want == "" && err != nil:
			t.Fatalf("step %d %s: %v", i, s.file, err)
		case s.want == "" && (f.Generation != s.gen || f.Epoch != s.epoch):
			t.Fatalf("step %d %s: floor (%d, %d), want (%d, %d)", i, s.file, f.Generation, f.Epoch, s.gen, s.epoch)
		}
		if m := storedMark(t, dir); m.Generation != s.markGen || m.Epoch != s.mark {
			t.Fatalf("step %d %s: stored (%d, %d), want (%d, %d)", i, s.file, m.Generation, m.Epoch, s.markGen, s.mark)
		}
	}
	assertMode0600(t, dir)
}

// TestFloorRetired: once generation 2 is accepted, a generation-1 statement
// at a newer epoch with a valid signature is refused, and so is a reset
// signed by the retired kid; a valid reset lowers the epoch but leaves the
// generation, so the retired key stays refused after it.
func TestFloorRetired(t *testing.T) {
	dir := t.TempDir()
	for _, file := range []string{"gen1-epoch7", "gen2-epoch8"} {
		if _, err := verifyAndStore(t, dir, floorFixture(t, file), NoRevocations()); err != nil {
			t.Fatal(file, err)
		}
	}
	old := KIDFromSPKI(spki(t, testkeys.Floor()))
	retired := "floor key " + old + " (generation 1) is retired for bobthecorp: accepted generation 2"
	if _, err := verifyAndStore(t, dir, floorFixture(t, "gen1-epoch9-after-gen2"), NoRevocations()); err == nil ||
		!strings.Contains(err.Error(), retired) {
		t.Fatalf("gen1 epoch 9 after gen2: %v", err)
	}

	writeReset(t, dir, floorFixture(t, "reset-retired-key"))
	if _, applied, err := applyReset(t, dir, NoRevocations()); applied || !errors.Is(err, ErrFloorResetIgnored) ||
		!strings.Contains(err.Error(), "floor key "+old+" (generation 1) is retired") {
		t.Fatalf("reset by retired kid: applied %v, err %v", applied, err)
	}
	if m := storedMark(t, dir); m.Generation != 2 || m.Epoch != 8 || !m.ResetIssuedAt.IsZero() {
		t.Fatalf("ignored reset changed the mark: %+v", m)
	}

	// A valid reset by the generation-2 key lowers the epoch only.
	digest := KeyringDigest()
	writeReset(t, dir, sign(t, PayloadFloorReset, floorResetPayload(digest, func(p map[string]any) {
		p["from_epoch"], p["issued_at"], p["expires_at"] = 8, "2026-10-06T03:30:00Z", "2026-10-07T03:30:00Z"
	}), testkeys.FloorNext()))
	if _, applied, err := applyReset(t, dir, NoRevocations()); !applied || err != nil {
		t.Fatal("valid reset:", applied, err)
	}
	if m := storedMark(t, dir); m.Generation != 2 || m.Epoch != 2 {
		t.Fatalf("after reset %+v: want generation 2, epoch 2", m)
	}
	post := func(key int, epoch int64, issued, expires string) []byte {
		signer := testkeys.Floor()
		if key == 2 {
			signer = testkeys.FloorNext()
		}
		return sign(t, PayloadFloor, floorStatement(digest, func(p map[string]any) {
			p["epoch"], p["issued_at"], p["expires_at"] = epoch, issued, expires
		}), signer)
	}
	// Issued after the reset, newer epoch, valid signature: still retired.
	if _, err := verifyAndStore(t, dir, post(1, 3, "2026-10-06T04:00:00Z", "2026-10-07T04:00:00Z"), NoRevocations()); err == nil ||
		!strings.Contains(err.Error(), retired) {
		t.Fatalf("gen1 after reset: %v", err)
	}
	f, err := verifyAndStore(t, dir, post(2, 3, "2026-10-06T04:30:00Z", "2026-10-07T04:30:00Z"), NoRevocations())
	if err != nil || f.Generation != 2 || f.Epoch != 3 {
		t.Fatalf("gen2 after reset: %v %v", f, err)
	}
	if m := storedMark(t, dir); m.Generation != 2 || m.Epoch != 3 {
		t.Fatalf("mark %+v: want generation 2, epoch 3", m)
	}
}
