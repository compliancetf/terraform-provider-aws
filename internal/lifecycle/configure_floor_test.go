//go:build ctftest

package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/trust"
	"github.com/compliancetf/terraform-provider-aws/internal/trust/testkeys"
)

// TestFloorPendingKeepsHighWater: a floor whose revocation epoch is pending
// fails Configure but still persists its (generation, epoch) high-water, so
// replaying the older accepted floor afterwards fails.
func TestFloorPendingKeepsHighWater(t *testing.T) {
	for _, mode := range []string{trust.FloorOnline, trust.FloorAirgap} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			for _, k := range []string{"COMPLIANCETF_ENFORCEMENT_MODE", "COMPLIANCETF_GOVERNED", "COMPLIANCETF_OFFLINE",
				"COMPLIANCETF_ORG_ID", "COMPLIANCETF_BUNDLE_PATH", "COMPLIANCETF_MIN_BUNDLE_VERSION", "COMPLIANCETF_MIN_PROFILE_VERSION"} {
				t.Setenv(k, "")
			}
			t.Setenv("COMPLIANCETF_STATE_DIR", filepath.Join(dir, "state"))
			t.Setenv("COMPLIANCETF_CACHE_DIR", filepath.Join(dir, "cache"))
			t.Setenv("COMPLIANCETF_TOKEN", "")
			t.Setenv("COMPLIANCETF_ORG_ID", "bobthecorp")
			if mode == trust.FloorOnline {
				t.Setenv("COMPLIANCETF_TOKEN", "t")
			}
			prof := filepath.Join(dir, "profile.dsse.json")
			writeFile(t, prof, signed(t, trust.PayloadProfile,
				merge(t, baseProfile(), json.RawMessage(`{"governed": true, "floor_mode": "`+mode+`"}`)), testkeys.Profile()))
			t.Setenv("COMPLIANCETF_PROFILE_PATH", prof)
			t.Setenv("COMPLIANCETF_EVIDENCE_DIR", filepath.Join(dir, "evidence"))

			step := func(over string) error {
				env := signed(t, trust.PayloadFloor, merge(t, baseFloor(), json.RawMessage(over)), testkeys.Floor())
				path := filepath.Join(dir, "floor.dsse.json")
				writeFile(t, path, env)
				if mode == trust.FloorAirgap {
					t.Setenv("COMPLIANCETF_FLOOR_PATH", path)
				} else {
					serve(t, map[string]string{}, env)
				}
				block := tftypes.NewValue(BlockType(), nil)
				l := New(Options{ProviderVersion: "6.40.0", Now: func() time.Time { return configureNow }})
				_, err := l.Configure(context.Background(), block, "1.14.0", nil)
				_ = l.Close() //nolint:errcheck // test cleanup
				return err
			}
			const epoch7 = `{"epoch": 7, "issued_at": "2026-10-06T01:00:00Z"}`
			if err := step(epoch7); err != nil {
				t.Fatalf("epoch 7: %v", err)
			}
			err := step(`{"epoch": 8, "revocation_epoch": 99, "issued_at": "2026-10-06T02:00:00Z"}`)
			if !errors.Is(err, trust.ErrFloorRevocationPending) {
				t.Fatalf("epoch 8 pending: %v, want ErrFloorRevocationPending", err)
			}
			s, err := trust.LoadState(filepath.Join(dir, "state"))
			if err != nil {
				t.Fatal(err)
			}
			if m := s.Floors["bobthecorp"]; m.Epoch != 8 || m.RevocationEpoch != 0 {
				t.Errorf("high-water %+v, want epoch 8 and revocation epoch 0", m)
			}
			if err := step(epoch7); err == nil || !strings.Contains(err.Error(), "below the accepted high-water") {
				t.Fatalf("epoch 7 replay: %v, want rollback rejected", err)
			}
		})
	}
}

// TestFloorResetConfigure: Configure applies $STATE_DIR/floor-reset.dsse.json
// before the floor statement (spec Floor statement). An
// applied reset lowers the epoch so a reissued lower floor loads and records
// event floor_reset; a reset whose revocation epoch is pending fails
// Configure with the state unchanged; an ignored reset warns and continues.
func TestFloorResetConfigure(t *testing.T) {
	setup := func(t *testing.T) (dir string, step func(floor string) (*Lifecycle, []string, error)) {
		dir = t.TempDir()
		for _, k := range []string{"COMPLIANCETF_ENFORCEMENT_MODE", "COMPLIANCETF_GOVERNED", "COMPLIANCETF_OFFLINE", "COMPLIANCETF_TOKEN",
			"COMPLIANCETF_BUNDLE_PATH", "COMPLIANCETF_MIN_BUNDLE_VERSION", "COMPLIANCETF_MIN_PROFILE_VERSION"} {
			t.Setenv(k, "")
		}
		t.Setenv("COMPLIANCETF_STATE_DIR", filepath.Join(dir, "state"))
		t.Setenv("COMPLIANCETF_CACHE_DIR", filepath.Join(dir, "cache"))
		t.Setenv("COMPLIANCETF_ORG_ID", "bobthecorp")
		t.Setenv("COMPLIANCETF_EVIDENCE_DIR", filepath.Join(dir, "evidence"))
		prof := filepath.Join(dir, "profile.dsse.json")
		writeFile(t, prof, signed(t, trust.PayloadProfile,
			merge(t, baseProfile(), json.RawMessage(`{"governed": true, "floor_mode": "airgap"}`)), testkeys.Profile()))
		t.Setenv("COMPLIANCETF_PROFILE_PATH", prof)
		path := filepath.Join(dir, "floor.dsse.json")
		t.Setenv("COMPLIANCETF_FLOOR_PATH", path)
		step = func(floor string) (*Lifecycle, []string, error) {
			writeFile(t, path, signed(t, trust.PayloadFloor, merge(t, baseFloor(), json.RawMessage(floor)), testkeys.Floor()))
			l := New(Options{ProviderVersion: "6.40.0", Now: func() time.Time { return configureNow }})
			t.Cleanup(func() { _ = l.Close() }) //nolint:errcheck // test cleanup
			warns, err := l.Configure(context.Background(), tftypes.NewValue(BlockType(), nil), "1.14.0", nil)
			return l, warns, err
		}
		if _, _, err := step(`{"epoch": 7, "issued_at": "2026-10-06T01:00:00Z"}`); err != nil {
			t.Fatalf("epoch 7: %v", err)
		}
		return dir, step
	}
	reset := func(t *testing.T, dir, over string) {
		base := map[string]any{"format": "compliancetf.floor-reset/v1", "org_id": "bobthecorp", "keyring_digest": trust.KeyringDigest(),
			"from_epoch": 7, "to_epoch": 2, "revocation_epoch": 0, "issued_at": "2026-10-06T02:00:00Z", "expires_at": "2026-10-07T02:00:00Z"}
		writeFile(t, filepath.Join(dir, "state", "floor-reset.dsse.json"),
			signed(t, trust.PayloadFloorReset, merge(t, base, json.RawMessage(over)), testkeys.Floor()))
	}
	epoch := func(t *testing.T, dir string) int64 {
		s, err := trust.LoadState(filepath.Join(dir, "state"))
		if err != nil {
			t.Fatal(err)
		}
		return s.Floors["bobthecorp"].Epoch
	}
	const epoch2 = `{"epoch": 2, "issued_at": "2026-10-06T03:00:00Z"}`

	t.Run("applied", func(t *testing.T) {
		dir, step := setup(t)
		reset(t, dir, `{}`)
		l, _, err := step(epoch2)
		if err != nil {
			t.Fatalf("epoch 2 after reset: %v", err)
		}
		if ev := l.Configured().Events; !slices.Contains(ev, "floor_reset") || ev[0] != "bundle_loaded" {
			t.Errorf("events %v, want bundle_loaded first and floor_reset", ev)
		}
		if e := epoch(t, dir); e != 2 {
			t.Errorf("epoch %d, want 2", e)
		}
		// The consumed reset stays on disk and is silent: no second event.
		l, _, err = step(epoch2)
		if err != nil || slices.Contains(l.Configured().Events, "floor_reset") {
			t.Fatalf("replayed reset: err %v, events %v", err, l.Configured().Events)
		}
	})
	// A reset applies, then the floor statement is revocation-pending: the
	// pending delta is persisted without undoing the reset marker, and
	// Configure fails (the reset stays applied; no configure record).
	t.Run("applied then floor pending", func(t *testing.T) {
		dir, step := setup(t)
		reset(t, dir, `{}`)
		if _, _, err := step(`{"epoch": 3, "revocation_epoch": 99, "issued_at": "2026-10-06T03:00:00Z"}`); !errors.Is(err, trust.ErrFloorRevocationPending) ||
			!strings.Contains(err.Error(), "floor reset for bobthecorp was applied") {
			t.Fatalf("pending floor after reset: %v, want ErrFloorRevocationPending", err)
		}
		s, err := trust.LoadState(filepath.Join(dir, "state"))
		if err != nil {
			t.Fatal(err)
		}
		m := s.Floors["bobthecorp"]
		if want := time.Date(2026, 10, 6, 2, 0, 0, 0, time.UTC); m.Epoch != 3 || !m.ResetIssuedAt.Equal(want) || m.RevocationEpoch != 0 {
			t.Errorf("mark %+v, want epoch 3, reset marker %s, revocation epoch 0", m, want)
		}
	})
	// a reset applied in runs that then fail is recorded by the
	// next successful Configure, exactly once, and the unrecorded flag is
	// cleared; repeated failures write no record.
	t.Run("applied then failed then recorded once", func(t *testing.T) {
		dir, step := setup(t)
		reset(t, dir, `{}`)
		resets := func() int {
			n := 0
			for _, r := range readChain(t, filepath.Join(dir, "evidence")) {
				if r.Event == "floor_reset" {
					n++
				}
			}
			return n
		}
		flag := func() bool {
			s, err := trust.LoadState(filepath.Join(dir, "state"))
			if err != nil {
				t.Fatal(err)
			}
			return s.Floors["bobthecorp"].ResetUnrecorded
		}
		for _, f := range []string{`{"epoch": 3, "revocation_epoch": 99, "issued_at": "2026-10-06T03:00:00Z"}`,
			`{"epoch": 4, "revocation_epoch": 99, "issued_at": "2026-10-06T03:30:00Z"}`} {
			if _, _, err := step(f); !errors.Is(err, trust.ErrFloorRevocationPending) {
				t.Fatalf("pending floor: %v", err)
			}
			if n := resets(); n != 0 || !flag() {
				t.Fatalf("after failed run: %d floor_reset records, flag %v; want 0 and set", n, flag())
			}
		}
		l, _, err := step(`{"epoch": 4, "issued_at": "2026-10-06T04:00:00Z"}`)
		if err != nil {
			t.Fatalf("recovered floor: %v", err)
		}
		if !slices.Contains(l.Configured().Events, "floor_reset") {
			t.Errorf("events %v, want floor_reset", l.Configured().Events)
		}
		_ = l.Close() //nolint:errcheck // flush the chain before reading it
		if n := resets(); n != 1 || flag() {
			t.Fatalf("after success: %d floor_reset records, flag %v; want 1 and cleared", n, flag())
		}
		l, _, err = step(`{"epoch": 4, "issued_at": "2026-10-06T04:00:00Z"}`)
		if err != nil || slices.Contains(l.Configured().Events, "floor_reset") {
			t.Fatalf("next run: err %v, events %v; want no floor_reset", err, l.Configured().Events)
		}
		_ = l.Close() //nolint:errcheck // flush
		if n := resets(); n != 1 {
			t.Errorf("%d floor_reset records, want 1", n)
		}
	})
	t.Run("pending", func(t *testing.T) {
		dir, step := setup(t)
		reset(t, dir, `{"revocation_epoch": 99}`)
		if _, _, err := step(epoch2); !errors.Is(err, trust.ErrFloorRevocationPending) {
			t.Fatalf("pending reset: %v, want ErrFloorRevocationPending", err)
		}
		if e := epoch(t, dir); e != 7 {
			t.Errorf("epoch %d, want 7 unchanged", e)
		}
	})
	t.Run("ignored", func(t *testing.T) {
		dir, step := setup(t)
		reset(t, dir, `{"from_epoch": 6}`)
		l, warns, err := step(`{"epoch": 7, "issued_at": "2026-10-06T01:00:00Z"}`)
		if err != nil {
			t.Fatalf("ignored reset: %v", err)
		}
		if !slices.ContainsFunc(warns, func(w string) bool { return strings.Contains(w, "floor reset ignored") }) {
			t.Errorf("warnings %q, want floor reset ignored", warns)
		}
		if slices.Contains(l.Configured().Events, "floor_reset") || epoch(t, dir) != 7 {
			t.Errorf("events %v epoch %d, want no floor_reset and epoch 7", l.Configured().Events, epoch(t, dir))
		}
	})
}
