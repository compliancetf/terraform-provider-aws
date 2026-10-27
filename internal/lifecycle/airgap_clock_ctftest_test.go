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

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/exceptions"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
	"github.com/compliancetf/terraform-provider-aws/internal/trust/testkeys"
)

const airgapClockSidecar = `
exception "legacy-reporting-db" {
  controls      = ["rds_db_instance_encryption_at_rest_enabled"]
  match         = "type == 'aws_db_instance' && resource.identifier.matches('^legacy-')"
  workspace = "bobthecorp-reporting-prod"
  reason    = "Migration ticket OPS-4411"
  expires   = "2026-10-06"
}
`

// legacyCtl is the control the airgap sidecar and grant name.
var legacyCtl = &bundle.Control{ID: "rds_db_instance_encryption_at_rest_enabled", Kind: bundle.KindResource, ResourceType: "aws_db_instance"}

// idSchemas is aws_db_instance with only identifier, the attribute the
// airgap selectors read.
type idSchemas struct{ dbSchemas }

func (idSchemas) Resource(typ string) (*tfprotov5.Schema, bool) {
	return &tfprotov5.Schema{Block: &tfprotov5.SchemaBlock{Attributes: []*tfprotov5.SchemaAttribute{
		{Name: "identifier", Type: tftypes.String, Optional: true}}}}, typ == "aws_db_instance"
}

// TestAirgapClockConfigure: Configure under floor_mode airgap hands
// the sidecar the stored floor issued_at, so plan-time Lookup gives the same
// result under any process clock; an airgap profile whose floor was skipped
// (not governed, no bundles) has no air-gap time and applies no entry. The
// floor is issued 2026-10-05T12:00Z and Configure runs at 2026-10-06T06:00Z,
// so the entry expiring 2026-10-06 applies only against the floor time.
// The profile also lists break_glass, dropped with a warning.
func TestAirgapClockConfigure(t *testing.T) {
	for _, tc := range []struct {
		name, profile, want string
	}{
		{"governed airgap", `{"governed": true}`, exceptions.StatusApplied},
		{"airgap floor skipped", `{"governed": false}`, exceptions.StatusRejected},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, k := range []string{"COMPLIANCETF_ENFORCEMENT_MODE", "COMPLIANCETF_GOVERNED", "COMPLIANCETF_OFFLINE", "COMPLIANCETF_TOKEN",
				"COMPLIANCETF_WORKSPACE", "COMPLIANCETF_BUNDLE_PATH", "COMPLIANCETF_MIN_BUNDLE_VERSION", "COMPLIANCETF_MIN_PROFILE_VERSION"} {
				t.Setenv(k, "")
			}
			t.Setenv("COMPLIANCETF_STATE_DIR", filepath.Join(dir, "state"))
			t.Setenv("COMPLIANCETF_CACHE_DIR", filepath.Join(dir, "cache"))
			t.Setenv("COMPLIANCETF_ORG_ID", "bobthecorp")
			t.Setenv("COMPLIANCETF_EVIDENCE_DIR", filepath.Join(dir, "evidence"))
			prof := filepath.Join(dir, "profile.dsse.json")
			over := merge(t, map[string]any{"floor_mode": "airgap", "scope": map[string]string{"workspace": "bobthecorp-reporting-prod"},
				"exceptions": map[string]any{"max_lifetime_days": 30, "self_service": []string{"rds_db_instance_encryption_at_rest_enabled"},
					"coverable": map[string][]string{"rds_db_instance_encryption_at_rest_enabled": {"break_glass", "self_service"}}}}, json.RawMessage(tc.profile))
			writeFile(t, prof, signed(t, trust.PayloadProfile, merge(t, baseProfile(), over), testkeys.Profile()))
			t.Setenv("COMPLIANCETF_PROFILE_PATH", prof)
			floor := filepath.Join(dir, "floor.dsse.json")
			writeFile(t, floor, signed(t, trust.PayloadFloor, merge(t, baseFloor(), json.RawMessage(`{"issued_at": "2026-10-05T12:00:00Z"}`)), testkeys.Floor()))
			t.Setenv("COMPLIANCETF_FLOOR_PATH", floor)
			side := filepath.Join(dir, "exceptions.hcl")
			writeFile(t, side, []byte(airgapClockSidecar))
			t.Setenv("COMPLIANCETF_EXCEPTIONS_FILE", side)

			l := New(Options{ProviderVersion: "6.40.0", Now: func() time.Time { return configureNow }})
			t.Cleanup(func() { _ = l.Close() }) //nolint:errcheck // test cleanup
			warns, err := l.Configure(context.Background(), tftypes.NewValue(BlockType(), nil), "1.14.0", nil)
			if err != nil {
				t.Fatal(err)
			}
			// air-gap has no break-glass; the profile-listed kind is dropped.
			const bg = "break_glass coverability ignored for rds_db_instance_encryption_at_rest_enabled: floor_mode airgap has no break-glass"
			if !slices.Contains(warns, bg) || l.Configured() == nil {
				t.Errorf("warnings %q, want %q", warns, bg)
			}
			// plan eligibility reads the post-drop map Configure kept.
			if cov := l.Configured().Coverability; cov.Coverable(legacyCtl.ID, "break_glass") || !cov.Coverable(legacyCtl.ID, "self_service") {
				t.Errorf("Configured.Coverability for %s: break_glass %v, self_service %v", legacyCtl.ID,
					cov.Coverable(legacyCtl.ID, "break_glass"), cov.Coverable(legacyCtl.ID, "self_service"))
			}
			// the drop is one value-free configure event.
			if ev := l.Configured().Events; !slices.Contains(ev, "break_glass_dropped") {
				t.Errorf("events %v, want break_glass_dropped", ev)
			}
			res := tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{"identifier": tftypes.String}},
				map[string]tftypes.Value{"identifier": tftypes.NewValue(tftypes.String, "legacy-reporting")})
			// A long deadline: these check statuses, not the 50 ms selector budget.
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			for _, local := range []time.Time{time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)} {
				d := l.Configured().Sidecar.Lookup(ctx, legacyCtl, idSchemas{}, &engine.Activation{Resource: res}, local)
				if d.Exception == nil || d.Exception.Status != tc.want {
					t.Errorf("process clock %s: %+v, want status %s", local.Format(time.DateOnly), d.Exception, tc.want)
				}
			}
		})
	}
}

// TestAirgapClockGrantConfigure: Configure hands the grant
// verifier the same exceptions clock as the sidecar, so under floor_mode
// airgap a grant expiring 2026-10-06T00:00Z verifies against the floor
// issued_at (2026-10-05T12:00Z) although Configure runs at 2026-10-06T06:00Z,
// and plan-time Lookup gives the same result under any process clock. An
// airgap profile whose floor was skipped has no air-gap time: no grant. A
// grant expired at the air-gap time (06:00Z) never applies, though a process
// clock of 2026-01-01 would still call it valid (E10, F7): apply
// then blocks the control whatever the verdict lists.
func TestAirgapClockGrantConfigure(t *testing.T) {
	for _, tc := range []struct {
		name, profile, expires string
		applied, unknown       bool
	}{
		{"governed airgap", `{"governed": true}`, "2026-10-06T00:00:00Z", true, false},
		{"airgap floor skipped", `{"governed": false}`, "2026-10-06T00:00:00Z", false, true},
		{"expired at the air-gap time", `{"governed": true}`, "2026-10-05T06:00:00Z", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, k := range []string{"COMPLIANCETF_ENFORCEMENT_MODE", "COMPLIANCETF_GOVERNED", "COMPLIANCETF_OFFLINE", "COMPLIANCETF_TOKEN",
				"COMPLIANCETF_WORKSPACE", "COMPLIANCETF_BUNDLE_PATH", "COMPLIANCETF_MIN_BUNDLE_VERSION", "COMPLIANCETF_MIN_PROFILE_VERSION",
				"COMPLIANCETF_EXCEPTIONS_FILE"} {
				t.Setenv(k, "")
			}
			t.Setenv("COMPLIANCETF_STATE_DIR", filepath.Join(dir, "state"))
			t.Setenv("COMPLIANCETF_CACHE_DIR", filepath.Join(dir, "cache"))
			t.Setenv("COMPLIANCETF_ORG_ID", "bobthecorp")
			t.Setenv("COMPLIANCETF_EVIDENCE_DIR", filepath.Join(dir, "evidence"))
			gk := customerGrantKey(t)
			prof := filepath.Join(dir, "profile.dsse.json")
			over := merge(t, map[string]any{"floor_mode": "airgap", "scope": map[string]string{"workspace": "bobthecorp-reporting-prod"},
				"exceptions": map[string]any{"max_lifetime_days": 30,
					"coverable": map[string][]string{"rds_db_instance_encryption_at_rest_enabled": {"grant"}},
					"grant_keys": []map[string]string{{"kid": gk.KID, "alg": gk.Alg, "spki_b64": gk.SPKIB64,
						"not_before": "2026-09-01T00:00:00Z", "not_after": "2026-10-30T00:00:00Z"}}}}, json.RawMessage(tc.profile))
			writeFile(t, prof, signed(t, trust.PayloadProfile, merge(t, baseProfile(), over), testkeys.Profile()))
			t.Setenv("COMPLIANCETF_PROFILE_PATH", prof)
			floor := filepath.Join(dir, "floor.dsse.json")
			writeFile(t, floor, signed(t, trust.PayloadFloor, merge(t, baseFloor(), json.RawMessage(`{"issued_at": "2026-10-05T12:00:00Z"}`)), testkeys.Floor()))
			t.Setenv("COMPLIANCETF_FLOOR_PATH", floor)
			configure := func() (*Lifecycle, []string) {
				l := New(Options{ProviderVersion: "6.40.0", Now: func() time.Time { return configureNow }})
				t.Cleanup(func() { _ = l.Close() }) //nolint:errcheck // test cleanup
				warns, err := l.Configure(context.Background(), tftypes.NewValue(BlockType(), nil), "1.14.0", nil)
				if err != nil {
					t.Fatal(err)
				}
				return l, warns
			}
			// the grant binds the content digest this Configure loads.
			first, _ := configure()
			c := first.Configured()
			cov, _ := exceptions.NewCoverability(c.Controls.Coverable(), c.Table.Exceptions)
			grants := filepath.Join(dir, "grants")
			sel := "type == 'aws_db_instance' && resource.identifier.matches('^legacy-')"
			p := grantPayload([]string{"rds_db_instance_encryption_at_rest_enabled"}, sel, tc.expires)
			p["content_digest"] = c.Controls.ContentDigest(cov.Kinds())
			if c.Floor != nil {
				p["floor_epoch"] = c.Floor.Epoch // at the high-water read from trust state
			}
			writeFile(t, filepath.Join(grants, "g.dsse.json"), grantEnvelope(t, p, testkeys.CustomerKMS()))
			t.Setenv("COMPLIANCETF_EXCEPTION_GRANTS", grants)
			l, warns := configure()
			unknown := slices.ContainsFunc(warns, func(w string) bool { return strings.Contains(w, exceptions.CodeAirgapTimeUnknown) })
			if tc.unknown != unknown || slices.ContainsFunc(warns, func(w string) bool { return tc.applied && strings.Contains(w, "grant") }) {
				t.Errorf("warnings %q", warns)
			}
			res := tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{"identifier": tftypes.String}},
				map[string]tftypes.Value{"identifier": tftypes.NewValue(tftypes.String, "legacy-reporting")})
			// A long deadline: these check statuses, not the 50 ms selector budget.
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			for _, local := range []time.Time{time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)} {
				d := l.Configured().Grants.Lookup(ctx, legacyCtl, idSchemas{}, &engine.Activation{Resource: res}, local)
				if d.Applied != tc.applied {
					t.Errorf("process clock %s: %+v", local.Format(time.DateOnly), d)
				}
			}
		})
	}
}

// TestAirgapClockIgnoresPendingFloor: a floor statement refused as
// revocation-pending never sets the air-gap time. After an accepted floor
// issued 2026-10-05T12:00Z and a pending one issued 2026-10-06T05:00Z, a run
// that skips the floor (not governed, no bundles) still times exceptions at
// the accepted issued_at, so the entry expiring 2026-10-06 applies.
func TestAirgapClockIgnoresPendingFloor(t *testing.T) {
	dir := t.TempDir()
	for _, k := range []string{"COMPLIANCETF_ENFORCEMENT_MODE", "COMPLIANCETF_GOVERNED", "COMPLIANCETF_OFFLINE", "COMPLIANCETF_TOKEN",
		"COMPLIANCETF_WORKSPACE", "COMPLIANCETF_BUNDLE_PATH", "COMPLIANCETF_MIN_BUNDLE_VERSION", "COMPLIANCETF_MIN_PROFILE_VERSION",
		"COMPLIANCETF_EXCEPTION_GRANTS"} {
		t.Setenv(k, "")
	}
	t.Setenv("COMPLIANCETF_STATE_DIR", filepath.Join(dir, "state"))
	t.Setenv("COMPLIANCETF_CACHE_DIR", filepath.Join(dir, "cache"))
	t.Setenv("COMPLIANCETF_ORG_ID", "bobthecorp")
	t.Setenv("COMPLIANCETF_EVIDENCE_DIR", filepath.Join(dir, "evidence"))
	side := filepath.Join(dir, "exceptions.hcl")
	writeFile(t, side, []byte(airgapClockSidecar))
	t.Setenv("COMPLIANCETF_EXCEPTIONS_FILE", side)
	prof, floor := filepath.Join(dir, "profile.dsse.json"), filepath.Join(dir, "floor.dsse.json")
	t.Setenv("COMPLIANCETF_PROFILE_PATH", prof)
	t.Setenv("COMPLIANCETF_FLOOR_PATH", floor)
	configure := func(profile, statement string) (*Lifecycle, error) {
		over := merge(t, map[string]any{"floor_mode": "airgap", "scope": map[string]string{"workspace": "bobthecorp-reporting-prod"},
			"exceptions": map[string]any{"max_lifetime_days": 30, "self_service": []string{"rds_db_instance_encryption_at_rest_enabled"},
				"coverable": map[string][]string{"rds_db_instance_encryption_at_rest_enabled": {"self_service"}}}}, json.RawMessage(profile))
		writeFile(t, prof, signed(t, trust.PayloadProfile, merge(t, baseProfile(), over), testkeys.Profile()))
		writeFile(t, floor, signed(t, trust.PayloadFloor, merge(t, baseFloor(), json.RawMessage(statement)), testkeys.Floor()))
		l := New(Options{ProviderVersion: "6.40.0", Now: func() time.Time { return configureNow }})
		t.Cleanup(func() { _ = l.Close() }) //nolint:errcheck // test cleanup
		_, err := l.Configure(context.Background(), tftypes.NewValue(BlockType(), nil), "1.14.0", nil)
		return l, err
	}
	if _, err := configure(`{"governed": true}`, `{"issued_at": "2026-10-05T12:00:00Z"}`); err != nil {
		t.Fatalf("accepted floor: %v", err)
	}
	const pending = `{"epoch": 2, "revocation_epoch": 99, "issued_at": "2026-10-06T05:00:00Z"}`
	if _, err := configure(`{"governed": true}`, pending); !errors.Is(err, trust.ErrFloorRevocationPending) {
		t.Fatalf("pending floor: %v, want ErrFloorRevocationPending", err)
	}
	l, err := configure(`{"governed": false}`, pending)
	if err != nil {
		t.Fatalf("floor skipped: %v", err)
	}
	res := tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{"identifier": tftypes.String}},
		map[string]tftypes.Value{"identifier": tftypes.NewValue(tftypes.String, "legacy-reporting")})
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	for _, local := range []time.Time{time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)} {
		d := l.Configured().Sidecar.Lookup(ctx, legacyCtl, idSchemas{}, &engine.Activation{Resource: res}, local)
		if d.Exception == nil || d.Exception.Status != exceptions.StatusApplied {
			t.Errorf("process clock %s: %+v, want the entry applied at the accepted floor time", local.Format(time.DateOnly), d.Exception)
		}
	}
}
