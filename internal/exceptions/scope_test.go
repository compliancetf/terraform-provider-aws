package exceptions

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/hcl/v2"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

const scopeEntry = `exception "legacy-reporting-db" {
  controls  = ["rds_db_instance_encryption_at_rest_enabled"]
  match     = "type == 'aws_db_instance' && resource.identifier.matches('^legacy-')"
  workspace = "bobthecorp-reporting-prod"
  reason    = "Migration ticket OPS-4411"
  expires   = "2027-03-31"
  %s
}
%s
`

func scopeInput() SidecarInput {
	return SidecarInput{Now: time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC),
		Table: profile.ModeTable{
			Workspace:       profile.Dim{Value: "bobthecorp-reporting-prod", Source: "profile"},
			Exceptions:      &profile.Exceptions{MaxLifetimeDays: 365, SelfService: []string{rdsEnc}},
			SidecarControls: []string{rdsEnc},
		},
		Resolve: func(ref string) []string { return sidecarAliases[ref] }}
}

// TestSelfServiceScope (F12): self_service covers exceptions only; a
// sidecar carrying a baseline, quarantine, floor or run-key construct, as a
// block or an attribute at any depth, fails the load with self_service_scope.
// Any other unknown name still fails through strict decoding.
func TestSelfServiceScope(t *testing.T) {
	in := scopeInput()
	for _, f := range []string{"self_service_baseline_block", "self_service_floor_block"} {
		_, _, err := LoadSidecar(filepath.Join("testdata", "coverable", f+".hcl"), in)
		if !errors.Is(err, ErrSelfServiceScope) || !strings.Contains(err.Error(), "exceptions_file: self_service_scope: ") {
			t.Errorf("%s: %v", f, err)
		}
	}
	reserved := []string{"baseline", "baselines", "Base-Line", "BASELINE", "quarantine", "quarantine_clearing",
		"clear_quarantine", "floor", "floor_mode", "floor_statement", "run_key", "run-key", "run__key", "runkey", "run_keys"}
	for _, name := range reserved {
		for _, where := range []string{"top", "exception", "nested"} {
			for _, form := range []string{name + " {\n}", name + ` = "x"`, name + " = upper(\"x\")"} {
				src := placeScope(where, form)
				_, _, err := parseSidecar([]byte(src), "exceptions.hcl", in)
				if err == nil || !strings.Contains(err.Error(), "self_service_scope: "+name+" at exceptions.hcl:") {
					t.Errorf("%s in %s (%q): %v", name, where, form, err)
				}
			}
		}
	}
	// The earliest offender by source position is reported.
	src := placeScope("top", "run_key = \"a\"\nfloor = \"b\"\nbaseline = \"c\"")
	for range 20 {
		if _, _, err := parseSidecar([]byte(src), "exceptions.hcl", in); err == nil || !strings.Contains(err.Error(), "self_service_scope: run_key at") {
			t.Fatalf("first offender: %v", err)
		}
	}
	// Diagnostic only: other unknown names fail through strict decoding.
	for _, where := range []string{"top", "exception", "nested"} {
		for _, form := range []string{"waiver {\n}", `waiver = "x"`} {
			_, _, err := parseSidecar([]byte(placeScope(where, form)), "exceptions.hcl", in)
			if err == nil || errors.Is(err, ErrSelfServiceScope) || strings.Contains(err.Error(), "self_service_scope") {
				t.Errorf("unknown %q in %s: %v", form, where, err)
			}
		}
	}
	if err := selfServiceScope(hcl.EmptyBody()); err == nil {
		t.Error("a non-native body is not walked")
	}
	if sc, _, err := parseSidecar([]byte(placeScope("top", "")), "exceptions.hcl", in); err != nil || sc == nil {
		t.Errorf("valid sidecar: %v", err)
	}
}

// placeScope puts form at the top level, in the exception block or in a
// block nested in it.
func placeScope(where, form string) string {
	if where == "nested" {
		where, form = "exception", "notes {\n"+form+"\n}"
	}
	a := map[string]string{where: form}
	return fmt.Sprintf(scopeEntry, a["exception"], a["top"])
}

type coverableGolden struct {
	Declared  map[string][]bundle.ExemptionKind `json:"declared"`
	Coverable map[string][]string               `json:"coverable"`
	Modes     []string                          `json:"modes"`
	Kinds     map[string]bool                   `json:"kinds"`
	Warnings  []string                          `json:"warnings"`
}

// TestAirgapBreakGlassCoverable (F12): under floor_mode airgap, or
// any floor mode other than online or empty, break_glass is dropped from
// every list of the effective map with one warning per id; online keeps it.
func TestAirgapBreakGlassCoverable(t *testing.T) {
	for _, f := range []string{"airgap_break_glass_dropped", "online_break_glass_kept"} {
		b, err := os.ReadFile(filepath.Join("testdata", "coverable", f+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var g coverableGolden
		if err := json.Unmarshal(b, &g); err != nil {
			t.Fatal(err)
		}
		c, w := NewCoverability(g.Declared, &profile.Exceptions{Coverable: g.Coverable}, g.Modes...)
		for kind, want := range g.Kinds {
			if got := c.Coverable(rdsEnc, kind); got != want {
				t.Errorf("%s: Coverable(%s) = %v", f, kind, got)
			}
		}
		if !slices.Equal(w, g.Warnings) {
			t.Errorf("%s: warnings %q", f, w)
		}
	}

	declared := map[string][]bundle.ExemptionKind{
		"b_ctl": {bundle.CoverBreakGlass}, "a_ctl": {bundle.CoverBreakGlass, bundle.CoverGrant}, "forbidden": {bundle.CoverBreakGlass}, "plain": {bundle.CoverGrant}}
	ex := &profile.Exceptions{Coverable: map[string][]string{"a_ctl": {"break_glass"}}, ForbidControls: []string{"forbidden"}}
	airgapW := func(id string) string {
		return "break_glass coverability ignored for " + id + ": floor_mode airgap has no break-glass"
	}
	invalidW := func(id string) string {
		return "break_glass coverability ignored for " + id + `: floor_mode "bogus" is not online or airgap`
	}
	modes := []string{"", "online", "airgap", "bogus"}
	floorAt := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	local := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	floorState := trust.State{Floors: map[string]trust.FloorMark{"bobthecorp": {Generation: 1, Epoch: 1, IssuedAt: floorAt}}}
	for _, m1 := range modes {
		for _, m2 := range modes {
			c, w := NewCoverability(declared, ex, m1, m2)
			var want []string
			switch {
			case m1 == "bogus" || m2 == "bogus":
				want = []string{invalidW("a_ctl"), invalidW("b_ctl")}
			case m1 == "airgap" || m2 == "airgap":
				want = []string{airgapW("a_ctl"), airgapW("b_ctl")}
			}
			if kept := want == nil; c.Coverable("a_ctl", "break_glass") != kept || c.Coverable("b_ctl", "break_glass") != kept ||
				!c.Coverable("a_ctl", "grant") || !c.Coverable("plain", "grant") || c.Coverable("forbidden", "break_glass") {
				t.Errorf("modes %q %q: map %v", m1, m2, c.m)
			}
			if !slices.Equal(w, want) {
				t.Errorf("modes %q %q: warnings %q", m1, m2, w)
			}
			// The clock agrees: an invalid mode is unknown, never the local clock.
			at, why := NewClock(floorState, "bobthecorp", m1, m2).resolve(local)
			switch {
			case m1 == "bogus" || m2 == "bogus":
				if why == "" {
					t.Errorf("modes %q %q: clock known", m1, m2)
				}
			case want != nil:
				if !at.Equal(floorAt) {
					t.Errorf("modes %q %q: clock %v", m1, m2, at)
				}
			case !at.Equal(local):
				t.Errorf("modes %q %q: clock %v", m1, m2, at)
			}
		}
	}
	// Inputs are never mutated.
	if !slices.Equal(declared["a_ctl"], []bundle.ExemptionKind{bundle.CoverBreakGlass, bundle.CoverGrant}) ||
		!slices.Equal(ex.Coverable["a_ctl"], []string{"break_glass"}) {
		t.Error("inputs mutated")
	}
}
