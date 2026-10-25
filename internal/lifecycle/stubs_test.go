package lifecycle

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/baseline"
	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
)

// TestStubsGrandfatherActsAsHardFail: without a baseline file, or without a
// verdict entry, nothing is grandfathered, so every severity cell of
// grandfather equals hard_fail.
func TestStubsGrandfatherActsAsHardFail(t *testing.T) {
	ctl := &bundle.Control{ID: "cis_aws_s3_1"}
	if grandfathered(nil, ctl, baseline.Instance{}) || grandfathered(&Configured{}, ctl, baseline.Instance{Refreshed: "true"}) {
		t.Fatal("no baseline grandfathered a violation")
	}
	for stage, ops := range stageOps {
		for _, op := range ops {
			for _, a := range []bundle.Action{bundle.ActionDeny, bundle.ActionWarn} {
				for _, s := range []engine.State{engine.Pass, engine.Fail, engine.Unknown, engine.NotEvaluable} {
					g := Classify(profile.Grandfather, a, s, stage, op, false)
					h := Classify(profile.HardFail, a, s, stage, op, false)
					if g != h {
						t.Errorf("%s/%s/%s/%s: grandfather %+v, hard_fail %+v", stage, op, a, s, g, h)
					}
				}
			}
		}
	}
	// A grandfathered violation only stops blocking under grandfather mode.
	if !Blocking(profile.HardFail, bundle.ActionDeny, true) || Blocking(profile.Grandfather, bundle.ActionDeny, true) {
		t.Error("grandfathered: hard_fail must block, grandfather must not")
	}
}

// TestStubsBreakGlassFailsConfigure: any COMPLIANCETF_BREAK_GLASS value, even
// empty, fails Configure before anything is loaded or fetched.
func TestStubsBreakGlassFailsConfigure(t *testing.T) {
	for _, v := range []string{"receipt.json", ""} {
		t.Setenv("COMPLIANCETF_BREAK_GLASS", v)
		t.Setenv("COMPLIANCETF_STATE_DIR", t.TempDir())
		t.Setenv("COMPLIANCETF_CACHE_DIR", t.TempDir())
		l := New(Options{ProviderVersion: "6.40.0"})
		_, err := l.Configure(context.Background(), tftypes.NewValue(BlockType(), nil), "1.14.0", nil)
		if err == nil || !strings.Contains(err.Error(), "COMPLIANCETF_BREAK_GLASS is set, but this provider version cannot verify break-glass overrides. Unset it or upgrade.") {
			t.Errorf("%q: err %v", v, err)
		}
		if l.Configured() != nil {
			t.Errorf("%q: Configure succeeded", v)
		}
	}
}

// TestPhase3Warnings: an enabled break_glass whose
// policy rules every receipt out is named, with why, in a Configure warning,
// never silently dropped; a disabled break_glass, an online break_glass, a
// verdict and a baseline need none.
func TestPhase3Warnings(t *testing.T) {
	if w := phase3Warnings(nil, profile.FloorOnline); w != nil {
		t.Fatalf("no profile: %v", w)
	}
	if w := phase3Warnings(&profile.Profile{BreakGlass: &profile.BreakGlass{}}, profile.FloorOnline); w != nil {
		t.Fatalf("disabled break_glass: %v", w)
	}
	w := phase3Warnings(&profile.Profile{Verdict: &profile.Verdict{}, Baseline: &profile.Baseline{}, BreakGlass: &profile.BreakGlass{Enabled: true}}, profile.FloorOnline)
	if len(w) != 1 || !strings.Contains(w[0], "no break-glass receipt can be honored: the profile lists no break_glass.receipt_keys") {
		t.Fatalf("warnings %q", w)
	}
	keys := []profile.SignerKey{{KID: "sha256:" + strings.Repeat("a", 64)}}
	if w := phase3Warnings(&profile.Profile{BreakGlass: &profile.BreakGlass{Enabled: true, ReceiptKeys: keys}}, profile.FloorAirgap); len(w) != 1 ||
		!strings.Contains(w[0], "no break-glass receipt can be honored: the floor was not obtained online") {
		t.Errorf("airgap floor: warnings %q", w)
	}
	if w := phase3Warnings(&profile.Profile{BreakGlass: &profile.BreakGlass{Enabled: true, ReceiptKeys: keys}}, profile.FloorOnline); w != nil {
		t.Errorf("online break_glass: warnings %q, want none", w)
	}
}
