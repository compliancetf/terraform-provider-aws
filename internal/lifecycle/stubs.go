package lifecycle

// Stubs that fail closed for profile settings this version cannot honor.

import (
	"errors"
	"os"
	"sync/atomic"

	"github.com/compliancetf/terraform-provider-aws/internal/baseline"
	"github.com/compliancetf/terraform-provider-aws/internal/breakglass"
	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
)

// Baseline decides whether a violation predates the org baseline: the
// signed baseline matcher, *baseline.Set, loaded at Configure.
type Baseline interface {
	Grandfathered(ctl *bundle.Control, in baseline.Instance) baseline.Decision
}

var _ Baseline = (*baseline.Set)(nil)

// grandfathered is the baseline decision for ctl on in; a nil snapshot or
// no baseline file grandfathers nothing. Only apply_pre with exactly one
// matched verdict entry, and the apply_post of that RPC, pass a
// filled in; every other caller passes the zero Instance, which never
// matches.
func grandfathered(c *Configured, ctl *bundle.Control, in baseline.Instance) bool {
	return baselineDecision(c, ctl, in).Grandfathered
}

// baselineDecision is the baseline match for ctl on in; none without a
// snapshot or baseline.
func baselineDecision(c *Configured, ctl *bundle.Control, in baseline.Instance) baseline.Decision {
	if c == nil || c.Baseline == nil {
		return baseline.Decision{}
	}
	return c.Baseline.Grandfathered(ctl, in)
}

// grandfatherWarned makes the grandfather warning once per process.
var grandfatherWarned atomic.Bool

// grandfatherWarning returns the no-baseline warning the first time, per
// process, that the run mode or a control floor resolves to grandfather
// and no baseline file is loaded.
func grandfatherWarning(t profile.ModeTable, loaded bool) []string {
	used := t.RunMode == profile.Grandfather
	for _, m := range t.ControlFloors {
		used = used || m == profile.Grandfather && t.RunMode < profile.HardFail
	}
	if !used || loaded || !grandfatherWarned.CompareAndSwap(false, true) {
		return nil
	}
	return []string{"grandfather mode without a baseline file: every violation is treated as new"}
}

// checkBreakGlass fails Configure when COMPLIANCETF_BREAK_GLASS is set, to any
// value, even empty: this version cannot verify a break-glass receipt.
func checkBreakGlass() error {
	if _, set := os.LookupEnv("COMPLIANCETF_BREAK_GLASS"); set {
		return errors.New("COMPLIANCETF_BREAK_GLASS is set, but this provider version cannot verify break-glass overrides. Unset it or upgrade.") //nolint:staticcheck // spec text
	}
	return nil
}

// phase3Warnings names each verdict, baseline or break_glass profile
// setting this version loads but cannot honor. Not honoring one never relaxes enforcement: no
// break-glass receipt is honored when the policy rules every receipt out, so
// the setting is reported (with why) instead of rejecting the profile; with
// an online policy receipts are verified at apply and need no line.
// Verdict entries are matched and the baseline is matched to them, and the
// verdict check honors revoked_kids, so none needs a line.
// floorMode is the mode the floor was obtained in.
func phase3Warnings(p *profile.Profile, floorMode string) []string {
	if p == nil {
		return nil
	}
	var w []string
	if p.BreakGlass != nil && p.BreakGlass.Enabled {
		if why := (breakglass.Policy{Profile: p, FloorMode: floorMode}).Unavailable(); why != "" {
			w = append(w, "Profile enables break_glass, but no break-glass receipt can be honored: "+why+".")
		}
	}
	return w
}
