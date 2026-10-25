package lifecycle

import (
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/bundlegen"
)

// TestInRange: only ">=" and "<" constraints, trust.CheckWrapper ordering,
// and every malformed input fails closed. A provider version that is not a
// release (dev builds) meets a well-formed range only on a ctftest
// build; a release build keeps it out (go test without tags pins that).
func TestInRange(t *testing.T) {
	const r = ">= 2.0.0, < 3.0.0"
	for _, c := range []struct {
		v, r string
		want bool
	}{
		{"2.0.0", r, true},
		{"2.9.9", r, true},
		{"v2.1.0", r, true},
		{"3.0.0", r, false},
		{"1.9.9", r, false},
		{"3.0.0-rc1", r, devVersions}, // prerelease provider: in range only on a ctftest build
		{"2.0.0-rc1", r, devVersions}, // a prerelease does not meet 2.0.0
		{"2.0.0-beta.1", r, true},     // parity beta of 2.0.0: meets what 2.0.0 meets
		{"v2.0.0-beta.12", r, true},
		{"2.9.9-compliancetf.1", r, true}, // proxy-only fix of 2.9.9
		{"2.0.0-compliancetf.0", r, true},
		{"3.0.0-beta.1", r, false}, // 3.0.0 is out, so is its beta, on every build
		{"3.0.0-compliancetf.2", r, false},
		{"1.9.9-beta.1", r, false},
		{"2.0.0-ctf.1", r, devVersions},   // only the full word: any other suffix is a dev version
		{"2.0.0-beta", r, devVersions},    // no number
		{"2.0.0-beta.01", r, devVersions}, // leading zero
		{"2.0.0-beta.1.2", r, devVersions},
		{"2.0.0-compliancetf.1+meta", r, devVersions},
		{"2.0.0-beta.1", "< 2.0.0", false},      // the range is still checked: no dev pass
		{"2.0.0", ">= 2.0.0", true},             // one-sided range
		{"dev", r, devVersions},                 // not a semantic version (main.go default)
		{"v0.1.0-137-g3533839", r, devVersions}, // make build: git describe
		{"3533839-dirty", r, devVersions},       // make build: no tag
		{"dev", "", false},                      // a dev version still needs a well-formed range
		{"dev", "> 1.0.0", false},
		{"dev", ">= x", false},
		{"2.0.0", "", false},         // empty range
		{"2.0.0", r + ",", false},    // trailing comma
		{"2.0.0", "> 1.0.0", false},  // unsupported operator
		{"2.0.0", "<= 3.0.0", false}, // unsupported operator
		{"2.0.0", ">= x", false},     // non-semver bound
		{"2.0.0", "< x", false},      // non-semver bound
		{"2.0.0", ">=2.0.0", false},  // no separator
		{"2.0.0", ">=", false},       // empty bound
		{"2.0.0", ">= ", false},      // empty bound
		{"2.0.0", ">= , < 3.0.0", false},
		{"2.0.0-rc2", "< 2.0.0-rc1", false}, // prerelease bounds rejected
		{"dev", "< 2.0.0-rc1", false},
		{"2.0.0-rc1", ">= 2.0.0-rc1", false},
		{"2.0.0", ">= 2.0", false},        // partial version
		{"2.0.0", ">= 1.0.0+meta", false}, // build metadata
		{"", r, false},                    // no provider version: both bounds
		{"", "< 3.0.0", false},            // upper bound only
		{"", ">= 2.0.0", false},           // lower bound only
		{"", "", false},                   // empty range
		{" ", "< 3.0.0", false},           // blank version
	} {
		if got := inRange(c.v, c.r); got != c.want {
			t.Errorf("inRange(%q, %q) = %v, want %v", c.v, c.r, got, c.want)
		}
	}
}

// TestVersionRangeParses: the build.json provider and upstream
// version_range the bundle generator derives from the release floor is well
// formed for inRange: the floor, a later release of its major and their
// parity betas and fixes are in, the next major and the release before the
// floor are out.
func TestVersionRangeParses(t *testing.T) {
	for _, c := range []struct{ floor, later, nextMajor, prevMinor string }{
		{"6.67.0", "6.80.1", "7.0.0", "6.66.9"},
		{"1.2.3", "1.3.0", "2.0.0", "1.1.99"},
	} {
		r, err := bundlegen.VersionRange(c.floor)
		if err != nil {
			t.Fatal(err)
		}
		for v, want := range map[string]bool{
			c.floor: true, c.later: true, c.nextMajor: false, c.prevMinor: false,
			c.floor + "-beta.1": true, c.floor + "-compliancetf.1": true, c.later + "-compliancetf.2": true,
			c.nextMajor + "-beta.1": false, c.prevMinor + "-compliancetf.1": false,
		} {
			if got := inRange(v, r); got != want {
				t.Errorf("inRange(%q, %q) = %v, want %v", v, r, got, want)
			}
		}
	}
}
