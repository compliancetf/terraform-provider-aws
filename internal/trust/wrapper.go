package trust

import (
	"cmp"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var (
	semverRE = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$`)
	// parityPreRE matches the prereleases of the version parity scheme:
	// X.Y.Z-beta.N comes before upstream X.Y.Z, X.Y.Z-compliancetf.N is a
	// proxy-only fix on top of it. Only these canonical forms are ordered: a
	// non-canonical one (compliancetf.01, Beta.1) is an "other" prerelease
	// and a floor of it admits the plain release, so the floor signer must
	// issue canonical forms only. The base orders first across bases because
	// every release is built from master: a proxy fix ships in the next base.
	parityPreRE = regexp.MustCompile(`^(beta|compliancetf)\.(0|[1-9][0-9]*)$`)
)

// CheckWrapper fails when provider version v is below minimum m. An empty m
// passes; a v that is not a semantic version (e.g. "dev") fails any minimum.
// The order is compareWrapper's.
func CheckWrapper(v, m string) error {
	if m == "" {
		return nil
	}
	a, b := semverRE.FindStringSubmatch(v), semverRE.FindStringSubmatch(m)
	if b == nil {
		return errors.New("org minimum is not a semantic version")
	}
	if a == nil {
		return belowErr(v, b)
	}
	if c, ok := compareWrapper(a, b); !ok || c < 0 {
		return belowErr(v, b)
	}
	return nil
}

// belowErr names the signed minimum m: a parity prerelease in full, any
// other prerelease as its numeric core only, never the free-form text.
func belowErr(v string, m []string) error {
	core := m[1] + "." + m[2] + "." + m[3]
	switch {
	case parityPreRE.MatchString(m[4]):
		core += "-" + m[4]
	case m[4] != "":
		core += " prerelease"
	}
	return fmt.Errorf("provider %s is below the org minimum %s", v, core)
}

// maxWrapper returns the higher of two wrapper minimums; "" is the lowest. A
// minimum that is not a semantic version wins, so CheckWrapper fails closed
// (of two, the lexically higher, so the merge order does not matter). Two
// unordered prereleases of one base merge to that base's release: it admits
// exactly what both admit, whatever the merge order.
func maxWrapper(a, b string) string {
	if a == "" {
		return b
	}
	x, y := semverRE.FindStringSubmatch(a), semverRE.FindStringSubmatch(b)
	switch {
	case b == "":
		return a
	case x == nil && y == nil:
		return max(a, b)
	case x == nil:
		return a
	case y == nil:
		return b
	}
	switch c, ok := compareWrapper(x, y); {
	case !ok:
		return x[1] + "." + x[2] + "." + x[3]
	case c < 0:
		return b
	}
	return a
}

// compareWrapper orders two semverRE matches for wrapper floors. The base
// X.Y.Z compares first, numerically. Within one base:
// beta.N < release < compliancetf.N, N numeric; plain semver would put a
// compliancetf.N fix below the release that lacks it. Any other prerelease
// sits below the release like a beta but is ordered against no other
// prerelease of its base except itself: ok is false for such a pair.
func compareWrapper(a, b []string) (c int, ok bool) {
	for i := 1; i <= 3; i++ {
		if c := compareNum(a[i], b[i]); c != 0 {
			return c, true
		}
	}
	if a[4] == b[4] {
		return 0, true
	}
	ta, na, ka := preTier(a[4])
	tb, nb, kb := preTier(b[4])
	switch {
	case ta != tb:
		return cmp.Compare(ta, tb), true
	case ka && kb:
		return compareNum(na, nb), true
	}
	return 0, false
}

// preTier places prerelease p within its base: -1 beta (or any other
// prerelease), 0 release, 1 compliancetf. known reports a parity form, whose
// counter is n.
func preTier(p string) (tier int, n string, known bool) {
	if p == "" {
		return 0, "", true
	}
	m := parityPreRE.FindStringSubmatch(p)
	if m == nil {
		return -1, "", false
	}
	if m[1] == "compliancetf" {
		return 1, m[2], true
	}
	return -1, m[2], true
}

// compareNum compares two decimal digit strings of any length.
func compareNum(a, b string) int {
	x, y := strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	return cmp.Or(cmp.Compare(len(x), len(y)), strings.Compare(x, y))
}
