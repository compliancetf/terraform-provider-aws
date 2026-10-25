//go:build ctftest

package upstream

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
)

// TestUpstreamPathEnv names an unpinned upstream binary that a ctftest build
// launches instead of the pinned one. Release builds do not compile this file,
// so they have no way to skip pin verification.
const TestUpstreamPathEnv = "CTFTEST_UPSTREAM_PATH" // not COMPLIANCETF_*: Launch strips those from the child env

func init() {
	testOverride = func() (VerifiedBinary, bool) {
		p := os.Getenv(TestUpstreamPathEnv)
		return NewTestVerifiedBinary(p), p != ""
	}
}

// NewTestVerifiedBinary wraps path as a protocol 5 VerifiedBinary without
// checking it against a pin. Its sha256 is the file's current hash ("" when
// unreadable), so the proxy schema cache stays keyed per binary.
// ctftest builds only.
func NewTestVerifiedBinary(path string) VerifiedBinary {
	var sum string
	if b, err := os.ReadFile(path); err == nil { //nolint:gosec // test-only path
		h := sha256.Sum256(b)
		sum = hex.EncodeToString(h[:])
	}
	return VerifiedBinary{path: path, sha256: sum, protocol: 5, version: "0.0.0-ctftest", name: "ctftest/upstream"}
}
