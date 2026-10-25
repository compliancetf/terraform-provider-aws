//go:build ctftest

package scrub

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/test/scrub/scrubtest"
)

// TestScrubMemo: after every case ran twice, the prefilter memo dump
// (ctftest only: a key is a sha256 over projected values) holds the pass and
// fail decisions as "<sha256 hex> pass|fail" lines and no marker.
func TestScrubMemo(t *testing.T) {
	logs := scrubtest.CaptureLogs(t)
	s := schemas(t)
	comp := loadEngine(t, s, time.Minute)
	evalCases(t, s, comp)
	dump := comp.MemoDump()
	lines := strings.Split(dump, "\n")
	if dump == "" || len(lines) < 2 {
		t.Fatalf("memo dump has %d entries, want the pass and fail decisions", len(lines))
	}
	shape := regexp.MustCompile(`^[0-9a-f]{64} (pass|fail)$`)
	for _, l := range lines {
		if !shape.MatchString(l) {
			t.Errorf("memo dump line %q is not <sha256 hex> pass|fail", scrubtest.Mask(l))
		}
	}
	scrubtest.NoMarker(t, "memo dump", dump)
	scrubtest.NoMarker(t, "log", logs())
}
