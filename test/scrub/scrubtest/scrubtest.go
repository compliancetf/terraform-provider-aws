// Package scrubtest is the marker scanner and output capture of the
// value-free scrub tests: test/scrub and the proxy
// scrub test share it. Tests only.
package scrubtest

import (
	"bytes"
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/go-hclog"
)

// MarkerRE finds a marker in any case and any prefix: a lowercased IAM
// action or a truncated value is still a leak. Markers are ASCII
// BOBTHECORP-MARKER-<n>, or bobthecorp_marker_<n> where a value must pass
// the evidence path format ([a-z0-9_]), so JSON escaping cannot hide one.
var MarkerRE = regexp.MustCompile(`(?i)MARKER[-_][0-9]+`)

// Marker is marker number n.
func Marker(n int) string { return fmt.Sprintf("BOBTHECORP-MARKER-%d", n) }

// Mask hides every marker, so a failure message never prints one.
func Mask(s string) string { return MarkerRE.ReplaceAllString(s, "<marker>") }

// NoMarker fails when out, one output stream, contains a marker. The
// message names the stream and offset and shows a masked window.
func NoMarker(t testing.TB, stream, out string) {
	t.Helper()
	if loc := MarkerRE.FindStringIndex(out); loc != nil {
		t.Errorf("LEAK: %s at offset %d: ...%s...", stream, loc[0], Mask(out[max(0, loc[0]-60):min(len(out), loc[1]+60)]))
	}
}

// Must scans a product error, then stops the test on it.
func Must(t testing.TB, stream string, err error) {
	t.Helper()
	if err != nil {
		NoMarker(t, stream, err.Error())
		t.Fatalf("%s: %s", stream, Mask(err.Error()))
	}
}

// syncBuf is a log sink safe for concurrent writers.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// CaptureLogs sends the std log and the hclog default logger to one buffer
// and file descriptor 2 (os.Stderr included) to a file until the test ends,
// and proves each reaches its sink with a canary. The returned func is
// everything captured. The calling package must not run tests in parallel.
func CaptureLogs(t testing.TB) func() string {
	t.Helper()
	buf := &syncBuf{}
	w, flags := log.Writer(), log.Flags()
	log.SetOutput(buf)
	// Default first: before its first use SetDefault returns nil, and
	// restoring nil leaves every later hclog.Default() caller a nil logger.
	hclog.Default()
	old := hclog.SetDefault(hclog.New(&hclog.LoggerOptions{Output: buf, Level: hclog.Trace}))
	t.Cleanup(func() {
		log.SetOutput(w)
		log.SetFlags(flags)
		hclog.SetDefault(old)
	})
	stderr := redirectStderr(t)
	log.Print("scrub-canary-log")
	hclog.Default().Info("scrub-canary-hclog")
	out := func() string { return buf.String() + stderr() }
	for _, c := range []string{"scrub-canary-log", "scrub-canary-hclog", stderrCanary} {
		if !strings.Contains(out(), c) {
			t.Fatalf("log capture: canary %s missing", c)
		}
	}
	return out
}
