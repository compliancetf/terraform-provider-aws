//go:build !unix

package scrubtest

import "testing"

const stderrCanary = ""

// redirectStderr is unix only (dup2): elsewhere stderr is not scanned.
func redirectStderr(t testing.TB) func() string {
	t.Log("stderr is not captured on this platform")
	return func() string { return "" }
}
