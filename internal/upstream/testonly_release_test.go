//go:build !ctftest

package upstream

import "testing"

// A release build must not be able to skip pin verification.
func TestReleaseHasNoTestOverride(t *testing.T) {
	if testOverride != nil {
		t.Fatal("testOverride is set in a non-ctftest build")
	}
}
