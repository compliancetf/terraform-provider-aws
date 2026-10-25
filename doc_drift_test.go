package main

import (
	"os/exec"
	"testing"
)

// TestDocDrift runs scripts/doc-drift.sh so make test and CI fail when a name
// removed in v2 reappears outside history.
func TestDocDrift(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	if err := exec.Command("git", "rev-parse", "--git-dir").Run(); err != nil {
		t.Skip("not a git checkout")
	}
	out, err := exec.Command("bash", "scripts/doc-drift.sh").CombinedOutput()
	if err != nil {
		t.Fatalf("scripts/doc-drift.sh: %v\n%s", err, out)
	}
}
