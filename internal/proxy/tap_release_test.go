//go:build !conformance && !record

package proxy

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestInvariantTapNotInRelease: a build without the conformance or record
// tag carries no tap, no envelope edit, no test evaluator, no conformance pins
// and no apply recorder (each env var name is its code's only string).
func TestInvariantTapNotInRelease(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "provider")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = filepath.Join("..", "..")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v: %s", err, out)
	}
	b, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"COMPLIANCETF_CONFORMANCE_TAP", "COMPLIANCETF_CONFORMANCE_EVALUATOR", "COMPLIANCETF_CONFORMANCE_RPCSEQ",
		"COMPLIANCETF_CONFORMANCE_PINS", "COMPLIANCETF_CONFORMANCE_ENVELOPE", "COMPLIANCETF_RECORD_DIR"} {
		if bytes.Contains(b, []byte(name)) {
			t.Fatalf("release build contains %s", name)
		}
	}
}
