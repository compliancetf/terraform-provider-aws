package bundle

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
)

// TestBundletestNeedsCtftest: bundletest re-signs archives with a
// caller-supplied key, so it compiles only under the ctftest tag and no
// untagged (release) build can link it.
func TestBundletestNeedsCtftest(t *testing.T) {
	for _, c := range []struct {
		tags string
		want bool
	}{{"", false}, {"ctftest", true}} {
		// Output, not CombinedOutput: go may warn on stderr (toolchain
		// download), which must not reach the parsed count.
		out, err := exec.Command("go", "list", "-e", "-tags", c.tags, "-f", "{{len .GoFiles}}", "./bundletest").Output()
		if errors.Is(err, exec.ErrNotFound) {
			t.Skip("go not on PATH:", err)
		}
		if err != nil {
			var stderr []byte
			if ee := (*exec.ExitError)(nil); errors.As(err, &ee) {
				stderr = ee.Stderr
			}
			t.Fatalf("tags %q: go list: %v\n%s", c.tags, err, stderr)
		}
		if got := strings.TrimSpace(string(out)) != "0"; got != c.want {
			t.Errorf("tags %q: bundletest has Go files = %v, want %v", c.tags, got, c.want)
		}
	}
}
