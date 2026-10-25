//go:build !unix

package verdict

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadFailsClosedOffUnix: without ownership and no-follow checks every
// verdict file is refused, so no verdict loads.
func TestLoadFailsClosedOffUnix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "verdict.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvVerdict, path)
	v, err := Load(Input{})
	want := Error{Summary: SummaryInvalid, Detail: "The file named by COMPLIANCETF_VERDICT cannot be opened as a regular file without following a symlink."}
	if e, ok := err.(*Error); v != nil || !ok || *e != want {
		t.Fatalf("verdict %v, err %v", v, err)
	}
}
