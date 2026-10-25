package upstream

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func chmodACL(t *testing.T, ace, path string) {
	t.Helper()
	if out, err := exec.Command("chmod", "+a", ace, path).CombinedOutput(); err != nil { //nolint:gosec // test fixture
		t.Fatalf("chmod +a %q: %v %s", ace, err, out)
	}
	t.Cleanup(func() { _ = exec.Command("chmod", "-N", path).Run() }) //nolint:gosec // test fixture
}

// TestExecDirRefusesMacACL: an extended ACL that lets everyone add entries to
// a parent, or read the child, is refused although the mode bits are 0700.
// A deny entry (as macOS puts on ~/Library) and an entry for root are fine.
func TestExecDirRefusesMacACL(t *testing.T) {
	base := realTempDir(t)
	parent := filepath.Join(base, "p")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	chmodACL(t, "everyone deny delete", parent)
	chmodACL(t, "user:root allow add_file,delete_child", parent) // root's real GUID is the compat GUID
	d := mustExecDir(t, []string{filepath.Join(parent, "exec")}, nil)

	chmodACL(t, "everyone allow read", d.dir)
	if err := checkDir(d.dir, true); err == nil {
		t.Fatal("child readable through an ACL accepted")
	}

	chmodACL(t, "everyone allow add_file,add_subdirectory", parent)
	_, err := newExecDir([]string{filepath.Join(parent, "exec2")}, nil)
	wantUnsafe(t, err, "ACL")
}
