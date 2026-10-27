package fsutil

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// grant runs icacls /grant on dir (Everyone is *S-1-1-0).
func grant(t *testing.T, dir, ace string) {
	t.Helper()
	if out, err := exec.Command("icacls", dir, "/grant", ace).CombinedOutput(); err != nil {
		t.Fatalf("icacls: %v %s", err, out)
	}
}

// TestOpenTreeWindowsACL: the default per-user temp ACL is accepted for
// readers and writers; a dir Everyone may write is refused for both, at the
// root and below it, and Everyone read only is accepted.
func TestOpenTreeWindowsACL(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "profiles", "bobthecorp")
	r, err := OpenTree(root, dir, true)
	if err != nil {
		t.Fatal(err)
	}
	r.Close() //nolint:errcheck // test
	if err := SecureDir(dir, false); err != nil {
		t.Fatal(err)
	}

	grant(t, dir, "*S-1-1-0:(RX)")
	if err := SecureDir(dir, false); err != nil {
		t.Fatalf("read for Everyone refused: %v", err)
	}
	grant(t, dir, "*S-1-1-0:(M)")
	for _, create := range []bool{false, true} {
		if _, err := OpenTree(root, dir, create); err == nil || !strings.Contains(err.Error(), "ACL grants write") {
			t.Fatalf("create=%v: want ACL refusal, got %v", create, err)
		}
	}
	if err := SecureDir(dir, true); err == nil {
		t.Fatal("SecureDir accepted a dir Everyone may write")
	}

	open := t.TempDir()
	grant(t, open, "*S-1-1-0:(M)")
	if _, err := OpenTree(open, open, false); err == nil {
		t.Fatal("OpenTree accepted a root Everyone may write")
	}
}

// TestOpenTreeWindowsCreatesPrivate: a cache root the provider creates
// under a parent that Everyone may write gets a private DACL (and the dirs
// below inherit it), as mode 0700 on unix.
func TestOpenTreeWindowsCreatesPrivate(t *testing.T) {
	parent := t.TempDir()
	grant(t, parent, "*S-1-1-0:(OI)(CI)(M)")
	root := filepath.Join(parent, "cache")
	r, err := OpenTree(root, filepath.Join(root, "bundles", "bobthecorp"), true)
	if err != nil {
		t.Fatal(err)
	}
	r.Close() //nolint:errcheck // test
	d, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close() //nolint:errcheck // test
	if err := WinACLFile(d, true); err != nil {
		t.Fatalf("created root is not private: %v", err)
	}
}

// TestSecureDirWindowsRefusesJunction: a junction to a private dir is not
// followed.
func TestSecureDirWindowsRefusesJunction(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Skipf("mklink /J: %v %s", err, out)
	}
	if err := SecureDir(link, false); err == nil {
		t.Fatal("SecureDir followed a junction")
	}
}
