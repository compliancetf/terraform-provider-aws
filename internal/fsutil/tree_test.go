//go:build unix

package fsutil

import (
	"os"
	"path/filepath"
	"testing"
)

// TestOpenTreeAnchorsReads: once a cache dir is checked, a component swapped
// for a symlink to another dir is never followed: reads stay on the checked
// dir. A path-based open after the check read the planted file instead.
func TestOpenTreeAnchorsReads(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "profiles", "bobthecorp")
	evil := filepath.Join(t.TempDir(), "evil")
	for d, body := range map[string]string{dir: "orig", evil: "planted"} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "f"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r, err := OpenTree(root, dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close() //nolint:errcheck // test
	if err := os.Rename(filepath.Join(root, "profiles"), filepath.Join(root, "old")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "profiles"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(evil, dir); err != nil {
		t.Fatal(err)
	}
	if b, err := ReadFile(r, "f", 100); err != nil || string(b) != "orig" {
		t.Fatalf("read %q, %v; want the checked dir's file", b, err)
	}
	// A symlinked component is refused at open time.
	if _, err := OpenTree(root, dir, false); err == nil {
		t.Fatal("symlinked component accepted")
	}
}

// TestReadFileRefusesSymlink: a file name that is a symlink is never
// followed, even to a regular file inside the checked dir.
func TestReadFileRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "real"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	r, err := OpenTree(dir, dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close() //nolint:errcheck // test
	if _, err := ReadFile(r, "link", 100); err == nil {
		t.Fatal("symlink followed")
	}
}
