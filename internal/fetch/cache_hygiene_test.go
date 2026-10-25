//go:build unix

package fetch

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/fsutil"
)

func TestWriteAtomicSweepsStaleTemps(t *testing.T) {
	dir := t.TempDir()
	old := time.Now().Add(-2 * staleTmpAge)
	write := func(name string, mtime time.Time) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, mtime, mtime); err != nil {
			t.Fatal(err)
		}
		return p
	}
	stale := write(".tmp-stale", old)
	fresh := write(".tmp-fresh", time.Now())
	other := write("notes.txt", old)

	// A symlink named like a temp file, whose target is outside the cache: the link may
	// go, the target must never be touched or followed.
	outside := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(outside, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, ".tmp-link")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	// A stale-looking directory is not ours either.
	sub := filepath.Join(dir, ".tmp-dir")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(sub, old, old); err != nil {
		t.Fatal(err)
	}

	if err := writeAtomic(dir, dir, "v1.dsse.json", []byte("{}"), false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(stale); !os.IsNotExist(err) {
		t.Errorf("stale temp file kept: %v", err)
	}
	for _, p := range []string{fresh, other, link, sub, outside} {
		if _, err := os.Lstat(p); err != nil {
			t.Errorf("%s removed: %v", filepath.Base(p), err)
		}
	}
	if b, _ := os.ReadFile(outside); string(b) != "keep" {
		t.Errorf("symlink target changed: %q", b)
	}
}

func TestWriteAtomicTightensOwnedDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bundles")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil { //nolint:gosec // the test widens it on purpose
		t.Fatal(err)
	}
	if err := writeAtomic(filepath.Dir(dir), dir, "a", []byte("x"), true); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o700 {
		t.Errorf("cache dir mode %o, want 700", got)
	}
}

func TestCacheDirRefusesSymlink(t *testing.T) {
	real := t.TempDir()
	dir := filepath.Join(t.TempDir(), "bundles")
	if err := os.Symlink(real, dir); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(filepath.Dir(dir), dir, "a", []byte("x"), true); err == nil {
		t.Error("write through a symlinked cache dir succeeded")
	}
	if _, err := os.Lstat(filepath.Join(real, "a")); !os.IsNotExist(err) {
		t.Errorf("file written through the symlink: %v", err)
	}
	if _, warns, _ := loadCachedBundles(filepath.Dir(dir), dir, bundleIDForHygiene, nil); len(warns) == 0 {
		t.Error("symlinked cache dir read without a warning")
	}
}

func TestCacheDirForeignOwnerFailsClosed(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root owns everything it creates; needs a non-root uid")
	}
	// The filesystem root is owned by root, not by this uid.
	if err := fsutil.SecureDir("/", false); err == nil {
		t.Error("foreign-owned dir accepted")
	}
}

func TestCacheDirRefusesSymlinkedIntermediate(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	stale := filepath.Join(outside, "bobthecorp", ".tmp-victim")
	if err := os.MkdirAll(filepath.Dir(stale), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stale, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * staleTmpAge)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "profiles")); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "profiles", "bobthecorp")
	if err := writeAtomic(root, dir, "v1.dsse.json", []byte("{}"), false); err == nil {
		t.Error("write through a symlinked intermediate dir succeeded")
	}
	if _, err := os.Lstat(stale); err != nil {
		t.Errorf("temp file outside the cache removed: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(outside, "bobthecorp", "v1.dsse.json")); !os.IsNotExist(err) {
		t.Errorf("file written outside the cache: %v", err)
	}

	// Nothing, not even an empty dir, is created through the symlink.
	root2, empty := t.TempDir(), t.TempDir()
	if err := os.Symlink(empty, filepath.Join(root2, "profiles")); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(root2, filepath.Join(root2, "profiles", "bobthecorp"), "v1.dsse.json", []byte("{}"), false); err == nil {
		t.Error("write through a symlinked intermediate dir succeeded")
	}
	if ents, _ := os.ReadDir(empty); len(ents) != 0 {
		t.Errorf("created outside the cache: %v", ents[0].Name())
	}
}

const bundleIDForHygiene = "bobthecorp-soc2"
