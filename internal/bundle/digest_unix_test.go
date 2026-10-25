//go:build unix

package bundle

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestDigestAlgorithmsSpecialFiles: a symlink (to a file, to a directory, or
// as the root) or a FIFO at any depth is digest_special_file, and
// setuid is part of the mode.
func TestDigestAlgorithmsSpecialFiles(t *testing.T) {
	cases := map[string]func(root string) error{
		"sub/link":     func(root string) error { return os.Symlink("../a.txt", filepath.Join(root, "sub/link")) },
		"sub/dirlink":  func(root string) error { return os.Symlink("..", filepath.Join(root, "sub/dirlink")) },
		"b/fifo":       func(root string) error { return syscall.Mkfifo(filepath.Join(root, "b/fifo"), 0o644) },
		"dangling.txt": func(root string) error { return os.Symlink("missing", filepath.Join(root, "dangling.txt")) },
	}
	for rel, mk := range cases {
		t.Run(rel, func(t *testing.T) {
			root := copyTree(t)
			if err := mk(root); err != nil {
				t.Fatal(err)
			}
			wantSpecial(t, root, rel)
		})
	}

	t.Run("root symlink", func(t *testing.T) {
		link := filepath.Join(t.TempDir(), "root")
		if err := os.Symlink(copyTree(t), link); err != nil {
			t.Fatal(err)
		}
		for _, root := range []string{link, link + "/", link + "/."} {
			wantSpecial(t, root, ".")
		}
	})

	t.Run("noncharacter name", func(t *testing.T) {
		root := copyTree(t)
		if err := os.WriteFile(filepath.Join(root, "x\uFDD0"), nil, 0o644); err != nil {
			t.Skipf("file system refuses the name: %v", err) // APFS: illegal byte sequence
		}
		if _, err := DigestDir(root); !errors.Is(err, ErrNotJSON) {
			t.Fatalf("noncharacter file name: %v", err)
		}
	})

	t.Run("open refuses a swapped symlink", func(t *testing.T) {
		root := copyTree(t)
		p := filepath.Join(root, "a.txt")
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("b.txt", p); err != nil {
			t.Fatal(err)
		}
		if _, err := dirEntry(p, "a.txt"); err == nil || !strings.HasSuffix(err.Error(), "digest_special_file") {
			t.Fatalf("dirEntry on a symlink: %v", err)
		}
		fifo := filepath.Join(root, "fifo")
		if err := syscall.Mkfifo(fifo, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := dirEntry(fifo, "fifo"); err == nil || !strings.HasSuffix(err.Error(), "digest_special_file") {
			t.Fatalf("dirEntry on a FIFO: %v", err) // returns, never blocks
		}
	})

	t.Run("removed or unreadable after the walk", func(t *testing.T) {
		root := copyTree(t)
		gone := filepath.Join(root, "gone.txt")
		if _, err := dirEntry(gone, "gone.txt"); !errors.Is(err, ErrChanged) || errors.Is(err, ErrSpecialFile) {
			t.Fatalf("dirEntry on a removed file: %v, want digest_changed", err)
		}
		if os.Geteuid() == 0 {
			t.Skip("root reads a 0000 file")
		}
		p := filepath.Join(root, "a.txt")
		if err := os.Chmod(p, 0); err != nil {
			t.Fatal(err)
		}
		_, err := DigestDir(root)
		if !errors.Is(err, fs.ErrPermission) || errors.Is(err, ErrChanged) || errors.Is(err, ErrSpecialFile) {
			t.Fatalf("DigestDir with an unreadable file: %v, want the permission error", err)
		}
	})

	t.Run("changed while digested", func(t *testing.T) {
		for name, edit := range map[string]func(root, p string) error{
			"replaced": func(root, p string) error {
				other := filepath.Join(root, "other")
				if err := os.WriteFile(other, []byte("other"), 0o644); err != nil {
					return err
				}
				return os.Rename(other, p)
			},
			"unlinked": func(_, p string) error { return os.Remove(p) },
			"rewritten in place": func(_, p string) error {
				fi, err := os.Stat(p)
				if err != nil {
					return err
				}
				if err := os.WriteFile(p, make([]byte, fi.Size()), 0o644); err != nil {
					return err
				}
				return os.Chtimes(p, fi.ModTime(), fi.ModTime().Add(time.Second)) // past mtime granularity
			},
			"mode changed":      func(_, p string) error { return os.Chmod(p, 0o600) },
			"directory removed": func(root, _ string) error { return os.RemoveAll(filepath.Join(root, "sub")) },
		} {
			t.Run(name, func(t *testing.T) {
				root := copyTree(t)
				var hookErr error
				testHookAfterCopy = func(p string) {
					if filepath.Base(p) == "a.b" { // hashed first; sub is walked later
						hookErr = edit(root, p)
					}
				}
				t.Cleanup(func() { testHookAfterCopy = nil })
				_, err := DigestDir(root)
				if hookErr != nil {
					t.Fatal(hookErr)
				}
				if !errors.Is(err, ErrChanged) {
					t.Fatalf("DigestDir: %v, want digest_changed", err)
				}
			})
		}
	})

	t.Run("setuid", func(t *testing.T) {
		root := copyTree(t)
		p := filepath.Join(root, "sub/run.sh")
		if err := os.Chmod(p, 0o755|os.ModeSetuid); err != nil {
			t.Fatal(err)
		}
		e, err := dirEntry(p, "sub/run.sh")
		if err != nil || e["mode"] != "4755" {
			t.Fatalf("setuid mode: %v (%v)", e, err)
		}
	})
}
