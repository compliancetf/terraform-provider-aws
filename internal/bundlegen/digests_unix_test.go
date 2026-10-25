//go:build unix

package bundlegen

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// noBlock runs f and fails the test when it does not return within 5s.
func noBlock(t *testing.T, what string, f func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- f() }()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatalf("%s blocked on a FIFO", what)
		return nil
	}
}

// TestDigestsFIFO: a FIFO in the generator input or output fails
// E_SPECIAL_FILE at once, never blocking on it.
func TestDigestsFIFO(t *testing.T) {
	dir := copyCatalog(t, func(_ string, data []byte) []byte { return data })
	p := filepath.Join(dir, "provider_dispositions.json")
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := noBlock(t, "LoadCatalog", func() error { _, err := LoadCatalog(dir); return err }); errCode(err) != "E_SPECIAL_FILE" {
		t.Errorf("FIFO catalog input: %v", err)
	}

	out := &Output{Files: map[string][]byte{"soc2-aws/build.json": []byte("{}\n")}}
	for _, rel := range []string{"pipe", "soc2-aws/build.json", "old/nested/pipe"} {
		dir := t.TempDir()
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(p, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := noBlock(t, "WriteDir", func() error { return out.WriteDir(dir) }); errCode(err) != "E_SPECIAL_FILE" {
			t.Errorf("FIFO %s in the output dir: %v", rel, err)
		}
		if err := noBlock(t, "ReadOutputDir", func() error { _, err := ReadOutputDir(dir); return err }); errCode(err) != "E_SPECIAL_FILE" {
			t.Errorf("ReadOutputDir with FIFO %s: %v", rel, err)
		}
	}

	// A FIFO that appears after the empty check: the O_EXCL create fails on
	// it instead of opening it for write.
	dir = t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "build.json"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close() //nolint:errcheck // test
	if err := noBlock(t, "createFile", func() error { return createFile(root, "build.json", []byte("{}\n")) }); errCode(err) != "E_SPECIAL_FILE" {
		t.Errorf("createFile on a FIFO: %v", err)
	}
}

// TestWalkRootSwap: a directory swapped for a FIFO, another
// directory or a symlink to itself, after its parent was listed and before the walk descends fails
// E_SPECIAL_FILE at once in WriteDir and ReadOutputDir; the FIFO is never
// opened blocking. walkHook runs at that point, so no timed race is needed.
func TestWalkRootSwap(t *testing.T) {
	swaps := map[string]func(p string) error{
		"fifo": func(p string) error {
			if err := os.RemoveAll(p); err != nil {
				return err
			}
			return syscall.Mkfifo(p, 0o600)
		},
		"symlink to the same dir": func(p string) error {
			real := filepath.Join(filepath.Dir(p), "real")
			if err := os.Rename(p, real); err != nil {
				return err
			}
			return os.Symlink("real", p)
		},
		"other dir": func(p string) error {
			if err := os.RemoveAll(p); err != nil {
				return err
			}
			return os.Mkdir(p, 0o755)
		},
	}
	for name, swap := range swaps {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			hook := func(rel string) {
				if rel == "soc2-aws" {
					if err := swap(filepath.Join(dir, rel)); err != nil {
						t.Error(err)
					}
				}
			}
			walkHook = hook
			t.Cleanup(func() { walkHook = nil })
			out := &Output{Files: map[string][]byte{"soc2-aws/build.json": []byte("{}\n")}}
			// The empty check lists nothing to descend into; the post-write
			// walk descends into soc2-aws and meets the swap.
			if err := noBlock(t, "WriteDir", func() error { return out.WriteDir(dir) }); errCode(err) != "E_SPECIAL_FILE" {
				t.Errorf("WriteDir with %s swapped in: %v", name, err)
			}
			// ReadOutputDir descends into soc2-aws of a written output.
			walkHook = nil
			dir = t.TempDir()
			if err := out.WriteDir(dir); err != nil {
				t.Fatal(err)
			}
			walkHook = hook
			if err := noBlock(t, "ReadOutputDir", func() error { _, err := ReadOutputDir(dir); return err }); errCode(err) != "E_SPECIAL_FILE" {
				t.Errorf("ReadOutputDir with %s swapped in: %v", name, err)
			}
		})
	}
}

// TestWalkRootCode: a subdirectory the walk cannot open takes the caller's
// code, E_INPUT on the ReadOutputDir path and E_OUTPUT on the WriteDir one.
func TestWalkRootCode(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a 0o000 directory")
	}
	dir := t.TempDir()
	sub := filepath.Join(dir, "soc2-aws")
	if err := os.Mkdir(sub, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(sub, 0o755) }) //nolint:errcheck,gosec // test cleanup
	if _, err := ReadOutputDir(dir); errCode(err) != "E_INPUT" {
		t.Errorf("ReadOutputDir: %v", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close() //nolint:errcheck // test
	if _, err := walkRoot(root); errCode(err) != "E_OUTPUT" {
		t.Errorf("walkRoot: %v", err)
	}
}
