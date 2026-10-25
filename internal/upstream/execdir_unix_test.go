//go:build !windows

package upstream

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestExecDirRefusesForeignOwner(t *testing.T) {
	base := realTempDir(t)
	defer func(u int) { currentUID = u }(currentUID)
	currentUID++ // our own temp dirs now look foreign
	_, err := newExecDir([]string{filepath.Join(base, "exec")}, nil)
	wantUnsafe(t, err, "owned")
}

func TestExecDirAllowsStickyRootAncestor(t *testing.T) {
	tmp, err := filepath.EvalSymlinks("/tmp")
	if err != nil || !stickyRootDir(tmp) {
		t.Skip("no root-owned sticky /tmp")
	}
	base, err := os.MkdirTemp(tmp, "execdir-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	mustExecDir(t, []string{filepath.Join(base, "exec")}, nil)
	// The candidate itself must still be private.
	_, err = newExecDir([]string{tmp}, nil)
	wantUnsafe(t, err, "writable")
}

// TestExecDirFallsBackOnDiskFull: ENOSPC while copying into the first parent
// (a small tmpfs XDG_RUNTIME_DIR) moves the copy to the next parent instead of
// failing, and the abandoned child is removed.
func TestExecDirFallsBackOnDiskFull(t *testing.T) {
	small, big := filepath.Join(realTempDir(t), "small"), filepath.Join(realTempDir(t), "big")
	body := []byte("pinned bytes")
	p := testPins(body)
	src := writeBin(t, filepath.Join(realTempDir(t), "aws"), body)
	defer func(f func(io.Writer, io.Reader, int64) (int64, string, error)) { copyBytes = f }(copyBytes)
	copyBytes = func(w io.Writer, r io.Reader, n int64) (int64, string, error) {
		if f, ok := w.(*os.File); ok && strings.HasPrefix(f.Name(), small+string(filepath.Separator)) {
			return 0, "", &os.PathError{Op: "write", Path: f.Name(), Err: syscall.ENOSPC}
		}
		return copyHashed(w, r, n)
	}
	d := mustExecDir(t, []string{small, big}, nil)
	first := d.dir
	vb, err := d.copy(context.Background(), src, p, testOSArch)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(filepath.Dir(vb.Path())) != big || vb.execDir != d.dir {
		t.Fatalf("copy %q not under %q", vb.Path(), big)
	}
	if _, err := os.Lstat(first); !os.IsNotExist(err) {
		t.Fatalf("abandoned child %q kept: %v", first, err)
	}
	// With no parent left, disk full is the error.
	d2 := mustExecDir(t, []string{small}, nil)
	if _, err := d2.copy(context.Background(), src, p, testOSArch); !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("want ENOSPC, got %v", err)
	}
}
