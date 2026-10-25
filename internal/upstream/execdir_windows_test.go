package upstream

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

// Windows-only; these run on a Windows host (follow-up bead), and
// GOOS=windows go vet compiles them everywhere.

// TestExecDirWindowsShortNameAlias: an 8.3 short spelling of a plugin cache
// is the same directory, so the exec dir is never placed under it.
func TestExecDirWindowsShortNameAlias(t *testing.T) {
	base := realTempDir(t)
	cache := filepath.Join(base, "plugin cache long name")
	if err := os.Mkdir(cache, 0o700); err != nil {
		t.Fatal(err)
	}
	long, err := syscall.UTF16PtrFromString(cache)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]uint16, 1024)
	n, err := syscall.GetShortPathName(long, &buf[0], uint32(len(buf)))
	short := syscall.UTF16ToString(buf[:n])
	if err != nil || n == 0 || short == cache {
		t.Skip("no 8.3 names on this volume")
	}
	_, err = newExecDir([]string{filepath.Join(cache, "x")}, []string{short})
	wantUnsafe(t, err, "Terraform")
	_, err = newExecDir([]string{filepath.Join(cache, "x")}, []string{`\\?\` + short})
	wantUnsafe(t, err, "Terraform")
}

// TestExecDirRefusesWindowsACL: a parent that Everyone may write is refused,
// the default per-user ACL is accepted.
func TestExecDirRefusesWindowsACL(t *testing.T) {
	base := realTempDir(t)
	mustExecDir(t, []string{filepath.Join(base, "ok")}, nil)
	open := filepath.Join(base, "open")
	if err := os.Mkdir(open, 0o700); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("icacls", open, "/grant", "*S-1-1-0:(M)").CombinedOutput(); err != nil {
		t.Fatalf("icacls: %v %s", err, out)
	}
	_, err := newExecDir([]string{filepath.Join(open, "exec")}, nil)
	wantUnsafe(t, err, "ACL")
}
