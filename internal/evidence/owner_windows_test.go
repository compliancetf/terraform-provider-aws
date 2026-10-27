package evidence

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func grant(t *testing.T, dir, ace string) {
	t.Helper()
	if out, err := exec.Command("icacls", dir, "/grant", ace).CombinedOutput(); err != nil {
		t.Fatalf("icacls: %v %s", err, out)
	}
}

func openRun(dir string) error {
	w, err := Open(Options{Dir: dir, Run: Run{ID: "bobthecorp-run-1", IDSource: "compliancetf"}})
	if err == nil {
		err = w.Close()
	}
	return err
}

// TestOpenWindowsACL: the default per-user temp ACL is accepted; an evidence
// dir Everyone may write is refused, and so is a run dir Everyone may read
// (it inherits the evidence dir's ACL), as a 0o077 mode is on unix.
func TestOpenWindowsACL(t *testing.T) {
	if err := openRun(filepath.Join(t.TempDir(), "evidence")); err != nil {
		t.Fatal(err)
	}

	writable := filepath.Join(t.TempDir(), "evidence")
	if err := os.Mkdir(writable, 0o700); err != nil {
		t.Fatal(err)
	}
	grant(t, writable, "*S-1-1-0:(M)")
	if err := openRun(writable); err == nil || !strings.Contains(err.Error(), "ACL grants write") {
		t.Fatalf("want evidence dir ACL refusal, got %v", err)
	}

	readable := filepath.Join(t.TempDir(), "evidence")
	if err := os.Mkdir(readable, 0o700); err != nil {
		t.Fatal(err)
	}
	grant(t, readable, "*S-1-1-0:(OI)(CI)(RX)")
	if err := openRun(readable); err == nil || !strings.Contains(err.Error(), "run dir") || !strings.Contains(err.Error(), "ACL grants access") {
		t.Fatalf("want run dir ACL refusal, got %v", err)
	}
}

// TestOpenWindowsCreatesPrivate: an evidence dir the provider creates under
// a parent that Everyone may write gets a private DACL, as mode 0700 on unix.
func TestOpenWindowsCreatesPrivate(t *testing.T) {
	parent := t.TempDir()
	grant(t, parent, "*S-1-1-0:(OI)(CI)(M)")
	if err := openRun(filepath.Join(parent, "a", "evidence")); err != nil {
		t.Fatal(err)
	}
}
