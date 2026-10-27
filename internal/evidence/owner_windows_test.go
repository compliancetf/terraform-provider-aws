package evidence

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/fsutil"
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

// evidenceDir makes an evidence dir with the inherited temp ACL plus ace.
func evidenceDir(t *testing.T, ace string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "evidence")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	grant(t, dir, ace)
	return dir
}

// TestOpenWindowsACL: the default per-user temp ACL is accepted. An evidence
// dir that Everyone may write, or that passes write to what is created in it
// (an inherit-only entry), is refused. One that Everyone may read is
// accepted, as 0o755 is on unix, and the run dir is still created private.
func TestOpenWindowsACL(t *testing.T) {
	if err := openRun(filepath.Join(t.TempDir(), "evidence")); err != nil {
		t.Fatal(err)
	}
	for _, ace := range []string{"*S-1-1-0:(M)", "*S-1-1-0:(OI)(CI)(IO)(M)"} {
		if err := openRun(evidenceDir(t, ace)); err == nil || !strings.Contains(err.Error(), "evidence dir") || !strings.Contains(err.Error(), "ACL grants write") {
			t.Fatalf("%s: want evidence dir ACL refusal, got %v", ace, err)
		}
	}

	readable := evidenceDir(t, "*S-1-1-0:(OI)(CI)(RX)")
	if err := openRun(readable); err != nil {
		t.Fatalf("evidence dir Everyone may read: %v", err)
	}
	d, err := os.Open(filepath.Join(readable, "bobthecorp-run-1"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := fsutil.WinACLFile(d, true); err != nil {
		t.Fatalf("run dir is not private: %v", err)
	}
}

// TestOpenWindowsRefusesOpenRunDir: an existing run dir (a sibling process
// made it) that Everyone may read is refused, as a 0o077 mode is on unix.
func TestOpenWindowsRefusesOpenRunDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")
	run := filepath.Join(dir, "bobthecorp-run-1")
	if err := os.MkdirAll(run, 0o700); err != nil {
		t.Fatal(err)
	}
	grant(t, run, "*S-1-1-0:(RX)")
	if err := openRun(dir); err == nil || !strings.Contains(err.Error(), "run dir") || !strings.Contains(err.Error(), "ACL grants access") {
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
