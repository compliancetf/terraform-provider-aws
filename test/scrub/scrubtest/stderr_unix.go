//go:build unix

package scrubtest

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

const stderrCanary = "scrub-canary-stderr"

// redirectStderr points file descriptor 2 and os.Stderr at a file until the
// test ends, so anything written to stderr by any code is scanned, and
// writes the canary through the descriptor. The returned func reads it.
func redirectStderr(t testing.TB) func() string {
	t.Helper()
	f, err := os.Create(filepath.Join(t.TempDir(), "stderr"))
	if err != nil {
		t.Fatal(err)
	}
	saved, err := unix.Dup(2)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Dup2(int(f.Fd()), 2); err != nil { //nolint:gosec // a file descriptor fits in int
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = f
	t.Cleanup(func() {
		os.Stderr = old
		_ = unix.Dup2(saved, 2) //nolint:errcheck // best effort restore at test end
		_ = unix.Close(saved)   //nolint:errcheck // best effort restore at test end
		_ = f.Close()           //nolint:errcheck // read-only from here
	})
	if _, err := unix.Write(2, []byte(stderrCanary+"\n")); err != nil {
		t.Fatal(err)
	}
	return func() string {
		b, err := os.ReadFile(f.Name())
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
}
