//go:build unix

package trust

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestStateDirChecked: the trust state is the anti-rollback anchor, so it is
// read only from a dir that passes the cache dir checks (owned, not a
// symlink, not writable by others) and never through a symlinked file.
func TestStateDirChecked(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("needs a non-root uid")
	}
	t.Run("symlinked state file", func(t *testing.T) {
		dir, other := t.TempDir(), t.TempDir()
		if _, err := UpdateState(other, stateDelta(t, 1)); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(other, stateFileName), filepath.Join(dir, stateFileName)); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadState(dir); err == nil {
			t.Error("LoadState followed a symlinked state file")
		}
		if _, err := UpdateState(dir, stateDelta(t, 2)); err == nil || errors.Is(err, ErrStateNotSaved) {
			t.Errorf("UpdateState over a symlinked state file: err = %v, want fatal", err)
		}
	})
	t.Run("symlinked state dir", func(t *testing.T) {
		real := t.TempDir()
		if _, err := UpdateState(real, stateDelta(t, 1)); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(t.TempDir(), "state")
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadState(link); err == nil {
			t.Error("LoadState followed a symlinked state dir")
		}
	})
	t.Run("floor reset in a symlinked state dir", func(t *testing.T) {
		real := t.TempDir()
		if _, err := UpdateState(real, stateDelta(t, 5)); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(real, floorResetFile), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(t.TempDir(), "state")
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		// A dir that fails the checks is fatal, never warn-and-continue
		// with the caller's (possibly older) state.
		s, applied, err := (&Keyring{}).applyFloorReset(link, FloorInput{OrgID: "bobthecorp"}, "")
		if applied || err == nil || errors.Is(err, ErrStateNotSaved) || s.loaded {
			t.Errorf("reset in a symlinked dir: applied %v, err %v, loaded %v; want fatal", applied, err, s.loaded)
		}
	})
	t.Run("dir writable by others", func(t *testing.T) {
		dir := t.TempDir()
		if _, err := UpdateState(dir, stateDelta(t, 1)); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o777); err != nil { //nolint:gosec // the point of the test
			t.Fatal(err)
		}
		if _, err := LoadState(dir); err == nil {
			t.Error("LoadState read a state dir others can write")
		}
		// A writer tightens its own dir to 0700 and goes on.
		if _, err := UpdateState(dir, stateDelta(t, 2)); err != nil {
			t.Fatal(err)
		}
		if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
			t.Fatalf("state dir mode after a write: %v, %v", fi.Mode().Perm(), err)
		}
	})
}
