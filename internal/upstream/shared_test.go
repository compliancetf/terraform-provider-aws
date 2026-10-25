package upstream

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// sharedSource is a source whose only candidate holds the release binary.
func sharedSource(t *testing.T, r *release) *source {
	t.Helper()
	s := newSource(t, r, nil)
	good := t.TempDir()
	writeBin(t, registryPath(good, r), r.bin)
	s.dirs = []string{good}
	return s
}

// countIO counts copies (writes to a file) and hashes (writes to io.Discard)
// of the binary from here on.
func countIO(t *testing.T) (copies, hashes *int) {
	t.Helper()
	copies, hashes = new(int), new(int)
	orig := copyBytes
	t.Cleanup(func() { copyBytes = orig })
	copyBytes = func(w io.Writer, r io.Reader, limit int64) (int64, string, error) {
		if w == io.Discard {
			*hashes++
		} else {
			*copies++
		}
		return orig(w, r, limit)
	}
	return copies, hashes
}

func mustShared(t *testing.T, s *source, parent string) VerifiedBinary {
	t.Helper()
	vb, done, err := s.discoverShared(context.Background(), parent)
	if err != nil || !done {
		t.Fatalf("discoverShared: done=%v err=%v", done, err)
	}
	return vb
}

func entryOf(parent string, r *release) string {
	return filepath.Join(parent, sharedPrefix+hexSum(r.bin))
}

func TestSharedPublishThenReuse(t *testing.T) {
	r := newRelease(t)
	parent := realTempDir(t)
	copies, hashes := countIO(t)

	vb := mustShared(t, sharedSource(t, r), parent)
	entry := entryOf(parent, r)
	if vb.Path() != filepath.Join(entry, r.pins.Platforms[testOSArch].Binary) || vb.execDir != "" || vb.SHA256() != hexSum(r.bin) {
		t.Fatalf("published %+v, want the entry %q", vb, entry)
	}
	if st, err := os.Stat(vb.Path()); err != nil || (runtime.GOOS != "windows" && st.Mode().Perm() != 0o500) {
		t.Fatalf("published binary: %v %v", st, err)
	}
	if entries, _ := os.ReadDir(parent); len(entries) != 1 {
		t.Fatalf("parent holds %d entries, want only the shared one", len(entries))
	}
	(&Upstream{execDir: vb.execDir}).removeExecDir() // Close
	*copies, *hashes = 0, 0

	again := mustShared(t, sharedSource(t, r), parent)
	if again.Path() != vb.Path() || *copies != 0 || *hashes != 0 {
		t.Fatalf("reuse: path %q, %d copies, %d hashes; want %q and no I/O", again.Path(), *copies, *hashes, vb.Path())
	}
}

func TestSharedStampDriftRehashes(t *testing.T) {
	r := newRelease(t)
	parent := realTempDir(t)
	vb := mustShared(t, sharedSource(t, r), parent)
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(vb.Path(), old, old); err != nil {
		t.Fatal(err)
	}
	copies, hashes := countIO(t)
	if again := mustShared(t, sharedSource(t, r), parent); again.Path() != vb.Path() || *copies != 0 || *hashes != 1 {
		t.Fatalf("drift: path %q, %d copies, %d hashes; want reuse after one hash", again.Path(), *copies, *hashes)
	}
	// The stamp was repaired: the next start needs no hash.
	*hashes = 0
	if mustShared(t, sharedSource(t, r), parent); *hashes != 0 {
		t.Fatalf("stamp not repaired: %d hashes", *hashes)
	}
}

func TestSharedDefectiveEntryRepublishes(t *testing.T) {
	r := newRelease(t)
	for name, spoil := range map[string]func(t *testing.T, bin string){
		"bytes": func(t *testing.T, bin string) {
			if err := os.Chmod(bin, 0o700); err != nil {
				t.Fatal(err)
			}
			writeBin(t, bin, []byte("tampered"))
		},
		"missing binary": func(t *testing.T, bin string) {
			if err := os.Remove(bin); err != nil {
				t.Fatal(err)
			}
		},
		"hard link": func(t *testing.T, bin string) {
			if runtime.GOOS == "windows" {
				t.Skip("no link count on windows")
			}
			if err := os.Link(bin, bin+".link"); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			parent := realTempDir(t)
			vb := mustShared(t, sharedSource(t, r), parent)
			spoil(t, vb.Path())
			again := mustShared(t, sharedSource(t, r), parent)
			if b, err := os.ReadFile(again.Path()); err != nil || string(b) != string(r.bin) || again.execDir != "" {
				t.Fatalf("not republished: %q %v", b, err)
			}
			if _, err := os.Lstat(vb.Path() + ".link"); err == nil {
				t.Fatal("defective entry kept")
			}
		})
	}
}

func TestSharedUnsafeEntryUntouched(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no mode bits on windows")
	}
	r := newRelease(t)
	parent := realTempDir(t)
	vb := mustShared(t, sharedSource(t, r), parent)
	entry := filepath.Dir(vb.Path())
	if err := os.Chmod(entry, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, done, err := sharedSource(t, r).discoverShared(context.Background(), parent); done || err != nil {
		t.Fatalf("unsafe entry: done=%v err=%v, want a private copy", done, err)
	}
	if _, err := os.Stat(vb.Path()); err != nil {
		t.Fatalf("unsafe entry was touched: %v", err)
	}
}

func TestSharedLostRace(t *testing.T) {
	r := newRelease(t)
	parent := realTempDir(t)
	winner := mustShared(t, sharedSource(t, r), parent)

	// A second start finished its private copy after the winner published.
	loser := func() VerifiedBinary {
		s := sharedSource(t, r)
		s.exec = mustExecDir(t, []string{parent}, nil)
		vb, err := s.find(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return vb
	}
	vb := loser()
	got, ok := sharedSource(t, r).publish(context.Background(), vb, entryOf(parent, r))
	if !ok || got.Path() != winner.Path() {
		t.Fatalf("lost race: %q ok=%v, want the winner %q", got.Path(), ok, winner.Path())
	}
	if _, err := os.Stat(vb.execDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("loser copy kept: %v", err)
	}

	// A winner whose entry does not check out: the loser runs its own copy.
	if err := os.Remove(filepath.Join(entryOf(parent, r), stampName)); err != nil {
		t.Fatal(err)
	}
	vb = loser()
	if got, ok := sharedSource(t, r).publish(context.Background(), vb, entryOf(parent, r)); !ok || got.Path() != vb.Path() || got.execDir != vb.execDir {
		t.Fatalf("bad winner: ran %q, want the private copy %q", got.Path(), vb.Path())
	}
}

func TestSharedExplicitMismatchIsFatal(t *testing.T) {
	r := newRelease(t)
	parent := realTempDir(t)
	mustShared(t, sharedSource(t, r), parent)
	s := sharedSource(t, r)
	s.explicit = writeBin(t, filepath.Join(t.TempDir(), "aws"), []byte("tampered"))
	_, done, err := s.discoverShared(context.Background(), parent)
	var nv *NotVerifiedError
	if !done || !errors.As(err, &nv) || nv.Path != s.explicit {
		t.Fatalf("explicit mismatch with a good entry: done=%v err=%v", done, err)
	}
}

func TestSharedGC(t *testing.T) {
	r := newRelease(t)
	parent := realTempDir(t)
	mk := func(name string, age time.Duration, mode os.FileMode) string {
		p := filepath.Join(parent, name)
		if err := os.Mkdir(p, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		at := time.Now().Add(-age)
		if err := os.Chtimes(p, at, at); err != nil {
			t.Fatal(err)
		}
		return p
	}
	idle := mk(sharedPrefix+"idle", 30*24*time.Hour, 0o700)
	fresh := mk(sharedPrefix+"fresh", time.Hour, 0o700)
	unsafe := mk(sharedPrefix+"unsafe", 30*24*time.Hour, 0o755)
	foreign := mk("not-shared", 30*24*time.Hour, 0o700)

	mustShared(t, sharedSource(t, r), parent)
	if _, err := os.Stat(idle); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("idle entry kept: %v", err)
	}
	keep := []string{fresh, foreign, entryOf(parent, r)}
	if runtime.GOOS != "windows" {
		keep = append(keep, unsafe)
	}
	for _, p := range keep {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%q removed: %v", p, err)
		}
	}
}

func TestLaunchRetriesSharedStartFailure(t *testing.T) {
	sentinel := errors.New("private copy made")
	calls := 0
	bin := VerifiedBinary{path: filepath.Join(t.TempDir(), "gone"), protocol: 5, name: "hashicorp/aws",
		retry: func(context.Context) (VerifiedBinary, error) { calls++; return VerifiedBinary{}, sentinel }}
	if _, err := Launch(context.Background(), bin, NewLogger(io.Discard, "hashicorp/aws")); !errors.Is(err, sentinel) || calls != 1 {
		t.Fatalf("Launch = %v after %d retries, want one private retry", err, calls)
	}
}

// An ACL on the binary fails checkOwnerPerm only: the entry is left alone and
// this start makes a private copy.
func TestSharedForeignACLUntouched(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS ACLs")
	}
	r := newRelease(t)
	parent := realTempDir(t)
	vb := mustShared(t, sharedSource(t, r), parent)
	if out, err := exec.Command("chmod", "+a", "everyone allow read", vb.Path()).CombinedOutput(); err != nil {
		t.Fatalf("chmod +a: %v %s", err, out)
	}
	if _, done, err := sharedSource(t, r).discoverShared(context.Background(), parent); done || err != nil {
		t.Fatalf("ACL on the binary: done=%v err=%v, want a private copy", done, err)
	}
	if _, err := os.Stat(vb.Path()); err != nil {
		t.Fatalf("entry removed: %v", err)
	}
}
