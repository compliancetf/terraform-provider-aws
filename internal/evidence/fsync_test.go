package evidence

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Every directory Open creates on the way to evidence_dir has its parent
// fsynced, so a crash cannot drop the new entry and orphan the chain.
func TestOpenSyncsCreatedParents(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "a", "b", "evidence")
	synced := map[string]bool{}
	w, err := Open(Options{
		Dir:     dir,
		Run:     Run{ID: "bobthecorp-run-1", IDSource: "compliancetf"},
		dirSync: func(d *os.File) error { synced[filepath.Clean(d.Name())] = true; return syncDir(d) },
	})
	if err != nil {
		t.Fatal(err)
	}
	must(t, w.Close())
	for _, p := range []string{base, filepath.Join(base, "a"), filepath.Join(base, "a", "b")} {
		if !synced[p] {
			t.Errorf("parent %s of a created dir not fsynced (synced: %v)", p, synced)
		}
	}
}

func TestOpenRejectsFileAncestor(t *testing.T) {
	base := t.TempDir()
	if err := os.WriteFile(filepath.Join(base, "a"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Open(Options{Dir: filepath.Join(base, "a", "evidence"), Run: Run{ID: "bobthecorp-run-1", IDSource: "compliancetf"}})
	wantClass(t, err, ClassOpen)
}

func TestOpenParentSyncFailure(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", "evidence")
	_, err := Open(Options{
		Dir:     dir,
		Run:     Run{ID: "bobthecorp-run-1", IDSource: "compliancetf"},
		dirSync: func(*os.File) error { return errors.New("i/o error") },
	})
	wantClass(t, err, ClassOpen)
}
