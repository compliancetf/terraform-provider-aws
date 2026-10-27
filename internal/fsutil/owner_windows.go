package fsutil

import (
	"fmt"
	"io/fs"
	"os"
)

// SecureDir refuses a symlink or junction, opens dir and applies checkDir to
// the opened handle (the same directory Lstat saw).
func SecureDir(dir string, repair bool) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() || fi.Mode()&(fs.ModeSymlink|fs.ModeIrregular) != 0 {
		return fmt.Errorf("%s is not a directory (symlinks and junctions are refused)", dir)
	}
	f, err := os.Open(dir) //nolint:gosec // cache path built from validated ids
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck // read-only
	got, err := f.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(fi, got) {
		return fmt.Errorf("%s changed while it was checked", dir)
	}
	return checkDir(f, got, dir, repair)
}

// checkDir requires a directory, open as d, owned by the current user (or a
// trusted admin SID such as Administrators, the default owner of what an
// elevated admin creates) whose DACL lets nobody else write. Unlike unix,
// writers get no repair: a DACL is never rewritten, so a dir others can
// write fails closed for readers and writers alike (an availability cost
// only; the cache is never a trust input).
func checkDir(d *os.File, fi fs.FileInfo, path string, _ bool) error {
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", path)
	}
	if err := WinACLFile(d, false); err != nil {
		return fmt.Errorf("%s: %w; remove it or limit its ACL to the current user", path, err)
	}
	return nil
}
