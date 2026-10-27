//go:build unix

package fsutil

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// SecureDir opens dir without following a symlink and applies checkDir.
func SecureDir(dir string, repair bool) error {
	f, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0) //nolint:gosec // cache path built from validated ids
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck // read-only
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	return checkDir(f, fi, dir, repair)
}

// checkDir requires a directory, open as d, owned by this process's uid.
// With repair (writers) it tightens the dir to 0700 through the open handle.
// Without repair (readers) it never changes the dir and refuses one that
// group or others can write, since files planted there must not be read. Any
// other dir fails closed: the caller neither reads nor writes the cache (an
// availability cost only; the cache is never a trust input).
func checkDir(d *os.File, fi fs.FileInfo, path string, repair bool) error {
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", path)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s is not owned by the current user; fix its owner or remove it", path)
	}
	perm := fi.Mode().Perm()
	if !repair {
		if perm&0o022 != 0 {
			return fmt.Errorf("%s is writable by other users (mode %o); run chmod 700 on it", path, perm)
		}
		return nil
	}
	if perm != 0o700 {
		// A failed chmod (read-only filesystem) is fatal only when others
		// could write into the dir.
		if err := d.Chmod(0o700); err != nil && perm&0o022 != 0 {
			return err
		}
	}
	return nil
}

// MkdirPrivate creates dir with mode 0700.
func MkdirPrivate(dir string) error { return os.Mkdir(dir, 0o700) }
