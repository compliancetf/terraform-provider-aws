// Package fsutil holds the directory checks shared by the local caches
// (bundle and profile), so a different local user cannot plant or swap
// cache files. Signatures stay the trust boundary; these checks only keep
// other users out.
package fsutil

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// OpenTree checks root and every directory below it down to dir, and returns
// dir as an *os.Root opened through the checked handles: each component is
// opened inside its already checked parent, refused if it is a symlink, and
// checked (checkDir) through its own open handle. Later reads and writes go
// through the returned Root, so a component renamed or swapped after the
// check is never followed. Ancestors of root (the user's home) are not
// checked. With create, missing dirs are made 0700 one component at a time
// inside a checked parent and modes are tightened (writers). Without create
// (readers) nothing is changed and a dir others can write fails.
func OpenTree(root, dir string, create bool) (*os.Root, error) {
	rel, err := filepath.Rel(root, dir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("%s is outside the cache %s", dir, root)
	}
	if create {
		// The dirs below root inherit its DACL on Windows, so root is made private.
		if err := os.MkdirAll(filepath.Dir(root), 0o700); err != nil {
			return nil, err
		}
		if err := MkdirPrivate(root); err != nil && !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
	}
	r, err := openChecked(nil, root, root, create)
	if err != nil || rel == "." {
		return r, err
	}
	p := root
	for _, c := range strings.Split(rel, string(filepath.Separator)) {
		p = filepath.Join(p, c)
		if create {
			if err := r.Mkdir(c, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
				r.Close() //nolint:errcheck,gosec // read-only handle
				return nil, err
			}
		}
		next, err := openChecked(r, c, p, create)
		r.Close() //nolint:errcheck,gosec // read-only handle
		if err != nil {
			return nil, err
		}
		r = next
	}
	return r, nil
}

// openChecked opens name (in parent, or as a path when parent is nil) as a
// Root. The name must not be a symlink, and the opened dir must be the one
// Lstat saw, so a swap between the two is refused.
func openChecked(parent *os.Root, name, path string, repair bool) (*os.Root, error) {
	lstat, open := os.Lstat, os.OpenRoot
	if parent != nil {
		lstat, open = parent.Lstat, parent.OpenRoot
	}
	fi, err := lstat(name)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("%s is not a directory (symlinks are refused)", path)
	}
	r, err := open(name)
	if err != nil {
		return nil, err
	}
	if err := checkOpened(r, fi, path, repair); err != nil {
		r.Close() //nolint:errcheck,gosec // read-only handle
		return nil, err
	}
	return r, nil
}

func checkOpened(r *os.Root, want fs.FileInfo, path string, repair bool) error {
	d, err := r.Open(".")
	if err != nil {
		return err
	}
	defer d.Close() //nolint:errcheck // read-only
	got, err := d.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(want, got) {
		return fmt.Errorf("%s changed while it was checked", path)
	}
	return checkDir(d, got, path, repair)
}

// ReadFile reads name in r: a regular file of at most maxBytes. os.Root
// follows a symlink inside the root on open (it ignores O_NOFOLLOW), so the
// name must Lstat as a regular file and the opened file must be that same
// file: a name swapped for a symlink in between is refused, never followed.
func ReadFile(r *os.Root, name string, maxBytes int64) ([]byte, error) {
	fi, err := r.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", name)
	}
	f, err := r.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only
	if got, err := f.Stat(); err != nil || !os.SameFile(fi, got) {
		return nil, fmt.Errorf("%s changed while it was read", name)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxBytes {
		return nil, fmt.Errorf("%s: larger than %d bytes", name, maxBytes)
	}
	return b, nil
}

// ReadDir lists the entries of the dir r is opened on.
func ReadDir(r *os.Root) ([]os.DirEntry, error) {
	d, err := r.Open(".")
	if err != nil {
		return nil, err
	}
	defer d.Close() //nolint:errcheck // read-only
	return d.ReadDir(-1)
}
