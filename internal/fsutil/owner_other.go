//go:build !unix && !windows

package fsutil

import (
	"fmt"
	"io/fs"
	"os"
)

// SecureDir outside unix only refuses a symlink or a non-directory: there is
// no owner check and no mode change (a weaker guarantee than on unix).
func SecureDir(dir string, _ bool) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	return checkDir(nil, fi, dir, false)
}

func checkDir(_ *os.File, fi fs.FileInfo, path string, _ bool) error {
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", path)
	}
	return nil
}

// MkdirPrivate creates dir with mode 0700.
func MkdirPrivate(dir string) error { return os.Mkdir(dir, 0o700) }
