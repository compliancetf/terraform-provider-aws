//go:build unix

package verdict

import (
	"io/fs"
	"os"
	"syscall"
)

// openNoFollow opens path read-only without following a final symlink and
// without blocking on a FIFO, and returns the fstat of the opened file, so
// every check applies to the bytes read.
func openNoFollow(path string) (*os.File, fs.FileInfo, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) //nolint:gosec // the path comes from ctfkit apply; checked after open
	if err != nil {
		return nil, nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close() //nolint:errcheck,gosec // read-only
		return nil, nil, err
	}
	return f, fi, nil
}

// ownedByUser reports whether fi is owned by this process's uid.
func ownedByUser(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Getuid()
}
