//go:build unix

package evidence

import (
	"errors"
	"os"
	"syscall"
)

// checkOwner requires the directory to be owned by this process's uid and to
// have none of the permission bits in deny.
func checkOwner(fi os.FileInfo, deny os.FileMode) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Getuid() {
		return errors.New("not owned by the current user")
	}
	if fi.Mode().Perm()&deny != 0 {
		return errors.New("permissions too wide")
	}
	return nil
}

// syncDir fsyncs a directory so a new entry in it survives a crash.
func syncDir(d *os.File) error { return d.Sync() }
