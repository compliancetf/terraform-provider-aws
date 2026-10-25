//go:build !windows

package upstream

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"syscall"
)

const (
	openNoFollow = syscall.O_NOFOLLOW
	openNonBlock = syscall.O_NONBLOCK
)

// currentUID is the uid exec dirs and copies must belong to (tests change it).
var currentUID = os.Getuid()

// privateDir creates dir with mode 0700 and requires it to be a real
// directory owned by the current uid that no group or other can write.
func privateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	switch {
	case !st.IsDir():
		return fmt.Errorf("cache %q is not a directory", dir)
	case !ok || int(sys.Uid) != os.Getuid():
		return fmt.Errorf("cache %q is not owned by the current user", dir)
	case st.Mode().Perm()&0o022 != 0:
		return fmt.Errorf("cache %q is group or world writable", dir)
	}
	return nil
}

// checkOwnerPerm requires path (with Lstat st) to be owned by us (or root,
// unless ownOnly) and not group/world writable, mode bits or ACL; ownOnly
// also forbids any group/world access.
func checkOwnerPerm(path string, st os.FileInfo, ownOnly bool) error {
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("no owner information")
	}
	uid, perm := int(sys.Uid), st.Mode().Perm()
	switch {
	case uid != currentUID && (ownOnly || uid != 0):
		return fmt.Errorf("owned by uid %d, not %d", uid, currentUID)
	case perm&0o022 != 0:
		return fmt.Errorf("group or world writable (mode %#o)", perm)
	case ownOnly && perm&0o077 != 0:
		return fmt.Errorf("accessible to group or others (mode %#o)", perm)
	}
	return unixACL(path, ownOnly, false)
}

// unixACL applies checkACL to path's extended ACL (macOS; none elsewhere).
func unixACL(path string, ownOnly, sticky bool) error {
	entries, err := pathACL(path)
	if err != nil {
		return fmt.Errorf("reading ACL: %w", err)
	}
	return checkACL(entries, macCompatGUID(currentUID), map[string]bool{macCompatGUID(0): true}, ownOnly, sticky)
}

// macCompatGUID is the GUID macOS uses for a uid without a directory record.
func macCompatGUID(uid int) string {
	return fmt.Sprintf("FFFFEEEE-DDDD-CCCC-BBBB-AAAA%08X", uint32(uid)) //nolint:gosec // uids are 32-bit
}

// diskFull reports an out-of-space or quota error.
func diskFull(err error) bool {
	return errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT)
}

// pidNamespace names this process's PID namespace on Linux ("" elsewhere).
// When Linux hides it, a random name keeps this process's tag unique, so it
// sweeps nothing and nothing sweeps its child (a leak, never a wrong delete).
var pidNamespace = sync.OnceValue(func() string {
	ns, err := os.Readlink("/proc/self/ns/pid")
	switch {
	case err == nil:
		return ns
	case runtime.GOOS == "linux":
		return "unknown:" + rand.Text()
	}
	return ""
})

// pidAlive is false only when the process is confirmed gone (ESRCH).
func pidAlive(pid int) bool {
	return !errors.Is(syscall.Kill(pid, 0), syscall.ESRCH)
}

// stickyRootDir reports whether path is a real root-owned directory with the
// sticky bit, in which only an entry's owner can rename or delete it (and
// no ACL lets others do so).
func stickyRootDir(path string) bool {
	st, err := os.Lstat(path)
	if err != nil || !st.IsDir() || st.Mode()&os.ModeSticky == 0 {
		return false
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	return ok && sys.Uid == 0 && unixACL(path, false, true) == nil
}
