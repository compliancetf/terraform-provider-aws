package upstream

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/compliancetf/terraform-provider-aws/internal/fsutil"
)

// Windows has no O_NOFOLLOW/O_NONBLOCK: sources are resolved before open and
// O_EXCL maps to CREATE_NEW, which fails on any existing entry.
const (
	openNoFollow = 0
	openNonBlock = 0
)

// privateDir creates dir and requires it to be a real directory (no link or
// junction) owned by the current user or a trusted admin SID, with a DACL
// that lets nobody else write it or what is created in it. The DACL is read
// through the handle of the directory Lstat saw.
func privateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return fmt.Errorf("cache %q is not a directory", dir)
	}
	d, err := os.Open(dir) //nolint:gosec // the user cache dir
	if err != nil {
		return err
	}
	defer d.Close() //nolint:errcheck // read-only
	if got, err := d.Stat(); err != nil || !os.SameFile(st, got) {
		return fmt.Errorf("cache %q changed while it was checked", dir)
	}
	if err := fsutil.WinACLFile(d, false); err != nil {
		return fmt.Errorf("cache %q: %w", dir, err)
	}
	return nil
}

// checkOwnerPerm requires path to be owned by us or a trusted admin SID with
// a DACL that gives nobody else write (ownOnly: any access).
func checkOwnerPerm(path string, _ os.FileInfo, ownOnly bool) error {
	return fsutil.WinACL(path, ownOnly, false)
}

// stickyRootDir: a real directory (no link or junction) such as C:\ that
// lets Authenticated Users create folders but not delete or rename ours,
// like a sticky /tmp.
func stickyRootDir(path string) bool {
	st, err := os.Lstat(path)
	if err != nil || !st.IsDir() || st.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return false
	}
	return fsutil.WinACL(path, false, true) == nil
}

// diskFull reports ERROR_DISK_FULL or ERROR_HANDLE_DISK_FULL.
func diskFull(err error) bool {
	return errors.Is(err, syscall.Errno(112)) || errors.Is(err, syscall.Errno(39))
}

// pidNamespace: Windows has no PID namespaces.
func pidNamespace() string { return "" }

const (
	stillActive                    = 259    // STILL_ACTIVE
	processQueryLimitedInformation = 0x1000 // PROCESS_QUERY_LIMITED_INFORMATION
	errorInvalidParameter          = syscall.Errno(87)
)

// pidAlive is false only when the process is confirmed gone: no such PID, or
// an exit code other than STILL_ACTIVE. Any other failure counts as alive.
func pidAlive(pid int) bool {
	h, err := syscall.OpenProcess(processQueryLimitedInformation, false, uint32(pid)) //nolint:gosec // pid > 0 checked by caller
	if err != nil {
		return !errors.Is(err, errorInvalidParameter)
	}
	defer syscall.CloseHandle(h) //nolint:errcheck // query handle
	var code uint32
	if err := syscall.GetExitCodeProcess(h, &code); err != nil {
		return true
	}
	return code == stillActive
}

// fileID: Lstat on Windows does not expose the file index.
// shortcut: Windows stamps hold size and mtime only; read the index with GetFileInformationByHandle if stamps need it.
func fileID(os.FileInfo) (dev, ino uint64) { return 0, 0 }

// sealed: Windows has no link count or mode bits here; winACL covers access.
func sealed(os.FileInfo) bool { return true }
