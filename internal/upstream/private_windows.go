package upstream

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows has no O_NOFOLLOW/O_NONBLOCK: sources are resolved before open and
// O_EXCL maps to CREATE_NEW, which fails on any existing entry.
const (
	openNoFollow = 0
	openNonBlock = 0
)

// privateDir creates dir; the per-user profile ACLs under %LocalAppData%
// keep it private.
// shortcut: no ACL check on the download cache; add winACL here if it leaves the user profile.
func privateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("cache %q is not a directory", dir)
	}
	return nil
}

// Well-known SIDs trusted like root: SYSTEM, Administrators, TrustedInstaller,
// and OWNER RIGHTS (the owner is checked separately).
var winTrusted = map[string]bool{
	"S-1-5-18":     true,
	"S-1-5-32-544": true,
	"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464": true,
	"S-1-3-4": true,
}

// winSelf is the current user's SID ("" if unknown, which trusts nobody extra).
var winSelf = sync.OnceValue(func() string {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return ""
	}
	return u.User.Sid.String()
})

// Windows file access bits (winnt.h).
const (
	winAdd    = 0x2 | 0x4 // FILE_ADD_FILE/WRITE_DATA, FILE_ADD_SUBDIRECTORY/APPEND_DATA
	winModify = 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000 |
		0x1000000 | 0x2000000 | 0x10000000 | 0x40000000 // WRITE_EA, DELETE_CHILD, WRITE_ATTRIBUTES, DELETE, WRITE_DAC, WRITE_OWNER, ACCESS_SYSTEM_SECURITY, MAXIMUM_ALLOWED, GENERIC_ALL, GENERIC_WRITE
)

// checkOwnerPerm requires path to be owned by us or a trusted admin SID with
// a DACL that gives nobody else write (ownOnly: any access).
func checkOwnerPerm(path string, _ os.FileInfo, ownOnly bool) error {
	return winACL(path, ownOnly, false)
}

// stickyRootDir: a real directory (no link or junction) such as C:\ that
// lets Authenticated Users create folders but not delete or rename ours,
// like a sticky /tmp.
func stickyRootDir(path string) bool {
	st, err := os.Lstat(path)
	if err != nil || !st.IsDir() || st.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return false
	}
	return winACL(path, false, true) == nil
}

func winACL(path string, ownOnly, sticky bool) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("reading ACL: %w", err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return errors.New("no owner information")
	}
	if o := owner.String(); o != winSelf() && !winTrusted[o] {
		return fmt.Errorf("owned by %s, not %s", o, winSelf())
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return errors.New("no DACL: everyone has full access")
	}
	entries := make([]aclEntry, 0, dacl.AceCount)
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Errorf("reading ACE %d: %w", i, err)
		}
		e := aclEntry{
			allow:       !winDenyACE[ace.Header.AceType],
			inheritOnly: ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0,
			rights:      coarsen(uint32(ace.Mask), winAdd, winModify),
		}
		if ace.Header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE {
			e.who = (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String() //nolint:gosec // G103: the SID starts at SidStart
		} // other allow types (object, callback) put the SID elsewhere: unknown, refused
		entries = append(entries, e)
	}
	return checkACL(entries, winSelf(), winTrusted, ownOnly, sticky)
}

// winDenyACE lists the deny ACE types; they only take rights away.
var winDenyACE = map[byte]bool{1: true, 6: true, 10: true, 12: true}

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
