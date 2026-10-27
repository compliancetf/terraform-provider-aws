package fsutil

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

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

const winSecurityInfo = windows.OWNER_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION

// WinACL requires path to be owned by the current user or a trusted admin
// SID, with a DACL that gives nobody else write (ownOnly: any access; sticky:
// others may add entries but not delete or rename them).
func WinACL(path string, ownOnly, sticky bool) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, winSecurityInfo)
	if err != nil {
		return fmt.Errorf("reading ACL: %w", err)
	}
	return winCheckSD(sd, ownOnly, sticky)
}

// WinACLFile is WinACL on the open file f, with no lookup by path, so a
// directory swapped after it was opened is never the one checked.
func WinACLFile(f *os.File, ownOnly bool) error {
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT, winSecurityInfo)
	if err != nil {
		return fmt.Errorf("reading ACL: %w", err)
	}
	return winCheckSD(sd, ownOnly, false)
}

func winCheckSD(sd *windows.SECURITY_DESCRIPTOR, ownOnly, sticky bool) error {
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
	entries := make([]ACLEntry, 0, dacl.AceCount)
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Errorf("reading ACE %d: %w", i, err)
		}
		e := ACLEntry{
			Allow:       !winDenyACE[ace.Header.AceType],
			InheritOnly: ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0,
			Rights:      Coarsen(uint32(ace.Mask), winAdd, winModify),
		}
		if ace.Header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE {
			e.Who = (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String() //nolint:gosec // G103: the SID starts at SidStart
		} // other allow types (object, callback) put the SID elsewhere: unknown, refused
		entries = append(entries, e)
	}
	return CheckACL(entries, winSelf(), winTrusted, ownOnly, sticky)
}

// MkdirPrivate creates dir with a protected DACL (nothing inherited) that
// gives the current user, SYSTEM and Administrators full control and nobody
// else access, as mode 0700 does on unix.
func MkdirPrivate(dir string) error {
	self := winSelf()
	if self == "" {
		return &os.PathError{Op: "mkdir", Path: dir, Err: errors.New("current user SID unknown")}
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + self + ")")
	if err != nil {
		return &os.PathError{Op: "mkdir", Path: dir, Err: err}
	}
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return &os.PathError{Op: "mkdir", Path: dir, Err: err}
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd} //nolint:gosec // G103: struct size
	if err := windows.CreateDirectory(p, sa); err != nil {
		return &os.PathError{Op: "mkdir", Path: dir, Err: err}
	}
	return nil
}

// winDenyACE lists the deny ACE types; they only take rights away.
var winDenyACE = map[byte]bool{1: true, 6: true, 10: true, 12: true}
