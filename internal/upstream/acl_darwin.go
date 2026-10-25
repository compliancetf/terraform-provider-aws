package upstream

import (
	"encoding/binary"
	"errors"
	"unsafe"

	"golang.org/x/sys/unix"
)

// aclMaxEntries is KAUTH_ACL_MAX_ENTRIES.
const aclMaxEntries = 128

// pathACL reads the extended ACL of path (not following a final symlink).
// x/sys/unix has no Getattrlist wrapper, so it goes through libc syscall(2);
// getattrlist has been number 220 since Mac OS X 10.4. Any failure refuses
// the directory (fail closed).
func pathACL(path string) ([]aclEntry, error) {
	p, err := unix.BytePtrFromString(path)
	if err != nil {
		return nil, err
	}
	al := unix.Attrlist{Bitmapcount: unix.ATTR_BIT_MAP_COUNT, Commonattr: unix.ATTR_CMN_EXTENDED_SECURITY}
	buf := make([]byte, 12+filesecHeader+aclMaxEntries*kauthACESize) // length, attrreference, filesec
	//nolint:gosec,staticcheck // G103: live Go memory for the call; SA1019: no libSystem wrapper exists
	_, _, e := unix.Syscall6(unix.SYS_GETATTRLIST, uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&al)),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), unix.FSOPT_NOFOLLOW, 0)
	if e != 0 {
		return nil, e
	}
	// attrreference: offset from itself (at byte 4) and length of the filesec.
	off, n := int64(int32(binary.NativeEndian.Uint32(buf[4:]))), int64(binary.NativeEndian.Uint32(buf[8:])) //nolint:gosec // attrreference offset is signed
	if n == 0 {
		return nil, nil // no ACL
	}
	if off < 8 || 4+off+n > int64(len(buf)) {
		return nil, errors.New("bad ACL reference")
	}
	return parseFilesec(buf[4+off : 4+off+n])
}
