package upstream

// acl.go maps macOS extended ACLs to aclEntry values for fsutil.CheckACL
// (Windows DACLs are read in internal/fsutil).

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/compliancetf/terraform-provider-aws/internal/fsutil"
)

// The ACL policy is shared with the cache and evidence checks.
type aclEntry = fsutil.ACLEntry

const (
	aclRead   = fsutil.ACLRead
	aclAdd    = fsutil.ACLAdd
	aclModify = fsutil.ACLModify
)

// macOS kauth ACE bits (sys/kauth.h).
const (
	kauthMagic       uint32 = 0x012cc16d
	kauthNoACL              = 0xFFFFFFFF
	kauthPermit             = 1
	kauthKindMask           = 0xf
	kauthOnlyInherit        = 1 << 8
	kauthAdd                = 1<<2 | 1<<5                                                // WRITE_DATA/ADD_FILE, APPEND_DATA/ADD_SUBDIRECTORY
	kauthModify             = 1<<4 | 1<<6 | 1<<8 | 1<<10 | 1<<12 | 1<<13 | 1<<21 | 1<<23 // DELETE, DELETE_CHILD, WRITE_(EXT)ATTRIBUTES, WRITE_SECURITY, CHANGE_OWNER, GENERIC_ALL, GENERIC_WRITE
	filesecHeader           = 44                                                         // magic, owner and group GUIDs, entrycount, flags
	kauthACESize            = 24                                                         // GUID, flags, rights
)

// parseFilesec decodes a kauth_filesec (getattrlist ATTR_CMN_EXTENDED_SECURITY).
// The magic number tells the byte order.
func parseFilesec(b []byte) ([]aclEntry, error) {
	if len(b) < filesecHeader {
		return nil, errors.New("short ACL")
	}
	var order binary.ByteOrder = binary.LittleEndian
	switch kauthMagic {
	case binary.LittleEndian.Uint32(b):
	case binary.BigEndian.Uint32(b):
		order = binary.BigEndian
	default:
		return nil, errors.New("bad ACL magic")
	}
	n := order.Uint32(b[36:])
	if n == kauthNoACL {
		return nil, nil
	}
	if uint64(len(b)) != filesecHeader+uint64(n)*kauthACESize {
		return nil, fmt.Errorf("ACL of %d bytes for %d entries", len(b), n)
	}
	entries := make([]aclEntry, 0, n)
	for a := b[filesecHeader:]; len(a) > 0; a = a[kauthACESize:] {
		g, flags, mask := a[:16], order.Uint32(a[16:]), order.Uint32(a[20:])
		e := aclEntry{
			Who:         fmt.Sprintf("%X-%X-%X-%X-%X", g[0:4], g[4:6], g[6:8], g[8:10], g[10:16]),
			Allow:       flags&kauthKindMask == kauthPermit,
			InheritOnly: flags&kauthOnlyInherit != 0,
		}
		e.Rights = fsutil.Coarsen(mask, kauthAdd, kauthModify)
		entries = append(entries, e)
	}
	return entries, nil
}

// stripWinPrefix drops the \\?\ and \\.\ prefixes (and \\?\UNC\ -> \\) so
// both spellings of a Windows path compare equal. Volume GUID paths keep theirs.
func stripWinPrefix(p string) string {
	for _, pre := range []string{`\\?\`, `\\.\`} {
		if len(p) < len(pre) || p[:len(pre)] != pre {
			continue
		}
		rest := p[len(pre):]
		if len(rest) >= 4 && strings.EqualFold(rest[:4], `UNC\`) {
			return `\\` + rest[4:]
		}
		if len(rest) >= 2 && rest[1] == ':' {
			return rest
		}
	}
	return p
}
