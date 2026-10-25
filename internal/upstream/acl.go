package upstream

// acl.go holds the platform-neutral half of the ACL checks: macOS extended
// ACLs and Windows DACLs are mapped to aclEntry values and judged by checkACL,
// so the policy is tested on every platform.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// aclEntry rights, coarsened from the platform masks.
const (
	aclRead   uint8 = 1 << iota // any right that does not change the object
	aclAdd                      // create an entry in a directory (or write file data)
	aclModify                   // delete, rename children, change attributes, ACL or owner
)

// aclEntry is one ACL entry that applies to an object.
type aclEntry struct {
	who         string // SID or GUID; "" when unknown
	allow       bool   // deny entries only take rights away
	inheritOnly bool   // applies to children, not to the object
	rights      uint8
}

// checkACL refuses an allow entry for anyone but self or a trusted admin
// that grants write (any access when ownOnly). On a sticky-like ancestor
// others may add entries but not delete or rename ours.
func checkACL(entries []aclEntry, self string, trusted map[string]bool, ownOnly, sticky bool) error {
	for _, e := range entries {
		if !e.allow || e.inheritOnly || e.rights == 0 || (e.who != "" && (e.who == self || trusted[e.who])) {
			continue
		}
		who := e.who
		if who == "" {
			who = "(unknown)"
		}
		switch {
		case ownOnly:
			return fmt.Errorf("ACL grants access to %s", who)
		case e.rights&aclModify != 0 || (e.rights&aclAdd != 0 && !sticky):
			return fmt.Errorf("ACL grants write to %s", who)
		}
	}
	return nil
}

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
			who:         fmt.Sprintf("%X-%X-%X-%X-%X", g[0:4], g[4:6], g[6:8], g[8:10], g[10:16]),
			allow:       flags&kauthKindMask == kauthPermit,
			inheritOnly: flags&kauthOnlyInherit != 0,
		}
		e.rights = coarsen(mask, kauthAdd, kauthModify)
		entries = append(entries, e)
	}
	return entries, nil
}

// coarsen maps a platform access mask to aclEntry rights.
func coarsen(mask, add, modify uint32) uint8 {
	var r uint8
	if mask&add != 0 {
		r |= aclAdd
	}
	if mask&modify != 0 {
		r |= aclModify
	}
	if mask&^(add|modify) != 0 {
		r |= aclRead
	}
	return r
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
