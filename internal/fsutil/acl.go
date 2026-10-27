package fsutil

// acl.go holds the platform-neutral ACL policy: macOS extended ACLs
// (internal/upstream) and Windows DACLs are mapped to ACLEntry values and
// judged by CheckACL, so the policy is tested on every platform.

import "fmt"

// ACLEntry rights, coarsened from the platform masks.
const (
	ACLRead   uint8 = 1 << iota // any right that does not change the object
	ACLAdd                      // create an entry in a directory (or write file data)
	ACLModify                   // delete, rename children, change attributes, ACL or owner
)

// ACLEntry is one ACL entry that applies to an object.
type ACLEntry struct {
	Who         string // SID or GUID; "" when unknown
	Allow       bool   // deny entries only take rights away
	InheritOnly bool   // applies to children, not to the object
	Rights      uint8
}

// CheckACL refuses an allow entry for anyone but self or a trusted admin
// that grants write (any access when ownOnly). On a sticky-like ancestor
// others may add entries but not delete or rename ours.
func CheckACL(entries []ACLEntry, self string, trusted map[string]bool, ownOnly, sticky bool) error {
	for _, e := range entries {
		if !e.Allow || e.InheritOnly || e.Rights == 0 || (e.Who != "" && (e.Who == self || trusted[e.Who])) {
			continue
		}
		who := e.Who
		if who == "" {
			who = "(unknown)"
		}
		switch {
		case ownOnly:
			return fmt.Errorf("ACL grants access to %s", who)
		case e.Rights&ACLModify != 0 || (e.Rights&ACLAdd != 0 && !sticky):
			return fmt.Errorf("ACL grants write to %s", who)
		}
	}
	return nil
}

// Coarsen maps a platform access mask to ACLEntry rights.
func Coarsen(mask, add, modify uint32) uint8 {
	var r uint8
	if mask&add != 0 {
		r |= ACLAdd
	}
	if mask&modify != 0 {
		r |= ACLModify
	}
	if mask&^(add|modify) != 0 {
		r |= ACLRead
	}
	return r
}
