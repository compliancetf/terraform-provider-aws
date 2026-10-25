//go:build !darwin && !windows

package upstream

// pathACL: Linux POSIX ACLs are bounded by the group mode bits (the mask),
// which checkOwnerPerm already checks.
func pathACL(string) ([]aclEntry, error) { return nil, nil }
