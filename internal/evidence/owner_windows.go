package evidence

import (
	"os"
	"path/filepath"

	"github.com/compliancetf/terraform-provider-aws/internal/fsutil"
)

// checkOwner requires the directory, open as d, to be owned by the current
// user (or a trusted admin SID) with a DACL that gives nobody else write,
// itself or what is created in it; when deny covers more than the write bits
// (the run dir, 0o077), nobody else may have any access.
func checkOwner(d *os.File, _ os.FileInfo, deny os.FileMode) error {
	return fsutil.WinACLFile(d, deny&^0o022 != 0)
}

// mkdirRun creates the run dir name (a single path component) in the
// evidence dir with a private DACL, as mode 0700 on unix; inheriting the
// evidence dir's DACL could let others read it. It is created by path:
// openDir then opens it through root and checks that handle.
func mkdirRun(_ *os.Root, dir, name string) error {
	return fsutil.MkdirPrivate(filepath.Join(dir, name))
}

// syncDir: Windows cannot fsync a directory handle.
func syncDir(*os.File) error { return nil }
