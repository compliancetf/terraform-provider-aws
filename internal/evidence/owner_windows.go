package evidence

import (
	"os"

	"github.com/compliancetf/terraform-provider-aws/internal/fsutil"
)

// checkOwner requires the directory, open as d, to be owned by the current
// user (or a trusted admin SID) with a DACL that gives nobody else write;
// when deny covers more than the write bits (the run dir, 0o077), nobody
// else may have any access.
func checkOwner(d *os.File, _ os.FileInfo, deny os.FileMode) error {
	return fsutil.WinACLFile(d, deny&^0o022 != 0)
}

// syncDir: Windows cannot fsync a directory handle.
func syncDir(*os.File) error { return nil }
