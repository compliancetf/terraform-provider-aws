//go:build !unix

package evidence

import "os"

// Outside unix the evidence and run directories get no owner or mode check
// and no directory fsync: a weaker guarantee than on unix runners.

func checkOwner(os.FileInfo, os.FileMode) error { return nil }

func syncDir(*os.File) error { return nil }
