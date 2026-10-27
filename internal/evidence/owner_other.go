//go:build !unix && !windows

package evidence

import "os"

// Outside unix and Windows the evidence and run directories get no owner or
// mode check and no directory fsync: a weaker guarantee than on unix runners.

func checkOwner(*os.File, os.FileInfo, os.FileMode) error { return nil }

func syncDir(*os.File) error { return nil }

func mkdirRun(root *os.Root, _, name string) error { return root.Mkdir(name, 0o700) }
