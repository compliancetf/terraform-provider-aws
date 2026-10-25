//go:build unix

package bundlegen

import (
	"os"
	"syscall"
)

// openNoFollow opens p read-only, failing on a final symlink and never
// blocking on a FIFO.
// openNonBlock is the extra flag for opens under an os.Root: never block on
// a FIFO swapped in after a check.
const openNonBlock = syscall.O_NONBLOCK

// openDirectory makes an open fail at once on anything but a directory.
const openDirectory = syscall.O_DIRECTORY

func openNoFollow(p string) (*os.File, error) {
	return os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}
