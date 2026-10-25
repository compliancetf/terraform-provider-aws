//go:build unix

package bundle

import (
	"os"
	"syscall"
)

// openNoFollow opens p read-only, failing on a final symlink and never
// blocking on a FIFO.
func openNoFollow(p string) (*os.File, error) {
	return os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}
