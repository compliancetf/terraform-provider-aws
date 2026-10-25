//go:build !windows

package trust

import (
	"os"
	"syscall"
)

func lockFile(f *os.File) error {
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX) //nolint:gosec // fd fits in int
		if err != syscall.EINTR {
			return err
		}
	}
}

func unlockFile(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_UN) } //nolint:gosec // fd fits in int
