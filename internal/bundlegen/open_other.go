//go:build !unix

package bundlegen

import "os"

// openNoFollow opens p read-only; readRegular then requires the descriptor
// to be the regular file Lstat sees at p.
const (
	openNonBlock  = 0
	openDirectory = 0
)

func openNoFollow(p string) (*os.File, error) {
	return os.Open(p)
}
