//go:build !unix

package bundle

import "os"

// openNoFollow opens p read-only; dirEntry then requires the descriptor to
// be the regular file Lstat sees at p.
func openNoFollow(p string) (*os.File, error) {
	return os.Open(p)
}
