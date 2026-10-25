//go:build !unix

package verdict

import (
	"errors"
	"io/fs"
	"os"
)

// openNoFollow fails closed where ownership and symlink checks are not
// implemented: no verdict loads, so verdict_required blocks every change.
func openNoFollow(string) (*os.File, fs.FileInfo, error) {
	return nil, nil, errors.New("verdict files are not supported on this platform")
}

func ownedByUser(fs.FileInfo) bool { return false }
