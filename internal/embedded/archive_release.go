//go:build !ctftest

package embedded

import _ "embed"

// cisArchive is signed with the production bundle key; only the release
// keyring verifies it.
//
//go:embed cis.tar.gz
var cisArchive []byte
