//go:build ctftest

package embedded

import _ "embed"

// cisArchive is the test-signed copy of the CIS bundle (go generate).
//
//go:embed cis_ctftest.tar.gz
var cisArchive []byte
