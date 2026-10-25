//go:build !ctftest

package wrapper

// cisPath is the CIS archive the compiled release keyring verifies. The CIS
// bundle error rows need test-signed archives: cis_ctftest_test.go.
const cisPath = "../embedded/cis.tar.gz"
