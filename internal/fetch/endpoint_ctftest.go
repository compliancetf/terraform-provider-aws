//go:build ctftest

package fetch

import "crypto/x509"

// Test-only endpoint override, compiled only under ctftest.
var testBase string
var testRoots *x509.CertPool

// SetTestEndpoint points both clients at an httptest server for tests in
// other packages; it returns the reset. ctftest builds only.
func SetTestEndpoint(base string, roots *x509.CertPool) (reset func()) {
	testBase, testRoots = base, roots
	return func() { testBase, testRoots = "", nil }
}

func endpoint() (string, *x509.CertPool) {
	if testBase != "" {
		return testBase, testRoots
	}
	return baseURL, nil
}
