//go:build !ctftest

package fetch

import "crypto/x509"

// endpoint is the compiled bundle service; release builds have no override.
// nil roots means the system pool.
func endpoint() (string, *x509.CertPool) { return baseURL, nil }
