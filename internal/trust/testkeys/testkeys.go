// Package testkeys derives the test signing keys from public labels, so no
// private key material is committed. Their public halves are in
// internal/trust/keyring_test.json, which only ctftest builds trust; release
// keyrings never contain them (TestReleaseKeyring).
package testkeys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
)

// Labels are public by design: anyone can derive these keys.
const (
	bundleLabel  = "compliancetf.test-bundle-key/bobthecorp"
	profileLabel = "compliancetf.test-profile-key/bobthecorp"
	floorLabel   = "compliancetf.test-floor-key/bobthecorp"
	nextLabel    = "compliancetf.test-floor-key-next/bobthecorp"
)

// Bundle is the ES256 (P-256) test key with purpose bundle.
func Bundle() *ecdsa.PrivateKey { return es256(bundleLabel) }

// Floor is the ES256 test key with purpose floor, generation 1.
func Floor() *ecdsa.PrivateKey { return es256(floorLabel) }

// FloorNext is the ES256 test key with purpose floor, generation 2 (the
// compiled next floor key).
func FloorNext() *ecdsa.PrivateKey { return es256(nextLabel) }

// Exception and CustomerKMS are ES256 exception grant signers for the
// internal/exceptions tests. Neither is in keyring_test.json: the tests
// add them through trust.ExceptionKeyring.
func Exception() *ecdsa.PrivateKey { return es256("compliancetf.test-exception-key/bobthecorp") }

// CustomerKMS stands in for a customer KMS key listed in a profile's
// exceptions.grant_keys.
func CustomerKMS() *ecdsa.PrivateKey { return es256("compliancetf.test-customer-kms-key/bobthecorp") }

func es256(label string) *ecdsa.PrivateKey {
	d := sha256.Sum256([]byte(label))
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d[:])
	if err != nil {
		panic(err) // fixed label; cannot fail
	}
	return k
}

// Profile is the Ed25519 test key with purpose profile.
func Profile() ed25519.PrivateKey {
	s := sha256.Sum256([]byte(profileLabel))
	return ed25519.NewKeyFromSeed(s[:])
}
