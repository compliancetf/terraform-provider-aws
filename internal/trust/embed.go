package trust

import (
	_ "embed"
	"sync"
)

// keyringJSON is the release keyring. It ships empty until the owner adds the
// ES256 KMS public keys; an empty keyring trusts nothing.
//
//go:embed keyring.json
var keyringJSON []byte

var embedded = sync.OnceValues(loadEmbedded)

// Embedded returns the compiled keyring. A parse failure is returned on every
// call, so every Verify fails closed.
func Embedded() (*Keyring, error) {
	return embedded()
}

// KeyringDigest returns the keyring_digest that floor statements bind.
func KeyringDigest() string {
	return keyringDigest()
}
