//go:build !ctftest

package trust

import (
	"crypto/sha256"
	"encoding/hex"
)

func loadEmbedded() (*Keyring, error) {
	keys, err := parseKeyring(keyringJSON, false)
	if err != nil {
		return nil, err
	}
	return newKeyring(keys)
}

// keyringDigest is "sha256:" + hex(sha256(keyring.json bytes)).
func keyringDigest() string {
	sum := sha256.Sum256(keyringJSON)
	return "sha256:" + hex.EncodeToString(sum[:])
}
