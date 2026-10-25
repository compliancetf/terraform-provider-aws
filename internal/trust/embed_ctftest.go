//go:build ctftest

package trust

import (
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"slices"
)

// keyringTestJSON holds dev and test keys; it is compiled only under ctftest.
//
//go:embed keyring_test.json
var keyringTestJSON []byte

// loadEmbedded parses keyring.json with the release allowlist (ES256 only)
// and keyring_test.json with Ed25519 allowed; a kid in both files fails.
// Release floor keys are dropped: their statements can never bind the
// ctftest keyring digest, and the floor anchors must be exactly the current
// and next test keys.
func loadEmbedded() (*Keyring, error) {
	release, err := parseKeyring(keyringJSON, false)
	if err != nil {
		return nil, err
	}
	test, err := parseKeyring(keyringTestJSON, true)
	if err != nil {
		return nil, err
	}
	if _, err := newKeyring(release, test); err != nil { // a kid in both files
		return nil, err
	}
	release = slices.DeleteFunc(release, func(k Key) bool { return k.Purpose == PurposeFloor })
	return newKeyring(release, test)
}

// keyringDigest under ctftest is domain separated and covers both files, so
// a test-signed artifact can never bind a release keyring digest.
func keyringDigest() string {
	h := sha256.New()
	h.Write([]byte("compliancetf.keyring-digest/ctftest\x00"))
	for _, b := range [][]byte{keyringJSON, keyringTestJSON} {
		h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(b))))
		h.Write(b)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}
