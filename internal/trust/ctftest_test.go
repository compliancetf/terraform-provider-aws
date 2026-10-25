//go:build ctftest

package trust

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCtftestKeyring(t *testing.T) {
	kr, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	if len(kr.Keys()) == 0 {
		t.Fatal("ctftest build has no test keys")
	}
	sum := sha256.Sum256(keyringJSON)
	if KeyringDigest() == "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatal("ctftest digest equals the release digest")
	}
	// The committed good vector is signed by the keyring_test.json bundle key.
	raw, err := os.ReadFile(filepath.Join("testdata", "dsse", "good.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v dsseVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(v.Envelope, v.PayloadType, NoRevocations()); err != nil {
		t.Fatal(err)
	}
}
