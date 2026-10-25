//go:build !ctftest

package trust

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

// TestReleaseFloorFailsClosed: while the release keyring has no floor keys,
// VerifyFloor refuses before reading the statement.
func TestReleaseFloorFailsClosed(t *testing.T) {
	kr, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	if kr.checkFloorKeys() == nil {
		t.Skip("release keyring has floor keys; TestReleaseFloorKeyCount covers them")
	}
	_, _, err = VerifyFloor([]byte(`{}`), FloorInput{OrgID: "bobthecorp", Mode: FloorOnline, Now: floorNow,
		Revs: NoRevocations(), State: loadedState(t, nil)})
	if err == nil || !strings.Contains(err.Error(), "floor keys") {
		t.Fatal(err)
	}
}

// TestReleaseKeyring: a build without ctftest trusts no Ed25519 key and no
// kid from keyring_test.json, and its digest is sha256 of keyring.json.
func TestReleaseKeyring(t *testing.T) {
	kr, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("keyring_test.json")
	if err != nil {
		t.Fatal(err)
	}
	testKeys, err := parseKeyring(raw, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range kr.Keys() {
		if k.Alg != AlgES256 {
			t.Errorf("release keyring trusts %s key %s", k.Alg, k.KID)
		}
		for _, tk := range testKeys {
			if tk.KID == k.KID {
				t.Errorf("release keyring trusts test key %s", k.KID)
			}
		}
	}
	sum := sha256.Sum256(keyringJSON)
	if got := KeyringDigest(); got != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Errorf("KeyringDigest = %s", got)
	}
}

// TestReleaseRejectsEd25519: a release build refuses the Ed25519 bundle key
// of the sigbugs set with the allowlist loadEmbedded applies to keyring.json,
// and its embedded keyring does not verify the Ed25519-signed manifest.
func TestReleaseRejectsEd25519(t *testing.T) {
	raw := readSigbug(t, "ed25519-release.keyring.json")
	if _, err := parseKeyring(raw, false); err == nil || err.Error() != "keyring: key 0: alg Ed25519 is not trusted in this build" {
		t.Errorf("release parse of an Ed25519 key: %v", err)
	}
	_ = kidFor(t, mustKeyring(t, raw, true), PurposeBundle) // the Ed25519 key exists under ctftest; the error never names it
	want := "dsse: no valid signature: signature 0: key not in keyring"
	if _, err := Verify(sigbugEnvelope(t, "ed25519-release"), PayloadBundleManifest, NoRevocations()); err == nil || err.Error() != want {
		t.Errorf("release Verify of an Ed25519-signed manifest: got %v, want %q", err, want)
	}
}
