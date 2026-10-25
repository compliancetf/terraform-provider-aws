package trust

import (
	"os"
	"strings"
	"testing"
)

// TestReleaseFloorKeyCount: a keyring must hold exactly two ES256 floor keys
// (current and next) of consecutive generations.
//
// The release keyring.json ships without production keys until the owner
// adds the KMS keys. With zero floor keys it fails closed: VerifyFloor
// refuses every floor statement, so governed runs fail Configure. By default
// this test logs that state; with COMPLIANCETF_RELEASE_KEYRING_CHECK=1 (set by
// the release workflow) zero floor keys fail the test. Any floor key in
// keyring.json makes the two-key rule mandatory in every mode.
func TestReleaseFloorKeyCount(t *testing.T) {
	a, b, c := newP256(t), newP256(t), newP256(t)
	cases := []struct {
		name string
		raw  []byte
		want string // "" passes
	}{
		{"no keys", keyringBytes(), "have 0"},
		{"bundle keys only", keyringBytes(entry(t, a, AlgES256, PurposeBundle, nb, na)), "have 0"},
		{"one floor key", keyringBytes(floorEntry(t, a, 1, nb, na)), "have 1"},
		{"three floor keys", keyringBytes(floorEntry(t, a, 1, nb, na), floorEntry(t, b, 2, nb, na), floorEntry(t, c, 3, nb, na)), "have 3"},
		{"generations 1 and 3", keyringBytes(floorEntry(t, a, 1, nb, na), floorEntry(t, b, 3, nb, na)), "not consecutive"},
		{"same generation", keyringBytes(floorEntry(t, a, 2, nb, na), floorEntry(t, b, 2, nb, na)), "not consecutive"},
		{"current and next", keyringBytes(floorEntry(t, a, 1, nb, na), floorEntry(t, b, 2, nb, na)), ""},
		{"next listed first", keyringBytes(floorEntry(t, a, 5, nb, na), floorEntry(t, b, 4, nb, na)), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := mustKeyring(t, tc.raw, false).checkFloorKeys()
			if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}

	ed := keyringBytes(floorEntry(t, newEd25519(t), 1, nb, na), floorEntry(t, a, 2, nb, na))
	ed = []byte(strings.Replace(string(ed), `"alg": "ES256"`, `"alg": "Ed25519"`, 1))
	if err := mustKeyring(t, ed, true).checkFloorKeys(); err == nil || !strings.Contains(err.Error(), "want ES256") {
		t.Fatalf("Ed25519 floor key: %v", err)
	}

	release := mustKeyring(t, keyringJSON, false)
	err := release.checkFloorKeys()
	nFloor := 0
	for _, k := range release.Keys() {
		if k.Purpose == PurposeFloor {
			nFloor++
		}
	}
	switch {
	case nFloor > 0 && err != nil:
		t.Fatalf("release keyring.json: %v", err)
	case nFloor == 0 && os.Getenv("COMPLIANCETF_RELEASE_KEYRING_CHECK") == "1":
		t.Fatalf("release keyring.json has no floor keys: %v", err)
	case nFloor == 0:
		if err == nil {
			t.Fatal("empty release floor keyring passed checkFloorKeys")
		}
		t.Logf("release keyring.json has no floor keys yet: floor verification fails closed (%v)", err)
	}
}
