package bundle

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

// sigbugs is the signature rejection set (ctfbundle sigbugs). The
// DSSE errors per fixture are pinned in internal/trust TestSigBugs; here the
// same files go through the archive reader and Check.
var sigbugs = []string{"unsigned", "tampered-payload", "untrusted-key", "empty-keyring", "ed25519-release", "revoked-in-grace"}

func readSigbug(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "sigbugs", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSigBugs(t *testing.T) {
	// An empty keyring trusts nothing: every fixture, signed or not, fails in
	// ReadArchive before its manifest is parsed.
	var empty trust.Keyring
	emptyVerify := func(env []byte, pt string) (trust.Verified, error) {
		return empty.Verify(env, pt, trust.NoRevocations())
	}
	for _, name := range sigbugs {
		t.Run(name, func(t *testing.T) {
			_, err := ReadArchive(readSigbug(t, name+".tar.gz"), emptyVerify)
			want := ": key not in keyring"
			if name == "unsigned" {
				want = "dsse: need 1 to 8 signatures"
			}
			if err == nil || !strings.HasPrefix(err.Error(), "dsse: ") || !strings.HasSuffix(err.Error(), want) {
				t.Fatalf("got %v, want ...%q", err, want)
			}
		})
	}

	// revoked-in-grace: a verified bundle inside its 7-day expiry grace loads
	// with a warning, and is refused outright once revoked (by bundle or by
	// signing key): a revoked bundle gets no grace.
	b, err := ReadArchive(readSigbug(t, "revoked-in-grace.tar.gz"), testVerify)
	if err != nil {
		t.Fatal(err)
	}
	m := b.Manifest
	inGrace := m.expires.Add(48 * time.Hour)
	if warn, err := b.Check("bobthecorp", inGrace, trust.NoRevocations()); err != nil || warn == "" {
		t.Fatalf("control: in grace without revocations: warn %q err %v", warn, err)
	}
	revDocs := map[string]string{
		"bundle": `"revoked_keys":[],"revoked_bundles":[{"bundle_id":"` + m.BundleID + `","below_version":13}]`,
		"key":    `"revoked_keys":[{"kid":"` + b.KeyID + `","revoked_at":"2026-10-02T00:00:00Z"}],"revoked_bundles":[]`,
	}
	want := "bundle bobthecorp-soc2 v12 (" + b.Digest + ") is revoked"
	for by, doc := range revDocs {
		r := revs(t, `{"format":"compliancetf.revocations/v1","epoch":4,`+doc+`,"revoked_controls":[]}`)
		warn, err := b.Check("bobthecorp", inGrace, r)
		if warn != "" || err == nil || err.Error() != want {
			t.Errorf("revoked by %s in grace: warn %q err %v, want %q", by, warn, err, want)
		}
	}
}

// TestConfigAnchorsIgnored (bundle side): bundle contents cannot carry key
// material; a manifest listing a keyring file is rejected.
func TestConfigAnchorsIgnored(t *testing.T) {
	raw := readFile(t, "manifest.json")
	for _, name := range []string{"keyring.json", "keyring_test.json", "trusted_keys.json"} {
		withFiles := strings.Replace(string(raw), `"issued_at"`,
			`"files":[{"path":"controls.json","sha256":"`+strings.Repeat("0", 64)+`","size":1},{"path":"`+name+`","sha256":"`+strings.Repeat("0", 64)+`","size":1}],"issued_at"`, 1)
		want := "manifest file 1 is unknown or listed twice" // the signed name is not echoed
		if _, err := ParseManifest([]byte(withFiles)); err == nil || err.Error() != want {
			t.Errorf("%s: got %v, want %q", name, err, want)
		}
	}
}
