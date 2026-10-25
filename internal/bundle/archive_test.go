package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/trust"
	"github.com/compliancetf/terraform-provider-aws/internal/trust/testkeys"
)

const simDir = "../../testdata/bundles/bobthecorp-soc2-sim"

// testVerify checks a single-signature envelope against the derived test
// bundle key, so these tests run without the ctftest keyring.
func testVerify(env []byte, payloadType string) (trust.Verified, error) {
	var e struct {
		PayloadType string `json:"payloadType"`
		Payload     string `json:"payload"`
		Signatures  []struct {
			KeyID string `json:"keyid"`
			Sig   string `json:"sig"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(env, &e); err != nil || len(e.Signatures) != 1 || e.PayloadType != payloadType {
		return trust.Verified{}, errors.New("bad envelope")
	}
	payload, _ := base64.StdEncoding.DecodeString(e.Payload)
	sig, _ := base64.StdEncoding.DecodeString(e.Signatures[0].Sig)
	sum := sha256.Sum256(trust.PAE(e.PayloadType, payload))
	if !ecdsa.VerifyASN1(&testkeys.Bundle().PublicKey, sum[:], sig) {
		return trust.Verified{}, errors.New("signature invalid")
	}
	return trust.Verified{Payload: payload, KeyID: e.Signatures[0].KeyID}, nil
}

func readFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(simDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func goodBundle(t *testing.T) *Bundle {
	t.Helper()
	b, err := ReadArchive(readFile(t, "good.tar.gz"), testVerify)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestArchiveGood(t *testing.T) {
	b := goodBundle(t)
	m := b.Manifest
	if m.BundleID != "bobthecorp-soc2" || m.BundleVersion != 12 || m.OrgID != "bobthecorp" || len(b.Controls) != 2 {
		t.Fatalf("manifest %+v, %d controls", m, len(b.Controls))
	}
	if b.Revocations.Epoch() != 1 || !b.Revocations.BundleRevoked("bobthecorp-soc2", 9) {
		t.Fatal("revocations.json not loaded")
	}
	// Bundle digest = sha256 of the raw manifest.dsse.json bytes.
	zr, _ := gzip.NewReader(bytes.NewReader(readFile(t, "good.tar.gz")))
	tr := tar.NewReader(zr)
	_, _ = tr.Next()
	env, _ := io.ReadAll(tr)
	if sum := sha256.Sum256(env); b.Digest != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("digest %s", b.Digest)
	}
	pub, _ := x509.MarshalPKIXPublicKey(&testkeys.Bundle().PublicKey)
	if b.KeyID != trust.KIDFromSPKI(pub) {
		t.Fatalf("kid %s", b.KeyID)
	}
}

// TestArchiveTampered is the oracle: every generated tampered archive
// is rejected, for the reason its name says.
func TestArchiveTampered(t *testing.T) {
	cases := map[string]string{
		"tamper-digest":          "digest mismatch",
		"unlisted-file":          "unlisted",
		"duplicate-entry":        "unlisted",
		"wrong-first":            "must be the first entry",
		"traversal":              "unlisted",
		"absolute":               "unlisted",
		"case-variant":           "unlisted",
		"symlink":                "not a plain USTAR regular file",
		"hardlink":               "not a plain USTAR regular file",
		"oldgnu-sparse":          "not a plain USTAR regular file",
		"pax-sparse":             "not a plain USTAR regular file",
		"pax-path":               "not a plain USTAR regular file",
		"gnu-longname":           "not a plain USTAR regular file",
		"oversize":               "size",
		"size-mismatch":          "size",
		"gzip-bomb":              "decompressed size exceeds",
		"trailing-gzip-member":   "after the gzip member",
		"trailing-garbage":       "after the gzip member",
		"trailing-tar-data":      "trailing data",
		"missing-file":           "missing file",
		"trailing-pax":           "trailing data",
		"trailing-pax-no-marker": "trailing data",
		"nonzero-padding":        "non-zero tar block padding",
		"bad-signature":          "signature invalid",
	}
	names, err := filepath.Glob(filepath.Join(simDir, "*.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, n := range names {
		got = append(got, strings.TrimSuffix(filepath.Base(n), ".tar.gz"))
	}
	slices.Sort(got)
	want := []string{"good"}
	for name := range cases {
		want = append(want, name)
	}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("fixtures %v, want %v (run go generate ./testdata/generate.go)", got, want)
	}
	for name, msg := range cases {
		_, err := ReadArchive(readFile(t, name+".tar.gz"), testVerify)
		if err == nil || !strings.Contains(err.Error(), msg) {
			t.Errorf("%s: got %v, want %q", name, err, msg)
		}
	}
}

// gz gzips one member.
func gz(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	_, _ = zw.Write(data)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestArchiveDecompressedLimit: exactly 32 MiB of decompressed stream (tar
// framing and trailing zeros included) loads; one more byte does not.
func TestArchiveDecompressedLimit(t *testing.T) {
	zr, _ := gzip.NewReader(bytes.NewReader(readFile(t, "good.tar.gz")))
	raw, _ := io.ReadAll(zr)
	for n, ok := range map[int]bool{maxDecompressed: true, maxDecompressed + 1: false} {
		padded := append(append([]byte(nil), raw...), make([]byte, n-len(raw))...)
		_, err := ReadArchive(gz(t, padded), testVerify)
		if (err == nil) != ok {
			t.Errorf("%d bytes: got %v", n, err)
		}
	}
	if _, err := ReadArchive(make([]byte, maxCompressed+1), testVerify); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("compressed limit: got %v", err)
	}
}

func revs(t *testing.T, doc string) trust.Revocations {
	t.Helper()
	r, err := trust.ParseRevocations([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestArchiveCheck(t *testing.T) {
	b := goodBundle(t)
	expires := time.Date(2027, 4, 1, 0, 0, 0, 0, time.UTC)
	none := trust.NoRevocations()
	revokedKey := revs(t, `{"format":"compliancetf.revocations/v1","epoch":2,"revoked_keys":[{"kid":"`+b.KeyID+`","revoked_at":"2026-10-02T00:00:00Z"}],"revoked_bundles":[],"revoked_controls":[]}`)
	revokedBundle := revs(t, `{"format":"compliancetf.revocations/v1","epoch":2,"revoked_keys":[],"revoked_bundles":[{"bundle_id":"bobthecorp-soc2","below_version":13}],"revoked_controls":[]}`)
	cases := []struct {
		name    string
		org     string
		now     time.Time
		revs    trust.Revocations
		warn    bool
		err     string
		expired bool
	}{
		{"fresh", "bobthecorp", expires, none, false, "", false},
		{"in grace", "bobthecorp", expires.Add(48 * time.Hour), none, true, "", false},
		{"grace end", "bobthecorp", expires.Add(ExpiryGrace), none, true, "", false},
		{"expired past grace", "bobthecorp", expires.Add(ExpiryGrace + time.Second), none, false, "expired", true},
		{"revoked key in grace", "bobthecorp", expires.Add(48 * time.Hour), revokedKey, false, "revoked", false},
		{"revoked bundle in grace", "bobthecorp", expires.Add(48 * time.Hour), revokedBundle, false, "revoked", false},
		{"revoked bundle fresh", "bobthecorp", expires, revokedBundle, false, "revoked", false},
		{"wrong org", "othercorp", expires, none, false, "org", false},
		{"issued in the future", "bobthecorp", time.Date(2026, 9, 30, 23, 54, 0, 0, time.UTC), none, false, "issued", false},
		{"issued within skew", "bobthecorp", time.Date(2026, 9, 30, 23, 56, 0, 0, time.UTC), none, false, "", false},
		{"invalid revocation set", "bobthecorp", expires, trust.Revocations{}, false, "revoked", false},
	}
	for _, c := range cases {
		warn, err := b.Check(c.org, c.now, c.revs)
		switch {
		case (warn != "") != c.warn:
			t.Errorf("%s: warning %q", c.name, warn)
		case c.err == "" && err != nil, c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)):
			t.Errorf("%s: got %v, want %q", c.name, err, c.err)
		case errors.Is(err, ErrExpired) != c.expired:
			t.Errorf("%s: errors.Is(ErrExpired) = %v", c.name, !c.expired)
		}
	}
	public := *b
	pm := *b.Manifest
	pm.OrgID = ""
	public.Manifest = &pm
	if _, err := public.Check("othercorp", expires, none); err != nil {
		t.Errorf("public bundle: %v", err)
	}
}

func TestParseManifestRejects(t *testing.T) {
	b := goodBundle(t)
	good, err := json.Marshal(b.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseManifest(good); err != nil {
		t.Fatal(err)
	}
	m := string(good)
	cases := map[string]string{
		"case variant key":   strings.Replace(m, `"profile"`, `"Profile"`, 1),
		"duplicate key":      strings.Replace(m, `"profile":"soc2"`, `"profile":"soc2","profile":"x"`, 1),
		"unknown field":      strings.Replace(m, `"profile"`, `"profil"`, 1),
		"null":               strings.Replace(m, `"label":"2026.10.1"`, `"label":null`, 1),
		"trailing":           m + "{}",
		"long bundle_id":     strings.Replace(m, `"bobthecorp-soc2"`, `"`+strings.Repeat("a", 64)+`"`, 1),
		"fractional version": strings.Replace(m, `"bundle_version":12`, `"bundle_version":12.5`, 1),
		"min above version":  strings.Replace(m, `"min_bundle_version":10`, `"min_bundle_version":13`, 1),
		"unknown file":       strings.Replace(m, `"path":"revocations.json"`, `"path":"extra.json"`, 1),
		"traversal file":     strings.Replace(m, `"path":"revocations.json"`, `"path":"../revocations.json"`, 1),
		"duplicate file":     strings.Replace(m, `"path":"revocations.json"`, `"path":"controls.json"`, 1),
		"no controls.json":   strings.Replace(m, `"path":"controls.json"`, `"path":"revocations.json"`, 1),
		"upper hex digest":   strings.Replace(m, `"sha256":"`, `"sha256":"A`, 1),
		"expires first":      strings.Replace(m, `"2027-04-01T00:00:00Z"`, `"2026-09-01T00:00:00Z"`, 1),
		"format":             strings.Replace(m, ManifestFormat, "compliancetf.bundle-manifest/v1", 1),
	}
	for name, doc := range cases {
		if doc == m {
			t.Fatalf("%s: replacement did not apply", name)
		}
		if _, err := ParseManifest([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestManifestErrorsValueFree: manifest and controls parse errors name the
// field, never a value from the signed manifest or the bound files.
func TestManifestErrorsValueFree(t *testing.T) {
	const marker = "BOBTHECORP-MARKER-2"
	b := goodBundle(t)
	good, err := json.Marshal(b.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	m := string(good)
	for name, doc := range map[string]string{
		"format":        strings.Replace(m, ManifestFormat, marker, 1),
		"bundle_id":     strings.Replace(m, `"bobthecorp-soc2"`, `"`+marker+`"`, 1),
		"schema digest": strings.Replace(m, `"schema_compat_digest":"`, `"schema_compat_digest":"`+marker, 1),
		"issued_at":     strings.Replace(m, `"2027-04-01T00:00:00Z"`, `"`+marker+`"`, 1),
		"file path":     strings.Replace(m, `"path":"revocations.json"`, `"path":"`+marker+`"`, 1),
		"unknown field": strings.Replace(m, `"profile"`, `"`+strings.ToLower(marker)+`"`, 1),
		"bad key":       strings.Replace(m, `"profile"`, `"`+marker+`"`, 1),
		"wrong type":    strings.Replace(m, `"profile":"soc2"`, `"profile":["`+marker+`"]`, 1),
	} {
		if doc == m {
			t.Fatalf("%s: replacement did not apply", name)
		}
		_, err := ParseManifest([]byte(doc))
		if err == nil || strings.Contains(strings.ToLower(err.Error()), strings.ToLower(marker)) {
			t.Errorf("%s: error %v", name, err)
		}
	}
	// Check runs after the manifest parsed; org_id has no format rule.
	other := *b
	om := *b.Manifest
	om.OrgID = marker
	other.Manifest = &om
	if _, err := other.Check("bobthecorp", time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC), trust.NoRevocations()); err == nil || strings.Contains(err.Error(), marker) {
		t.Errorf("Check org mismatch: error %v", err)
	}
	for name, doc := range map[string]string{
		"control id": `[{"id":"` + marker + `"}]`,
		"bad json":   `[` + marker + `]`,
	} {
		_, err := ParseControls([]byte(doc))
		if err == nil {
			t.Fatalf("%s: accepted", name)
		}
		var b Bundle
		err = b.parseFile(ControlsFile, []byte(doc))
		if err == nil || strings.Contains(err.Error(), marker) {
			t.Errorf("controls %s: error %v", name, err)
		}
	}
}

// TestArchiveErrorsValueFree: tar header names and sizes are unsigned input,
// so the errors that reject them carry the entry index only.
func TestArchiveErrorsValueFree(t *testing.T) {
	const marker = "BOBTHECORP-MARKER-1"
	for name, h := range map[string]*tar.Header{
		"first name": {Name: marker, Mode: 0o644, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR},
		"first size": {Name: ManifestEntry, Size: 987654321, Mode: 0o644, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR},
		"not plain":  {Name: marker, Linkname: "x", Mode: 0o644, Typeflag: tar.TypeSymlink, Format: tar.FormatUSTAR},
	} {
		var raw bytes.Buffer
		zw := gzip.NewWriter(&raw)
		tw := tar.NewWriter(zw)
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		zw.Close() //nolint:errcheck,gosec // in-memory; a short body is the point
		_, err := ReadArchive(raw.Bytes(), testVerify)
		if err == nil || strings.Contains(err.Error(), marker) || strings.Contains(err.Error(), "987654321") {
			t.Errorf("%s: error %v", name, err)
		}
	}
	// A corrupt DEFLATE stream: flate errors quote an input offset.
	bad := bytes.Clone(readFile(t, "good.tar.gz"))
	bad[20] ^= 0xff
	if _, err := ReadArchive(bad, testVerify); !errors.Is(err, errCorrupt) {
		t.Errorf("corrupt deflate: error %v", err)
	}
}
