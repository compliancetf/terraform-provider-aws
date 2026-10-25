package profile

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

// derivedP256 is a test-only P-256 key from a public label; it is in no keyring.
func derivedP256(label string) *ecdsa.PrivateKey {
	d := sha256.Sum256([]byte(label))
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d[:])
	if err != nil {
		panic(err)
	}
	return k
}

func grantKey(pub crypto.PublicKey, alg, notAfter string) map[string]any {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic(err)
	}
	return map[string]any{"kid": trust.KIDFromSPKI(der), "alg": alg, "spki_b64": base64.StdEncoding.EncodeToString(der),
		"not_before": "2026-01-01T00:00:00Z", "not_after": notAfter}
}

func withGrantKeys(version int, keys ...map[string]any) []byte {
	return basePayload(version, func(m map[string]any) { m["exceptions"].(map[string]any)["grant_keys"] = keys })
}

// TestKeyAlgAllowlist: a profile grant key with any alg but ES256 (Ed25519
// only in ctftest builds), or whose SPKI is not the key its alg names,
// rejects the whole profile; a key window is limited to the profile's expiry.
func TestKeyAlgAllowlist(t *testing.T) {
	p256 := derivedP256("compliancetf.test-grant-key/bobthecorp")
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edPub := testKey.Public()
	const na = "2027-01-01T00:00:00Z"

	for _, alg := range []string{"ES384", "RS256", "EdDSA", "es256", "none", ""} {
		k := grantKey(p256.Public(), alg, na)
		want := "profile: exceptions: grant key 0: alg not allowed" // the signed value is not echoed
		if _, _, err := Parse(withGrantKeys(7, k)); err == nil || err.Error() != want {
			t.Errorf("alg %q: got %v, want %q", alg, err, want)
		}
	}
	for name, k := range map[string]map[string]any{
		"ES256 label on P-384 key":   grantKey(p384.Public(), trust.AlgES256, na),
		"ES256 label on Ed25519 key": grantKey(edPub, trust.AlgES256, na),
	} {
		want := "profile: exceptions: grant key 0: spki_b64 is not an ES256 (P-256) key"
		if _, _, err := Parse(withGrantKeys(7, k)); err == nil || err.Error() != want {
			t.Errorf("%s: got %v, want %q", name, err, want)
		}
	}
	ed := grantKey(edPub, trust.AlgEd25519, na)
	_, _, err = Parse(withGrantKeys(7, ed))
	if allowEd25519 && err != nil {
		t.Errorf("ctftest: Ed25519 grant key rejected: %v", err)
	}
	if want := "profile: exceptions: grant key 0: alg not allowed"; !allowEd25519 && (err == nil || err.Error() != want) {
		t.Errorf("release: Ed25519 grant key: got %v, want %q", err, want)
	}
	if allowEd25519 {
		if _, _, err := Parse(withGrantKeys(7, grantKey(p256.Public(), trust.AlgEd25519, na))); err == nil {
			t.Error("Ed25519 label on a P-256 key accepted")
		}
	}

	// The key window ends no later than the profile:
	// a grant key never outlives the signed statement that vouches for it.
	p, _, err := Parse(withGrantKeys(7, grantKey(p256.Public(), trust.AlgES256, na)))
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Exceptions.GrantKeys[0].NotAfter; !got.Equal(p.ExpiresAt) {
		t.Errorf("grant key not_after %s, want the profile expires_at %s", got, p.ExpiresAt)
	}
	short := grantKey(p256.Public(), trust.AlgES256, "2026-10-10T00:00:00Z")
	if p, _, err := Parse(withGrantKeys(7, short)); err != nil || !p.Exceptions.GrantKeys[0].NotAfter.Equal(time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("shorter key window changed: %v", err)
	}
	late := grantKey(p256.Public(), trust.AlgES256, na)
	late["not_before"] = "2026-10-30T00:00:00Z" // the profile's expires_at
	if want := "profile: exceptions: grant key 0: empty validity window"; func() bool {
		_, _, err := Parse(withGrantKeys(7, late))
		return err == nil || err.Error() != want
	}() {
		t.Error("grant key valid only after the profile expires accepted")
	}
}

// TestConfigAnchorsIgnored (profile side): grant keys reach a caller only
// inside the one complete profile Resolve selects. Keys from a profile with
// a bad signature or below the floor are never exposed, and a profile key is
// never a DSSE trust anchor.
func TestConfigAnchorsIgnored(t *testing.T) {
	gk := derivedP256("compliancetf.test-grant-key/bobthecorp")
	key := grantKey(gk.Public(), trust.AlgES256, "2027-01-01T00:00:00Z")
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	badSig := signProfile(withGrantKeys(8, key))
	var env map[string]any
	_ = json.Unmarshal(badSig, &env)
	s := env["signatures"].([]any)[0].(map[string]any)
	sig, _ := base64.StdEncoding.DecodeString(s["sig"].(string))
	sig[0] ^= 1
	s["sig"] = base64.StdEncoding.EncodeToString(sig)
	badSig, _ = json.Marshal(env)

	src := Sources{
		HCLPath:  write("hcl.dsse.json", badSig),                             // v8, carries the key, bad signature
		EnvPath:  write("env.dsse.json", signProfile(withGrantKeys(6, key))), // v6, carries the key, below the floor
		CacheDir: cacheWith(t, map[string]string{"v7.dsse.json": "v7"}),      // committed v7 fixture
	}
	org := Org{ID: "bobthecorp"}
	r, err := Resolve(Input{Org: org, Candidates: LoadCandidates(src, org.ID, trust.NoRevocations()), MinVersion: 7,
		FloorMode: FloorOnline, ProviderVersion: "0.3.0", Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if r.Profile == nil || r.Profile.ProfileVersion != 7 {
		t.Fatalf("resolved %+v: want the committed v7", r.Profile)
	}
	for _, k := range r.Profile.Exceptions.GrantKeys {
		if k.KID == key["kid"] {
			t.Fatalf("grant key %s from a rejected profile reached the resolved v7", k.KID)
		}
	}

	// Without the v7 copy nothing is acceptable: no profile, no keys.
	src.CacheDir = ""
	r, err = Resolve(Input{Org: org, Candidates: LoadCandidates(src, org.ID, trust.NoRevocations()), MinVersion: 7,
		FloorMode: FloorOnline, ProviderVersion: "0.3.0", Now: now})
	if err != nil || r.Profile != nil || r.Fallback != HardFailFloor {
		t.Fatalf("no acceptable profile: %+v %v", r, err)
	}

	// A profile-listed key does not verify any DSSE payload type, even when
	// it comes from a valid profile.
	if p, _, err := Parse(withGrantKeys(7, key)); err != nil || len(p.Exceptions.GrantKeys) != 1 {
		t.Fatalf("valid profile with K: %v", err)
	}
	payload := []byte(`{"issued_at":"2026-10-05T00:00:00Z"}`)
	sum := sha256.Sum256(trust.PAE(trust.PayloadExceptionGrant, payload))
	gsig, err := gk.Sign(nil, sum[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	grant, _ := json.Marshal(map[string]any{"payloadType": trust.PayloadExceptionGrant, "payload": base64.StdEncoding.EncodeToString(payload),
		"signatures": []map[string]string{{"keyid": key["kid"].(string), "sig": base64.StdEncoding.EncodeToString(gsig)}}})
	want := "dsse: no valid signature: signature 0: key not in keyring"
	if _, err := trust.Verify(grant, trust.PayloadExceptionGrant, trust.NoRevocations()); err == nil || err.Error() != want {
		t.Errorf("grant signed by a profile key: got %v, want %q", err, want)
	}
}

// TestKeyAlgAllowlistCheckKeyAlg pins checkKeyAlg on its own, so its
// fail-closed default holds even if the Exceptions.validate allowlist that
// runs first changes.
func TestKeyAlgAllowlistCheckKeyAlg(t *testing.T) {
	p256, _ := x509.MarshalPKIXPublicKey(derivedP256("compliancetf.test-grant-key/bobthecorp").Public())
	ed, _ := x509.MarshalPKIXPublicKey(testKey.Public())
	cases := []struct {
		der  []byte
		alg  string
		want string
	}{
		{p256, trust.AlgES256, ""},
		{ed, trust.AlgEd25519, ""},
		{p256, "ES384", "alg not allowed"},
		{p256, "", "alg not allowed"},
		{ed, trust.AlgES256, "spki_b64 is not an ES256 (P-256) key"},
		{p256, trust.AlgEd25519, "spki_b64 is not an Ed25519 key"},
	}
	for _, c := range cases {
		err := checkKeyAlg(c.der, c.alg)
		if (c.want == "" && err != nil) || (c.want != "" && (err == nil || err.Error() != c.want)) {
			t.Errorf("checkKeyAlg(%q): got %v, want %q", c.alg, err, c.want)
		}
	}
}
