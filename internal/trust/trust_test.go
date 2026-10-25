package trust

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

const nb, na = "2026-01-01T00:00:00Z", "2030-01-01T00:00:00Z"

func mustKeyring(t *testing.T, raw []byte, allowEd25519 bool) *Keyring {
	t.Helper()
	keys, err := parseKeyring(raw, allowEd25519)
	if err != nil {
		t.Fatal(err)
	}
	kr, err := newKeyring(keys)
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

func newEd25519(t *testing.T) crypto.Signer {
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newP256(t *testing.T) crypto.Signer {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestVerifyEnvelopeRejects(t *testing.T) {
	bk := newP256(t)
	kr := mustKeyring(t, keyringBytes(entry(t, bk, AlgES256, PurposeBundle, nb, na)), false)
	good := sign(t, PayloadBundleManifest, []byte(vectorPayload), bk)
	kid := KIDFromSPKI(spki(t, bk))
	payloadB64 := base64.StdEncoding.EncodeToString([]byte(vectorPayload))
	sigOf := func(env []byte) string {
		var e envelope
		_ = json.Unmarshal(env, &e)
		return e.Signatures[0].Sig
	}
	sig := sigOf(good)
	cases := map[string]struct {
		env  string
		typ  string
		want string
	}{
		"unknown type":      {string(good), "application/x", "unknown payload type"},
		"type mismatch":     {string(good), PayloadProfile, "want"},
		"unknown field":     {`{"payloadType":"` + PayloadBundleManifest + `","payload":"` + payloadB64 + `","signatures":[{"keyid":"` + kid + `","sig":"` + sig + `"}],"x":1}`, "", "unknown member"},
		"case variant name": {`{"payloadType":"` + PayloadBundleManifest + `","Payload":"` + payloadB64 + `","signatures":[{"keyid":"` + kid + `","sig":"` + sig + `"}]}`, "", "unknown member"},
		"duplicate name":    {`{"payloadType":"` + PayloadBundleManifest + `","payload":"` + payloadB64 + `","payload":"` + payloadB64 + `","signatures":[{"keyid":"` + kid + `","sig":"` + sig + `"}]}`, "", "duplicate member"},
		"trailing data":     {string(good) + "{}", "", "trailing data"},
		"null element":      {`{"payloadType":"` + PayloadBundleManifest + `","payload":"` + payloadB64 + `","signatures":[null]}`, "", "null value"},
		"no signatures":     {`{"payloadType":"` + PayloadBundleManifest + `","payload":"` + payloadB64 + `","signatures":[]}`, "", "need 1 to 8"},
		"duplicate keyid":   {`{"payloadType":"` + PayloadBundleManifest + `","payload":"` + payloadB64 + `","signatures":[{"keyid":"` + kid + `","sig":"` + sig + `"},{"keyid":"` + kid + `","sig":"` + sig + `"}]}`, "", "duplicate keyid"},
		"empty keyid":       {`{"payloadType":"` + PayloadBundleManifest + `","payload":"` + payloadB64 + `","signatures":[{"keyid":"","sig":"` + sig + `"}]}`, "", "bad keyid"},
		"unpadded base64":   {`{"payloadType":"` + PayloadBundleManifest + `","payload":"e30","signatures":[{"keyid":"` + kid + `","sig":"` + sig + `"}]}`, "", "payload"},
		"long sig":          {`{"payloadType":"` + PayloadBundleManifest + `","payload":"` + payloadB64 + `","signatures":[{"keyid":"` + kid + `","sig":"` + strings.Repeat("A", 260) + `"}]}`, "", "too long"},
		"too deep":          {strings.Repeat("[", 40) + strings.Repeat("]", 40), "", "too deep"},
		"too large":         {strings.Repeat(" ", maxEnvelopeBytes+1), "", "too large"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			typ := c.typ
			if typ == "" {
				typ = PayloadBundleManifest
			}
			_, err := kr.Verify([]byte(c.env), typ, NoRevocations())
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want error containing %q", err, c.want)
			}
		})
	}
	if _, err := kr.Verify(good, PayloadBundleManifest, Revocations{}); err == nil {
		t.Fatal("zero-value Revocations must fail closed")
	}
}

func TestVerifyPayloadRules(t *testing.T) {
	bk := newP256(t)
	kr := mustKeyring(t, keyringBytes(entry(t, bk, AlgES256, PurposeBundle, nb, na)), false)
	for payload, want := range map[string]string{
		`{"bundle_id":"x"}`: "issued_at missing",
		`{"issued_at":"2026-10-01T00:00:00Z","Issued_At":"2026-10-02T00:00:00Z"}`: "duplicate member",
		`{"issued_at":"2026-10-01T00:00:00Z","iſſued_at":"2026-10-02T00:00:00Z"}`: "duplicate member",
		`["2026-10-01T00:00:00Z"]`:                "wrong shape",
		`{"issued_at":"yesterday"}`:               "issued_at",
		`{"issued_at":"2026-10-01T00:00:00Z"} {}`: "trailing data",
	} {
		_, err := kr.Verify(sign(t, PayloadBundleManifest, []byte(payload), bk), PayloadBundleManifest, NoRevocations())
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("payload %s: got %v, want %q", payload, err, want)
		}
	}
}

func TestVerifyMultiSignature(t *testing.T) {
	bk, other := newP256(t), newP256(t)
	kr := mustKeyring(t, keyringBytes(
		entry(t, other, AlgES256, PurposeProfile, nb, na),
		entry(t, bk, AlgES256, PurposeBundle, nb, na)), false)
	stranger := newP256(t)
	env := sign(t, PayloadBundleManifest, []byte(vectorPayload), stranger, other, bk)
	got, err := kr.Verify(env, PayloadBundleManifest, NoRevocations())
	if err != nil {
		t.Fatal(err)
	}
	if got.KeyID != KIDFromSPKI(spki(t, bk)) {
		t.Fatalf("accepted %s", got.KeyID)
	}
	// Empty keyring trusts nothing.
	empty := mustKeyring(t, keyringBytes(), false)
	if _, err := empty.Verify(env, PayloadBundleManifest, NoRevocations()); err == nil {
		t.Fatal("empty keyring accepted a signature")
	}
}

func TestVerifyEd25519(t *testing.T) {
	pk := newEd25519(t)
	raw := keyringBytes(entry(t, pk, AlgEd25519, PurposeProfile, nb, na))
	if _, err := parseKeyring(raw, false); err == nil || !strings.Contains(err.Error(), "not trusted") {
		t.Fatalf("release allowlist accepted Ed25519: %v", err)
	}
	kr := mustKeyring(t, raw, true)
	env := sign(t, PayloadProfile, []byte(`{"issued_at":"2026-10-01T00:00:00Z"}`), pk)
	if _, err := kr.Verify(env, PayloadProfile, NoRevocations()); err != nil {
		t.Fatal(err)
	}
}

func TestKeyringRejects(t *testing.T) {
	bk := newP256(t)
	base := func() map[string]any { return entry(t, bk, AlgES256, PurposeBundle, nb, na) }
	edit := func(f func(map[string]any)) []byte { e := base(); f(e); return keyringBytes(e) }
	gen := int64(1)
	cases := map[string][]byte{
		"bad format":        []byte(`{"format":"x","keys":[]}`),
		"duplicate kid":     keyringBytes(base(), base()),
		"kid mismatch":      edit(func(e map[string]any) { e["kid"] = "sha256:" + strings.Repeat("0", 64) }),
		"uppercase kid":     edit(func(e map[string]any) { e["kid"] = strings.ToUpper(e["kid"].(string)) }),
		"alg RS256":         edit(func(e map[string]any) { e["alg"] = "RS256" }),
		"alg type mismatch": edit(func(e map[string]any) { e["alg"] = AlgEd25519 }),
		"two purposes":      edit(func(e map[string]any) { e["purpose"] = []string{"bundle", "profile"} }),
		"unknown purpose":   edit(func(e map[string]any) { e["purpose"] = []string{"verdict"} }),
		"floor without gen": edit(func(e map[string]any) { e["purpose"] = []string{"floor"} }),
		"gen on bundle key": edit(func(e map[string]any) { e["generation"] = gen }),
		"bad not_before":    edit(func(e map[string]any) { e["not_before"] = "soon" }),
		"inverted window":   edit(func(e map[string]any) { e["not_before"] = na; e["not_after"] = nb }),
		"unknown field":     edit(func(e map[string]any) { e["comment"] = "x" }),
		"null generation":   edit(func(e map[string]any) { e["generation"] = nil }),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			keys, err := parseKeyring(raw, true)
			if err == nil {
				_, err = newKeyring(keys)
			}
			if err == nil {
				t.Fatal("accepted")
			}
		})
	}
	floor := edit(func(e map[string]any) { e["purpose"] = []string{"floor"}; e["generation"] = gen })
	if k := mustKeyring(t, floor, false).Keys(); k[0].Generation != 1 || k[0].Purpose != PurposeFloor {
		t.Fatalf("floor key parsed as %+v", k[0])
	}
}

func TestRevocations(t *testing.T) {
	kidA, kidB := "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64)
	a, err := ParseRevocations([]byte(`{"format":"compliancetf.revocations/v1","epoch":2,
		"revoked_keys":[{"kid":"` + kidA + `","revoked_at":"2026-05-01T00:00:00Z"}],
		"revoked_bundles":[{"bundle_id":"soc2-aws","below_version":5}],
		"revoked_controls":[{"id":"s3-1","version":2}]}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseRevocations([]byte(`{"format":"compliancetf.revocations/v1","epoch":1,
		"revoked_keys":[{"kid":"` + kidB + `","revoked_at":"2026-06-01T00:00:00Z"}],
		"revoked_bundles":[{"bundle_id":"soc2-aws","below_version":3}],
		"revoked_controls":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	m, err := Merge(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if m.Epoch() != 2 || !m.KeyRevoked(kidA) || !m.KeyRevoked(kidB) || !m.BundleRevoked("soc2-aws", 4) ||
		m.BundleRevoked("soc2-aws", 5) || !m.ControlRevoked("s3-1", 2) || m.ControlRevoked("s3-1", 3) {
		t.Fatalf("bad merge: %+v", m)
	}
	if b.BundleRevoked("soc2-aws", 4) || a.KeyRevoked(kidB) {
		t.Fatal("Merge mutated its inputs")
	}
	if _, err := Merge(a, Revocations{}); err == nil {
		t.Fatal("merge with zero value accepted")
	}
	var zero Revocations
	if !zero.KeyRevoked(kidA) || !zero.BundleRevoked("x", 99) || !zero.ControlRevoked("x", 1) {
		t.Fatal("zero-value Revocations must report revoked")
	}
	for name, raw := range map[string]string{
		"epoch 0":       `{"format":"compliancetf.revocations/v1","epoch":0}`,
		"float epoch":   `{"format":"compliancetf.revocations/v1","epoch":1.5}`,
		"bad kid":       `{"format":"compliancetf.revocations/v1","epoch":1,"revoked_keys":[{"kid":"abc","revoked_at":"2026-05-01T00:00:00Z"}]}`,
		"duplicate kid": `{"format":"compliancetf.revocations/v1","epoch":1,"revoked_keys":[{"kid":"` + kidA + `","revoked_at":"2026-05-01T00:00:00Z"},{"kid":"` + kidA + `","revoked_at":"2026-05-02T00:00:00Z"}]}`,
		"dup bundle":    `{"format":"compliancetf.revocations/v1","epoch":1,"revoked_bundles":[{"bundle_id":"x","below_version":1},{"bundle_id":"x","below_version":2}]}`,
		"unknown field": `{"format":"compliancetf.revocations/v1","epoch":1,"note":"x"}`,
		"wrong format":  `{"format":"compliancetf.revocations/v2","epoch":1}`,
	} {
		if r, err := ParseRevocations([]byte(raw)); err == nil || r.valid {
			t.Errorf("%s: accepted", name)
		}
	}
}
