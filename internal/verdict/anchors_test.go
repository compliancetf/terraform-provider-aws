package verdict

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/profile"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

// anchorFixture is one internal/verdict/testdata/anchors case: a key of
// Key type signs a document for Use, the key is placed at Source, and
// VerifySignature must return WantRelease (WantCtftest under -tags ctftest,
// default WantRelease; "" = verifies).
type anchorFixture struct {
	Description string `json:"description"`
	Use         string `json:"use"` // verdict, baseline or receipt
	// Source: "profile" (the floor-validated profile lists it for Use),
	// "other_use" (the profile lists it only for another use), "env"
	// (environment variables only), "file" (key files in the working dir,
	// HOME, TF_DATA_DIR and the state dir only), "none" (no validated
	// profile) or "compiled" (the signature names a compiled floor kid).
	Source string `json:"source"`
	Key    string `json:"key,omitempty"`     // p256 (default), p384 or ed25519
	KeyAlg string `json:"key_alg,omitempty"` // default by Key: ES256, ES384, Ed25519
	SigAlg string `json:"sig_alg,omitempty"` // default KeyAlg
	KeyUse string `json:"key_use,omitempty"` // default Use
	// Revoked lists the kid in revoked_kids.
	Revoked     bool    `json:"revoked,omitempty"`
	WantRelease string  `json:"want_release"`
	WantCtftest *string `json:"want_ctftest,omitempty"`
}

var otherUse = map[string]string{UseVerdict: UseBaseline, UseBaseline: UseReceipt, UseReceipt: UseVerdict}

// TestTrustAnchorFixtures: verdict, baseline and receipt signatures verify
// only with a key the floor-validated profile lists for that use; keys in
// env, files, another use list or the compiled keyring add no trust; ES256
// only, Ed25519 only in ctftest builds.
func TestTrustAnchorFixtures(t *testing.T) {
	files, err := filepath.Glob("testdata/anchors/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no fixtures: %v", err)
	}
	for _, f := range files {
		t.Run(strings.TrimSuffix(filepath.Base(f), ".json"), func(t *testing.T) {
			raw, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			var fx anchorFixture
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&fx); err != nil {
				t.Fatal(err)
			}
			want := fx.WantRelease
			if ctftestBuild && fx.WantCtftest != nil {
				want = *fx.WantCtftest
			}
			sig, signed, p, now := anchorCase(t, fx)
			if got := VerifySignature(sig, signed, p, trust.NoRevocations(), fx.Use, now); got != want {
				t.Errorf("%s: VerifySignature = %q, want %q", fx.Description, got, want)
			}
		})
	}
}

func anchorCase(t *testing.T, fx anchorFixture) (Signature, []byte, *profile.Profile, time.Time) {
	t.Helper()
	if otherUse[fx.Use] == "" {
		t.Fatalf("use %q", fx.Use)
	}
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	signed := []byte(`{"format":"compliancetf.verdict/v1","org_id":"bobthecorp"}`)
	pub, signFn, alg := anchorKey(t, fx.Key)
	if fx.KeyAlg != "" {
		alg = fx.KeyAlg
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	use := fx.Use
	if fx.KeyUse != "" {
		use = fx.KeyUse
	}
	key := profile.SignerKey{KID: trust.KIDFromSPKI(der), Alg: alg, Use: use, SPKIB64: base64.StdEncoding.EncodeToString(der),
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(24 * time.Hour)}
	sig := Signature{KID: key.KID, Alg: alg, Value: base64.RawURLEncoding.EncodeToString(signFn(signed))}
	if fx.SigAlg != "" {
		sig.Alg = fx.SigAlg
	}

	p := &profile.Profile{OrgID: "bobthecorp", Verdict: &profile.Verdict{}, Baseline: &profile.Baseline{}, BreakGlass: &profile.BreakGlass{}}
	if fx.Revoked {
		p.RevokedKIDs = []string{key.KID}
	}
	list := func(use string) *[]profile.SignerKey {
		return map[string]*[]profile.SignerKey{UseVerdict: &p.Verdict.PublicKeys, UseBaseline: &p.Baseline.PublicKeys, UseReceipt: &p.BreakGlass.ReceiptKeys}[use]
	}
	entry, err := json.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	switch fx.Source {
	case "profile":
		*list(fx.Use) = []profile.SignerKey{key}
	case "other_use":
		*list(otherUse[fx.Use]) = []profile.SignerKey{key}
	case "env":
		for _, name := range []string{"COMPLIANCETF_VERDICT_PUBLIC_KEYS", "COMPLIANCETF_BASELINE_PUBLIC_KEYS", "COMPLIANCETF_RECEIPT_KEYS",
			"COMPLIANCETF_TRUST_ANCHORS", "COMPLIANCETF_KEYRING", "TF_VAR_verdict_public_key"} {
			t.Setenv(name, string(entry))
		}
		t.Setenv("COMPLIANCETF_VERDICT_SPKI", key.SPKIB64)
	case "file":
		dir := t.TempDir()
		for name, body := range map[string]string{"keyring.json": `{"format":"compliancetf.keyring/v1","keys":[` + string(entry) + `]}`,
			"verdict-key.json": string(entry), "verdict.pub": key.SPKIB64, "anchors.json": "[" + string(entry) + "]"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		t.Chdir(dir)
		for _, name := range []string{"HOME", "TF_DATA_DIR", "COMPLIANCETF_STATE_DIR"} {
			t.Setenv(name, dir)
		}
	case "none":
		p = nil
	case "compiled":
		kr, err := trust.Embedded()
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range kr.Keys() {
			if k.Purpose == trust.PurposeFloor {
				sig.KID = k.KID
			}
		}
		if sig.KID == key.KID {
			t.Fatal("the compiled keyring holds no floor key")
		}
	default:
		t.Fatalf("source %q", fx.Source)
	}
	return sig, signed, p, now
}

// anchorKey returns a fresh key of kind, a signer in its alg's encoding and
// that alg.
func anchorKey(t *testing.T, kind string) (any, func([]byte) []byte, string) {
	t.Helper()
	switch kind {
	case "", "p256", "p384":
		curve, alg := elliptic.P256(), trust.AlgES256
		if kind == "p384" {
			curve, alg = elliptic.P384(), "ES384"
		}
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return &priv.PublicKey, func(b []byte) []byte {
			sum := sha256.Sum256(b)
			der, err := ecdsa.SignASN1(rand.Reader, priv, sum[:])
			if err != nil {
				t.Fatal(err)
			}
			return der
		}, alg
	case "ed25519":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return pub, func(b []byte) []byte { return ed25519.Sign(priv, b) }, trust.AlgEd25519
	}
	t.Fatalf("key %q", kind)
	return nil, nil, ""
}

// TestTrustAnchorEd25519BuildTag: Ed25519 is allowed exactly in ctftest
// builds; tools/releasegate refuses any tagged binary, so no release trusts
// an Ed25519 verdict, baseline or receipt key.
func TestTrustAnchorEd25519BuildTag(t *testing.T) {
	if allowEd25519 != ctftestBuild || algAllowed(trust.AlgEd25519) != ctftestBuild || !algAllowed(trust.AlgES256) {
		t.Fatalf("allowEd25519 = %v in a ctftest=%v build; want Ed25519 only under -tags ctftest", allowEd25519, ctftestBuild)
	}
	for _, alg := range []string{"", "es256", "ES384", "RS256", "EdDSA", "ed25519", "none"} {
		if algAllowed(alg) {
			t.Errorf("alg %q allowed", alg)
		}
	}
}

// TestTrustAnchorInputs: the floor-validated profile is the only input that
// can carry a key. Input has no other key-bearing field, so no provider
// config value reaches the verifier; a new field fails this test until it
// is reviewed here. Revocations only withdraws trust: it carries
// kids, never a key.
func TestTrustAnchorInputs(t *testing.T) {
	want := map[string]reflect.Type{
		"Profile": reflect.TypeFor[*profile.Profile](), "Revocations": reflect.TypeFor[trust.Revocations](), "BundleDigest": reflect.TypeFor[string](), "ContentDigest": reflect.TypeFor[string](),
		"WrapperName": reflect.TypeFor[string](), "WrapperVersion": reflect.TypeFor[string](), "UpstreamName": reflect.TypeFor[string](), "UpstreamVersion": reflect.TypeFor[string](), "Now": reflect.TypeFor[time.Time](),
	}
	in := reflect.TypeFor[Input]()
	if in.NumField() != len(want) {
		t.Fatalf("verdict.Input has %d fields, want %d: review any new field for key material", in.NumField(), len(want))
	}
	for i := range in.NumField() {
		f := in.Field(i)
		if want[f.Name] != f.Type {
			t.Errorf("verdict.Input.%s %s: not a reviewed field", f.Name, f.Type)
		}
	}
}

// TestTrustAnchorUses: Anchors reads only the list of its use, and nothing
// for a nil profile or an unknown use.
func TestTrustAnchorUses(t *testing.T) {
	k := func(kid string) []profile.SignerKey { return []profile.SignerKey{{KID: kid}} }
	p := &profile.Profile{Verdict: &profile.Verdict{PublicKeys: k("v")}, Baseline: &profile.Baseline{PublicKeys: k("b")},
		BreakGlass: &profile.BreakGlass{ReceiptKeys: k("r")}, Exceptions: profile.Exceptions{GrantKeys: []profile.GrantKey{{KID: "g"}}}}
	for use, kid := range map[string]string{UseVerdict: "v", UseBaseline: "b", UseReceipt: "r"} {
		if got := Anchors(p, use); len(got) != 1 || got[0].KID != kid {
			t.Errorf("Anchors(%s) = %v, want kid %s", use, got, kid)
		}
	}
	for _, use := range []string{"", "exception", "grant", "floor", "bundle", "profile", "Verdict"} {
		if got := Anchors(p, use); got != nil {
			t.Errorf("Anchors(%q) = %v, want none", use, got)
		}
	}
	if got := Anchors(nil, UseVerdict); got != nil {
		t.Errorf("Anchors(nil) = %v, want none", got)
	}
	if got := Anchors(&profile.Profile{}, UseReceipt); got != nil {
		t.Errorf("Anchors without break_glass = %v, want none", got)
	}
}

// TestVerifySignatureRevocations: a kid in the merged bundle
// revocations.json is revoked for verdicts, baselines and receipts alike,
// as one in the profile's revoked_kids; an unrelated revoked kid changes
// nothing, and the zero-value set revokes every kid.
func TestVerifySignatureRevocations(t *testing.T) {
	for _, use := range []string{UseVerdict, UseBaseline, UseReceipt} {
		sig, signed, p, now := anchorCase(t, anchorFixture{Use: use, Source: "profile"})
		revs := func(kid string) trust.Revocations {
			r, err := trust.ParseRevocations([]byte(`{"format":"compliancetf.revocations/v1","epoch":1,"revoked_keys":[{"kid":"` + kid +
				`","revoked_at":"2026-10-01T00:00:00Z"}],"revoked_bundles":[],"revoked_controls":[]}`))
			if err != nil {
				t.Fatal(err)
			}
			return r
		}
		for _, c := range []struct {
			name string
			revs trust.Revocations
			want string
		}{
			{"none", trust.NoRevocations(), ""},
			{"other kid", revs("sha256:" + strings.Repeat("0", 64)), ""},
			{"this kid", revs(sig.KID), "kid revoked"},
			{"zero value", trust.Revocations{}, "kid revoked"},
		} {
			if got := VerifySignature(sig, signed, p, c.revs, use, now); got != c.want {
				t.Errorf("%s %s: %q, want %q", use, c.name, got, c.want)
			}
		}
	}
}
