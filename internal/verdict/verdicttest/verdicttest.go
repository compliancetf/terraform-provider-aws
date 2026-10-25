// Package verdicttest builds signed compliancetf.verdict/v1 test documents
// with keys generated in code (never a key file of the repository).
package verdicttest

import (
	"cmp"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

// Key is a fresh ES256 verdict key and its profile entry.
type Key struct {
	Priv   *ecdsa.PrivateKey
	Signer profile.SignerKey
}

// NewKey returns an ES256 key valid from notBefore for 60 days.
func NewKey(t testing.TB, notBefore time.Time) Key {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return Key{priv, profile.SignerKey{KID: trust.KIDFromSPKI(der), Alg: trust.AlgES256, Use: "verdict",
		SPKIB64: base64.StdEncoding.EncodeToString(der), NotBefore: notBefore, NotAfter: notBefore.Add(60 * 24 * time.Hour)}}
}

// Binding is what a verdict binds; IssuedAt plus 12h is expires_at.
// Instances, Exceptions, Baselines and Receipts (break_glass_receipts) are the JSON
// arrays (nil: []); Secret is the run key (nil: random); Workspace and
// Environment the gate-asserted scope ("": prod and production).
type Binding struct {
	OrgID, ProfileDigest, BundleDigest, ContentDigest, Wrapper, Upstream string
	Workspace, Environment                                               string
	IssuedAt                                                             time.Time
	Instances, Exceptions, Baselines, Receipts                           json.RawMessage
	Secret                                                               []byte
}

// Leaf is the B3 leaf-hash key of secret.
func Leaf(t testing.TB, secret []byte) [32]byte {
	t.Helper()
	k, err := hkdf.Key(sha256.New, secret, nil, "compliancetf.verdict/v1 leaf", 32)
	if err != nil {
		t.Fatal(err)
	}
	return [32]byte(k)
}

// KeyCheck is the B3 instance_key_check of secret.
func KeyCheck(t testing.TB, secret []byte) string {
	t.Helper()
	const info = "compliancetf.verdict/v1 key-check"
	k, err := hkdf.Key(sha256.New, secret, nil, info, 32)
	if err != nil {
		t.Fatal(err)
	}
	m := hmac.New(sha256.New, k)
	m.Write([]byte(info))
	return hex.EncodeToString(m.Sum(nil))
}

// Doc is an unsigned verdict for b keyed by secret.
func Doc(t testing.TB, b Binding, secret []byte) map[string]json.RawMessage {
	t.Helper()
	s := func(v string) json.RawMessage { j, _ := json.Marshal(v); return j }                            //nolint:errcheck // a string always marshals
	pv, _ := json.Marshal(map[string]string{"compliancetf/aws": b.Wrapper, "hashicorp/aws": b.Upstream}) //nolint:errcheck // a string map always marshals
	ws, env := cmp.Or(b.Workspace, "prod"), cmp.Or(b.Environment, "production")
	return map[string]json.RawMessage{
		"format": s("compliancetf.verdict/v1"), "org_id": s(b.OrgID), "workspace": s(ws), "environment": s(env), "run_id": s("run-1"),
		"caller":              json.RawMessage(`{"account_id":"111122223333","region":"us-east-1","role_arn":"arn:aws:iam::111122223333:role/bobthecorp-ci"}`),
		"plan_digest":         s("sha256:4444444444444444444444444444444444444444444444444444444444444444"),
		"provenance":          json.RawMessage(`{"refresh":"true","tool":"ctfkit gate plan"}`),
		"plan_format_version": s("1.2"), "profile_digest": s(b.ProfileDigest), "bundle_digest": s(b.BundleDigest), "content_digest": s(b.ContentDigest),
		"floor_epoch": s("3"), "provider_versions": pv, "terraform_version": s("1.14.0"), "nonce": s("AAECAwQFBgcICQoLDA0ODw"),
		"issued_at": s(b.IssuedAt.UTC().Format(time.RFC3339)), "expires_at": s(b.IssuedAt.Add(12 * time.Hour).UTC().Format(time.RFC3339)),
		"instance_key_check": s(KeyCheck(t, secret)),
		"instances":          orEmpty(b.Instances),
		"exceptions":         orEmpty(b.Exceptions), "baselines": orEmpty(b.Baselines), "break_glass_receipts": orEmpty(b.Receipts),
	}
}

// Signature signs doc (without its signature member) with priv under kid:
// ES256 over sha256 of the JCS bytes, value base64url raw DER.
func Signature(t testing.TB, priv *ecdsa.PrivateKey, kid string, doc map[string]json.RawMessage) map[string]string {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := bundle.CanonicalJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(signed)
	der, err := ecdsa.SignASN1(rand.Reader, priv, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return map[string]string{"kid": kid, "alg": trust.AlgES256, "value": base64.RawURLEncoding.EncodeToString(der)}
}

// Write signs a verdict for b into dir (verdict.json 0600, ctfkit-run.key
// 0600) and returns both paths.
func Write(t testing.TB, dir string, k Key, b Binding) (verdictPath, keyPath string) {
	t.Helper()
	secret := b.Secret
	if secret == nil {
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			t.Fatal(err)
		}
	}
	doc := Doc(t, b, secret)
	sig, err := json.Marshal(Signature(t, k.Priv, k.Signer.KID, doc))
	if err != nil {
		t.Fatal(err)
	}
	doc["signature"] = sig
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	verdictPath, keyPath = filepath.Join(dir, "verdict.json"), filepath.Join(dir, "ctfkit-run.key")
	for p, data := range map[string][]byte{verdictPath: body, keyPath: []byte(hex.EncodeToString(secret))} {
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return verdictPath, keyPath
}

func orEmpty(a json.RawMessage) json.RawMessage {
	if a == nil {
		return json.RawMessage(`[]`)
	}
	return a
}
