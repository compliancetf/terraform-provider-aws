package verdict

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"slices"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/profile"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

// Key uses of the signing keys a floor-validated profile lists.
const (
	UseVerdict  = "verdict"  // verdict.public_keys: the customer gate key
	UseBaseline = "baseline" // baseline.public_keys: the customer baseline key
	UseReceipt  = "receipt"  // break_glass.receipt_keys: compliance.tf receipt keys
)

// Anchors returns the keys trusted for use. Their only source is
// p, the signed profile that passed floor validation at Configure; nil (no
// such profile) or an unknown use trusts no key. Keys or anchors in provider
// config, env, files, bundles or state are never read: this function takes
// nothing else, and floor issuer keys stay in the compiled keyring
// (internal/trust), which never vouches for a verdict, baseline or receipt.
func Anchors(p *profile.Profile, use string) []profile.SignerKey {
	if p == nil {
		return nil
	}
	switch {
	case use == UseVerdict && p.Verdict != nil:
		return p.Verdict.PublicKeys
	case use == UseBaseline && p.Baseline != nil:
		return p.Baseline.PublicKeys
	case use == UseReceipt && p.BreakGlass != nil:
		return p.BreakGlass.ReceiptKeys
	}
	return nil
}

// VerifySignature returns "" when sig verifies over signed with a use key
// of p (Anchors), else a fixed reason. A kid in the profile's revoked_kids
// or in revs (the merged bundle revocations.json) is revoked for
// every use; the zero-value revs revokes every kid (fail closed). The algorithm allowlist is ES256
// (ASN.1 DER over SHA-256 of signed); Ed25519 (raw signature over signed) is
// accepted only in ctftest builds. sig.Alg must equal the key's alg, and the
// key's spki_b64 must be the key type its alg names.
func VerifySignature(sig Signature, signed []byte, p *profile.Profile, revs trust.Revocations, use string, now time.Time) string {
	if p != nil && slices.Contains(p.RevokedKIDs, sig.KID) || revs.KeyRevoked(sig.KID) {
		return "kid revoked"
	}
	keys := Anchors(p, use)
	i := slices.IndexFunc(keys, func(k profile.SignerKey) bool { return k.KID == sig.KID })
	if i < 0 {
		return "kid unknown"
	}
	key := keys[i]
	switch {
	case key.Use != use:
		return "key use is not " + use
	case sig.Alg != key.Alg || !algAllowed(key.Alg):
		return "algorithm not allowed"
	case now.Before(key.NotBefore.Add(-Skew)) || now.After(key.NotAfter.Add(Skew)):
		return "key not valid at this time"
	}
	der, err := base64.StdEncoding.Strict().DecodeString(key.SPKIB64)
	if err != nil || trust.KIDFromSPKI(der) != key.KID {
		return "kid unknown"
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return "algorithm not allowed"
	}
	value, err := base64.RawURLEncoding.Strict().DecodeString(sig.Value)
	if err != nil {
		return "malformed signature value"
	}
	ok := false
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if key.Alg != trust.AlgES256 || k.Curve != elliptic.P256() {
			return "algorithm not allowed"
		}
		digest := sha256.Sum256(signed)
		ok = ecdsa.VerifyASN1(k, digest[:], value)
	case ed25519.PublicKey:
		if key.Alg != trust.AlgEd25519 {
			return "algorithm not allowed"
		}
		ok = ed25519.Verify(k, signed, value)
	default:
		return "algorithm not allowed"
	}
	if !ok {
		return "signature does not verify"
	}
	return ""
}

// algAllowed is the allowlist: ES256, and Ed25519 only in ctftest builds.
func algAllowed(alg string) bool {
	return alg == trust.AlgES256 || alg == trust.AlgEd25519 && allowEd25519
}
