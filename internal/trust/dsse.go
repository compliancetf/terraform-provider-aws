// Package trust verifies DSSE-signed compliance.tf artifacts against the
// compiled keyring and the merged revocation set.
package trust

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Payload types and the key purpose each requires.
const (
	PayloadBundleManifest = "application/vnd.compliancetf.bundle-manifest+json;v=2"
	PayloadProfile        = "application/vnd.compliancetf.profile+json;v=1"
	PayloadFloor          = "application/vnd.compliancetf.floor+json;v=1"
	PayloadFloorReset     = "application/vnd.compliancetf.floor-reset+json;v=1"
	PayloadExceptionGrant = "application/vnd.compliancetf.exception-grant+json;v=1"
)

var purposeFor = map[string]string{
	PayloadBundleManifest: PurposeBundle,
	PayloadProfile:        PurposeProfile,
	PayloadFloor:          PurposeFloor,
	PayloadFloorReset:     PurposeFloor,
	PayloadExceptionGrant: PurposeException,
}

const (
	maxEnvelopeBytes = 4 << 20
	maxSignatures    = 8
	maxKeyIDLen      = 80
	maxSigB64Len     = 256
	maxES256SigLen   = 72
)

type envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []signature `json:"signatures"`
}

type signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

var envelopeNames = names("payloadType", "payload", "signatures", "keyid", "sig")

// Verified is the result of a successful Verify.
type Verified struct {
	Payload  []byte // exact signed payload bytes; parse only after Verify
	KeyID    string // first accepted signature in envelope order
	IssuedAt time.Time
}

// PAE is the DSSE v1 pre-authentication encoding; lengths are byte counts.
func PAE(payloadType string, payload []byte) []byte {
	var b strings.Builder
	b.WriteString("DSSEv1 ")
	b.WriteString(strconv.Itoa(len(payloadType)))
	b.WriteByte(' ')
	b.WriteString(payloadType)
	b.WriteByte(' ')
	b.WriteString(strconv.Itoa(len(payload)))
	b.WriteByte(' ')
	b.Write(payload)
	return []byte(b.String())
}

// Verify checks env against the embedded keyring.
func Verify(env []byte, payloadType string, revs Revocations) (Verified, error) {
	kr, err := Embedded()
	if err != nil {
		return Verified{}, err
	}
	return kr.Verify(env, payloadType, revs)
}

// Verify checks a DSSE envelope. Structural problems reject the envelope;
// a signature with an unknown kid, wrong purpose, revoked kid, bad signature
// or issued_at outside its key window is skipped. At least one signature must
// pass. Wall-clock time is not checked here: artifact freshness is the
// caller's expires_at check.
func (k *Keyring) Verify(env []byte, payloadType string, revs Revocations) (Verified, error) {
	if !revs.valid {
		return Verified{}, errors.New("dsse: invalid revocation set")
	}
	purpose, ok := purposeFor[payloadType]
	if !ok {
		return Verified{}, errors.New("dsse: unknown payload type")
	}
	if len(env) > maxEnvelopeBytes {
		return Verified{}, errors.New("dsse: envelope too large")
	}
	var e envelope
	// Everything below until a signature verifies reads unsigned input: every
	// error is a fixed reason or a signature index, never a value from env.
	if err := strictUnmarshal(env, envelopeNames, &e); errors.Is(err, errWrongShape) {
		return Verified{}, errors.New("dsse: envelope has the wrong shape")
	} else if err != nil {
		return Verified{}, fmt.Errorf("dsse: %w", err) // checkJSON reasons are fixed
	}
	if e.PayloadType != payloadType {
		return Verified{}, fmt.Errorf("dsse: payload type mismatch, want %q", payloadType) // never echo the unsigned value
	}
	if len(e.Signatures) < 1 || len(e.Signatures) > maxSignatures {
		return Verified{}, fmt.Errorf("dsse: need 1 to %d signatures", maxSignatures)
	}
	b64 := base64.StdEncoding.Strict()
	sigs := make([][]byte, len(e.Signatures))
	seen := map[string]bool{}
	for i, s := range e.Signatures {
		if len(s.KeyID) > maxKeyIDLen || !kidRE.MatchString(s.KeyID) {
			return Verified{}, fmt.Errorf("dsse: signature %d: bad keyid", i)
		}
		if seen[s.KeyID] {
			return Verified{}, fmt.Errorf("dsse: signature %d: duplicate keyid", i) // unsigned input, never echoed
		}
		seen[s.KeyID] = true
		if len(s.Sig) > maxSigB64Len {
			return Verified{}, fmt.Errorf("dsse: signature %d too long", i)
		}
		var err error
		if sigs[i], err = b64.DecodeString(s.Sig); err != nil {
			return Verified{}, fmt.Errorf("dsse: signature %d: invalid base64", i)
		}
	}
	payload, err := b64.DecodeString(e.Payload)
	if err != nil {
		return Verified{}, errors.New("dsse: payload: invalid base64")
	}
	pae := PAE(payloadType, payload)

	var reasons []string
	var issuedAt *time.Time
	for i, s := range e.Signatures {
		key := k.byKID[s.KeyID]
		switch {
		case key == nil:
			reasons = append(reasons, fmt.Sprintf("signature %d: key not in keyring", i)) // unsigned kid, never echoed
			continue
		case key.Purpose != purpose:
			reasons = append(reasons, fmt.Sprintf("signature %d: key purpose %s, payload needs %s", i, key.Purpose, purpose))
			continue
		case revs.KeyRevoked(s.KeyID):
			reasons = append(reasons, fmt.Sprintf("signature %d: key revoked", i))
			continue
		case !verifySig(key, pae, sigs[i]):
			reasons = append(reasons, fmt.Sprintf("signature %d: signature invalid", i))
			continue
		}
		if issuedAt == nil {
			t, err := payloadIssuedAt(payload)
			if err != nil {
				return Verified{}, fmt.Errorf("dsse: payload: %w", err)
			}
			issuedAt = &t
		}
		if issuedAt.Before(key.NotBefore) || issuedAt.After(key.NotAfter) {
			reasons = append(reasons, fmt.Sprintf("signature %d: issued_at %s outside key window", i, issuedAt.Format(time.RFC3339)))
			continue
		}
		return Verified{Payload: payload, KeyID: s.KeyID, IssuedAt: *issuedAt}, nil
	}
	return Verified{}, fmt.Errorf("dsse: no valid signature: %s", strings.Join(reasons, "; "))
}

// verifySig: ES256 is ASN.1 DER ECDSA over SHA-256(PAE) (a KMS signer is
// given that digest, never the raw PAE); Ed25519 signs the raw PAE.
func verifySig(k *Key, pae, sig []byte) bool {
	switch pub := k.pub.(type) {
	case *ecdsa.PublicKey:
		if len(sig) > maxES256SigLen {
			return false
		}
		sum := sha256.Sum256(pae)
		return ecdsa.VerifyASN1(pub, sum[:], sig)
	case ed25519.PublicKey:
		return len(sig) == ed25519.SignatureSize && ed25519.Verify(pub, pae, sig)
	}
	return false
}

// payloadIssuedAt reads the top-level issued_at from a signed payload. The
// payload must be a single JSON object without duplicate member names; other
// fields are left to the caller's parser.
func payloadIssuedAt(payload []byte) (time.Time, error) {
	if err := checkJSON(payload, nil); err != nil {
		return time.Time{}, err
	}
	var p struct {
		IssuedAt *string `json:"issued_at"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return time.Time{}, errWrongShape // decoder text may quote the payload
	}
	if p.IssuedAt == nil {
		return time.Time{}, errors.New("issued_at missing")
	}
	t, err := time.Parse(time.RFC3339, *p.IssuedAt)
	if err != nil {
		return time.Time{}, errNotRFC3339("issued_at")
	}
	return t.UTC(), nil
}

// errNotRFC3339 replaces a time.Parse error, which quotes the value.
func errNotRFC3339(field string) error {
	return fmt.Errorf("%s is not an RFC 3339 time", field)
}

// MaxEnvelopeBytes is the largest envelope Verify accepts; signers must not
// emit a bigger one.
const MaxEnvelopeBytes = maxEnvelopeBytes

// CheckPayload applies the payload rules Verify enforces before any
// signature counts: a single JSON object without duplicate (folded) member
// names, and an RFC 3339 issued_at. Signers call it so they never emit an
// envelope Verify rejects.
func CheckPayload(payload []byte) error {
	_, err := payloadIssuedAt(payload)
	return err
}
