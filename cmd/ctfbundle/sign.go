package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

// envelope is the DSSE wire form; field order is fixed by the struct.
type envelope struct {
	PayloadType string     `json:"payloadType"`
	Payload     string     `json:"payload"`
	Signatures  []sigEntry `json:"signatures"`
}

type sigEntry struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// signTypes are the payload types `ctfbundle sign` accepts. Bundle manifests
// are signed only by build, which computes the file digests.
var signTypes = map[string]string{
	"profile":         trust.PayloadProfile,
	"floor":           trust.PayloadFloor,
	"floor-reset":     trust.PayloadFloorReset,
	"exception-grant": trust.PayloadExceptionGrant,
}

// signEnvelope signs PAE(payloadType, payload) with one key. Both algorithms
// are deterministic (Ed25519; ES256 per RFC 6979 with a nil rand), so the
// same input always yields the same envelope bytes.
func signEnvelope(payloadType string, payload []byte, key crypto.Signer) ([]byte, error) {
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, err
	}
	pae := trust.PAE(payloadType, payload)
	var sig []byte
	switch k := key.(type) {
	case ed25519.PrivateKey:
		sig = ed25519.Sign(k, pae)
	case *ecdsa.PrivateKey:
		if k.Curve != elliptic.P256() {
			return nil, errors.New("ecdsa key must be P-256 (ES256)")
		}
		sum := sha256.Sum256(pae)
		if sig, err = k.Sign(nil, sum[:], crypto.SHA256); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported key type %T: want ES256 or Ed25519", key)
	}
	env, err := json.Marshal(envelope{
		PayloadType: payloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  []sigEntry{{KeyID: trust.KIDFromSPKI(spki), Sig: base64.StdEncoding.EncodeToString(sig)}},
	})
	if err == nil && len(env) > trust.MaxEnvelopeBytes {
		err = fmt.Errorf("envelope %d bytes exceeds the verifier limit %d", len(env), trust.MaxEnvelopeBytes)
	}
	return env, err
}

// signPayload signs the raw payload bytes (never re-serialized) as kind.
func signPayload(kind string, payload []byte, key crypto.Signer) ([]byte, error) {
	payloadType, ok := signTypes[kind]
	if !ok {
		return nil, fmt.Errorf("unknown payload kind %q (want profile, floor, floor-reset or exception-grant)", kind)
	}
	if err := trust.CheckPayload(payload); err != nil {
		return nil, fmt.Errorf("payload: %w", err)
	}
	var p struct {
		Format     string `json:"format"`
		FloorMode  string `json:"floor_mode"`
		BreakGlass *struct {
			Enabled bool `json:"enabled"`
		} `json:"break_glass"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, fmt.Errorf("payload must be a JSON object: %w", err)
	}
	if kind == "profile" {
		if p.Format != "compliancetf.profile/v1" {
			return nil, fmt.Errorf("profile format %q, want compliancetf.profile/v1", p.Format)
		}
		// Break-glass is unavailable in air-gap mode (parent 6.4).
		if p.FloorMode == "airgap" && p.BreakGlass != nil && p.BreakGlass.Enabled {
			return nil, errors.New("refusing to sign: floor_mode airgap with break_glass.enabled true")
		}
	}
	return signEnvelope(payloadType, payload, key)
}

// loadKey reads a PKCS#8 PEM private key, or a derived test key
// ("test:bundle", "test:profile", "test:floor") in ctftest builds.
func loadKey(spec string) (crypto.Signer, error) {
	if name, ok := strings.CutPrefix(spec, "test:"); ok {
		return testKey(name)
	}
	raw, err := os.ReadFile(spec)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM block", spec)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%s: not a signing key", spec)
	}
	return s, nil
}
