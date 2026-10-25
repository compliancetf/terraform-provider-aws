//go:build ctftest

package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/compliancetf/terraform-provider-aws/internal/trust"
	"github.com/compliancetf/terraform-provider-aws/internal/trust/testkeys"
)

// Labels of the sigbugs-only keys. They are in no keyring: each fixture that
// uses one ships the keyring an attacker would plant (<case>.keyring.json).
const (
	untrustedLabel = "compliancetf.test-untrusted-bundle-key/bobthecorp"
	ed25519Label   = "compliancetf.test-ed25519-bundle-key/bobthecorp"
)

func untrustedKey() *ecdsa.PrivateKey {
	d := sha256.Sum256([]byte(untrustedLabel))
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d[:])
	if err != nil {
		panic(err) // fixed label; cannot fail
	}
	return k
}

func ed25519BundleKey() ed25519.PrivateKey {
	s := sha256.Sum256([]byte(ed25519Label))
	return ed25519.NewKeyFromSeed(s[:])
}

// sigbugsCmd writes the signature rejection set into outDir. Each
// <case>.tar.gz breaks exactly one signature property of a fresh build of
// src; the output is reproducible.
func sigbugsCmd(src, outDir string) error {
	files, err := sigbugSet(src)
	if err != nil {
		return err
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(outDir, name), data, 0o644); err != nil { //nolint:gosec // public fixtures
			return err
		}
	}
	return nil
}

func sigbugSet(src string) (map[string][]byte, error) {
	good, err := build(src, testkeys.Bundle())
	if err != nil {
		return nil, err
	}
	untrusted, err := build(src, untrustedKey())
	if err != nil {
		return nil, err
	}
	ed, err := build(src, ed25519BundleKey())
	if err != nil {
		return nil, err
	}
	unsigned, err := withEnvelope(good, func(e *envelope) error {
		e.Signatures = []sigEntry{}
		return nil
	})
	if err != nil {
		return nil, err
	}
	// The payload is changed after signing: expires_at moved out by years.
	tampered, err := withEnvelope(good, func(e *envelope) error {
		p, err := base64.StdEncoding.DecodeString(e.Payload)
		if err != nil {
			return err
		}
		q := bytes.Replace(p, []byte(`"expires_at":"2027-04-01T00:00:00Z"`), []byte(`"expires_at":"2099-04-01T00:00:00Z"`), 1)
		if bytes.Equal(p, q) {
			return fmt.Errorf("tampered-payload: expires_at 2027-04-01T00:00:00Z not found in the manifest")
		}
		e.Payload = base64.StdEncoding.EncodeToString(q)
		return nil
	})
	if err != nil {
		return nil, err
	}
	untrustedRing, err := keyringFor(untrustedKey(), trust.AlgES256)
	if err != nil {
		return nil, err
	}
	edRing, err := keyringFor(ed25519BundleKey(), trust.AlgEd25519)
	if err != nil {
		return nil, err
	}
	return map[string][]byte{
		"unsigned.tar.gz":              unsigned,
		"tampered-payload.tar.gz":      tampered,
		"untrusted-key.tar.gz":         untrusted,
		"untrusted-key.keyring.json":   untrustedRing,
		"empty-keyring.tar.gz":         good, // valid; the test supplies an empty keyring
		"ed25519-release.tar.gz":       ed,
		"ed25519-release.keyring.json": edRing,
		"revoked-in-grace.tar.gz":      good, // valid; the test revokes it inside the expiry grace
	}, nil
}

// withEnvelope rewrites the manifest envelope of a built archive.
func withEnvelope(archive []byte, edit func(*envelope) error) ([]byte, error) {
	es, _, err := goodEntries(archive)
	if err != nil {
		return nil, err
	}
	var e envelope
	if err := json.Unmarshal(es[0].body, &e); err != nil {
		return nil, err
	}
	if err := edit(&e); err != nil {
		return nil, err
	}
	body, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	es[0].body, es[0].h.Size = body, int64(len(body))
	t, err := tarOf(es)
	if err != nil {
		return nil, err
	}
	return gzipBytes(t), nil
}

// keyringFor is a one-key keyring file with purpose bundle.
func keyringFor(key crypto.Signer, alg string) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, err
	}
	b, err := json.MarshalIndent(map[string]any{"format": "compliancetf.keyring/v1", "keys": []map[string]any{{
		"kid": trust.KIDFromSPKI(der), "alg": alg, "purpose": []string{trust.PurposeBundle},
		"public_key": base64.StdEncoding.EncodeToString(der),
		"not_before": "2026-01-01T00:00:00Z", "not_after": "2030-01-01T00:00:00Z",
	}}}, "", "  ")
	return append(b, '\n'), err
}
