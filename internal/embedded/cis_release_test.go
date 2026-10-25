//go:build !ctftest

package embedded

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
	"github.com/compliancetf/terraform-provider-aws/internal/trust/testkeys"
)

// TestReleaseKeyGuard: a release build embeds cis.tar.gz, whose one
// signature is a valid ES256 signature by a bundle key of the release keyring
// (never the test key), over the same manifest payload bytes and controls as
// the test-signed cis_ctftest.tar.gz built from cis/. release.yml runs it. Whether the release keyring
// accepts it at run time (key window, revocation) is TestReleaseGuard's job.
func TestReleaseKeyGuard(t *testing.T) {
	var kid string
	var sig, pae, prodPayload, testPayload []byte
	calls := 0
	prod, err := bundle.ReadArchive(cisArchive, func(env []byte, payloadType string) (trust.Verified, error) {
		calls++
		payload, k, s, err := decodeEnvelope(env, payloadType)
		kid, sig, pae, prodPayload = k, s, trust.PAE(payloadType, payload), payload
		return trust.Verified{Payload: payload, KeyID: k}, err
	})
	if err != nil {
		t.Fatalf("cis.tar.gz: %v", err)
	}
	if calls != 1 {
		t.Fatalf("cis.tar.gz: %d signed envelopes, want 1", calls)
	}
	test, err := bundle.ReadArchive(cisTestArchive, func(env []byte, payloadType string) (trust.Verified, error) {
		v, err := testVerify(env, payloadType)
		testPayload = v.Payload
		return v, err
	})
	if err != nil {
		t.Fatalf("cis_ctftest.tar.gz: %v", err)
	}
	if !bytes.Equal(prodPayload, testPayload) || !reflect.DeepEqual(prod.Controls, test.Controls) {
		t.Fatal("cis.tar.gz and cis_ctftest.tar.gz differ: re-sign cis.tar.gz from cis/ with the production bundle key")
	}

	kr, err := trust.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	trusted := false
	for _, k := range kr.Keys() {
		trusted = trusted || k.KID == kid && k.Alg == trust.AlgES256 && k.Purpose == trust.PurposeBundle
	}
	testSPKI, err := x509.MarshalPKIXPublicKey(&testkeys.Bundle().PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if kid == trust.KIDFromSPKI(testSPKI) {
		t.Fatal("cis.tar.gz is signed by the derived test bundle key")
	}
	if !trusted {
		t.Fatalf("cis.tar.gz is signed by %s, not a bundle key of the release keyring", kid)
	}
	pub := releasePublicKey(t, kid)
	sum := sha256.Sum256(pae)
	if !ecdsa.VerifyASN1(pub, sum[:], sig) {
		t.Fatalf("cis.tar.gz signature by %s does not verify", kid)
	}
}

// releasePublicKey reads kid's public key from keyring.json; trust keeps
// parsed keys unexported.
func releasePublicKey(t *testing.T, kid string) *ecdsa.PublicKey {
	t.Helper()
	raw, err := os.ReadFile("../trust/keyring.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Keys []struct {
			KID       string `json:"kid"`
			PublicKey string `json:"public_key"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	for _, k := range f.Keys {
		if k.KID != kid {
			continue
		}
		der, err := base64.StdEncoding.DecodeString(k.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			t.Fatal(err)
		}
		ec, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("%s is not an ECDSA key", kid)
		}
		return ec
	}
	t.Fatalf("%s not in keyring.json", kid)
	return nil
}
