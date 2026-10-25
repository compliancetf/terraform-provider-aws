//go:build !ctftest

package profile

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

// testVerify replaces trust.Verify in release-keyring test builds, which do
// not trust testKey: Ed25519 over the DSSE PAE with testKey. ctftest builds
// keep the real trust.Verify (no swap).
func testVerify(env []byte, _ trust.Revocations) (trust.Verified, error) {
	var e struct {
		PayloadType string `json:"payloadType"`
		Payload     string `json:"payload"`
		Signatures  []struct {
			KeyID string `json:"keyid"`
			Sig   string `json:"sig"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(env, &e); err != nil {
		return trust.Verified{}, err
	}
	if e.PayloadType != trust.PayloadProfile || len(e.Signatures) != 1 || e.Signatures[0].KeyID != testKID() {
		return trust.Verified{}, errors.New("dsse: no valid signature")
	}
	payload, err1 := base64.StdEncoding.DecodeString(e.Payload)
	sig, err2 := base64.StdEncoding.DecodeString(e.Signatures[0].Sig)
	if err1 != nil || err2 != nil || !ed25519.Verify(testKey.Public().(ed25519.PublicKey), trust.PAE(e.PayloadType, payload), sig) {
		return trust.Verified{}, errors.New("dsse: no valid signature: signature invalid")
	}
	return trust.Verified{Payload: payload, KeyID: testKID()}, nil
}

func TestMain(m *testing.M) {
	verifyEnvelope = testVerify
	os.Exit(m.Run())
}
