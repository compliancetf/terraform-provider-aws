//go:build ctftest

package embedded

import (
	"crypto/x509"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/trust"
	"github.com/compliancetf/terraform-provider-aws/internal/trust/testkeys"
)

// TestCtftestCIS: a ctftest build trusts the derived test bundle key, so the
// embedded bundle loads through the production path.
func TestCtftestCIS(t *testing.T) {
	b, warn, err := CIS(cisIssued, trust.NoRevocations())
	if err != nil || warn != "" {
		t.Fatalf("CIS: %v %q", err, warn)
	}
	spki, err := x509.MarshalPKIXPublicKey(&testkeys.Bundle().PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if want := trust.KIDFromSPKI(spki); b.KeyID != want {
		t.Errorf("kid %s, want test bundle key %s", b.KeyID, want)
	}
}
