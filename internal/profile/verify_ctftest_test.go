//go:build ctftest

package profile

import (
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

// TestFixturesVerifyWithTrust: under ctftest the profile fixtures verify with
// the real trust.Verify and the derived profile key, with no verifier swap.
func TestFixturesVerifyWithTrust(t *testing.T) {
	v, err := trust.Verify(fixture(t, "v7"), trust.PayloadProfile, trust.NoRevocations())
	if err != nil || v.KeyID != testKID() {
		t.Fatalf("trust.Verify = %q, %v; want kid %s", v.KeyID, err, testKID())
	}
}
