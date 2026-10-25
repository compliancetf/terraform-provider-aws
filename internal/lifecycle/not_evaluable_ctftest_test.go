//go:build ctftest

package lifecycle

import (
	"os"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

// TestNotEvaluableProfileVerifies: the committed bobthecorp-permissive
// profile verifies against the ctftest keyring (profile purpose).
func TestNotEvaluableProfileVerifies(t *testing.T) {
	env, err := os.ReadFile("../../testdata/profiles/bobthecorp-permissive.dsse.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trust.Verify(env, trust.PayloadProfile, trust.NoRevocations()); err != nil {
		t.Fatal(err)
	}
}
