package profile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

// coverableFixtures are the signed coverability profiles.
func coverableFixtures() map[string][]byte {
	return map[string][]byte{
		// self_service lists bobthecorp-s3-001, but no list names self_service.
		"selfservice-not-coverable": signProfile(basePayload(10, func(m map[string]any) {
			m["exceptions"].(map[string]any)["coverable"] = map[string][]string{"bobthecorp-s3-001": {"grant"}}
		})),
		"coverable-unknown-kind": signProfile(basePayload(10, func(m map[string]any) {
			m["exceptions"].(map[string]any)["coverable"] = map[string][]string{"bobthecorp-s3-001": {"self_service", "waiver"}}
		})),
	}
}

func TestCoverableGenerateProfiles(t *testing.T) {
	if !*update {
		t.Skip("run with -update to regenerate")
	}
	for n, b := range coverableFixtures() {
		if err := os.WriteFile(filepath.Join(fixtureDir, "bobthecorp-"+n+".dsse.json"), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// TestCoverableProfile: an unknown kind rejects the profile at load; a
// self_service id is checked against the effective coverable map, so a
// bundle-declared self_service kind counts and a missing one rejects.
func TestCoverableProfile(t *testing.T) {
	load := func(name string) (*Profile, error) {
		v, err := verifyEnvelope(fixture(t, name), trust.NoRevocations())
		if err != nil {
			t.Fatal(err)
		}
		p, _, err := Parse(v.Payload)
		return p, err
	}
	if _, err := load("coverable-unknown-kind"); err == nil || !strings.Contains(err.Error(), "unknown exemption kind") {
		t.Fatalf("unknown kind: %v", err)
	}
	p, err := load("selfservice-not-coverable")
	if err != nil {
		t.Fatal(err)
	}
	none := func(string) bool { return false } // e.g. grant only
	if err := p.Exceptions.CheckSelfService(none); err == nil || !strings.Contains(err.Error(), "self_service_not_coverable") {
		t.Fatalf("missing self_service kind: %v", err)
	}
	bundleDeclared := func(id string) bool { return id == "bobthecorp-s3-001" }
	if err := p.Exceptions.CheckSelfService(bundleDeclared); err != nil {
		t.Fatalf("bundle-declared self_service: %v", err)
	}
	var nilEx *Exceptions
	if err := nilEx.CheckSelfService(none); err != nil || nilEx.Forbidden("x") {
		t.Fatal("nil Exceptions")
	}
}
