//go:build conformance

package upstream

import (
	"os"
	"path/filepath"
	"testing"
)

// TestConformancePinsReplaceEmbedded: a conformance build reads its pins from
// $COMPLIANCETF_CONFORMANCE_PINS when set, still through ParsePins, and fails
// closed when the file is missing or invalid.
func TestConformancePinsReplaceEmbedded(t *testing.T) {
	data, err := MarshalPins(validPins(t))
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(t.TempDir(), "pins.json")
	if err := os.WriteFile(f, data, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("COMPLIANCETF_CONFORMANCE_PINS", f)
	p, err := loadPins(nil, mustSource(t, awsAddress))
	if err != nil || p.Version != "6.40.0" {
		t.Fatalf("loadPins = %v, %v; want the conformance pins", p, err)
	}

	if err := os.WriteFile(f, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPins(nil, mustSource(t, awsAddress)); err == nil {
		t.Error("non-canonical conformance pins accepted")
	}
	t.Setenv("COMPLIANCETF_CONFORMANCE_PINS", filepath.Join(t.TempDir(), "missing.json"))
	if _, err := loadPins(nil, mustSource(t, awsAddress)); err == nil {
		t.Error("missing conformance pins file accepted")
	}
}
