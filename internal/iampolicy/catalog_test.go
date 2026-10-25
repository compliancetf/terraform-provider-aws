package iampolicy

import (
	"strings"
	"testing"
)

// TestCatalogHas: HasAction and HasService fold ASCII case and match exactly;
// "*" and prefixes are not patterns here.
func TestCatalogHas(t *testing.T) {
	b, err := EncodeCatalog("2026-10-01", "sha256:"+strings.Repeat("0", 64), map[string][]string{
		"kms": {"decrypt", "encrypt"},
		"s3":  {"getobject"},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, err := LoadCatalog(b)
	if err != nil {
		t.Fatal(err)
	}
	for action, want := range map[string]bool{
		"kms:decrypt":   true,
		"KMS:Decrypt":   true,
		"s3:GetObject":  true,
		"kms:decrypt2":  false,
		"kms:decryp":    false,
		"kms:*":         false,
		"kms:Decrypt*":  false,
		"*:decrypt":     false,
		"*":             false,
		"kms":           false,
		"kms:":          false,
		":decrypt":      false,
		"s3:decrypt":    false,
		"ec2:decrypt":   false,
		"kms:dEcRyPt":   true,
		"kms:getobject": false,
	} {
		if got := c.HasAction(action); got != want {
			t.Errorf("HasAction(%q) = %v, want %v", action, got, want)
		}
	}
	for svc, want := range map[string]bool{
		"kms":  true,
		"KMS":  true,
		"S3":   true,
		"km":   false,
		"kms2": false,
		"*":    false,
		"kms*": false,
		"ec2":  false,
		"":     false,
	} {
		if got := c.HasService(svc); got != want {
			t.Errorf("HasService(%q) = %v, want %v", svc, got, want)
		}
	}
}
