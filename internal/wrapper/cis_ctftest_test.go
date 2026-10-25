//go:build ctftest

package wrapper

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/bundle/bundletest"
	"github.com/compliancetf/terraform-provider-aws/internal/trust/testkeys"
)

// cisPath is the CIS archive the compiled test keyring verifies.
const cisPath = "../embedded/cis_ctftest.tar.gz"

// TestLoadCISErrors are the CIS bundle rows: archives re-signed with the test
// bundle key (or a key outside the keyring for the signature row).
func TestLoadCISErrors(t *testing.T) {
	cis := read(t, cisPath)
	unknown, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := func(key *ecdsa.PrivateKey, edit func(*bundle.Manifest)) []byte {
		t.Helper()
		b, err := bundletest.WithManifest(cis, key, func(m *bundle.Manifest) error { edit(m); return nil })
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	controls := func(old, repl string) []byte {
		t.Helper()
		var body []byte
		if _, err := bundletest.Rewrite(cis, func(name string, b []byte) ([]byte, bool, error) {
			if name == "controls.json" {
				body = b
			}
			return b, true, nil
		}); err != nil {
			t.Fatal(err)
		}
		edited := bytes.Replace(body, []byte(old), []byte(repl), 1)
		if bytes.Equal(edited, body) {
			t.Fatalf("controls.json has no %q", old)
		}
		b, err := bundletest.WithFile(cis, "controls.json", edited, testkeys.Bundle())
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	signed := manifest(unknown, func(*bundle.Manifest) {})
	cases := []struct {
		name string
		cis  []byte
		want string
	}{
		{"signature", signed, sigErr(t, signed)},
		{"control outside prefix", controls(`"resource_type": "aws_db_instance"`, `"resource_type": "google_sql_database_instance"`),
			"wrapper: CIS bundle control rds_db_instance_encryption_at_rest_enabled targets google_sql_database_instance, outside resource_prefix aws_"},
		{"bundle id", manifest(testkeys.Bundle(), func(m *bundle.Manifest) { m.BundleID = "cis-azure" }),
			`wrapper: CIS bundle is "cis-azure", wrapper.json says cis-aws`},
		{"provider address", manifest(testkeys.Bundle(), func(m *bundle.Manifest) { m.Provider.Address = "registry.compliance.tf/compliancetf/google" }),
			`wrapper: CIS bundle is for provider "registry.compliance.tf/compliancetf/google", wrapper.json says registry.compliance.tf/compliancetf/aws`},
		{"upstream source", manifest(testkeys.Bundle(), func(m *bundle.Manifest) { m.Upstream.Source = "hashicorp/google" }),
			`wrapper: CIS bundle is for upstream "hashicorp/google", wrapper.json says registry.terraform.io/hashicorp/aws`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := awsInputs(t)
			in.cis = tc.cis
			cfg, err := in.load()
			checkErr(t, cfg, err, tc.want)
		})
	}
}
