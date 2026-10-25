package lifecycle

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/exceptions"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
	"github.com/compliancetf/terraform-provider-aws/internal/trust/testkeys"
)

// grantEnvelope signs a grant payload with key as a DSSE envelope.
func grantEnvelope(t *testing.T, p map[string]any, key crypto.Signer) []byte {
	t.Helper()
	body, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(trust.PAE(trust.PayloadExceptionGrant, body))
	sig, err := key.Sign(rand.Reader, sum[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	env, err := json.Marshal(map[string]any{"payloadType": trust.PayloadExceptionGrant, "payload": base64.StdEncoding.EncodeToString(body),
		"signatures": []map[string]string{{"keyid": trust.KIDFromSPKI(der), "sig": base64.StdEncoding.EncodeToString(sig)}}})
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// grantPayload is a bobthecorp grant for controls, expiring at expires.
func grantPayload(controls []string, sel string, expires string) map[string]any {
	idp := "https://idp.bobthecorp.example"
	return map[string]any{"format": exceptions.Format, "grant_id": "bobthecorp-pg-encryption", "org_id": "bobthecorp",
		"workspaces": []string{"bobthecorp-reporting-prod"}, "controls": controls, "selector": sel,
		"reason": "Encrypted copy in progress, OPS-4411", "ticket": "OPS-4411",
		"approvers":      []map[string]string{{"subject": "alice@bobthecorp.example", "issuer": idp}, {"subject": "bob@bobthecorp.example", "issuer": idp + "/oidc"}},
		"content_digest": "sha256:" + "abababababababababababababababababababababababababababababababab", "floor_epoch": 0,
		"issued_at": "2026-10-01T00:00:00Z", "expires_at": expires}
}

// customerGrantKey is the profile grant_keys entry for testkeys.CustomerKMS.
func customerGrantKey(t *testing.T) profile.GrantKey {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(testkeys.CustomerKMS().Public())
	if err != nil {
		t.Fatal(err)
	}
	return profile.GrantKey{KID: trust.KIDFromSPKI(der), Alg: trust.AlgES256, SPKIB64: base64.StdEncoding.EncodeToString(der),
		NotBefore: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)}
}

// TestGrantStages runs stages/grant_*.json: a verified grant coverable for
// grant waives its controls in the lifecycle like a sidecar entry, recorded
// with source grant.
func TestGrantStages(t *testing.T) {
	now := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	runStages(t, "grant_*.json", func(t *testing.T, _ *stageGolden, l *Lifecycle) {
		withGrant(t, l, "type == 'aws_db_instance' && resource.deletion_protection == true", now)
	})
}

// withGrant installs in l a verified grant with selector sel on
// rds_db_instance_encryption_at_rest_enabled, coverable for grant, scoped
// to the trusted workspace bobthecorp-reporting-prod and to no environment.
func withGrant(t *testing.T, l *Lifecycle, sel string, now time.Time) {
	t.Helper()
	if n := withGrantOn(t, l, "rds_db_instance_encryption_at_rest_enabled", sel, now, true); len(n.Warnings) != 0 {
		t.Fatalf("%+v", n)
	}
}

// withGrantOn installs a verified grant on control: coverable for grant when
// coverable, else with the bundle-declared exemption_coverable lists only.
func withGrantOn(t *testing.T, l *Lifecycle, control, sel string, now time.Time, coverable bool) exceptions.Notices {
	t.Helper()
	declared := l.cfg.Controls.Coverable()
	if coverable {
		declared = map[string][]bundle.ExemptionKind{control: {bundle.CoverGrant}}
	}
	return withGrantCov(t, l, control, sel, now, declared)
}

// withGrantCov installs a verified grant on control, expiring 2026-10-20,
// under the signed coverable lists declared.
func withGrantCov(t *testing.T, l *Lifecycle, control, sel string, now time.Time, declared map[string][]bundle.ExemptionKind) exceptions.Notices {
	t.Helper()
	l.opt.Now = func() time.Time { return now }
	c := *l.cfg
	c.Table.Workspace = profile.Dim{Value: "bobthecorp-reporting-prod", Source: "profile"}
	c.Table.Exceptions = &profile.Exceptions{GrantKeys: []profile.GrantKey{customerGrantKey(t)}}
	dir := t.TempDir()
	cov, _ := exceptions.NewCoverability(declared, c.Table.Exceptions)
	p := grantPayload([]string{control}, sel, "2026-10-20T00:00:00Z")
	p["content_digest"] = c.Controls.ContentDigest(cov.Kinds()) // bound to the loaded content
	env := grantEnvelope(t, p, testkeys.CustomerKMS())
	if err := os.WriteFile(filepath.Join(dir, "g.dsse.json"), env, 0o600); err != nil {
		t.Fatal(err)
	}
	c.Block.GrantsDir = dir
	grants, n, err := loadGrants(c.Block, c.Table, c.Controls, cov, "bobthecorp", now, exceptions.Clock{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	c.Grants = grants
	l.cfg = &c
	return n
}

// TestDataSourceGrant runs stages/dsgrant_*.json: a signed grant on the deny
// data source control ds_lookup_encrypted (data_sources deny, hard_fail)
// never waives it while its exemption_coverable is empty, as the bundle
// declares, and waives it once it is coverable for grant.
func TestDataSourceGrant(t *testing.T) {
	now := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	runStages(t, "dsgrant_*.json", func(t *testing.T, g *stageGolden, l *Lifecycle) {
		coverable := strings.Contains(g.Description, "coverable for grant")
		n := withGrantOn(t, l, "ds_lookup_encrypted", "type == 'aws_db_lookup'", now, coverable)
		if coverable == (len(n.Warnings) != 0) {
			t.Fatalf("coverable %v: grant notices %+v", coverable, n)
		}
	})
}
