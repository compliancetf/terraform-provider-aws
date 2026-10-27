package embedded

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/bundlegen"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/celeng"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
	"github.com/compliancetf/terraform-provider-aws/internal/trust/testkeys"
)

// cisTestArchive is the test-signed copy in every build, so the content
// tests below run in release builds too, where cisArchive is production-signed.
//
//go:embed cis_ctftest.tar.gz
var cisTestArchive []byte

var (
	cisIssued  = time.Date(2026, 10, 6, 1, 0, 0, 0, time.UTC)
	cisExpires = time.Date(2027, 10, 6, 0, 0, 0, 0, time.UTC)
)

// testVerify checks a one-signature envelope against the derived test bundle
// key, independent of the compiled keyring.
func testVerify(env []byte, payloadType string) (trust.Verified, error) {
	payload, kid, sig, err := decodeEnvelope(env, payloadType)
	if err != nil {
		return trust.Verified{}, err
	}
	sum := sha256.Sum256(trust.PAE(payloadType, payload))
	if !ecdsa.VerifyASN1(&testkeys.Bundle().PublicKey, sum[:], sig) {
		return trust.Verified{}, errors.New("signature invalid")
	}
	return trust.Verified{Payload: payload, KeyID: kid}, nil
}

// decodeEnvelope returns the payload, kid and signature of a one-signature
// envelope without checking the signature.
func decodeEnvelope(env []byte, payloadType string) (payload []byte, kid string, sig []byte, err error) {
	var e struct {
		PayloadType string `json:"payloadType"`
		Payload     string `json:"payload"`
		Signatures  []struct {
			KeyID string `json:"keyid"`
			Sig   string `json:"sig"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(env, &e); err != nil || len(e.Signatures) != 1 || e.PayloadType != payloadType {
		return nil, "", nil, errors.New("bad envelope")
	}
	if payload, err = base64.StdEncoding.DecodeString(e.Payload); err != nil {
		return nil, "", nil, err
	}
	if sig, err = base64.StdEncoding.DecodeString(e.Signatures[0].Sig); err != nil {
		return nil, "", nil, err
	}
	return payload, e.Signatures[0].KeyID, sig, nil
}

func loadTest(t *testing.T, now time.Time, revs trust.Revocations) (*bundle.Bundle, string) {
	t.Helper()
	b, warn, err := load(cisTestArchive, testVerify, now, revs)
	if err != nil {
		t.Fatal(err)
	}
	return b, warn
}

// TestEmbeddedIDsInCatalog: every embedded control id is a catalog id of the pinned
// snapshot the manifest names (L12).
func TestEmbeddedIDsInCatalog(t *testing.T) {
	b, _ := loadTest(t, cisIssued, trust.NoRevocations())
	f, err := os.Open("../../testdata/catalog/" + b.Manifest.Catalog.SnapshotID + ".ids.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ids := map[string]bool{}
	for s := bufio.NewScanner(f); s.Scan(); {
		if line := s.Text(); line != "" && !strings.HasPrefix(line, "#") {
			ids[line] = true
		}
	}
	if len(b.Controls) == 0 {
		t.Fatal("embedded CIS bundle has no controls")
	}
	for _, c := range b.Controls {
		if !ids[c.ID] {
			t.Errorf("control %s (%s) is not in catalog snapshot %s", c.ID, c.ResourceType, b.Manifest.Catalog.SnapshotID)
		}
	}
}

// TestEmbeddedSource: cis/controls.json passes ParseControls and the JSON
// Schema, and the test-signed archive was built from exactly cis/ (regenerate
// with go generate ./internal/embedded/).
func TestEmbeddedSource(t *testing.T) {
	src, err := os.ReadFile("cis/controls.json")
	if err != nil {
		t.Fatal(err)
	}
	want, err := bundle.ParseControls(src)
	if err != nil {
		t.Fatal(err)
	}
	sch, err := jsonschema.NewCompiler().Compile("../../schema/bundle-control-2.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if err := sch.Validate(doc); err != nil {
		t.Errorf("schema rejects cis/controls.json: %v", err)
	}
	rawManifest, err := os.ReadFile("cis/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	wantManifest, err := bundle.DecodeManifest(rawManifest)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := loadTest(t, cisIssued, trust.NoRevocations())
	got := *b.Manifest
	got.Files = nil
	if !reflect.DeepEqual(&got, wantManifest) || !reflect.DeepEqual(b.Controls, want) {
		t.Error("cis_ctftest.tar.gz is stale: run go generate ./internal/embedded/")
	}
	if b.Manifest.BundleID != "cis-aws" || b.Manifest.OrgID != "" {
		t.Errorf("bundle %s org %q: want public cis-aws", b.Manifest.BundleID, b.Manifest.OrgID)
	}
}

// TestEmbeddedSchemaCompat checks the controls against testdata/schema_compat.tsv
// (type, read, cty type, computed flag; from `terraform providers schema
// -json` of the pinned hashicorp/aws, tools/cispin): the manifest
// schema_compat_digest is sha256 of its first three columns and equals the
// digest of the captured aws-subset.json schema, every read is listed, a
// Computed read is bound with presence_mode configured, and the controls load
// in the CEL engine against that schema without a diagnostic (reads resolve
// and cover the expr). TestEmbeddedVerdicts pins literal types by verdict.
func TestEmbeddedSchemaCompat(t *testing.T) {
	raw, err := os.ReadFile("testdata/schema_compat.tsv")
	if err != nil {
		t.Fatal(err)
	}
	type attr struct {
		cty      string
		computed bool
	}
	attrs := map[string]attr{}
	var pre []string
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 4 {
			t.Fatalf("bad line %q", line)
		}
		attrs[f[0]+" "+f[1]] = attr{f[2], f[3] == "computed"}
		pre = append(pre, strings.Join(f[:3], "\t"))
	}
	b, _ := loadTest(t, cisIssued, trust.NoRevocations())
	if sum := sha256.Sum256([]byte(strings.Join(pre, "\n"))); b.Manifest.SchemaCompatDigest != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Errorf("schema_compat_digest %s does not match testdata/schema_compat.tsv", b.Manifest.SchemaCompatDigest)
	}
	s := awsSchemas(t)
	if d, err := bundlegen.SchemaCompatDigest(b.Controls, s); err != nil || d != b.Manifest.SchemaCompatDigest {
		t.Errorf("aws-subset.json digest %s (%v), manifest %s", d, err, b.Manifest.SchemaCompatDigest)
	}
	for _, c := range b.Controls {
		for _, r := range c.Reads {
			a, ok := attrs[c.ResourceType+" "+r]
			if !ok {
				t.Errorf("%s: read %s.%s missing from schema_compat.tsv", c.ID, c.ResourceType, r)
			}
			if a.computed && c.PresenceMode != bundle.PresenceConfigured {
				t.Errorf("%s: Computed read %s needs presence_mode configured", c.ID, r)
			}
		}
	}
	if _, diags, err := celeng.Load(b.Controls, s.ProviderSchema()); err != nil || len(diags) > 0 {
		t.Errorf("celeng.Load: %v, diagnostics %v", err, diags)
	}
}

// TestEmbeddedExpiry: only ErrExpired is downgraded to a warning; the bundle
// stays loaded past the grace window, while revocation and a future
// issued_at still refuse it.
func TestEmbeddedExpiry(t *testing.T) {
	if _, warn := loadTest(t, cisIssued, trust.NoRevocations()); warn != "" {
		t.Errorf("fresh bundle warns: %s", warn)
	}
	for _, now := range []time.Time{cisExpires.Add(24 * time.Hour), cisExpires.Add(bundle.ExpiryGrace + time.Hour), cisExpires.AddDate(5, 0, 0)} {
		b, warn := loadTest(t, now, trust.NoRevocations())
		if b == nil || !strings.Contains(warn, "expired") {
			t.Errorf("at %s: bundle %v, warning %q; want loaded with an expiry warning", now, b != nil, warn)
		}
	}
	revs, err := trust.ParseRevocations([]byte(`{"format":"compliancetf.revocations/v1","epoch":1,"revoked_keys":[],` +
		`"revoked_bundles":[{"bundle_id":"cis-aws","below_version":3}],"revoked_controls":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, now := range []time.Time{cisIssued, cisExpires.AddDate(1, 0, 0)} {
		if b, _, err := load(cisTestArchive, testVerify, now, revs); b != nil || err == nil || errors.Is(err, bundle.ErrExpired) {
			t.Errorf("revoked at %s: bundle %v, err %v; want refused", now, b != nil, err)
		}
	}
	if b, _, err := load(cisTestArchive, testVerify, cisIssued.AddDate(0, 0, -1), trust.NoRevocations()); b != nil || err == nil {
		t.Errorf("issued in the future: bundle %v, err %v; want refused", b != nil, err)
	}
}
