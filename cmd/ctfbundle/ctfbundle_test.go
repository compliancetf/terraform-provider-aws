package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/trust"
	"github.com/compliancetf/terraform-provider-aws/internal/trust/testkeys"
)

const fixture = "../../testdata/bundles/bobthecorp-soc2-sim"

func mustBuild(t *testing.T) []byte {
	t.Helper()
	b, err := build(fixture, testkeys.Bundle())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestBuildReproducible is the oracle: two builds are byte-equal and
// equal the committed good.tar.gz, so `go generate` is reproducible.
func TestBuildReproducible(t *testing.T) {
	a, b := mustBuild(t), mustBuild(t)
	if !bytes.Equal(a, b) {
		t.Fatal("two builds differ")
	}
	committed, err := os.ReadFile(filepath.Join(fixture, "good.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, committed) {
		t.Fatal("good.tar.gz is stale: run go generate ./testdata/generate.go")
	}
}

// TestBuildIAMCatalog: the release-iam bundle packs iam-actions.json
// into its signed manifest and equals the committed archive; without the file
// build refuses its iam.* controls (iam_catalog_missing).
func TestBuildIAMCatalog(t *testing.T) {
	const src = "../../testdata/bundles/release-iam"
	got, err := build(src, testkeys.Bundle())
	if err != nil {
		t.Fatal(err)
	}
	committed, err := os.ReadFile(src + ".tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, committed) {
		t.Fatal("release-iam.tar.gz is stale: run go generate ./testdata/generate.go")
	}
	dir := t.TempDir()
	for _, name := range []string{"manifest.json", "controls.json"} {
		b, err := os.ReadFile(filepath.Join(src, name))
		if err != nil {
			t.Fatal(err)
		}
		_ = os.WriteFile(filepath.Join(dir, name), b, 0o600)
	}
	if _, err := build(dir, testkeys.Bundle()); err == nil || !strings.Contains(err.Error(), "iam_catalog_missing") {
		t.Fatalf("got %v, want iam_catalog_missing", err)
	}
}

func TestBuildRejectsBadSource(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(fixture, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	m := string(raw)
	cases := map[string]string{
		"format":            `{"format":"v1"}`,
		"unknown member":    strings.Replace(m, `"profile"`, `"profil"`, 1),
		"files is computed": strings.Replace(m, `"profile"`, `"files":[],"profile"`, 1),
		"expires_at":        strings.Replace(m, `"2027-04-01T00:00:00Z"`, `"2026-09-01T00:00:00Z"`, 1),
		"controls.json":     m, // no controls.json in the source dir
		"schema_compat":     strings.Replace(m, `"sha256:3864`, `"sha256:XX`, 1),
		"needs profile":     strings.Replace(m, `"profile": "soc2"`, `"profile": ""`, 1),
	}
	for want, manifest := range cases {
		dir := t.TempDir()
		_ = os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifest), 0o600)
		if _, err := build(dir, testkeys.Bundle()); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v", want, err)
		}
	}
	// A controls.json ParseControls accepts but DigestJSON rejects is not signed.
	ctl, err := os.ReadFile(filepath.Join(fixture, "controls.json"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0o600)
	_ = os.WriteFile(filepath.Join(dir, "controls.json"), []byte(strings.Replace(string(ctl), "RDS storage", "RDS \xff storage", 1)), 0o600)
	if _, err := build(dir, testkeys.Bundle()); err == nil || !strings.Contains(err.Error(), "digest_not_json") {
		t.Errorf("invalid UTF-8: got %v", err)
	}
}

func TestSignProfile(t *testing.T) {
	profile := []byte(`{"format":"compliancetf.profile/v1","org_id":"bobthecorp","profile_version":7,"issued_at":"2026-10-01T00:00:00Z","expires_at":"2026-10-20T00:00:00Z","floor_mode":"online","break_glass":{"enabled":true}}`)
	a, err := signPayload("profile", profile, testkeys.Profile())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := signPayload("profile", profile, testkeys.Profile())
	if !bytes.Equal(a, b) {
		t.Fatal("profile signature not deterministic")
	}
	var e envelope
	_ = json.Unmarshal(a, &e)
	if e.PayloadType != trust.PayloadProfile || e.Payload != base64.StdEncoding.EncodeToString(profile) {
		t.Fatalf("envelope %+v: payload must be the raw input bytes", e)
	}
	airgap := bytes.Replace(profile, []byte(`"online"`), []byte(`"airgap"`), 1)
	if _, err := signPayload("profile", airgap, testkeys.Profile()); err == nil || !strings.Contains(err.Error(), "break_glass") {
		t.Fatalf("airgap break-glass profile signed: %v", err)
	}
	dup := bytes.Replace(profile, []byte(`"floor_mode":"online"`), []byte(`"floor_mode":"online","floor_mode":"airgap"`), 1)
	if _, err := signPayload("profile", dup, testkeys.Profile()); err == nil {
		t.Fatal("payload with duplicate members signed")
	}
	if _, err := signPayload("profile", []byte(`[]`), testkeys.Profile()); err == nil {
		t.Fatal("non-object payload signed")
	}
	if _, err := signPayload("bundle-manifest", profile, testkeys.Profile()); err == nil {
		t.Fatal("manifest signed outside build")
	}
}
