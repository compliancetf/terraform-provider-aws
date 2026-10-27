//go:build ctftest

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

// TestSignedArtifactsVerifyCtftest: the committed fixture manifest and a
// CLI-signed profile verify against the embedded ctftest keyring
// (keyring_test.json), so the derived test keys and the keyring agree.
func TestSignedArtifactsVerifyCtftest(t *testing.T) {
	f, err := os.Open(filepath.Join(fixture, "good.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(zr)
	if h, err := tr.Next(); err != nil || h.Name != bundle.ManifestEntry {
		t.Fatalf("first entry: %v %v", h, err)
	}
	env, _ := io.ReadAll(tr)
	if _, err := trust.Verify(env, trust.PayloadBundleManifest, trust.NoRevocations()); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	in, signed := filepath.Join(dir, "p.json"), filepath.Join(dir, "p.dsse.json")
	profile := `{"format":"compliancetf.profile/v1","org_id":"bobthecorp","profile_version":7,"issued_at":"2026-10-01T00:00:00Z","expires_at":"2026-10-20T00:00:00Z"}`
	if err := os.WriteFile(in, []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"sign", "-type", "profile", "-in", in, "-key", "test:profile", "-out", signed}, io.Discard); err != nil {
		t.Fatal(err)
	}
	env, _ = os.ReadFile(signed)
	if _, err := trust.Verify(env, trust.PayloadProfile, trust.NoRevocations()); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	for _, p := range []string{filepath.Join(fixture, "good.tar.gz"), signed} {
		if err := run([]string{"verify", p}, &out); err != nil {
			t.Fatalf("verify %s: %v", p, err)
		}
	}
	if !strings.HasPrefix(out.String(), "ok bundle bobthecorp-soc2 v12") || !strings.Contains(out.String(), "ok "+trust.PayloadProfile+" kid=sha256:") {
		t.Fatalf("verify output: %s", out.String())
	}
}

// TestSigBugsReproducible: the committed signature rejection set equals a fresh
// `ctfbundle sigbugs` run, file for file; archives compare by tar stream
// (see sameTar).
func TestSigBugsReproducible(t *testing.T) {
	set, err := sigbugSet(fixture)
	if err != nil {
		t.Fatal(err)
	}
	dir := "../../internal/bundle/testdata/sigbugs"
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(set) {
		t.Fatalf("%d committed files, generator writes %d", len(entries), len(set))
	}
	for name, want := range set {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		same := bytes.Equal(got, want)
		if !same && strings.HasSuffix(name, ".tar.gz") {
			same = sameTar(t, got, want)
		}
		if !same {
			t.Errorf("%s is stale: run go generate ./testdata/generate.go", name)
		}
	}
}
