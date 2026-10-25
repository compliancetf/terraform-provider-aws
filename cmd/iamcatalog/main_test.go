package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/iampolicy"
)

func TestBuild(t *testing.T) {
	out := filepath.Join(t.TempDir(), "iam-actions.json")
	args := []string{"-source", "testdata/snapshot", "-retrieved", "2026-10-01", "-out", out}
	if err := run(args, io.Discard); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	// sha256sum lines of kms.json and s3.json, sorted, hashed.
	want := `{"format":"compliancetf.iam-actions/v1","retrieved":"2026-10-01",` +
		`"services":{"kms":["createkey","decrypt"],"s3":["getobject","putobject"]},` +
		`"snapshot":"sha256:` + snapshotDigest(t) + `","source":"aws-service-reference"}`
	if string(got) != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
	if _, err := iampolicy.LoadCatalog(got); err != nil {
		t.Fatalf("output does not load: %v", err)
	}
	again, err := build("testdata/snapshot", "2026-10-01")
	if err != nil || !bytes.Equal(again, got) {
		t.Fatalf("rebuild is not byte-identical: %v", err)
	}
}

func TestBuildRejects(t *testing.T) {
	write := func(files map[string]string) string {
		dir := t.TempDir()
		for n, c := range files {
			if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}
	kms := `{"Name":"kms","Actions":[{"Name":"Decrypt"}]}`
	for name, tc := range map[string]struct {
		dir, retrieved string
	}{
		"empty_dir":     {t.TempDir(), "2026-10-01"},
		"bad_date":      {write(map[string]string{"kms.json": kms}), "2026-10-1"},
		"not_service":   {write(map[string]string{"index.json": `[{"service":"kms"}]`}), "2026-10-01"},
		"duplicate":     {write(map[string]string{"a.json": kms, "b.json": kms}), "2026-10-01"},
		"bad_name":      {write(map[string]string{"kms.json": `{"Name":"kms","Actions":[{"Name":"De crypt"}]}`}), "2026-10-01"},
		"no_actions":    {write(map[string]string{"kms.json": `{"Name":"kms","Actions":[]}`}), "2026-10-01"},
		"missing_flags": {"", ""},
	} {
		t.Run(name, func(t *testing.T) {
			args := []string{"-out", filepath.Join(t.TempDir(), "x.json")}
			if tc.dir != "" {
				args = append(args, "-source", tc.dir, "-retrieved", tc.retrieved)
			}
			if err := run(args, io.Discard); err == nil {
				t.Fatal("want error")
			}
		})
	}
}

func snapshotDigest(t *testing.T) string {
	t.Helper()
	var lines strings.Builder
	for _, f := range []string{"kms.json", "s3.json"} {
		b, err := os.ReadFile(filepath.Join("testdata/snapshot", f))
		if err != nil {
			t.Fatal(err)
		}
		lines.WriteString(hexSum(b) + "  " + f + "\n")
	}
	return hexSum([]byte(lines.String()))
}

func hexSum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
