package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const golden = "../../internal/bundlegen/testdata/golden/fixture"

// TestVerifyCmd: the committed golden output verifies clean; a case whose
// expectation is flipped fails; missing flags print the usage.
func TestVerifyCmd(t *testing.T) {
	const schema = "../../internal/bundlegen/testdata/inputs/schema.json"
	if err := run([]string{"verify", "--schema", schema, "--dir", golden}); err != nil {
		t.Fatalf("golden: %v", err)
	}
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS(golden)); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "cis-aws/cases/rds_bobthecorp_storage_encrypted/resource.aws_db_instance.pass.json")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(strings.Replace(string(b), `"state": "pass"`, `"state": "fail"`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"verify", "--schema", schema, "--dir", dir}); err == nil || !strings.Contains(err.Error(), "findings") {
		t.Fatalf("flipped case: %v", err)
	}
	for _, args := range [][]string{{"verify", "--dir", golden}, {"verify", "--schema", schema}, {"verify", "--schema", schema, "--dir", golden, "extra"}} {
		if err := run(args); err == nil || !strings.Contains(err.Error(), "usage") {
			t.Errorf("%v: err %v, want usage", args, err)
		}
	}
}
