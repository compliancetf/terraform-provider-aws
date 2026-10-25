package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sd = "../../internal/schemadiff/testdata/"

// TestSchemaCmds: prune-schema output feeds schemadiff; a clean diff exits 0,
// a removed read exits non-zero, and both write the report.
func TestSchemaCmds(t *testing.T) {
	dir := t.TempDir()
	pruned := filepath.Join(dir, "pruned.json")
	if err := run([]string{"prune-schema", "--content", sd + "controls.json", "--schema", sd + "base.json", "--out", pruned}); err != nil {
		t.Fatal(err)
	}
	rep := filepath.Join(dir, "report.json")
	if err := run([]string{"schemadiff", "--content", sd + "controls.json", "--base", sd + "base.json", "--schema", pruned, "--out", rep}); err != nil {
		t.Fatalf("clean diff: %v", err)
	}
	if b, _ := os.ReadFile(rep); !strings.Contains(string(b), `"result": "pass"`) {
		t.Errorf("clean report:\n%s", b)
	}
	err := run([]string{"schemadiff", "--content", sd + "controls.json", "--base", sd + "base.json", "--schema", sd + "removed-attr.json", "--out", rep})
	if err == nil {
		t.Fatal("removed read: exit 0")
	}
	if b, _ := os.ReadFile(rep); !strings.Contains(string(b), `"check": "read_missing"`) {
		t.Errorf("removed-attr report:\n%s", b)
	}
	for _, args := range [][]string{
		{"schemadiff", "--content", sd + "controls.json"},
		{"prune-schema", "--schema", sd + "base.json", "--out", pruned},
		{"schemadiff", "--content", sd + "controls.json", "--base", sd + "base.json", "--schema", pruned, "extra"},
	} {
		if err := run(args); err == nil || !strings.Contains(err.Error(), "usage") {
			t.Errorf("%v: err %v, want usage", args, err)
		}
	}
}
