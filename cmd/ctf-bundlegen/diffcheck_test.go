package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const rdsID = "rds_bobthecorp_storage_encrypted"

// diffcheckWorkspace copies the generator fixture inputs into a temp
// directory, chdirs there (the case schema path must be relative) and
// replaces the intents with one rds intent carrying postcondition post; the
// rds authored file is removed so the intent is translated.
func diffcheckWorkspace(t *testing.T, post string) {
	t.Helper()
	abs, err := filepath.Abs("../../internal/bundlegen/testdata")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS(filepath.Join(abs, "inputs"))); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "authored", rdsID+".yaml")); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"lock.json": "{}\n",
		"intents.json": `{"format": "content.provider-intents/1", "content_version": "0.27.1", "content_commit": "1f2a3ad",
 "catalog_snapshot_id": "snap_20261004_000000_000000",
 "policies": [{"id": "` + rdsID + `", "resource_type": "aws_db_instance",
  "attributes": [{"schema_path": "storage_encrypted", "condition": "equals_any", "values": [true], "values_from_ref": null}],
  "explanation": "Attribute storage_encrypted must be true.", "postcondition": ` + post + `, "has_strategy_condition": false}]}`,
		"fixtures.json": `{"format": "content.policy-fixtures/1", "content_version": "0.27.1", "content_commit": "1f2a3ad", "policies": []}`,
		"allow.yaml":    "- {id: " + rdsID + ", case: pass, cel: pass, postcondition: fail, reason: planted}\n",
	}
	// generate reads --pins (default pins.json): the provider's root pins;
	// and --releases (default releases.json): here the pin is the floor, so
	// no older release schema is needed for the fixture types.
	pins, err := os.ReadFile(filepath.Join("..", "..", "pins.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pin struct{ Version string }
	if err := json.Unmarshal(pins, &pin); err != nil {
		t.Fatal(err)
	}
	files["pins.json"] = string(pins)
	files["releases.json"] = `{"format": "compliancetf.releases/v1", "floor": "` + pin.Version + `", "releases": ["` + pin.Version + `"]}`
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(dir)
}

var genArgs = []string{"generate", "--catalog", "catalog", "--intents", "intents.json", "--schema", "schema.json", "--lock", "lock.json",
	"--authored", "authored", "--iam-actions", "iam-actions.json", "--out", "out"}

func args(extra ...string) []string { return append(append([]string{}, genArgs...), extra...) }

// TestGenerateDiffcheckFlags: generate needs --policy-fixtures or
// --no-diffcheck (not both, and no allow file without diffcheck); a
// planted disagreement moves the id to review-queue.md and the written
// output diffchecks clean; the same intents against an output that still
// has the control fail the diffcheck subcommand.
func TestGenerateDiffcheckFlags(t *testing.T) {
	diffcheckWorkspace(t, `"self.storage_encrypted == false"`)
	for _, a := range [][]string{args(), args("--no-diffcheck", "--policy-fixtures", "fixtures.json"),
		args("--no-diffcheck", "--diffcheck-allow", "allow.yaml"), args("--diffcheck-allow", "allow.yaml")} {
		if err := run(a); err == nil || !strings.Contains(err.Error(), "usage") {
			t.Errorf("%v: err %v, want usage", a[len(genArgs):], err)
		}
	}
	if _, err := os.Lstat("out"); !os.IsNotExist(err) {
		t.Fatalf("usage errors wrote output: %v", err)
	}

	if err := run(args("--no-diffcheck", "--out", "off")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat("off/diffcheck.json"); !os.IsNotExist(err) {
		t.Fatalf("--no-diffcheck wrote diffcheck.json: %v", err)
	}

	if err := run(args("--policy-fixtures", "fixtures.json")); err != nil {
		t.Fatal(err)
	}
	q, err := os.ReadFile("out/review-queue.md")
	if err != nil {
		t.Fatal(err)
	}
	c, err := os.ReadFile("out/all/controls.json")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(q), "E_REVIEW_PENDING "+rdsID+" -: diffcheck: ") || strings.Contains(string(c), rdsID) {
		t.Fatalf("review-queue.md:\n%s\ncontrols.json:\n%s", q, c)
	}
	if _, err := os.ReadFile("out/diffcheck.json"); err != nil {
		t.Fatal(err)
	}
	dc := []string{"diffcheck", "--schema", "schema.json", "--intents", "intents.json", "--policy-fixtures", "fixtures.json"}
	if err := run(append(dc, "--dir", "out")); err != nil {
		t.Fatalf("diffcheck of the generated output: %v", err)
	}
	if err := run(append(dc, "--dir", "off")); err == nil || !strings.Contains(err.Error(), "E_ findings") {
		t.Fatalf("diffcheck with the mismatched control: %v", err)
	}
	if err := run(append(dc, "--dir", "off", "--diffcheck-allow", "allow.yaml")); err == nil {
		t.Fatal("one direction allowed, the other still mismatches")
	}
	for _, a := range [][]string{dc, {"diffcheck", "--dir", "out", "--schema", "schema.json", "--intents", "intents.json"}, append(dc, "--dir", "out", "extra")} {
		if err := run(a); err == nil || !strings.Contains(err.Error(), "usage") {
			t.Errorf("%v: err %v, want usage", a, err)
		}
	}
}

// TestGenerateDiffcheckEval: a postcondition diffcheck cannot evaluate
// fails generate with nothing written.
func TestGenerateDiffcheckEval(t *testing.T) {
	diffcheckWorkspace(t, `"self.bobthecorp_missing == true"`)
	if err := run(args("--policy-fixtures", "fixtures.json")); err == nil || !strings.Contains(err.Error(), "E_DIFFCHECK_EVAL") {
		t.Fatalf("eval error: %v", err)
	}
	if _, err := os.Lstat("out"); !os.IsNotExist(err) {
		t.Fatalf("failed generate wrote output: %v", err)
	}
}

// TestGeneratePinsFlag: generate fails closed on a missing or invalid --pins
// file instead of writing a build.json without the upstream version.
func TestGeneratePinsFlag(t *testing.T) {
	diffcheckWorkspace(t, `"self.storage_encrypted == false"`)
	if err := run(args("--no-diffcheck", "--pins", "missing.json")); err == nil || !strings.Contains(err.Error(), "pass --pins") {
		t.Errorf("missing pins: %v", err)
	}
	if err := run(args("--no-diffcheck", "--pins", "lock.json")); err == nil || !strings.Contains(err.Error(), "lock.json: pins:") {
		t.Errorf("invalid pins: %v", err)
	}
}
