package bundlegen

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// TestCoverage: coverage.json, coverage.md and the ledger generation_status
// column of the synthetic catalog match the goldens. The catalog has every
// status: generated (three authored ids), pending_review (intents content in
// "empty"), pending_authoring (a local id with no content) and
// not_applicable (a graph and an untargeted runtime id).
func TestCoverage(t *testing.T) {
	ledger, err := os.ReadFile(filepath.Join(inputs, "ledger.json"))
	if err != nil {
		t.Fatal(err)
	}
	for name, authored := range map[string]bool{"empty": false, "fixture": true} {
		t.Run(name, func(t *testing.T) {
			in := loadInputs(t, inputs, authored)
			files := generate(t, in)
			got, err := UpdateLedger(in, files, ledger)
			if err != nil {
				t.Fatal(err)
			}
			golden := filepath.Join("testdata/golden", "ledger-"+name+".json")
			if *update {
				if err := os.WriteFile(golden, got, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("ledger differs from %s (run with -update)", golden)
			}
			for _, f := range []string{"coverage.json", "coverage.md"} {
				want, err := os.ReadFile(filepath.Join("testdata/golden", name, f))
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(files[f], want) {
					t.Errorf("%s differs from golden (run TestGolden with -update)", f)
				}
			}
		})
	}

	// Golden-independent checks of the fixture semantics.
	in := loadInputs(t, inputs, true)
	files := generate(t, in)
	var rep coverageReport
	if err := json.Unmarshal(files["coverage.json"], &rep); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]string{"cis-aws": "ga", "soc2-aws": "ga", "pci-dss-aws": "preview", "hipaa-aws": "preview", "all": "preview"} {
		if got := rep.Bundles[id].Release; got != want {
			t.Errorf("%s release = %s, want %s", id, got, want)
		}
	}
	if got := rep.Bundles["hipaa-aws"]; got.Generated != 0 || !slices.Equal(got.PendingAuthoring, []string{"rds_bobthecorp_deletion_guard"}) {
		t.Errorf("hipaa-aws: generated %d, pending authoring %v", got.Generated, got.PendingAuthoring)
	}
	if got := rep.Bundles["soc2-aws"].Clauses["soc_2"]; got != (clauseCoverage{Covered: 3, Total: 4}) {
		t.Errorf("soc_2 clauses = %+v, want 3 of 4", got)
	}
	if got := rep.Bundles["soc2-aws"].NotVisible["aws_s3_bucket_versioning"]["graph"]; !slices.Equal(got, []string{"s3_bobthecorp_lifecycle_versioned"}) {
		t.Errorf("soc2-aws not visible = %v", got)
	}
	if got := rep.Bundles["cis-aws"].NotVisibleUntargeted; !slices.Equal(got, []string{"acct_bobthecorp_contact_set"}) {
		t.Errorf("cis-aws untargeted = %v", got)
	}
}

// TestCoverageGeneratedFromControls: generated status follows the emitted
// controls.json bytes, not the authored inputs.
func TestCoverageGeneratedFromControls(t *testing.T) {
	in := loadInputs(t, inputs, true)
	files := generate(t, in)
	delete(files, "all/controls.json")
	ledger, err := os.ReadFile(filepath.Join(inputs, "ledger.json"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := UpdateLedger(in, files, ledger)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(got, []byte(`"generated"`)) {
		t.Error("an id without an emitted control is generated")
	}
}

// TestCoverageLedgerErrors: each planted ledger breaks exactly one rule of
// an otherwise complete ledger and fails E_LEDGER with that rule's message.
func TestCoverageLedgerErrors(t *testing.T) {
	in := loadInputs(t, inputs, true)
	files := generate(t, in)
	src, err := os.ReadFile(filepath.Join(inputs, "ledger.json"))
	if err != nil {
		t.Fatal(err)
	}
	var base []map[string]any
	if err := json.Unmarshal(src, &base); err != nil {
		t.Fatal(err)
	}
	with := func(edit func([]map[string]any) []map[string]any) []byte {
		rows := edit(slices.Clone(base))
		data, err := json.Marshal(rows)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	cases := map[string]struct {
		ledger []byte
		msg    string
	}{
		"unknown id": {with(func(r []map[string]any) []map[string]any {
			return append(r, map[string]any{"id": "bobthecorp_unknown"})
		}), "bobthecorp_unknown has no provider disposition"},
		"no id": {with(func(r []map[string]any) []map[string]any {
			return append(r, map[string]any{"disposition": "runtime"})
		}), "has no id"},
		"duplicate": {with(func(r []map[string]any) []map[string]any {
			return append(r, map[string]any{"id": "s3_bobthecorp_versioning_on"})
		}), "duplicate id s3_bobthecorp_versioning_on"},
		"missing": {with(func(r []map[string]any) []map[string]any {
			return slices.DeleteFunc(r, func(m map[string]any) bool { return m["id"] == "s3_bobthecorp_versioning_on" })
		}), "1 ids without a ledger row: [s3_bobthecorp_versioning_on]"},
		"malformed": {append(slices.Clone(src), 'x'), "trailing data"},
		"not rows":  {[]byte(`{"id":"s3_bobthecorp_versioning_on"}`), "ledger:"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := UpdateLedger(in, files, tc.ledger)
			var e *Error
			if !errors.As(err, &e) || e.Code != "E_LEDGER" || !strings.Contains(e.Msg, tc.msg) {
				t.Fatalf("err = %v, want E_LEDGER %q", err, tc.msg)
			}
		})
	}
	if _, err := UpdateLedger(in, files, src); err != nil {
		t.Fatalf("complete ledger: %v", err)
	}
}

// TestCoverageFrameworkMissing: a selector framework without clause metadata
// fails instead of reporting 0 of 0 clauses.
func TestCoverageFrameworkMissing(t *testing.T) {
	in := loadInputs(t, inputs, true)
	delete(in.Catalog.Frameworks, "soc_2")
	var e *Error
	if _, err := Generate(in, testOpts); !errors.As(err, &e) || e.Code != "E_INPUT" {
		t.Fatalf("err = %v, want E_INPUT", err)
	}
}

// TestCoverageWriteLedger: the ledger is replaced by rename with its mode
// (0640) kept and no temp file left; a symlinked ledger fails E_SPECIAL_FILE and
// its target is left byte-identical.
func TestCoverageWriteLedger(t *testing.T) {
	in := loadInputs(t, inputs, true)
	out, err := Generate(in, testOpts)
	if err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile(filepath.Join(inputs, "ledger.json"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "ledger.json")
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	var e *Error
	if err := WriteLedger(in, out, link); !errors.As(err, &e) || e.Code != "E_SPECIAL_FILE" {
		t.Fatalf("symlinked ledger: err = %v, want E_SPECIAL_FILE", err)
	}
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, src) {
		t.Fatalf("symlink target changed (err %v)", err)
	}
	// 0640 differs from the 0600 os.CreateTemp gives, so the mode is kept, not defaulted.
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := WriteLedger(in, out, path); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/golden/ledger-fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Error("written ledger differs from golden")
	}
	// Windows keeps only the owner-write bit, so 0640 reads back as 0666 there.
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o640 {
			t.Errorf("mode = %v, want 0640", fi.Mode().Perm())
		}
	}
	ents, err := os.ReadDir(dir)
	if err != nil || len(ents) != 2 {
		t.Errorf("dir has %d entries (err %v), want ledger.json and link.json only", len(ents), err)
	}
}
