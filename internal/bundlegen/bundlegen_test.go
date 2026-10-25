package bundlegen

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"maps"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/iampolicy"
)

var update = flag.Bool("update", false, "rewrite testdata/golden")

const inputs = "testdata/inputs"

func loadInputs(t *testing.T, dir string, authored bool) Inputs {
	t.Helper()
	in, err := LoadInputs(filepath.Join(dir, "catalog"), filepath.Join(dir, "intents.json"), filepath.Join(dir, "schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	if authored {
		a, err := LoadAuthored(filepath.Join(dir, "authored"))
		if err != nil {
			t.Fatal(err)
		}
		in.SetAuthored(a)
		// The catalog is canonical bytes, never shuffled: always the original.
		if in.IAMActions, err = LoadIAMActions(filepath.Join(inputs, "iam-actions.json")); err != nil {
			t.Fatal(err)
		}
	}
	return in
}

// testOpts pins hashicorp/aws 6.67.0, the version in pins.json, and the
// releases of releases.json (floor 6.67.0, the only release).
var testOpts = Options{GeneratorVersion: "0.0.0-test", GeneratorCommit: "0000000", UpstreamPin: "6.67.0",
	Releases: Releases{Format: ReleasesFormat, Floor: "6.67.0", Releases: []string{"6.67.0"}}, CaseSchema: "schema.json"}

func generate(t *testing.T, in Inputs) map[string][]byte {
	t.Helper()
	out, err := Generate(in, testOpts)
	if err != nil {
		t.Fatal(err)
	}
	return out.Files
}

func readTree(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		files[filepath.ToSlash(rel)], err = os.ReadFile(p)
		return err
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	return files
}

// TestGolden: "empty" has no content (content intents are not translated in this
// fixture), so no bundle is emitted, only the coverage report; "fixture" adds
// three synthetic authored controls, one of them iam.* in soc2-aws (and all)
// only.
func TestGolden(t *testing.T) {
	for name, authored := range map[string]bool{"empty": false, "fixture": true} {
		t.Run(name, func(t *testing.T) {
			got := generate(t, loadInputs(t, inputs, authored))
			dir := filepath.Join("testdata/golden", name)
			if *update {
				if err := os.RemoveAll(dir); err != nil {
					t.Fatal(err)
				}
				if err := (&Output{Files: got}).WriteDir(dir); err != nil {
					t.Fatal(err)
				}
			}
			want := readTree(t, dir)
			if bad := diffFiles(got, want); bad != nil {
				t.Errorf("differs from golden (run with -update): %v", bad)
			}
		})
	}
}

// diffFiles lists paths whose bytes differ between two file trees.
func diffFiles(got, want map[string][]byte) []string {
	all := maps.Clone(got)
	maps.Copy(all, want)
	var bad []string
	for _, p := range slices.Sorted(maps.Keys(all)) {
		if !bytes.Equal(got[p], want[p]) {
			bad = append(bad, p)
		}
	}
	return bad
}

// TestDeterministic: inputs rewritten with shuffled object key order (the
// authored YAML copied as is) produce byte-identical output on every run.
func TestDeterministic(t *testing.T) {
	want := generate(t, loadInputs(t, inputs, true))
	if len(want) == 0 {
		t.Fatal("no output")
	}
	for seed := range uint64(8) {
		r := rand.New(rand.NewPCG(seed, seed))
		dir := t.TempDir()
		writeSections(t, readDirFiles(t, filepath.Join(inputs, "authored")), "", filepath.Join(dir, "authored"))
		for _, f := range []string{"catalog/controls.json", "catalog/provider_dispositions.json", "catalog/frameworks_metadata.json", "catalog/manifest.json", "intents.json", "schema.json"} {
			data, err := os.ReadFile(filepath.Join(inputs, f))
			if err != nil {
				t.Fatal(err)
			}
			var v any
			if err := json.Unmarshal(data, &v); err != nil {
				t.Fatal(err)
			}
			var b strings.Builder
			writeShuffled(&b, v, r)
			if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, f)), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, f), []byte(b.String()), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		got := generate(t, loadInputs(t, dir, true))
		if bad := diffFiles(got, want); bad != nil {
			t.Fatalf("seed %d: not byte-identical: %v", seed, bad)
		}
	}
}

// readDirFiles returns the files of dir by name.
func readDirFiles(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string][]byte{}
	for _, e := range ents {
		if m[e.Name()], err = os.ReadFile(filepath.Join(dir, e.Name())); err != nil {
			t.Fatal(err)
		}
	}
	return m
}

// writeShuffled encodes v as JSON with object keys in random order.
func writeShuffled(b *strings.Builder, v any, r *rand.Rand) {
	switch x := v.(type) {
	case map[string]any:
		ks := slices.Sorted(maps.Keys(x))
		r.Shuffle(len(ks), func(i, j int) { ks[i], ks[j] = ks[j], ks[i] })
		b.WriteString("{")
		for i, k := range ks {
			if i > 0 {
				b.WriteString(",")
			}
			kb, _ := json.Marshal(k)
			b.Write(kb)
			b.WriteString(":")
			writeShuffled(b, x[k], r)
		}
		b.WriteString("}")
	case []any:
		b.WriteString("[")
		for i, e := range x {
			if i > 0 {
				b.WriteString(",")
			}
			writeShuffled(b, e, r)
		}
		b.WriteString("]")
	default:
		vb, _ := json.Marshal(x)
		b.Write(vb)
	}
}

// TestEmitRoundTrip: every emitted controls.json loads through
// bundle.ParseControls, validates against the JSON Schema, and re-emits to
// the same bytes.
func TestEmitRoundTrip(t *testing.T) {
	sch, err := jsonschema.NewCompiler().Compile("../../schema/bundle-control-2.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	files := generate(t, loadInputs(t, inputs, true))
	n := 0
	for p, data := range files {
		if !strings.HasSuffix(p, "/controls.json") {
			continue
		}
		n++
		cs, err := bundle.ParseControls(data)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		if err := sch.Validate(doc); err != nil {
			t.Errorf("%s: schema: %v", p, err)
		}
		again, err := EmitControls(cs)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(again, data) {
			t.Errorf("%s: re-emit differs", p)
		}
	}
	if n == 0 {
		t.Fatal("no controls.json emitted")
	}
}

func TestInputErrors(t *testing.T) {
	cases := map[string]struct {
		edit func(in *Inputs)
		code string
	}{
		"coverage gap": {func(in *Inputs) {
			delete(in.Catalog.Dispositions.Controls, "s3_bobthecorp_versioning_on")
		}, "E_DISPOSITION_COVERAGE"},
		"unknown control": {func(in *Inputs) {
			in.Catalog.Dispositions.Controls["bobthecorp_unknown"] = Disposition{Disposition: "runtime", Content: "none"}
		}, "E_DISPOSITION_COVERAGE"},
		"unknown type": {func(in *Inputs) {
			d := in.Catalog.Dispositions.Controls["s3_bobthecorp_versioning_on"]
			d.Targets = []Target{{Kind: "resource", Type: "aws_bobthecorp_widget"}}
			in.Catalog.Dispositions.Controls["s3_bobthecorp_versioning_on"] = d
		}, "E_SCHEMA_TYPE"},
		"authored missing": {func(in *Inputs) {
			d := in.Catalog.Dispositions.Controls["s3_bobthecorp_versioning_on"]
			d.Content = "authored"
			in.Catalog.Dispositions.Controls["s3_bobthecorp_versioning_on"] = d
			delete(in.Authored, "s3_bobthecorp_versioning_on")
		}, "E_AUTHORED_MISSING"},
		"unknown content": {func(in *Inputs) {
			d := in.Catalog.Dispositions.Controls["s3_bobthecorp_versioning_on"]
			d.Content = "bobthecorp"
			in.Catalog.Dispositions.Controls["s3_bobthecorp_versioning_on"] = d
		}, "E_DISPOSITION"},
		"authored for non-local": {func(in *Inputs) {
			in.Authored = map[string][]bundle.Control{"acct_bobthecorp_contact_set": in.Authored["s3_bobthecorp_versioning_on"]}
		}, "E_DISPOSITION"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			in := loadInputs(t, inputs, true)
			tc.edit(&in)
			_, err := Generate(in, testOpts)
			var e *Error
			if !errors.As(err, &e) || e.Code != tc.code {
				t.Fatalf("err = %v, want %s", err, tc.code)
			}
		})
	}
}

func TestFailClosedIO(t *testing.T) {
	abs, err := filepath.Abs(inputs)
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	code := func(err error) string {
		var e *Error
		if errors.As(err, &e) {
			return e.Code
		}
		return fmt.Sprint(err)
	}
	trailing := filepath.Join(tmp, "trailing.json")
	if err := os.WriteFile(trailing, []byte(`{"format":"content.provider-intents/1"}]x`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIntents(trailing); code(err) != "E_INPUT" {
		t.Errorf("trailing data: %v", err)
	}
	if err := os.Symlink(filepath.Join(abs, "catalog"), filepath.Join(tmp, "catalog")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCatalog(filepath.Join(tmp, "catalog")); code(err) != "E_SPECIAL_FILE" {
		t.Errorf("symlinked catalog dir: %v", err)
	}
	out := &Output{Files: map[string][]byte{"all/build.json": []byte("{}\n")}}
	if err := out.WriteDir(filepath.Join(tmp, "catalog")); code(err) != "E_SPECIAL_FILE" {
		t.Errorf("symlinked out dir: %v", err)
	}
	if err := out.WriteDir(abs); code(err) != "E_OUTPUT" {
		t.Errorf("non-empty out dir: %v", err)
	}
	if err := out.WriteDir(filepath.Join(tmp, "fresh")); err != nil {
		t.Errorf("fresh out dir: %v", err)
	}
}

func TestSpecialFile(t *testing.T) {
	dir := t.TempDir()
	abs, err := filepath.Abs(inputs)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(abs, "intents.json"), filepath.Join(dir, "intents.json")); err != nil {
		t.Fatal(err)
	}
	_, err = LoadIntents(filepath.Join(dir, "intents.json"))
	var e *Error
	if !errors.As(err, &e) || e.Code != "E_SPECIAL_FILE" {
		t.Fatalf("symlink input: err = %v, want E_SPECIAL_FILE", err)
	}
}

// TestIAMActionsHandoff: a bundle with an iam.* control ships the catalog
// bytes and lists iam-actions.json in build.json files; a bundle without one
// ships neither; a missing or non-canonical catalog fails closed.
func TestIAMActionsHandoff(t *testing.T) {
	in := loadInputs(t, inputs, true)
	files := generate(t, in)
	for id, want := range map[string][]string{"cis-aws": {}, "pci-dss-aws": {}, "soc2-aws": {"iam-actions.json"}, "all": {"iam-actions.json"}} {
		var b struct {
			Files []string `json:"files"`
		}
		if err := json.Unmarshal(files[id+"/build.json"], &b); err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if b.Files == nil || !slices.Equal(b.Files, want) {
			t.Errorf("%s: files = %#v, want %#v", id, b.Files, want)
		}
		cat, ok := files[id+"/iam-actions.json"]
		if ok != (len(want) > 0) || ok && !bytes.Equal(cat, in.IAMActions) {
			t.Errorf("%s: iam-actions.json present %v, equal to input %v", id, ok, bytes.Equal(cat, in.IAMActions))
		}
	}

	catalog := in.IAMActions
	in.IAMActions = nil
	var e *Error
	if _, err := Generate(in, testOpts); !errors.As(err, &e) || e.Code != "E_IAM_CATALOG_MISSING" {
		t.Errorf("no catalog: err = %v, want E_IAM_CATALOG_MISSING", err)
	}

	// In-process callers skip LoadIAMActions: Generate checks the bytes.
	in.IAMActions = append(slices.Clone(catalog), '\n')
	if _, err := Generate(in, testOpts); !errors.As(err, &e) || e.Code != "E_INPUT" {
		t.Errorf("non-canonical catalog in Generate: err = %v, want E_INPUT", err)
	}
	// A catalog without the service iam.grants_all looks up (kms).
	noKMS, err := iampolicy.EncodeCatalog("2026-10-01", "sha256:"+strings.Repeat("0", 64), map[string][]string{"s3": {"getobject"}})
	if err != nil {
		t.Fatal(err)
	}
	in.IAMActions = noKMS
	if _, err := Generate(in, testOpts); !errors.As(err, &e) || e.Code != "E_IAM_CATALOG_COVERAGE" || !strings.Contains(e.Msg, `"kms"`) {
		t.Errorf("catalog without kms: err = %v, want E_IAM_CATALOG_COVERAGE", err)
	}

	bad := filepath.Join(t.TempDir(), "iam-actions.json")
	if err := os.WriteFile(bad, append(slices.Clone(catalog), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIAMActions(bad); !errors.As(err, &e) || e.Code != "E_INPUT" {
		t.Errorf("non-canonical catalog: err = %v, want E_INPUT", err)
	}
}

// TestIAMCatalogCoverageGrants: an iam.grants literal action missing from the
// catalog fails E_IAM_CATALOG_COVERAGE; a loop variable shadowed by a
// non-literal binding is not a literal reference and passes that check.
func TestIAMCatalogCoverageGrants(t *testing.T) {
	s3Only, err := iampolicy.EncodeCatalog("2026-10-01", "sha256:"+strings.Repeat("0", 64), map[string][]string{"s3": {"getobject"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, expr string
		wantErr    bool
	}{
		{"missing action", `iam.parse(resource.policy).statements.all(s, !iam.grants(s, "kms:Decrypt"))`, true},
		{"shadowed loop variable", `iam.parse(resource.policy).statements.all(s, ["kms:Decrypt"].exists(a, [resource.policy].exists(a, iam.grants(s, a))))`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := loadInputs(t, inputs, true)
			const id = "iam_bobthecorp_no_kms_wildcard"
			c := slices.Clone(in.Authored[id])
			c[0].Expr = &tc.expr
			in.Authored[id] = c
			in.IAMActions = s3Only
			_, err := Generate(in, testOpts)
			var e *Error
			if tc.wantErr {
				if !errors.As(err, &e) || e.Code != "E_IAM_CATALOG_COVERAGE" || !strings.Contains(e.Msg, `iam.grants action "kms:Decrypt"`) {
					t.Errorf("err = %v, want E_IAM_CATALOG_COVERAGE for kms:Decrypt", err)
				}
			} else if !errors.As(err, &e) || e.Code != "E_FIXTURE_MISMATCH" || !strings.HasPrefix(e.Msg, "verify: ") {
				// The shadowed expr evaluates not_evaluable on the authored
				// fixtures. Verify runs only after every bundle passed
				// checkCatalogCoverage, so a verify finding proves the check
				// ran and accepted the control.
				t.Errorf("err = %v, want the verify finding E_FIXTURE_MISMATCH", err)
			}
		})
	}
}

// TestVersionRange: the range is same major, at least the floor; an empty
// or non x.y.z floor fails E_UPSTREAM_PIN. internal/lifecycle
// TestVersionRangeParses round-trips the range through the provider's
// version_range parser.
func TestVersionRange(t *testing.T) {
	for floor, want := range map[string]string{
		"6.67.0":  ">= 6.67.0, < 7.0.0",
		"0.1.0":   ">= 0.1.0, < 1.0.0",
		"10.0.12": ">= 10.0.12, < 11.0.0",
	} {
		if got, err := VersionRange(floor); err != nil || got != want {
			t.Errorf("VersionRange(%q) = %q, %v; want %q", floor, got, err, want)
		}
	}
	for _, floor := range []string{"", " ", "6", "6.67", "v6.67.0", "6.67.0-rc1", "6.67.0+meta", "06.67.0", "6.067.0", " 6.67.0", ">= 6.67.0", "99999999999999999999.0.0"} {
		var e *Error
		if got, err := VersionRange(floor); !errors.As(err, &e) || e.Code != "E_UPSTREAM_PIN" || got != "" {
			t.Errorf("VersionRange(%q) = %q, %v; want E_UPSTREAM_PIN", floor, got, err)
		}
	}
	in := loadInputs(t, inputs, true)
	for _, pin := range []string{"", "6.67"} {
		opts := testOpts
		opts.UpstreamPin = pin
		var e *Error
		if out, err := Generate(in, opts); !errors.As(err, &e) || e.Code != "E_UPSTREAM_PIN" || out != nil {
			t.Errorf("Generate with pin %q: err = %v, want E_UPSTREAM_PIN", pin, err)
		}
	}
}
