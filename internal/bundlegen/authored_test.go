package bundlegen

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/tools/txtar"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
)

// readTxtar returns the archive and its files by name.
func readTxtar(t *testing.T, f string) (*txtar.Archive, map[string][]byte) {
	t.Helper()
	ar, err := txtar.ParseFile(f)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string][]byte{}
	for _, x := range ar.Files {
		m[x.Name] = x.Data
	}
	return ar, m
}

// writeSections writes the sections under prefix to dir (prefix stripped).
func writeSections(t *testing.T, sections map[string][]byte, prefix, dir string) {
	t.Helper()
	for name, data := range sections {
		rel, ok := strings.CutPrefix(name, prefix)
		if !ok || strings.HasPrefix(name, "want") {
			continue
		}
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// setWant replaces the data of section name (-update).
func setWant(t *testing.T, f string, ar *txtar.Archive, name string, data []byte) {
	t.Helper()
	for i := range ar.Files {
		if ar.Files[i].Name == name {
			ar.Files[i].Data = data
		}
	}
	if err := os.WriteFile(f, txtar.Format(ar), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestAuthoredLoad replays testdata/authored/load/*.txtar: the <id>.yaml
// sections form a provider/controls directory; want.json is the
// loaded result or {"error": "<E_* code>"}.
func TestAuthoredLoad(t *testing.T) {
	files, err := filepath.Glob("testdata/authored/load/*.txtar")
	if err != nil || len(files) < 10 {
		t.Fatalf("%d load cases, %v", len(files), err)
	}
	for _, f := range files {
		t.Run(strings.TrimSuffix(filepath.Base(f), ".txtar"), func(t *testing.T) {
			ar, sections := readTxtar(t, f)
			dir := t.TempDir()
			writeSections(t, sections, "", dir)
			got, err := LoadAuthored(dir)
			var gotJSON []byte
			if err != nil {
				gotJSON, _ = canonicalJSON(map[string]string{"error": errCode(err)})
			} else if gotJSON, err = canonicalJSON(got); err != nil {
				t.Fatal(err)
			}
			if *update {
				setWant(t, f, ar, "want.json", gotJSON)
				return
			}
			var want, have any
			if err := decodeStrictJSON(sections["want.json"], &want); err != nil {
				t.Fatalf("want.json: %v", err)
			}
			if err := decodeStrictJSON(gotJSON, &have); err != nil {
				t.Fatal(err)
			}
			if !jsonEqual(want, have) {
				t.Errorf("got %s\nwant %s", gotJSON, sections["want.json"])
			}
		})
	}
}

func jsonEqual(a, b any) bool {
	x, err1 := canonicalJSON(a)
	y, err2 := canonicalJSON(b)
	return err1 == nil && err2 == nil && string(x) == string(y)
}

// TestAuthoredSpecialFiles: a symlinked <id>.yaml and a non-directory fail
// with E_SPECIAL_FILE, never followed.
func TestAuthoredSpecialFiles(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "x.yaml")
	if err := os.WriteFile(target, []byte("targets: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "rds_bobthecorp_storage_encrypted.yaml")); err != nil {
		t.Skip(err)
	}
	if _, err := LoadAuthored(dir); errCode(err) != "E_SPECIAL_FILE" {
		t.Errorf("symlink: got %v", err)
	}
	if _, err := LoadAuthored(target); errCode(err) != "E_SPECIAL_FILE" {
		t.Errorf("file as dir: got %v", err)
	}
}

// TestReviewPending replays testdata/authored/review/*.txtar over
// testdata/inputs: intents.json replaces the intents, authored/ is loaded
// with LoadAuthored. A translation review item emits no control and is
// E_REVIEW_PENDING in Output.ReviewQueue and review-queue.md; an authored
// override takes the id out of the queue; autos are in review-sheet.md.
func TestReviewPending(t *testing.T) {
	files, err := filepath.Glob("testdata/authored/review/*.txtar")
	if err != nil || len(files) < 2 {
		t.Fatalf("%d review cases, %v", len(files), err)
	}
	for _, f := range files {
		t.Run(strings.TrimSuffix(filepath.Base(f), ".txtar"), func(t *testing.T) {
			ar, sections := readTxtar(t, f)
			dir := t.TempDir()
			writeSections(t, sections, "", dir)
			in := loadInputs(t, inputs, false)
			var err error
			if in.Intents, err = LoadIntents(filepath.Join(dir, "intents.json")); err != nil {
				t.Fatal(err)
			}
			if hasPrefix(sections, "authored/") {
				a, err := LoadAuthored(filepath.Join(dir, "authored"))
				if err != nil {
					t.Fatal(err)
				}
				in.SetAuthored(a)
			}
			out, err := Generate(in, testOpts)
			if err != nil {
				t.Fatal(err)
			}

			generated := map[string]bool{}
			for p, data := range out.Files {
				if strings.HasSuffix(p, "/controls.json") {
					ids, err := generatedIDs(data, in.Catalog.Dispositions.Controls)
					if err != nil {
						t.Fatal(err)
					}
					maps.Copy(generated, ids)
				}
			}
			if got, want := slices.Sorted(maps.Keys(generated)), strings.Fields(string(sections["want-generated"])); !slices.Equal(got, want) {
				t.Errorf("generated %v, want %v", got, want)
			}
			var pending []string
			for _, r := range out.ReviewQueue {
				if !strings.HasPrefix(r.PendingLine(), "E_REVIEW_PENDING "+r.ID+" ") {
					t.Errorf("pending line %q", r.PendingLine())
				}
				if generated[r.ID] {
					t.Errorf("%s is queued and generated", r.ID)
				}
				pending = append(pending, r.ID)
			}
			if want := strings.Fields(string(sections["want-pending"])); !slices.Equal(pending, want) {
				t.Errorf("pending %v, want %v", pending, want)
			}

			for _, name := range []string{"review-queue.md", "review-sheet.md"} {
				if *update {
					setWant(t, f, ar, "want-"+name, out.Files[name])
					continue
				}
				if got := out.Files[name]; string(got) != string(sections["want-"+name]) {
					t.Errorf("%s:\n%s\nwant:\n%s", name, got, sections["want-"+name])
				}
			}
		})
	}
}

func hasPrefix(m map[string][]byte, prefix string) bool {
	for k := range m {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	return false
}

// TestAuthoredErrorValueFree: YAML decode errors keep line and type
// information but never quote a scalar of the file.
func TestAuthoredErrorValueFree(t *testing.T) {
	const marker = "BOBTHECORP-SECRET-SENTINEL"
	for name, doc := range map[string]string{
		"type":   "targets:\n  - kind: resource\n    reads: " + marker + "\n",
		"state":  "targets: []\nfixtures:\n  - {kind: resource, expect: {state: " + marker + "}}\n",
		"quoted": "fix: [\"" + marker + "\"]\n",
		// a backtick in the scalar ends yaml.v3's quoting early
		"backtick":  "targets:\n  - kind: resource\n    reads: \"`" + marker + "\"\n",
		"backtick2": "targets:\n  - kind: resource\n    reads: \"a` into x " + marker + "` into []string\"\n",
		"quotes":    "targets:\n  - kind: resource\n    reads: '\"" + marker + "\" x'\n",
		"newline":   "targets:\n  - kind: resource\n    reads: \"a\\n" + marker + "\\nb\"\n",
		"key":       "targets:\n  - kind: resource\n    \"" + marker + "\": 1\n",
		"syntax":    "targets: [\"" + marker + "\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseAuthored("rds_bobthecorp_storage_encrypted", []byte(doc))
			if errCode(err) != "E_AUTHORED" || strings.Contains(err.Error(), marker) || strings.Contains(err.Error(), "SECRET") || !strings.Contains(err.Error(), "line ") && name != "state" {
				t.Fatalf("got %v", err)
			}
		})
	}
}

// TestReviewSheetNilExpr: a control without expr is an error, never a panic.
func TestReviewSheetNilExpr(t *testing.T) {
	if _, err := ReviewSheet([]bundle.Control{{ID: "rds_bobthecorp_storage_encrypted"}}); errCode(err) != "E_EMIT" {
		t.Fatalf("got %v", err)
	}
}

// TestReviewPartialTargets: a one-type intent on a two-target disposition
// emits the covered target, queues the other as partial_targets
// (E_REVIEW_PENDING), and coverage keeps the id pending_review.
func TestReviewPartialTargets(t *testing.T) {
	in := loadInputs(t, inputs, false)
	_, sections := readTxtar(t, "testdata/authored/review/review_pending.txtar")
	dir := t.TempDir()
	writeSections(t, sections, "", dir)
	var err error
	if in.Intents, err = LoadIntents(filepath.Join(dir, "intents.json")); err != nil {
		t.Fatal(err)
	}
	const id = "rds_bobthecorp_storage_encrypted"
	d := in.Catalog.Dispositions.Controls[id]
	d.Targets = append(slices.Clone(d.Targets), Target{Kind: "resource", Type: "aws_s3_bucket_versioning"})
	in.Catalog.Dispositions.Controls = maps.Clone(in.Catalog.Dispositions.Controls)
	in.Catalog.Dispositions.Controls[id] = d

	out, err := Generate(in, testOpts)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, r := range out.ReviewQueue {
		if r.ID == id {
			lines = append(lines, r.PendingLine())
		}
	}
	want := "E_REVIEW_PENDING " + id + " aws_s3_bucket_versioning: partial_targets: resource target not covered by the content intent on aws_db_instance"
	if !slices.Equal(lines, []string{want}) {
		t.Fatalf("queue for %s: %q", id, lines)
	}
	if !strings.Contains(string(out.Files["review-queue.md"]), want) {
		t.Error("review-queue.md lacks the partial target")
	}
	var rep coverageReport
	if err := json.Unmarshal(out.Files["coverage.json"], &rep); err != nil {
		t.Fatal(err)
	}
	seen := false
	for name, b := range rep.Bundles {
		if data := out.Files[name+"/controls.json"]; data != nil {
			ids, err := generatedIDs(data, in.Catalog.Dispositions.Controls)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(data), `"resource_type": "aws_db_instance"`) || ids[id] {
				t.Errorf("bundle %s: covered target missing or id counted generated", name)
			}
		}
		if slices.Contains(b.PendingReview, id) {
			seen = true
		}
	}
	if !seen {
		t.Errorf("%s is pending_review in no bundle: %s", id, out.Files["coverage.json"])
	}

	// Clause coverage equals a run where rds has no intent (not generated
	// at all): a partially covered id covers no clause.
	none := in
	none.Intents.Policies = slices.DeleteFunc(slices.Clone(in.Intents.Policies), func(it Intent) bool { return it.ID == id })
	ref, err := Generate(none, testOpts)
	if err != nil {
		t.Fatal(err)
	}
	var refRep coverageReport
	if err := json.Unmarshal(ref.Files["coverage.json"], &refRep); err != nil {
		t.Fatal(err)
	}
	for name, b := range rep.Bundles {
		if !jsonEqual(b.Clauses, refRep.Bundles[name].Clauses) {
			t.Errorf("bundle %s: partial id changes clause coverage: %v, want %v", name, b.Clauses, refRep.Bundles[name].Clauses)
		}
	}
}

// TestReviewPartialAuthored: an authored file that leaves a disposition
// target out queues it as partial_targets and the id is not generated.
func TestReviewPartialAuthored(t *testing.T) {
	in := loadInputs(t, inputs, true)
	const id = "rds_bobthecorp_storage_encrypted"
	d := in.Catalog.Dispositions.Controls[id]
	d.Targets = append(slices.Clone(d.Targets), Target{Kind: "resource", Type: "aws_s3_bucket_versioning"})
	in.Catalog.Dispositions.Controls = maps.Clone(in.Catalog.Dispositions.Controls)
	in.Catalog.Dispositions.Controls[id] = d
	out, err := Generate(in, testOpts)
	if err != nil {
		t.Fatal(err)
	}
	want := "E_REVIEW_PENDING " + id + " aws_s3_bucket_versioning: partial_targets: resource target not covered by the authored file"
	var lines []string
	for _, r := range out.ReviewQueue {
		lines = append(lines, r.PendingLine())
	}
	if !slices.Equal(lines, []string{want}) {
		t.Fatalf("queue %q, want only %q", lines, want)
	}
	ids, err := generatedIDs(out.Files["all/controls.json"], in.Catalog.Dispositions.Controls)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ids[id]; ok || !ids["s3_bobthecorp_versioning_on"] {
		t.Errorf("generated ids %v", ids)
	}
}
