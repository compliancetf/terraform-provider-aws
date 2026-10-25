package lifecycle

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/compliancetf/terraform-provider-aws/internal/evidence"
)

// TestEvidence runs stages/evidence_*.json: evidence.required at apply_pre.
func TestEvidence(t *testing.T) { runStages(t, "evidence_*.json") }

// wantEvidence is the eval record a stage golden expects; results compare
// control, state, decision and half.
type wantEvidence struct {
	Envelope string       `json:"envelope,omitempty"`
	Op       string       `json:"op"`
	Results  []wantResult `json:"results"`
	// Resource, when set, is the whole expected resource object; the scope
	// then must equal Scope (all parts null when absent), and the record
	// must carry digests.control_versions with digests.content null.
	Resource *evidence.Resource `json:"resource,omitempty"`
	Scope    *evidence.Scope    `json:"scope,omitempty"`
}

type wantResult struct {
	Control  string `json:"control"`
	State    string `json:"state"`
	Decision string `json:"decision"`
	Half     string `json:"half,omitempty"`
	// Exception, when set, is the recorded exception as source/status.
	Exception string `json:"exception,omitempty"`
}

var evidenceSchema *jsonschema.Schema

// readChain verifies every chain file under dir, validates every line
// against schema/evidence-record-1 and returns the records.
func readChain(t *testing.T, dir string) []evidence.Record {
	t.Helper()
	if evidenceSchema == nil {
		s, err := jsonschema.NewCompiler().Compile(filepath.Join("..", "..", "schema", "evidence-record-1.schema.json"))
		if err != nil {
			t.Fatal(err)
		}
		evidenceSchema = s
	}
	var out []evidence.Record
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(p) != ".jsonl" {
			return err
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if _, err := evidence.Verify(bytes.NewReader(raw)); err != nil {
			t.Errorf("%s: %v", p, err)
		}
		for _, line := range bytes.Split(bytes.TrimSuffix(raw, []byte("\n")), []byte("\n")) {
			v, err := jsonschema.UnmarshalJSON(bytes.NewReader(line))
			if err != nil {
				return err
			}
			if err := evidenceSchema.Validate(v); err != nil {
				t.Errorf("schema: %v\n%s", err, line)
			}
			var r evidence.Record
			if err := json.Unmarshal(line, &r); err != nil {
				return err
			}
			out = append(out, r)
		}
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return out
}

// checkEvalRecord asserts the stage call wrote exactly one eval record for
// stage and, when want is set, its op, envelope and results.
func checkEvalRecord(t *testing.T, recs []evidence.Record, stage, typeName string, want *wantEvidence) {
	t.Helper()
	var evals []evidence.Record
	for _, r := range recs {
		if r.Kind == evidence.KindEval {
			evals = append(evals, r)
		}
	}
	if len(evals) != 1 || evals[0].Stage != stage || evals[0].Resource.Type != typeName {
		t.Fatalf("want one %s eval record, got %+v", stage, evals)
	}
	if want == nil {
		return
	}
	r := evals[0]
	got := wantEvidence{Envelope: r.Envelope, Op: r.Resource.Op, Results: []wantResult{}}
	for i, x := range r.Results {
		w := wantResult{Control: x.Control, State: x.State, Decision: x.Decision, Half: x.Half}
		if x.Exception != nil && i < len(want.Results) && want.Results[i].Exception != "" {
			w.Exception = x.Exception.Source + "/" + x.Exception.Status
		}
		got.Results = append(got.Results, w)
	}
	if want.Resource != nil {
		got.Resource, got.Scope = r.Resource, r.Scope
		if want.Scope == nil {
			want.Scope = &evidence.Scope{}
		}
		if r.Digests == nil || r.Digests.ControlVersions == nil || r.Digests.Content != nil {
			t.Errorf("digests = %+v, want control_versions set and content null (these fixtures load no content digest; TestDigestsContent)", r.Digests)
		}
	}
	if want.Results == nil {
		want.Results = []wantResult{}
	}
	gj, _ := json.MarshalIndent(got, "", "  ")
	wj, _ := json.MarshalIndent(want, "", "  ")
	if !bytes.Equal(gj, wj) {
		t.Errorf("evidence\n got %s\nwant %s", gj, wj)
	}
}

// TestDigestsContent: digests.content is the loaded content digest, null
// only when none was loaded.
func TestDigestsContent(t *testing.T) {
	c := &Configured{Controls: stageControlSetDigest(t, "ab")}
	if d := digests(c, ""); d.Content != nil {
		t.Fatalf("no content digest loaded: content = %q, want null", *d.Content)
	}
	c.Content = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	if d := digests(c, ""); d.Content == nil || *d.Content != c.Content {
		t.Fatalf("content = %v, want %s", d.Content, c.Content)
	}
}
