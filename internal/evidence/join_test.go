package evidence

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// evalGoldens returns every eval record golden: testdata/records/*.json (one
// line each) and the eval lines of the chain goldens.
func evalGoldens(t *testing.T) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	files, _ := filepath.Glob(filepath.Join("testdata", "records", "*.json"))
	for _, f := range files {
		out[filepath.Base(f)] = bytes.TrimSuffix(readFile(t, f), []byte("\n"))
	}
	for i, l := range goodLines(t) {
		if bytes.Contains(l, []byte(`"kind":"eval"`)) {
			out["chain-good.jsonl:"+strconv.Itoa(i+1)] = l
		}
	}
	if len(files) == 0 || len(out) == len(files) {
		t.Fatal("missing record or chain goldens")
	}
	return out
}

// TestJoinFields: every eval record carries the inventory join
// fields - resource.identity_kind, identity and id, scope with a source on
// every known part, digests.control_versions and digests.content (null
// without a content digest) - validates against evidence-record-1, is the writer's own
// canonical encoding, and has an identity_kind that matches what it carries.
func TestJoinFields(t *testing.T) {
	sch := compileSchema(t)
	for name, line := range evalGoldens(t) {
		t.Run(name, func(t *testing.T) {
			if err := validateLine(sch, line); err != nil {
				t.Fatalf("schema: %v", err)
			}
			var r Record
			if err := json.Unmarshal(line, &r); err != nil {
				t.Fatal(err)
			}
			if err := validate(&r); err != nil {
				t.Fatalf("validate: %v", err)
			}
			if enc, err := encode(&r); err != nil || !bytes.Equal(bytes.TrimSuffix(enc, []byte("\n")), line) {
				t.Errorf("not the canonical line (%v):\n got %s\nwant %s", err, enc, line)
			}
			var m struct {
				Digests  map[string]json.RawMessage `json:"digests"`
				Resource map[string]json.RawMessage `json:"resource"`
				Scope    map[string]*Sourced        `json:"scope"`
			}
			if err := json.Unmarshal(line, &m); err != nil {
				t.Fatal(err)
			}
			for _, k := range []string{"type", "op", "id", "identity_kind", "identity"} {
				if _, ok := m.Resource[k]; !ok {
					t.Errorf("resource.%s missing", k)
				}
			}
			for _, k := range []string{"control_versions", "content"} {
				if _, ok := m.Digests[k]; !ok {
					t.Errorf("digests.%s missing", k)
				}
			}
			if string(m.Digests["content"]) != "null" {
				t.Errorf("digests.content = %s, want null without a content digest", m.Digests["content"])
			}
			for _, k := range []string{"workspace", "environment", "account_id", "region"} {
				s, ok := m.Scope[k]
				if !ok || (s != nil && s.Source == "") {
					t.Errorf("scope.%s missing or without a source", k)
				}
			}
			res := r.Resource
			switch res.IdentityKind {
			case "identity":
				if len(res.Identity) == 0 {
					t.Error("identity_kind identity without an identity")
				}
			case "id":
				if res.ID == nil || res.Identity != nil {
					t.Error("identity_kind id needs an id and no identity")
				}
			case "none":
				if res.ID != nil || res.Identity != nil {
					t.Error("identity_kind none with an id or identity")
				}
			}
		})
	}
}

// TestImportNotInventory: an import stage record carries stage
// import and resource.op import, and the schema marks both as never an
// inventory source.
func TestImportNotInventory(t *testing.T) {
	sch := compileSchema(t)
	line := readFile(t, filepath.Join("testdata", "records", "import_identity.json"))
	line = bytes.TrimSuffix(line, []byte("\n"))
	if err := validateLine(sch, line); err != nil {
		t.Fatal(err)
	}
	var r Record
	if err := json.Unmarshal(line, &r); err != nil {
		t.Fatal(err)
	}
	if r.Stage != "import" || r.Resource.Op != "import" {
		t.Errorf("stage %q op %q, want import and import", r.Stage, r.Resource.Op)
	}
	var s struct {
		OneOf []struct {
			Properties map[string]struct {
				Description string `json:"description"`
			} `json:"properties"`
		} `json:"oneOf"`
		Defs struct {
			Resource struct {
				Properties map[string]struct {
					Description string `json:"description"`
				} `json:"properties"`
			} `json:"resource"`
		} `json:"$defs"`
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "schema", "evidence-record-1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	const mark = "never an inventory source"
	var stageDesc string
	for _, b := range s.OneOf {
		if d := b.Properties["stage"].Description; d != "" {
			stageDesc = d
		}
	}
	if !strings.Contains(stageDesc, "import") || !strings.Contains(stageDesc, mark) {
		t.Errorf("eval stage description %q does not mark import as %s", stageDesc, mark)
	}
	if d := s.Defs.Resource.Properties["op"].Description; !strings.Contains(d, "import") || !strings.Contains(d, mark) {
		t.Errorf("resource.op description %q does not mark import as %s", d, mark)
	}
}
