package evidence

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// The read_digest goldens: plan_read_digest.json is the plan record of a
// no-op update written with COMPLIANCETF_BASELINE_KEY_FILE set, and
// plan_no_read_digest.json the same record written without it. The
// provider's lifecycle tests write both and compare their results here
// (internal/lifecycle TestPlanReadDigest); TestJoinFields checks them
// against the schema, validate and the canonical encoding.
func TestReadDigestGoldens(t *testing.T) {
	load := func(name string) (Record, string) {
		line := string(readFile(t, filepath.Join("testdata", "records", name)))
		var r Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		if err := validate(&r); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return r, strings.TrimSuffix(line, "\n")
	}
	with, line := load("plan_read_digest.json")
	without, _ := load("plan_no_read_digest.json")
	if len(with.Results) == 0 || len(with.Results) != len(without.Results) {
		t.Fatalf("results: %d with the key, %d without", len(with.Results), len(without.Results))
	}
	first := `"read_digest":"` + with.Results[0].ReadDigest + `"`
	for i := range with.Results {
		if !reDigest.MatchString(with.Results[i].ReadDigest) {
			t.Errorf("key set: result %d read_digest %q", i, with.Results[i].ReadDigest)
		}
		if without.Results[i].ReadDigest != "" {
			t.Errorf("key unset: result %d carries read_digest", i)
		}
		with.Results[i].ReadDigest = ""
	}
	a, _ := json.Marshal(with)
	b, _ := json.Marshal(without)
	if string(a) != string(b) {
		t.Errorf("the goldens differ beyond read_digest:\n%s\n%s", a, b)
	}

	sch := compileSchema(t)
	if !strings.Contains(line, first) {
		t.Fatalf("fixture lacks %s", first)
	}
	for name, bad := range map[string]string{
		"not a digest": `"read_digest":"sha256:00"`,
		"upper hex":    `"read_digest":"sha256:` + strings.Repeat("A", 64) + `"`,
		"bare hex":     `"read_digest":"` + strings.Repeat("a", 64) + `"`,
		"null":         `"read_digest":null`,
	} {
		t.Run(name, func(t *testing.T) {
			l := strings.Replace(line, first, bad, 1)
			if err := validateLine(sch, []byte(l)); err == nil {
				t.Error("schema accepted it")
			}
			var r Record
			if err := json.Unmarshal([]byte(l), &r); err != nil {
				t.Fatal(err)
			}
			if err := validate(&r); err == nil && name != "null" { // null decodes as absent
				t.Error("validate accepted it")
			}
		})
	}
}
