package exceptions

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
)

// TestEntryDigestVectors checks the per-entry sidecar digest (B8) against the
// verdict producer's vectors: canonical bytes and digest are byte-equal for
// every self_service vector, so the gate's listed digest matches at apply.
func TestEntryDigestVectors(t *testing.T) {
	dir := filepath.Join("testdata", "entrydigest")
	raw, err := os.ReadFile(filepath.Join(dir, "expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	var want struct {
		SelfService []struct{ File, Canonical, Digest string } `json:"self_service"`
	}
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	if len(want.SelfService) == 0 {
		t.Fatal("no self_service vectors")
	}
	for _, v := range want.SelfService {
		t.Run(v.File, func(t *testing.T) {
			src, err := os.ReadFile(filepath.Join(dir, v.File))
			if err != nil {
				t.Fatal(err)
			}
			f, diags := hclparse.NewParser().ParseHCL(src, v.File)
			if diags.HasErrors() {
				t.Fatal(diags)
			}
			var file struct {
				Exceptions []Entry `hcl:"exception,block"`
			}
			if diags := gohcl.DecodeBody(f.Body, nil, &file); diags.HasErrors() || len(file.Exceptions) != 1 {
				t.Fatalf("decode: %v, %d entries", diags, len(file.Exceptions))
			}
			e := file.Exceptions[0]
			if _, _, err := e.validate(); err != nil {
				t.Fatalf("validate: %v", err)
			}
			c, err := e.canonical()
			if err != nil {
				t.Fatal(err)
			}
			d, err := e.digest()
			if err != nil {
				t.Fatal(err)
			}
			if string(c) != v.Canonical || d != v.Digest {
				t.Errorf("canonical %s digest %s, want %s %s", c, d, v.Canonical, v.Digest)
			}
		})
	}
}

// TestEntryDigestInvalidUTF8 fails closed rather than digest a replaced string.
func TestEntryDigestInvalidUTF8(t *testing.T) {
	e := Entry{Label: "x", Controls: []string{"a"}, Match: "type == '\xff'", Workspace: "w", Expires: "2027-01-01"}
	if _, err := e.digest(); err == nil {
		t.Fatal("want an error for invalid UTF-8")
	}
}
