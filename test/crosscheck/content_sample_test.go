package crosscheck

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// notExpressibleFile records the sampled checks that CEL over one
// resource cannot express, with the reason.
const notExpressibleFile = "not-expressible.json"

// TestContentSample runs the 20 synthetic content-sample controls:
// each file is named after its control id and
// has a positive and a negative fixture.
func TestContentSample(t *testing.T) {
	dir := filepath.Join(root, "controls", "content-sample")
	if n, _ := runControls(t, dir, false, notExpressibleFile); n != 20 {
		t.Fatalf("%d content-sample controls, want 20", n)
	}
	data, err := os.ReadFile(filepath.Join(dir, notExpressibleFile))
	if err != nil {
		t.Fatal(err)
	}
	var recs []struct {
		Policy       string
		ResourceType string `json:"resource_type"`
		Reason       string
	}
	if err := decodeStrict(data, &recs); err != nil {
		t.Fatalf("%s: %v", notExpressibleFile, err)
	}
	for _, r := range recs {
		if r.Policy == "" || r.ResourceType == "" || r.Reason == "" {
			t.Errorf("%s: incomplete record %+v", notExpressibleFile, r)
		}
		switch _, err := os.Stat(filepath.Join(dir, r.Policy+".json")); {
		case err == nil:
			t.Errorf("%s: %s is both sampled and not expressible", notExpressibleFile, r.Policy)
		case !errors.Is(err, fs.ErrNotExist):
			t.Fatal(err)
		}
	}
}
