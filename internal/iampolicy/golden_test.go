package iampolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite testdata/iam/cases/*.golden.json")

const casesDir = "../../testdata/iam/cases"

// TestGolden normalizes every testdata/iam/cases/<name>.json and compares
// the result with <name>.golden.json, the language-neutral contract shared
// with ctfkit. Cases named nopartition_* run without Options.Partition, all
// others with partition "aws". An invalid document's golden is
// {"error": <class>, "reason": <code>}.
func TestGolden(t *testing.T) {
	inputs, err := filepath.Glob(filepath.Join(casesDir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	var n int
	for _, in := range inputs {
		if strings.HasSuffix(in, ".golden.json") {
			continue
		}
		n++
		name := strings.TrimSuffix(filepath.Base(in), ".json")
		t.Run(name, func(t *testing.T) {
			doc, err := os.ReadFile(in)
			if err != nil {
				t.Fatal(err)
			}
			got := render(t, string(doc), optionsFor(name))
			path := strings.TrimSuffix(in, ".json") + ".golden.json"
			if *update {
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("golden mismatch\ngot:\n%s\nwant:\n%s", got, want)
			}
		})
	}
	if n < 40 {
		t.Fatalf("only %d golden cases, want >= 40", n)
	}
}

func optionsFor(name string) Options {
	if strings.HasPrefix(name, "nopartition_") {
		return Options{}
	}
	return Options{Partition: "aws"}
}

// render is the golden form of Normalize's result.
func render(t testing.TB, doc string, o Options) []byte {
	p, err := Normalize(doc, o)
	var v any = p
	if err != nil {
		if p != nil {
			t.Fatalf("non-nil policy with error %v", err)
		}
		var e *Error
		if !errors.As(err, &e) {
			t.Fatalf("error %v is not *Error", err)
		}
		v = map[string]string{"error": e.Class(), "reason": e.Reason}
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}
