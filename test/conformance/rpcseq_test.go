//go:build conformance

package conformance

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the rpcseq goldens of the -tf binary's version")

// TestRPCSeq runs each rpcseq/scenarios/<name> with the conformance recorder
// and compares the hook calls of every step (stage, op, envelope op, value
// nullness) with rpcseq/goldens/<product>-<major.minor>/<name>.json. A
// version without goldens fails: record them with
//
//	make conformance RUN=rpcseq UPDATE=1 TF=/path/to/terraform
func TestRPCSeq(t *testing.T) {
	c, banner, err := detectCell(*tfBin)
	if err != nil {
		t.Fatal(err)
	}
	m := bannerRE.FindStringSubmatch(banner)
	if m == nil { // detectCell rejects this already; keep the index below safe
		t.Fatalf("unrecognized version banner %q: -tf must name a terraform or tofu binary", banner)
	}
	dir := filepath.Join("rpcseq", "goldens", fmt.Sprintf("%s-%s.%s", strings.ToLower(m[1]), m[2], m[3]))
	if *update {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	} else if _, err := os.Stat(dir); err != nil {
		t.Fatalf("no rpcseq goldens for %s (%v): record them with -update", banner, err)
	}
	entries, err := os.ReadDir(filepath.Join("rpcseq", "scenarios"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Run(e.Name(), func(t *testing.T) {
			var b bytes.Buffer
			b.WriteString("{\n  \"steps\": [")
			runScenario(t, c, filepath.Join("rpcseq", "scenarios", e.Name()), "", nil, func(i int, s step, calls string) {
				if i > 0 {
					b.WriteByte(',')
				}
				cmd, _ := json.Marshal(s.Cmd)
				fmt.Fprintf(&b, "\n    {\"cmd\": %s, \"calls\": [", cmd)
				for j, l := range readCalls(t, calls) {
					if j > 0 {
						b.WriteByte(',')
					}
					fmt.Fprintf(&b, "\n      %s", l)
				}
				b.WriteString("\n    ]}")
			})
			b.WriteString("\n  ]\n}\n")
			name := e.Name()
			if noDestroyIdentity() && hasNoDestroyIdentity(t, filepath.Join("rpcseq", "scenarios", name)) {
				name += ".no_destroy_identity"
			}
			golden := filepath.Join(dir, name+".json")
			if *update {
				if err := os.WriteFile(golden, b.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(want, b.Bytes()) {
				t.Fatalf("%s: recorded sequence differs from the golden\n--- golden\n%s--- recorded\n%s", golden, want, b.Bytes())
			}
		})
	}
}

// readCalls returns the compacted JSON lines of path with process ordinals
// (procOrdinals) and removes it, so the next step starts empty.
func readCalls(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	var lines []string
	for l := range bytes.Lines(raw) {
		var b bytes.Buffer
		if err := json.Compact(&b, l); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		lines = append(lines, b.String())
	}
	out, err := procOrdinals(lines)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return out
}

// hasNoDestroyIdentity reports whether scenario dir has a no_destroy_identity
// variant.
func hasNoDestroyIdentity(t *testing.T, dir string) bool {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "steps.json"))
	if err != nil {
		t.Fatal(err)
	}
	var sc scenario
	if err := strictUnmarshal(b, &sc); err != nil {
		t.Fatal(err)
	}
	return sc.NoDestroyIdentity != nil
}
