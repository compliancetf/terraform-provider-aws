package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// testdata/versions.json is a trimmed registry versions API response: the
// releases 5.100.0 and 6.65.0 to 6.70.0 (6.69.1 included), out of order,
// plus the 6.0.0-beta prereleases.
func fixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/versions.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDecide(t *testing.T) {
	const open = BranchPrefix + "6.68.0"
	cases := []struct {
		name, pinned, want string
		branches, heads    []string
		next               string
		queued             []string
	}{
		{name: "oldest newer release first", pinned: "6.67.0", next: "6.68.0", queued: []string{"6.69.0", "6.69.1", "6.70.0"}},
		{name: "patch release counts", pinned: "6.69.0", next: "6.69.1", queued: []string{"6.70.0"}},
		{name: "up to date", pinned: "6.70.0"},
		{name: "pin ahead of the registry", pinned: "6.71.0"},
		{name: "prereleases ignored, numeric order", pinned: "5.100.0", next: "6.65.0", queued: []string{"6.66.0", "6.67.0", "6.68.0", "6.69.0", "6.69.1", "6.70.0"}},
		{name: "open pin PR waits", pinned: "6.67.0", branches: []string{open}, heads: []string{"other", open}, queued: []string{"6.68.0", "6.69.0", "6.69.1", "6.70.0"}},
		{name: "leftover branch of a pinned release ignored", pinned: "6.68.0", branches: []string{open, BranchPrefix + "6.60.0"}, next: "6.69.0", queued: []string{"6.69.1", "6.70.0"}},
		{name: "other branches ignored", pinned: "6.67.0", branches: []string{"pin/other", "master"}, next: "6.68.0", queued: []string{"6.69.0", "6.69.1", "6.70.0"}},
		{name: "requested version", pinned: "6.67.0", want: "6.69.1", next: "6.69.1", queued: []string{"6.70.0"}},
		{name: "requested latest", pinned: "6.67.0", want: "6.70.0", next: "6.70.0"},
		{name: "requested waits for open PR", pinned: "6.67.0", want: "6.70.0", branches: []string{open}, heads: []string{open}, queued: []string{"6.68.0", "6.69.0", "6.69.1", "6.70.0"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, err := decide(fixture(t), c.pinned, c.branches, c.heads, c.want)
			if err != nil {
				t.Fatal(err)
			}
			if p.pinned != c.pinned || p.next != c.next || !slices.Equal(p.queued, c.queued) {
				t.Errorf("got pinned %q next %q queued %v, want %q %q %v", p.pinned, p.next, p.queued, c.pinned, c.next, c.queued)
			}
			if c.next == "" && p.note == "" {
				t.Error("nothing picked without a note")
			}
		})
	}
}

func TestDecideRefuses(t *testing.T) {
	cases := []struct {
		name, versions, pinned, want, errPart string
		branches, heads                       []string
	}{
		{name: "pin branch without open PR", pinned: "6.67.0", branches: []string{BranchPrefix + "6.68.0"}, heads: []string{BranchPrefix + "6.69.0"}, errPart: "has no open pull request"},
		{name: "requested not newer", pinned: "6.67.0", want: "6.66.0", errPart: "not a hashicorp/aws release newer"},
		{name: "requested equal", pinned: "6.67.0", want: "6.67.0", errPart: "not a hashicorp/aws release newer"},
		{name: "requested prerelease", pinned: "5.100.0", want: "6.0.0-beta1", errPart: "not a hashicorp/aws release newer"},
		{name: "requested unreleased", pinned: "6.67.0", want: "6.71.0", errPart: "not a hashicorp/aws release newer"},
		{name: "requested junk", pinned: "6.67.0", want: "6.68.0; rm -rf /", errPart: "not a hashicorp/aws release newer"},
		{name: "bad pin", pinned: "6.67", errPart: "is not X.Y.Z"},
		{name: "empty list", versions: `{"versions":[]}`, pinned: "6.67.0", errPart: "no versions listed"},
		{name: "not JSON", versions: `<html>`, pinned: "6.67.0", errPart: "versions:"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data := fixture(t)
			if c.versions != "" {
				data = []byte(c.versions)
			}
			_, err := decide(data, c.pinned, c.branches, c.heads, c.want)
			if err == nil || !strings.Contains(err.Error(), c.errPart) {
				t.Fatalf("err %v, want it to contain %q", err, c.errPart)
			}
		})
	}
}

func TestCompare(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"6.9.0", "6.10.0", -1}, {"6.10.0", "6.9.0", 1}, {"10.0.0", "9.99.99", 1},
		{"6.69.1", "6.69.0", 1}, {"6.70.0", "6.70.0", 0},
	} {
		if got := compare(c.a, c.b); got != c.want {
			t.Errorf("compare(%s, %s) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

// TestRun covers the file inputs and the $GITHUB_OUTPUT lines.
func TestRun(t *testing.T) {
	dir := t.TempDir()
	write := func(name, s string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	pins := write("pins.json", `{"version": "6.67.0"}`)
	branches := write("branches.txt", "\n")
	open := write("open.txt", "feature-x\n")
	var out, errOut bytes.Buffer
	if err := run(&out, &errOut, "testdata/versions.json", pins, branches, open, ""); err != nil {
		t.Fatal(err)
	}
	want := "pinned=6.67.0\nnext=6.68.0\nbranch=pin/hashicorp-aws-6.68.0\nqueued=6.69.0 6.69.1 6.70.0\n"
	if out.String() != want {
		t.Errorf("stdout %q, want %q", out.String(), want)
	}

	out.Reset()
	write("branches.txt", BranchPrefix+"6.68.0\n")
	write("open.txt", BranchPrefix+"6.68.0\n")
	if err := run(&out, &errOut, "testdata/versions.json", pins, branches, open, ""); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "\nnext=\nbranch=\n") || !strings.Contains(errOut.String(), "one pin PR at a time") {
		t.Errorf("open pin PR: stdout %q stderr %q", out.String(), errOut.String())
	}

	if err := run(&out, &errOut, "testdata/versions.json", pins, "", open, ""); err == nil {
		t.Error("missing -branches accepted")
	}
}
