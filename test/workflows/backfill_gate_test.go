package workflows

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// originScript is the run script of the release job's "origin" step.
func originScript(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(".github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	var wf struct {
		Jobs map[string]struct {
			Steps []struct {
				ID  string `yaml:"id"`
				Run string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(b, &wf); err != nil {
		t.Fatal(err)
	}
	for _, s := range wf.Jobs["release"].Steps {
		if s.ID == "origin" {
			return s.Run
		}
	}
	t.Fatal("release.yml: no step with id origin")
	return ""
}

// TestReleaseBackfillGateRuns runs the release gate against crafted tag
// commits: only a master commit, or one pins.json-only commit on a master
// commit to an older X.Y.Z of the same major, passes.
func TestReleaseBackfillGateRuns(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash gate")
	}
	for _, tool := range []string{"bash", "git", "jq"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed", tool)
		}
	}
	script := originScript(t)
	dir := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-c", "user.name=b", "-c", "user.email=b@example.com", "-c", "init.defaultBranch=master"}, args...)...)
		cmd.Dir = filepath.Join(dir, "w")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	write := func(name, body string, mode os.FileMode) {
		t.Helper()
		p := filepath.Join(dir, "w", name)
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
	}
	if out, err := exec.Command("git", "init", "-q", "--bare", filepath.Join(dir, "origin.git")).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	if err := os.Mkdir(filepath.Join(dir, "w"), 0o755); err != nil {
		t.Fatal(err)
	}
	git("init", "-q")
	git("remote", "add", "origin", filepath.Join(dir, "origin.git"))
	write("pins.json", `{"version":"6.70.0"}`+"\n", 0o644)
	write("other.txt", "a\n", 0o644)
	git("add", ".")
	git("commit", "-qm", "base")
	git("push", "-q", "origin", "HEAD:master")
	git("fetch", "-q", "origin")

	gate := func(t *testing.T) (bool, string, string) {
		t.Helper()
		out := filepath.Join(dir, "out")
		if err := os.WriteFile(out, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("bash", "-c", script)
		cmd.Dir = filepath.Join(dir, "w")
		cmd.Env = append(os.Environ(), "GITHUB_OUTPUT="+out, "GITHUB_SHA="+git("rev-parse", "HEAD"))
		log, err := cmd.CombinedOutput()
		b, rerr := os.ReadFile(out)
		if rerr != nil {
			t.Fatal(rerr)
		}
		return err == nil, string(b), string(log)
	}
	cases := []struct {
		name  string
		setup func()
		pass  bool
		why   string // the gate's error for a refused commit
	}{
		{"master commit", func() {}, true, ""},
		{"pins-only backfill", func() { write("pins.json", `{"version":"6.40.0"}`+"\n", 0o644); git("commit", "-qam", "c") }, true, ""},
		{"extra file", func() {
			write("pins.json", `{"version":"6.40.0"}`+"\n", 0o644)
			write("other.txt", "b\n", 0o644)
			git("commit", "-qam", "c")
		}, false, "modifies the regular file pins.json"},
		{"mode change", func() { write("pins.json", `{"version":"6.40.0"}`+"\n", 0o755); git("commit", "-qam", "c") }, false, "modifies the regular file pins.json"},
		{"leading zero", func() { write("pins.json", `{"version":"6.070.0"}`+"\n", 0o644); git("commit", "-qam", "c") }, false, "must be X.Y.Z"},
		{"newer", func() { write("pins.json", `{"version":"6.71.0"}`+"\n", 0o644); git("commit", "-qam", "c") }, false, "is not older"},
		{"same version", func() { write("pins.json", `{"version":"6.70.0"}`+"\n\n", 0o644); git("commit", "-qam", "c") }, false, "is not older"},
		{"other major", func() { write("pins.json", `{"version":"5.90.0"}`+"\n", 0o644); git("commit", "-qam", "c") }, false, "is not older"},
		{"two commits deep", func() {
			write("pins.json", `{"version":"6.40.0"}`+"\n", 0o644)
			git("commit", "-qam", "c1")
			write("pins.json", `{"version":"6.39.0"}`+"\n", 0o644)
			git("commit", "-qam", "c2")
		}, false, "nor one commit on a master commit"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			git("checkout", "-q", "--detach", "origin/master")
			c.setup()
			ok, out, log := gate(t)
			if ok != c.pass {
				t.Fatalf("gate passed=%v, want %v (outputs %q)\n%s", ok, c.pass, out, log)
			}
			if !ok && !strings.Contains(log, c.why) {
				t.Fatalf("gate refused for another reason, want %q:\n%s", c.why, log)
			}
			if ok && c.name == "pins-only backfill" && !strings.Contains(out, "backfill=true\nversion=6.40.0\n") {
				t.Fatalf("backfill outputs %q", out)
			}
			if ok && c.name == "master commit" && out != "backfill=false\n" {
				t.Fatalf("master outputs %q", out)
			}
		})
	}
}
