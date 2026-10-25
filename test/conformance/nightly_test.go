//go:build conformance && nightly

// Nightly runs the scenarios under nightly/ against the real hashicorp/aws
// upstream in the sandbox account; with -plan-only it renders and checks them
// and contacts no AWS API. Runs, setup and cleanup: nightly/README.md.
package conformance

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/upstream"
)

var (
	planOnly   = flag.Bool("plan-only", false, "render and check nightly scenarios without contacting AWS")
	upstreamFl = flag.String("upstream", "", "real hashicorp/aws provider binary (required unless -plan-only)")
	prefixFl   = flag.String("prefix", "bobthecorp-ctf-conf-planonly", "resource name prefix for this run")
)

func init() { tfOptional = func() bool { return *planOnly } }

// prefixRE keeps every name inside what the janitor and the role policy cover.
var prefixRE = regexp.MustCompile(`^bobthecorp-ctf-conf-[a-z0-9-]{1,40}$`)

// nightlyTypes are the managed resource types janitor.sh deletes and the
// README role policy allows; a scenario may create nothing else.
var nightlyTypes = []string{"aws_ssm_parameter"}

var resourceRE = regexp.MustCompile(`(?m)^\s*resource\s+"([^"]+)"`)

func TestNightly(t *testing.T) {
	if !prefixRE.MatchString(*prefixFl) {
		t.Fatalf("-prefix %q must match %s", *prefixFl, prefixRE)
	}
	up := *upstreamFl
	var c cell
	if *planOnly {
		if up == "" {
			up = cachedUpstream()
		}
	} else {
		if up == "" {
			t.Fatal("-upstream <hashicorp/aws binary> is required without -plan-only")
		}
		var banner string
		var err error
		if c, banner, err = detectCell(*tfBin); err != nil {
			t.Fatal(err)
		}
		t.Logf("cell %s: %s; upstream %s", c.Name, banner, up)
	}
	entries, err := os.ReadDir("nightly")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		t.Run(e.Name(), func(t *testing.T) {
			dir := renderScenario(t, filepath.Join("nightly", e.Name()), *prefixFl+"-"+e.Name())
			if *planOnly {
				validateScenario(t, dir, up)
				return
			}
			runScenario(t, c, dir, up, func(t *testing.T, work string) { destroyOnFailure(t, work, up) }, nil)
		})
	}
}

// renderScenario writes src's steps.json and main.tf (nightly/main.tf when
// src has none) to a temp dir with @PREFIX@ replaced, after checking that
// every bobthecorp name goes through the prefix, that main.tf creates only
// nightlyTypes, and that the step plan never leaves a resource behind.
func renderScenario(t *testing.T, src, prefix string) string {
	t.Helper()
	tf, err := os.ReadFile(filepath.Join(src, "main.tf"))
	if errors.Is(err, fs.ErrNotExist) {
		tf, err = os.ReadFile(filepath.Join(filepath.Dir(src), "main.tf"))
	}
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(tf), "@PREFIX@") || strings.Contains(strings.ReplaceAll(string(tf), "@PREFIX@", ""), "bobthecorp") {
		t.Fatal("main.tf must name everything through @PREFIX@ and nothing else bobthecorp")
	}
	for _, m := range resourceRE.FindAllStringSubmatch(string(tf), -1) {
		if !slices.Contains(nightlyTypes, m[1]) {
			t.Fatalf("main.tf: resource type %s is not in nightlyTypes (janitor and role policy)", m[1])
		}
	}
	var sc scenario
	b, err := os.ReadFile(filepath.Join(src, "steps.json"))
	if err == nil {
		err = strictUnmarshal(b, &sc)
	}
	if err == nil {
		err = checkSteps(sc)
	}
	if err != nil {
		t.Fatalf("steps.json: %v", err)
	}
	dst := t.TempDir()
	for name, b := range map[string][]byte{"main.tf": tf, "steps.json": b} {
		if err := os.WriteFile(filepath.Join(dst, name), []byte(strings.ReplaceAll(string(b), "@PREFIX@", prefix)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

// checkSteps rejects commands outside the nightly set, apply or destroy
// without -auto-approve, and a successful apply or import that no later
// successful destroy undoes.
func checkSteps(sc scenario) error {
	if len(sc.Steps) == 0 {
		return errors.New("no steps")
	}
	live := false
	for i, s := range sc.Steps {
		if len(s.Cmd) == 0 {
			return fmt.Errorf("step %d: empty cmd", i)
		}
		switch s.Cmd[0] {
		case "apply", "destroy":
			if !slices.Contains(s.Cmd, "-auto-approve") {
				return fmt.Errorf("step %d: %s without -auto-approve", i, s.Cmd[0])
			}
		case "plan", "refresh", "import", "state":
		default:
			return fmt.Errorf("step %d: command %q not allowed in nightly scenarios", i, s.Cmd[0])
		}
		if s.Exit != 0 {
			continue
		}
		switch {
		case s.Cmd[0] == "destroy" || s.Cmd[0] == "apply" && slices.Contains(s.Cmd, "-destroy"):
			live = false
		case s.Cmd[0] == "import" || s.Cmd[0] == "apply" && !slices.Contains(s.Cmd, "-refresh-only"):
			live = true
		}
	}
	if live {
		return errors.New("a successful apply or import is not followed by a successful destroy")
	}
	return nil
}

// validateScenario runs terraform validate through the proxy and the real upstream without AWS credentials.
func validateScenario(t *testing.T, dir, up string) {
	t.Helper()
	switch {
	case *tfBin == "":
		t.Skip("rendered and checked; skip terraform validate: no -tf binary")
	case up == "":
		t.Skipf("rendered and checked; skip terraform validate: pinned hashicorp/aws %q is not cached locally; pass -upstream", pinnedVersion())
	}
	var env []string
	for _, kv := range childEnv(filepath.Join(dir, "tap.jsonl"), "", up) {
		if !strings.HasPrefix(kv, "AWS_") {
			env = append(env, kv)
		}
	}
	env = append(env, "AWS_CONFIG_FILE="+os.DevNull, "AWS_SHARED_CREDENTIALS_FILE="+os.DevNull, "AWS_EC2_METADATA_DISABLED=true")
	cmd := exec.CommandContext(t.Context(), *tfBin, "validate", "-no-color")
	cmd.Dir, cmd.Env = dir, env
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "Success! The configuration is valid") {
		t.Fatalf("terraform validate: %v\n%s", err, out)
	}
}

// cachedUpstream finds the pinned hashicorp/aws version in the plugin cache,
// or returns "".
func cachedUpstream() string {
	v := pinnedVersion()
	if v == "" {
		return ""
	}
	home, _ := os.UserHomeDir()
	for _, r := range []string{os.Getenv("TF_PLUGIN_CACHE_DIR"), filepath.Join(home, ".terraform.d", "plugin-cache")} {
		pat := filepath.Join(r, "registry.terraform.io", "hashicorp", "aws", v, runtime.GOOS+"_"+runtime.GOARCH, awsSource.BinaryName(v, runtime.GOOS, 5))
		if m, _ := filepath.Glob(pat); r != "" && len(m) > 0 {
			return m[0]
		}
	}
	return ""
}

// pinnedVersion is the hashicorp/aws version pins.json pins, or "" while it
// pins none.
func pinnedVersion() string {
	data, err := os.ReadFile(filepath.Join("..", "..", "pins.json"))
	if err != nil {
		return ""
	}
	p, err := upstream.ParsePins(data, awsSource, upstream.HashiCorpFingerprint)
	if err != nil {
		return ""
	}
	return p.Version
}

// destroyOnFailure tears down what a failed nightly scenario left in work,
// without the scenario's evaluator; what it cannot remove the janitor deletes
// after 24 h.
func destroyOnFailure(t *testing.T, work, up string) {
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, *tfBin, "destroy", "-no-color", "-auto-approve")
		cmd.Dir, cmd.Env = work, childEnv(filepath.Join(work, "cleanup-tap.jsonl"), "", up)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("cleanup destroy in %s: %v (janitor removes leftovers after 24 h)\n%s", work, err, out)
		}
	})
}

func TestNightlyStepPlan(t *testing.T) {
	apply := step{Cmd: []string{"apply", "-auto-approve"}}
	destroy := step{Cmd: []string{"destroy", "-auto-approve"}}
	for name, tc := range map[string]struct {
		steps []step
		ok    bool
	}{
		"apply then destroy":      {[]step{apply, destroy}, true},
		"blocked apply":           {[]step{{Cmd: []string{"apply", "-auto-approve"}, Exit: 1}}, true},
		"apply -destroy":          {[]step{apply, {Cmd: []string{"apply", "-auto-approve", "-destroy"}}}, true},
		"refresh-only apply":      {[]step{{Cmd: []string{"apply", "-auto-approve", "-refresh-only"}}}, true},
		"apply after destroy":     {[]step{apply, destroy, apply}, false},
		"import left behind":      {[]step{{Cmd: []string{"import", "a.b", "id"}}}, false},
		"failed destroy":          {[]step{apply, {Cmd: []string{"destroy", "-auto-approve"}, Exit: 1}}, false},
		"apply without approve":   {[]step{{Cmd: []string{"apply"}, Exit: 1}}, false},
		"command outside the set": {[]step{{Cmd: []string{"force-unlock", "x"}}}, false},
	} {
		if err := checkSteps(scenario{Steps: tc.steps}); (err == nil) != tc.ok {
			t.Errorf("%s: checkSteps = %v, want ok %v", name, err, tc.ok)
		}
	}
}

// TestNightlyJanitor runs janitor.sh against a fake aws CLI: only prefixed
// parameters older than 24 h are deleted, and an unparseable date deletes
// nothing.
func TestNightlyJanitor(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq not installed")
	}
	old := time.Now().Add(-25 * time.Hour).UTC().Format("2006-01-02T15:04:05.000000+00:00")
	fresh := time.Now().Add(-time.Hour).UTC().Format("2006-01-02T15:04:05.000000+00:00")
	for name, tc := range map[string]struct {
		params, want string
		args         []string
		fail         bool
	}{
		"age and prefix": {
			params: fmt.Sprintf(`[{"Name":"bobthecorp-ctf-conf-1-apply-a","LastModifiedDate":%q},
				{"Name":"bobthecorp-ctf-conf-2-apply-a","LastModifiedDate":%q},
				{"Name":"bobthecorp-ctf-conf-3-plan-a","LastModifiedDate":%d},
				{"Name":"bobthecorp-other","LastModifiedDate":%q}]`, old, fresh, time.Now().Add(-48*time.Hour).Unix(), old),
			want: "bobthecorp-ctf-conf-1-apply-a\nbobthecorp-ctf-conf-3-plan-a\n",
		},
		"this run at any age": {
			params: fmt.Sprintf(`[{"Name":"bobthecorp-ctf-conf-7-1-apply-a","LastModifiedDate":%q},
				{"Name":"bobthecorp-ctf-conf-7-10-apply-a","LastModifiedDate":%q}]`, fresh, fresh),
			args: []string{"bobthecorp-ctf-conf-7-1-", "0"},
			want: "bobthecorp-ctf-conf-7-1-apply-a\n",
		},
		"prefix outside the namespace": {params: `[]`, args: []string{"bobthecorp-", "0"}, fail: true},
		"unparseable date": {
			params: `[{"Name":"bobthecorp-ctf-conf-1-apply-a","LastModifiedDate":"yesterday"}]`,
			fail:   true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			bin := t.TempDir()
			deleted := filepath.Join(bin, "deleted")
			fake := fmt.Sprintf(`#!/usr/bin/env bash
case "$2" in
describe-parameters) printf '%%s' '{"Parameters":%s}' ;;
delete-parameter) echo "$4" >> %q ;;
*) exit 9 ;;
esac
`, tc.params, deleted)
			if err := os.WriteFile(filepath.Join(bin, "aws"), []byte(fake), 0o700); err != nil { //nolint:gosec // test stub must be executable
				t.Fatal(err)
			}
			cmd := exec.CommandContext(t.Context(), "bash", append([]string{filepath.Join("nightly", "janitor.sh")}, tc.args...)...)
			cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			out, err := cmd.CombinedOutput()
			if (err != nil) != tc.fail {
				t.Fatalf("janitor: %v, want failure %v\n%s", err, tc.fail, out)
			}
			got, _ := os.ReadFile(deleted)
			if string(got) != tc.want {
				t.Fatalf("deleted %q, want %q\n%s", got, tc.want, out)
			}
		})
	}
}
