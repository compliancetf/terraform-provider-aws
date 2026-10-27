//go:build conformance

package conformance

import (
	"bytes"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"golang.org/x/mod/semver"
)

// minStateStore is the oldest Terraform that runs testdata/statestore:
// state_store is an experiment only alpha builds accept, and earlier alphas
// reject a state store provider installed through dev_overrides.
const minStateStore = "v1.16.0-alpha20260513"

// minStableStateStore is the oldest stable Terraform the test runs on. No
// stable release ships state_store yet (v1.17.0 does not), so it
// names one that does not exist: once state_store is GA, set it to that
// release (and drop the experiment flag in the init step if GA rejects it)
// instead of letting stable builds skip.
const minStableStateStore = "v1.18.0"

// stateStoreRPCs are the tfplugin6 state store methods the steps reach.
// DeleteState is not among them: the fake keeps states in memory per process,
// so no later command sees a workspace to delete (passthrough6_test covers it).
var stateStoreRPCs = []string{
	"ValidateStateStoreConfig", "ConfigureStateStore", "GetStates",
	"ReadStateBytes", "WriteStateBytes", "LockState", "UnlockState",
}

var tfBannerRE = regexp.MustCompile(`^Terraform (v\S+)`)

// stateStoreTF reports whether the tfBannerRE match m names a Terraform
// that runs testdata/statestore.
func stateStoreTF(m []string) bool {
	if m == nil {
		return false
	}
	switch pre := semver.Prerelease(m[1]); {
	case pre == "":
		return semver.Compare(m[1], minStableStateStore) >= 0
	case strings.HasPrefix(pre, "-alpha"):
		return semver.Compare(m[1], minStateStore) >= 0
	}
	return false
}

// TestStateStore runs real Terraform with a state_store "fake_store" block
// against forward6, the proxy's raw forwarder with the pinned tfplugin6
// routes, in front of test/fakeupstream/v6, and checks every state store RPC
// the steps make is forwarded and returns OK.
func TestStateStore(t *testing.T) {
	out, err := exec.Command(*tfBin, "version").Output()
	if err != nil {
		t.Fatalf("%s version: %v", *tfBin, err)
	}
	banner, _, _ := strings.Cut(string(out), "\n")
	m := tfBannerRE.FindStringSubmatch(banner)
	if !stateStoreTF(m) {
		t.Skipf("state_store needs a Terraform alpha >= %s or a stable release >= %s; -tf is %s", minStateStore, minStableStateStore, banner)
	}

	bin := t.TempDir()
	for _, b := range []struct{ wd, out, pkg, tags string }{
		{filepath.Join("..", "fakeupstream"), "fake6", "./v6", ""},
		{".", "terraform-provider-fake", "./forward6", "conformance"},
	} {
		cmd := exec.Command("go", "build", "-tags", b.tags, "-o", filepath.Join(bin, b.out), b.pkg)
		cmd.Dir = b.wd
		if o, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("go build %s: %v\n%s", b.pkg, err, o)
		}
	}
	rc := filepath.Join(bin, "terraformrc")
	if err := os.WriteFile(rc, fmt.Appendf(nil,
		"provider_installation {\n  dev_overrides {\n    \"bobthecorp/fake\" = %q\n  }\n  direct {\n    exclude = [\"registry.terraform.io/bobthecorp/*\"]\n  }\n}\n", bin), 0o600); err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	if err := os.CopyFS(work, os.DirFS(filepath.Join("testdata", "statestore"))); err != nil {
		t.Fatal(err)
	}
	calls, tfLog := filepath.Join(work, "calls.txt"), filepath.Join(work, "terraform.log")
	env := append(childEnv("", "", ""), // exec keeps the last value of a repeated key
		"TF_CLI_CONFIG_FILE="+rc,
		"FORWARD6_UPSTREAM="+filepath.Join(bin, "fake6"),
		"FORWARD6_CALLS="+calls,
		"TF_LOG=ERROR", "TF_LOG_PATH="+tfLog,
	)
	// forward6 fails a call it cannot record; Terraform logs the status.
	defer func() {
		b, err := os.ReadFile(tfLog)
		if err != nil {
			t.Errorf("read terraform log: %v", err)
			return
		}
		for line := range strings.Lines(string(b)) {
			if strings.Contains(line, "forward6: ERR") {
				t.Errorf("forward6 could not record a call: %s", strings.TrimSpace(line))
			}
		}
	}()

	for _, s := range []struct {
		cmd  []string
		want string
	}{
		{[]string{"init", "-no-color", "-enable-pluggable-state-storage-experiment"}, "Terraform has been successfully initialized!"},
		{[]string{"plan", "-no-color"}, "No changes."},
		{[]string{"workspace", "new", "-no-color", "dev"}, `Created and switched to workspace "dev"!`},
	} {
		cmd := exec.CommandContext(t.Context(), *tfBin, s.cmd...)
		cmd.Dir, cmd.Env = work, env
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil || !strings.Contains(stdout.String(), s.want) {
			t.Fatalf("%v: %v, stdout must contain %q\n--- stdout\n%s--- stderr\n%s", s.cmd, err, s.want, stdout.String(), stderr.String())
		}
	}

	b, err := os.ReadFile(calls)
	if err != nil {
		t.Fatalf("forward6 recorded no call: %v", err)
	}
	seen := map[string]bool{}
	for line := range strings.Lines(string(b)) {
		method, code, _ := strings.Cut(strings.TrimSpace(line), "\t")
		if code != "OK" {
			t.Errorf("forwarded %s returned %s", method, code)
		}
		seen[strings.TrimPrefix(method, "/tfplugin6.Provider/")] = true
	}
	for _, rpc := range stateStoreRPCs {
		if !seen[rpc] {
			t.Errorf("%s was not forwarded", rpc)
		}
	}
	if t.Failed() {
		t.Logf("forwarded: %v", slices.Sorted(maps.Keys(seen)))
	}
}

func TestStateStoreTF(t *testing.T) {
	for banner, want := range map[string]bool{
		"Terraform v1.16.0-alpha20260513":  true,
		"Terraform v1.17.0-alpha20260827":  true,
		"Terraform v1.15.0-alpha20260304":  false,
		"Terraform v1.17.0-rc2":            false,
		"Terraform v1.16.3":                false,
		"Terraform " + minStableStateStore: true,
		"OpenTofu v1.10.0":                 false,
	} {
		if got := stateStoreTF(tfBannerRE.FindStringSubmatch(banner)); got != want {
			t.Errorf("stateStoreTF(%q) = %v, want %v", banner, got, want)
		}
	}
}

func TestDestroyIdentityMissing(t *testing.T) {
	for banner, want := range map[string]bool{
		"Terraform v1.11.4": false,
		"Terraform v1.12.0": true,
		"Terraform v1.16.5": true,
		"Terraform v1.16.6": false,
		"Terraform v1.17.0": false,
		"OpenTofu v1.12.2":  false,
		"OpenTofu v1.13.1":  true,
		"OpenTofu v2.0.0":   true,
		"bogus":             false,
	} {
		if got := destroyIdentityMissing(banner); got != want {
			t.Errorf("destroyIdentityMissing(%q) = %v, want %v", banner, got, want)
		}
	}
}
