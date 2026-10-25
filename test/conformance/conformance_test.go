//go:build conformance

// Package conformance runs the scenarios under scenarios/ against the proxy
// (built with -tags conformance,ctftest) in front of test/fakeupstream, which
// pinned discovery verifies against a generated pins file, on whichever
// Terraform or OpenTofu binary -tf names. The binary's version picks its cell
// in matrix.json; a scenario whose requires lists a feature the cell lacks is
// skipped.
//
//	go test -count=1 -tags conformance ./test/conformance/... -tf "$(which terraform)"
package conformance

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/upstream"
)

const providerSource = "registry.compliance.tf/compliancetf/aws"

// awsSource is the upstream the fake pins name.
var awsSource = func() upstream.Source {
	s, err := upstream.ParseSource("registry.terraform.io/hashicorp/aws")
	if err != nil {
		panic(err)
	}
	return s
}()

var tfBin = flag.String("tf", "", "terraform or tofu binary under test (required)")

// binDir holds the proxy, the fake upstream and the generated CLI config.
var binDir string

type cell struct {
	Name     string   `json:"name"`
	Product  string   `json:"product"`
	Version  string   `json:"version"`
	Features []string `json:"features"`
}

type scenario struct {
	Requires      []string          `json:"requires"`
	Evaluator     string            `json:"evaluator"`
	Env           map[string]string `json:"env"` // "{work}" in a value names the scenario's work dir
	Steps         []step            `json:"steps"`
	ExpectApplies int               `json:"expect_applies"`
	// ExpectNoApplies fails the scenario on any forwarded apply (expect_applies
	// is a minimum).
	ExpectNoApplies bool `json:"expect_no_applies"`
	// NoDestroyIdentity replaces Steps and ExpectApplies on Terraform 1.12 to
	// 1.16.5 and OpenTofu 1.13 and later, which send no identity on the
	// destroy half of a replace, so the provider blocks it. TestRPCSeq then
	// compares with the golden <name>.no_destroy_identity.json.
	NoDestroyIdentity *struct {
		Steps         []step `json:"steps"`
		ExpectApplies int    `json:"expect_applies"`
	} `json:"no_destroy_identity"`
}

var patchRE = regexp.MustCompile(`^(Terraform|OpenTofu) v(\d+)\.(\d+)\.(\d+)`)

// noDestroyIdentity reports whether the -tf binary sends a prior identity
// at plan but none as the planned identity of a destroy half of a replace.
var noDestroyIdentity = sync.OnceValue(func() bool {
	out, err := exec.Command(*tfBin, "version").Output()
	return err == nil && destroyIdentityMissing(string(out))
})

// destroyIdentityMissing is noDestroyIdentity for a version banner: Terraform
// 1.12 to 1.16.5 (Core fills it from v1.16.6) and OpenTofu from 1.13 (checked
// with 1.13.1; a later fix shows as a replace_flag failure).
func destroyIdentityMissing(banner string) bool {
	m := patchRE.FindStringSubmatch(banner)
	if m == nil {
		return false
	}
	v := [3]int{}
	for i := range v {
		v[i], _ = strconv.Atoi(m[i+2])
	}
	if m[1] == "OpenTofu" {
		return v[0] > 1 || (v[0] == 1 && v[1] >= 13)
	}
	return v[0] == 1 && v[1] >= 12 && (v[1] < 16 || (v[1] == 16 && v[2] < 6))
}

type step struct {
	Cmd            []string `json:"cmd"`
	Exit           int      `json:"exit"`
	StderrContains []string `json:"stderr_contains"`
	StdoutContains []string `json:"stdout_contains"`
	// StdoutExcludes and StderrExcludes must not occur in the stream.
	StdoutExcludes []string `json:"stdout_excludes"`
	StderrExcludes []string `json:"stderr_excludes"`
	StateUnchanged bool     `json:"state_unchanged"`
	// Envelope, when set, is the envelope edit the proxy applies to every
	// ApplyResourceChange of this step (internal/proxy/tap_conformance.go).
	Envelope json.RawMessage `json:"envelope"`
}

// tfOptional reports whether this run may go without -tf; the nightly
// -plan-only dry run sets it.
var tfOptional = func() bool { return false }

func TestMain(m *testing.M) {
	flag.Parse()
	if *tfBin == "" && !tfOptional() {
		fmt.Fprintln(os.Stderr, "conformance: -tf <terraform or tofu binary> is required")
		os.Exit(2)
	}
	// Steps run in a scenario temp dir, so a relative -tf must be made absolute.
	var err error
	if *tfBin != "" {
		var bin string
		bin, err = exec.LookPath(*tfBin)
		if err == nil {
			*tfBin, err = filepath.Abs(bin)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "conformance: -tf:", err)
		os.Exit(2)
	}
	dir, err := os.MkdirTemp("", "ctf-conformance-")
	if err == nil {
		binDir = dir
		err = setup(dir)
	}
	code := 1
	if err == nil {
		code = m.Run()
	} else {
		fmt.Fprintln(os.Stderr, "conformance setup:", err)
	}
	if dir != "" {
		os.RemoveAll(dir)
	}
	os.Exit(code)
}

// setup builds the proxy and the fake upstream into dir and writes a CLI
// config whose dev_overrides point the proxy's source at dir. The user's own
// CLI config is never read: every run sets TF_CLI_CONFIG_FILE to this one.
func setup(dir string) error {
	builds := []struct {
		wd, out string
		args    []string
	}{
		{filepath.Join("..", ".."), "terraform-provider-aws", []string{"-tags", "conformance,ctftest", "."}},
		{filepath.Join("..", "fakeupstream"), "fakeupstream", []string{"./v5"}},
		{filepath.Join("..", ".."), "ctfbundle", []string{"-tags", "ctftest", "./cmd/ctfbundle"}}, // signs trust.json fixtures
	}
	for _, b := range builds {
		args := append([]string{"build", "-o", filepath.Join(dir, b.out)}, b.args...)
		cmd := exec.Command("go", args...)
		cmd.Dir = b.wd
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("go %s: %w\n%s", strings.Join(args, " "), err, out)
		}
	}
	if err := writeFakePins(dir); err != nil {
		return err
	}
	rc := fmt.Sprintf("provider_installation {\n  dev_overrides {\n    %q = %q\n  }\n  direct {\n    exclude = [\"registry.compliance.tf/*/*\"]\n  }\n}\n", providerSource, dir)
	return os.WriteFile(filepath.Join(dir, "terraformrc"), []byte(rc), 0o600)
}

// writeFakePins writes dir/pins.json pinning the fake upstream's sha256 for
// this platform, so the proxy verifies it like a release build verifies
// hashicorp/aws (COMPLIANCETF_CONFORMANCE_PINS, conformance builds only).
func writeFakePins(dir string) error {
	b, err := os.ReadFile(filepath.Join(dir, "fakeupstream"))
	if err != nil {
		return err
	}
	sum := sha256.Sum256(b)
	h := hex.EncodeToString(sum[:])
	const v = "0.0.0"
	data, err := upstream.MarshalPins(&upstream.Pins{
		Format: upstream.PinsFormat, Upstream: awsSource.String(), Version: v, Protocol: upstream.PinsProtocol,
		SigningKeyFingerprint: upstream.HashiCorpFingerprint, SHA256SumsSHA256: h,
		Platforms: map[string]upstream.PlatformPin{runtime.GOOS + "_" + runtime.GOARCH: {
			Zip: awsSource.ZipName(v, runtime.GOOS, runtime.GOARCH), ZipSHA256: h,
			Binary: awsSource.BinaryName(v, runtime.GOOS, upstream.PinsProtocol), BinarySHA256: h,
		}},
	})
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "pins.json"), data, 0o600)
}

func TestConformance(t *testing.T) {
	c, banner, err := detectCell(*tfBin)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("cell %s: %s", c.Name, banner)
	entries, err := os.ReadDir("scenarios")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("no scenarios")
	}
	for _, e := range entries {
		t.Run(e.Name(), func(t *testing.T) { runScenario(t, c, filepath.Join("scenarios", e.Name()), "", nil, nil) })
	}
}

var bannerRE = regexp.MustCompile(`^(Terraform|OpenTofu) v(\d+)\.(\d+)\.\d+\S*`)

// detectCell maps the binary to its matrix cell. `version -json` names both
// products terraform_version, so the product comes from the first line of
// plain `version` ("Terraform v1.16.3" / "OpenTofu v1.13.1"). A version
// matches a "1.5.x" cell by major.minor; a newer version than every pinned
// cell of its product takes the product's "latest" cell; anything else has
// no cell and fails rather than run with the wrong feature set.
func detectCell(bin string) (cell, string, error) {
	out, err := exec.Command(bin, "version").Output()
	if err != nil {
		return cell{}, "", fmt.Errorf("%s version: %w", bin, err)
	}
	banner, _, _ := strings.Cut(string(out), "\n")
	m := bannerRE.FindStringSubmatch(banner)
	if m == nil {
		return cell{}, banner, fmt.Errorf("unrecognized version banner %q", banner)
	}
	product := strings.ToLower(m[1])
	major, _ := strconv.Atoi(m[2])
	minor, _ := strconv.Atoi(m[3])
	b, err := os.ReadFile("matrix.json")
	if err != nil {
		return cell{}, banner, err
	}
	var mx struct {
		Cells []cell `json:"cells"`
	}
	if err := strictUnmarshal(b, &mx); err != nil {
		return cell{}, banner, fmt.Errorf("matrix.json: %w", err)
	}
	var latest *cell
	newest := true
	for i, c := range mx.Cells {
		if c.Product != product {
			continue
		}
		if c.Version == "latest" {
			if latest != nil {
				return cell{}, banner, fmt.Errorf("matrix.json: two latest cells for %s", product)
			}
			latest = &mx.Cells[i]
			continue
		}
		var cMajor, cMinor int
		if _, err := fmt.Sscanf(c.Version, "%d.%d.x", &cMajor, &cMinor); err != nil || fmt.Sprintf("%d.%d.x", cMajor, cMinor) != c.Version {
			return cell{}, banner, fmt.Errorf("matrix.json: cell %s: version %q is neither MAJOR.MINOR.x nor latest", c.Name, c.Version)
		}
		if cMajor == major && cMinor == minor {
			return c, banner, nil
		}
		if cMajor > major || (cMajor == major && cMinor > minor) {
			newest = false
		}
	}
	if latest == nil || !newest {
		return cell{}, banner, fmt.Errorf("matrix.json has no cell for %s", banner)
	}
	return *latest, banner, nil
}

// runScenario runs dir's steps on upstream ("" for the fake upstream). onWork,
// when set, is called with the scenario's work dir before any step. With a
// non-nil rec the proxy appends one line per hook call to the file rec
// receives after each step.
func runScenario(t *testing.T, c cell, dir, upstream string, onWork func(t *testing.T, work string), rec func(i int, s step, calls string)) {
	var sc scenario
	b, err := os.ReadFile(filepath.Join(dir, "steps.json"))
	if err == nil {
		err = strictUnmarshal(b, &sc)
	}
	if err != nil {
		t.Fatalf("steps.json: %v", err)
	}
	if sc.NoDestroyIdentity != nil && noDestroyIdentity() {
		sc.Steps, sc.ExpectApplies = sc.NoDestroyIdentity.Steps, sc.NoDestroyIdentity.ExpectApplies
	}
	if len(sc.Steps) == 0 {
		t.Fatal("steps.json: no steps")
	}
	for _, f := range sc.Requires {
		if !slices.Contains(c.Features, f) {
			t.Skipf("cell %s lacks feature %s", c.Name, f)
		}
	}
	work := t.TempDir()
	if err := os.CopyFS(work, os.DirFS(dir)); err != nil {
		t.Fatal(err)
	}
	if onWork != nil {
		onWork(t, work)
	}
	tap := filepath.Join(work, "tap.jsonl")
	env := append(childEnv(tap, sc.Evaluator, upstream), "COMPLIANCETF_CONFORMANCE_ENVELOPE="+filepath.Join(work, "envelope.json"))
	if sc.Evaluator == "lifecycle" { // empty trust state, cache and evidence dirs; no service
		for _, d := range []string{"STATE", "CACHE", "EVIDENCE"} {
			env = append(env, "COMPLIANCETF_"+d+"_DIR="+filepath.Join(work, strings.ToLower(d)))
		}
		env = append(env, "COMPLIANCETF_OFFLINE=true")
	}
	for k, v := range sc.Env { // exec keeps the last value of a repeated key
		env = append(env, k+"="+strings.ReplaceAll(v, "{work}", work))
	}
	if upstream == "" {
		requireFake(t, work, env) // before the recorder is on, so it records no probe calls
	}
	calls := filepath.Join(work, "rpcseq.jsonl")
	if rec != nil {
		env = append(env, "COMPLIANCETF_CONFORMANCE_RPCSEQ="+calls)
	}
	prev, err := readState(work)
	if err != nil {
		t.Fatal(err)
	}
	seeded := privates(prev)
	if prev != nil && len(seeded) == 0 {
		t.Fatal("seeded terraform.tfstate has no instance private to check")
	}
	for i, s := range sc.Steps {
		edit := filepath.Join(work, "envelope.json")
		if err := os.Remove(edit); err != nil && !errors.Is(err, fs.ErrNotExist) {
			t.Fatal(err)
		}
		if s.Envelope != nil {
			var e struct { // the edit the proxy applies; a typo must not pass as no edit
				V     *int           `json:"v"`
				CTF   map[string]any `json:"ctf"`
				Strip bool           `json:"strip"`
			}
			if err := strictUnmarshal(s.Envelope, &e); err != nil {
				t.Fatalf("step %d envelope: %v", i, err)
			}
			if err := os.WriteFile(edit, s.Envelope, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		cmd := exec.CommandContext(t.Context(), *tfBin, s.Cmd...)
		cmd.Dir, cmd.Env = work, env
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		exit := 0
		if err := cmd.Run(); err != nil {
			var ee *exec.ExitError
			if !errors.As(err, &ee) {
				t.Fatalf("step %d %v: %v", i, s.Cmd, err)
			}
			exit = ee.ExitCode()
		}
		ok := exit == s.Exit
		for _, want := range s.StdoutContains {
			ok = ok && strings.Contains(stdout.String(), want)
		}
		words := func(s string) string { return strings.Join(strings.Fields(s), " ") }
		for _, want := range s.StderrContains { // Terraform wraps diagnostics: compare words
			ok = ok && strings.Contains(words(stderr.String()), words(want))
		}
		var found []string // excluded substrings that occur
		for _, bad := range s.StdoutExcludes {
			if strings.Contains(stdout.String(), bad) {
				found = append(found, "stdout: "+bad)
			}
		}
		for _, bad := range s.StderrExcludes {
			if strings.Contains(stderr.String(), bad) {
				found = append(found, "stderr: "+bad)
			}
		}
		if !ok || len(found) > 0 {
			t.Fatalf("step %d %v: exit %d (want %d), stdout must contain %q, stderr must contain %q, excluded but found %q\n--- stdout\n%s--- stderr\n%s",
				i, s.Cmd, exit, s.Exit, s.StdoutContains, s.StderrContains, found, stdout.String(), stderr.String())
		}
		cur, err := readState(work)
		if err != nil {
			t.Fatalf("step %d %v: %v", i, s.Cmd, err)
		}
		if s.StateUnchanged && !reflect.DeepEqual(prev, cur) {
			t.Fatalf("step %d %v: state changed\n--- before\n%v\n--- after\n%v", i, s.Cmd, prev, cur)
		}
		got := privates(cur)
		for addr, want := range seeded {
			if got[addr] != want {
				t.Fatalf("step %d %v: %s private %q, seeded %q", i, s.Cmd, addr, got[addr], want)
			}
		}
		prev = cur
		if rec != nil {
			rec(i, s, calls)
		}
	}
	checkTap(t, tap, sc.ExpectApplies, sc.ExpectNoApplies)
}

// childEnv is the caller's environment without Terraform, OpenTofu,
// checkpoint, compliance.tf or ctftest settings, plus the generated CLI
// config, the tap and the upstream. COMPLIANCETF_UPSTREAM_PATH names the
// upstream, which pinned discovery hashes and copies like a release build:
// with upstream "" it is the fake upstream, checked against the generated
// COMPLIANCETF_CONFORMANCE_PINS; otherwise against the embedded pins.json.
func childEnv(tap, evaluator, upstream string) []string {
	up := []string{"COMPLIANCETF_UPSTREAM_PATH=" + upstream}
	if upstream == "" {
		up = []string{
			"COMPLIANCETF_UPSTREAM_PATH=" + filepath.Join(binDir, "fakeupstream"),
			"COMPLIANCETF_CONFORMANCE_PINS=" + filepath.Join(binDir, "pins.json"),
		}
	}
	var env []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if !strings.HasPrefix(k, "TF_") && !strings.HasPrefix(k, "TOFU_") && !strings.HasPrefix(k, "CHECKPOINT_") &&
			!strings.HasPrefix(k, "COMPLIANCETF_") && !strings.HasPrefix(k, "CTFTEST_") {
			env = append(env, kv)
		}
	}
	rc := filepath.Join(binDir, "terraformrc")
	env = append(env,
		"TF_CLI_CONFIG_FILE="+rc, "TOFU_CLI_CONFIG_FILE="+rc,
		"CHECKPOINT_DISABLE=1", "TF_IN_AUTOMATION=1", "TF_INPUT=0",
		"COMPLIANCETF_CONFORMANCE_TAP="+tap,
	)
	env = append(env, up...)
	if evaluator != "" {
		env = append(env, "COMPLIANCETF_CONFORMANCE_EVALUATOR="+evaluator)
	}
	return env
}

// requireFake fails unless the proxy, run with the scenario's env in work,
// serves the fake upstream's schema: only test/fakeupstream defines
// fake_thing, so a proxy that found no upstream, or a real one, cannot pass.
func requireFake(t *testing.T, work string, env []string) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), *tfBin, "providers", "schema", "-json")
	cmd.Dir, cmd.Env = work, env
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	var sch struct {
		Providers map[string]struct {
			Resources map[string]json.RawMessage `json:"resource_schemas"`
		} `json:"provider_schemas"`
	}
	if err == nil {
		err = json.Unmarshal(out, &sch)
	}
	if err != nil {
		t.Fatalf("proxy did not reach the fake upstream: providers schema: %v\n%s", err, stderr.String())
	}
	if _, ok := sch.Providers[providerSource].Resources["fake_thing"]; !ok {
		t.Fatalf("proxy did not reach the fake upstream: %s schema has no fake_thing", providerSource)
	}
}

// readState returns terraform.tfstate without serial and lineage, or nil when
// the file does not exist.
func readState(dir string) (map[string]any, error) {
	b, err := os.ReadFile(filepath.Join(dir, "terraform.tfstate"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var st map[string]any
	if err := dec.Decode(&st); err != nil {
		return nil, fmt.Errorf("terraform.tfstate: %w", err)
	}
	delete(st, "serial")
	delete(st, "lineage")
	return st, nil
}

// privates maps each instance address (module, mode, type, name, index_key)
// to its non-empty private string. A scenario that ships terraform.tfstate
// must seed at least one and keep each byte-for-byte through every step
// (SDKv2 private data survives refresh and blocked applies).
func privates(st map[string]any) map[string]string {
	out := map[string]string{}
	rs, _ := st["resources"].([]any)
	for _, r := range rs {
		r, _ := r.(map[string]any)
		insts, _ := r["instances"].([]any)
		for _, in := range insts {
			in, _ := in.(map[string]any)
			if p, ok := in["private"].(string); ok && p != "" {
				out[fmt.Sprintf("%v %v %v.%v[%v]", r["module"], r["mode"], r["type"], r["name"], in["index_key"])] = p
			}
		}
	}
	return out
}

// checkTap fails on a tap write the proxy could not make (path+".failed"), on
// any apply whose returned new_state differs from upstream's, on any
// GetMetadata call from Core and on fewer applies than the scenario's expected
// apply count.
func checkTap(t *testing.T, path string, want int, none bool) {
	t.Helper()
	if err := tapFailed(path); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		if want > 0 {
			t.Fatalf("tap: no apply recorded, want >= %d", want)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	n, line := 0, 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line++
		apply, err := tapLine(sc.Bytes())
		if err != nil {
			t.Errorf("tap line %d: %v", line, err)
		}
		if apply {
			n++
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if none && n > 0 {
		t.Fatalf("tap: %d applies recorded, want none", n)
	}
	if n < want {
		t.Fatalf("tap: %d applies recorded, want >= %d", n, want)
	}
}

// tapFailed returns the tap writes the proxy recorded as failed, if any.
func tapFailed(path string) error {
	b, err := os.ReadFile(path + ".failed")
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("tap: the proxy failed to write tap lines, so the tap checks are incomplete:\n%s", b)
}

// getMetadataDrift is the failure for a GetMetadata call from Core: the
// accepted GetMetadata drift relies on no client reading the v5 response.
const getMetadataDrift = "Terraform/OpenTofu called GetMetadata as a client: re-check the accepted tfplugin5 GetMetadata.Response.actions drift " +
	"(field 8 in core, 9 in terraform-plugin-go and the bytes the proxy forwards) in internal/tfplugin/proto/drift-accepted.txt"

// tapLine checks one tap line and reports whether it is an apply.
func tapLine(b []byte) (bool, error) {
	var l struct {
		RPC      string `json:"rpc"`
		Type     string `json:"type"`
		Upstream string `json:"upstream_sha256"`
		Returned string `json:"returned_sha256"`
	}
	if err := json.Unmarshal(b, &l); err != nil {
		return false, err
	}
	switch {
	case l.RPC == "GetMetadata":
		return false, errors.New(getMetadataDrift)
	case l.RPC != "ApplyResourceChange" || l.Upstream == "" || l.Upstream != l.Returned:
		return l.RPC == "ApplyResourceChange", fmt.Errorf("%s %s new_state upstream %s, returned %s", l.RPC, l.Type, l.Upstream, l.Returned)
	}
	return true, nil
}

// TestTapLine: a GetMetadata line fails with the drift message and is no
// apply; apply lines count, and only matching hashes pass.
func TestTapLine(t *testing.T) {
	for _, c := range []struct {
		line, err string
		apply     bool
	}{
		{`{"rpc":"GetMetadata"}`, getMetadataDrift, false},
		{`{"rpc":"ApplyResourceChange","type":"fake_thing","upstream_sha256":"aa","returned_sha256":"aa"}`, "", true},
		{`{"rpc":"ApplyResourceChange","type":"fake_thing","upstream_sha256":"aa","returned_sha256":"bb"}`, "new_state upstream aa, returned bb", true},
		{`{"rpc":"ReadResource"}`, "ReadResource", false},
	} {
		apply, err := tapLine([]byte(c.line))
		if apply != c.apply || (err == nil) != (c.err == "") || (err != nil && !strings.Contains(err.Error(), c.err)) {
			t.Errorf("%s: apply %v, err %v; want %v, %q", c.line, apply, err, c.apply, c.err)
		}
	}
}

// TestTapFailed: a <tap>.failed record fails the tap check; none passes.
func TestTapFailed(t *testing.T) {
	tap := filepath.Join(t.TempDir(), "tap.jsonl")
	if err := tapFailed(tap); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tap+".failed", []byte("open tap.jsonl: is a directory\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := tapFailed(tap); err == nil || !strings.Contains(err.Error(), "is a directory") {
		t.Fatalf("tapFailed = %v", err)
	}
}

func strictUnmarshal(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
