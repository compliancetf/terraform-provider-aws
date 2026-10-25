//go:build conformance

// Package harness is the shared end-to-end harness of the verdict and
// baseline conformance suites (test/conformance/verdict,
// test/conformance/baseline): real Terraform or OpenTofu (-tf) plans and
// applies through the proxy (built with -tags conformance,ctftest) in front
// of test/fakeupstream, under bundles and profiles signed with the ctftest
// keys, plus an in-repo stand-in for ctfkit gate plan and gate sign
// (gate.go). A suite's TestMain calls Main.
package harness

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
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/upstream"
	"github.com/compliancetf/terraform-provider-aws/internal/verdict"
	"github.com/compliancetf/terraform-provider-aws/internal/verdict/verdicttest"
)

// ProviderSource is the proxy's provider address.
const ProviderSource = "registry.compliance.tf/compliancetf/aws"

// FakeUpstreamVersion is the version the fake upstream is pinned at.
const FakeUpstreamVersion = "0.0.0"

// awsSource is the upstream the fake pins name.
var awsSource = func() upstream.Source {
	s, err := upstream.ParseSource("registry.terraform.io/hashicorp/aws")
	if err != nil {
		panic(err)
	}
	return s
}()

var (
	tfBin = flag.String("tf", "", "terraform or tofu binary under test (required)")
	_     = flag.Bool("update", false, "accepted for make conformance UPDATE=1; nothing here is a golden")
)

// binDir holds the proxy, the fake upstream, ctfbundle and the CLI config.
var binDir string

// Main is a suite's TestMain: it requires -tf, builds the binaries into a
// temp dir named with prefix, runs the tests and removes the dir.
func Main(m *testing.M, prefix string) {
	flag.Parse()
	if *tfBin == "" {
		fmt.Fprintln(os.Stderr, "conformance: -tf <terraform or tofu binary> is required")
		os.Exit(2)
	}
	bin, err := exec.LookPath(*tfBin)
	if err == nil {
		*tfBin, err = filepath.Abs(bin)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "conformance: -tf:", err)
		os.Exit(2)
	}
	dir, err := os.MkdirTemp("", prefix)
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
		if err := os.RemoveAll(dir); err != nil {
			fmt.Fprintln(os.Stderr, "conformance cleanup:", err)
		}
	}
	os.Exit(code)
}

// setup builds the proxy, the fake upstream and ctfbundle into dir, pins the
// fake upstream and writes a CLI config whose dev_overrides point the
// proxy's source at dir (as test/conformance does). The working directory
// is a suite's package dir, three levels below the repo root.
func setup(dir string) error {
	root := filepath.Join("..", "..", "..")
	for _, b := range []struct {
		wd, out string
		args    []string
	}{
		{root, "terraform-provider-aws", []string{"-tags", "conformance,ctftest", "."}},
		{filepath.Join(root, "test", "fakeupstream"), "fakeupstream", []string{"./v5"}},
		{root, "ctfbundle", []string{"-tags", "ctftest", "./cmd/ctfbundle"}},
	} {
		args := append([]string{"build", "-o", filepath.Join(dir, b.out)}, b.args...)
		cmd := exec.Command("go", args...) //nolint:gosec // a fixed go build of this repo's packages
		cmd.Dir = b.wd
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("go %s: %w\n%s", strings.Join(args, " "), err, out)
		}
	}
	b, err := os.ReadFile(filepath.Join(dir, "fakeupstream"))
	if err != nil {
		return err
	}
	sum := sha256.Sum256(b)
	h := hex.EncodeToString(sum[:])
	pins, err := upstream.MarshalPins(&upstream.Pins{
		Format: upstream.PinsFormat, Upstream: awsSource.String(), Version: FakeUpstreamVersion, Protocol: upstream.PinsProtocol,
		SigningKeyFingerprint: upstream.HashiCorpFingerprint, SHA256SumsSHA256: h,
		Platforms: map[string]upstream.PlatformPin{runtime.GOOS + "_" + runtime.GOARCH: {
			Zip: awsSource.ZipName(FakeUpstreamVersion, runtime.GOOS, runtime.GOARCH), ZipSHA256: h,
			Binary: awsSource.BinaryName(FakeUpstreamVersion, runtime.GOOS, upstream.PinsProtocol), BinarySHA256: h,
		}},
	})
	if err == nil {
		err = os.WriteFile(filepath.Join(dir, "pins.json"), pins, 0o600)
	}
	if err != nil {
		return err
	}
	rc := fmt.Sprintf("provider_installation {\n  dev_overrides {\n    %q = %q\n  }\n  direct {\n    exclude = [\"registry.compliance.tf/*/*\"]\n  }\n}\n", ProviderSource, dir)
	return os.WriteFile(filepath.Join(dir, "terraformrc"), []byte(rc), 0o600)
}

// Run is one scenario's work dir and child environment. Env is a plain
// slice: a test may append to it, later entries win (exec keeps the last
// value of a key).
type Run struct {
	T    *testing.T
	Work string
	Env  []string
}

// NewRun is a Run in a fresh work dir with the child environment.
func NewRun(t *testing.T) *Run {
	return &Run{T: t, Work: t.TempDir(), Env: childEnv()}
}

// childEnv is the caller's environment without Terraform, OpenTofu,
// checkpoint, compliance.tf, ctftest or AWS settings, plus the generated CLI
// config and the pinned fake upstream. The user's CLI config is never read.
func childEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if !strings.HasPrefix(k, "TF_") && !strings.HasPrefix(k, "TOFU_") && !strings.HasPrefix(k, "CHECKPOINT_") &&
			!strings.HasPrefix(k, "COMPLIANCETF_") && !strings.HasPrefix(k, "CTFTEST_") && !strings.HasPrefix(k, "AWS_") {
			env = append(env, kv)
		}
	}
	rc := filepath.Join(binDir, "terraformrc")
	return append(env, "TF_CLI_CONFIG_FILE="+rc, "TOFU_CLI_CONFIG_FILE="+rc, "CHECKPOINT_DISABLE=1", "TF_IN_AUTOMATION=1", "TF_INPUT=0",
		"COMPLIANCETF_UPSTREAM_PATH="+filepath.Join(binDir, "fakeupstream"),
		"COMPLIANCETF_CONFORMANCE_PINS="+filepath.Join(binDir, "pins.json"),
		"COMPLIANCETF_CONFORMANCE_EVALUATOR=lifecycle")
}

// Result is one terraform command's outcome.
type Result struct {
	Exit           int
	Stdout, Stderr string
}

// TF runs the binary under test in the work dir with r.Env.
func (r *Run) TF(args ...string) Result {
	r.T.Helper()
	cmd := exec.CommandContext(r.T.Context(), *tfBin, args...) //nolint:gosec // the -tf binary under test
	cmd.Dir, cmd.Env = r.Work, r.Env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	res := Result{}
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			r.T.Fatalf("%v: %v", args, err)
		}
		res.Exit = ee.ExitCode()
	}
	res.Stdout, res.Stderr = stdout.String(), stderr.String()
	return res
}

// Must runs TF and fails the test unless it exits 0.
func (r *Run) Must(args ...string) Result {
	r.T.Helper()
	res := r.TF(args...)
	if res.Exit != 0 {
		r.T.Fatalf("%v: exit %d\n--- stdout\n%s--- stderr\n%s", args, res.Exit, res.Stdout, res.Stderr)
	}
	return res
}

// Decode decodes s into v with numbers as json.Number.
func (r *Run) Decode(s string, v any) {
	r.T.Helper()
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		r.T.Fatalf("decode: %v\n%s", err, s)
	}
}

// State is terraform.tfstate decoded without serial and lineage, nil when
// absent.
func (r *Run) State() map[string]any {
	r.T.Helper()
	b, err := os.ReadFile(filepath.Join(r.Work, "terraform.tfstate"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	var st map[string]any
	if err == nil {
		err = json.Unmarshal(b, &st)
	}
	if err != nil {
		r.T.Fatal(err)
	}
	delete(st, "serial")
	delete(st, "lineage")
	return st
}

// Sign writes verdict.json and ctfkit-run.key for b signed by k (a key the
// profile need not list) under the work dir's gate dir and points
// COMPLIANCETF_VERDICT and COMPLIANCETF_VERDICT_KEY_FILE at them.
func (r *Run) Sign(k verdicttest.Key, b verdicttest.Binding) (verdictPath, keyPath string) {
	r.T.Helper()
	dir := filepath.Join(r.Work, "gate")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		r.T.Fatal(err)
	}
	verdictPath, keyPath = verdicttest.Write(r.T, dir, k, b)
	r.Env = append(r.Env, verdict.EnvVerdict+"="+verdictPath, verdict.EnvKeyFile+"="+keyPath)
	return verdictPath, keyPath
}

// Records calls fn with each evidence record line of the .jsonl files under
// dir, decoded into a fresh T (a line that does not decode is skipped).
func Records[T any](t testing.TB, dir string, fn func(T)) {
	t.Helper()
	var files []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".jsonl") {
			files = append(files, p)
		}
		return err
	})
	for _, p := range files {
		if err != nil {
			break
		}
		var b []byte
		if b, err = os.ReadFile(p); err != nil {
			break
		}
		sc := bufio.NewScanner(bytes.NewReader(b))
		sc.Buffer(nil, 1<<24)
		for sc.Scan() {
			var rec T
			if json.Unmarshal(sc.Bytes(), &rec) == nil {
				fn(rec)
			}
		}
		err = sc.Err()
	}
	if err != nil {
		t.Fatalf("evidence %s: %v", dir, err)
	}
}

// Loaded is the binding the provider loaded, read from the configure
// evidence records under dir (a plan is enough; no verdict needed): the
// profile, bundle and content digests and the wrapper and upstream
// versions, issued now.
func Loaded(t testing.TB, dir string) verdicttest.Binding {
	t.Helper()
	var b verdicttest.Binding
	Records(t, dir, func(rec struct {
		Digests *struct {
			Bundle, Content, Profile *string
		} `json:"digests"`
		Provider *struct {
			Version         string `json:"version"`
			UpstreamVersion string `json:"upstream_version"`
		} `json:"provider"`
	}) {
		if rec.Digests == nil || rec.Provider == nil || rec.Digests.Bundle == nil || rec.Digests.Content == nil || rec.Digests.Profile == nil {
			return
		}
		b.ProfileDigest, b.BundleDigest, b.ContentDigest = *rec.Digests.Profile, *rec.Digests.Bundle, *rec.Digests.Content
		b.Wrapper, b.Upstream = strings.TrimPrefix(rec.Provider.Version, "v"), strings.TrimPrefix(rec.Provider.UpstreamVersion, "v")
	})
	if b.BundleDigest == "" {
		t.Fatalf("no configure evidence record with digests under %s: run a plan first", dir)
	}
	b.OrgID, b.IssuedAt = "bobthecorp", time.Now().UTC().Truncate(time.Second)
	return b
}

// Ctfbundle runs the ctftest ctfbundle built by Main.
func Ctfbundle(t testing.TB, args ...string) {
	t.Helper()
	if out, err := exec.CommandContext(t.Context(), filepath.Join(binDir, "ctfbundle"), args...).CombinedOutput(); err != nil { //nolint:gosec // the ctfbundle Main built
		t.Fatalf("ctfbundle %v: %v\n%s", args, err, out)
	}
}

// Payload is base with over merged (nil deletes); an issued_at or
// expires_at given as a Go duration is relative to now.
func Payload(t testing.TB, now time.Time, base, over map[string]any) []byte {
	t.Helper()
	m := maps.Clone(base)
	for k, v := range over {
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	for _, k := range []string{"issued_at", "expires_at"} {
		if s, ok := m[k].(string); ok {
			if d, err := time.ParseDuration(s); err == nil {
				m[k] = now.Add(d).Format(time.RFC3339)
			}
		}
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// BaseManifest is the bundle manifest the suites sign, before overrides.
func BaseManifest() map[string]any {
	return map[string]any{"format": "compliancetf.bundle-manifest/v2", "bundle_id": "bobthecorp-fake", "bundle_version": 3,
		"label": "2026.10.8", "org_id": "bobthecorp", "profile": "fake",
		"catalog":              map[string]any{"snapshot_id": "snap_20261008_000000_000000", "schema_version": "1"},
		"provider":             map[string]any{"address": ProviderSource, "version_range": ">= 2.0.0, < 3.0.0"},
		"upstream":             map[string]any{"source": "hashicorp/aws", "version_range": ">= 6.0.0, < 7.0.0"},
		"schema_compat_digest": "sha256:" + hex.EncodeToString(make([]byte, 32)),
		"issued_at":            "-1h", "expires_at": "720h", "min_bundle_version": 0, "min_profile_version": 0}
}

// BaseProfile is the profile the suites sign, before overrides.
func BaseProfile() map[string]any {
	return map[string]any{"format": "compliancetf.profile/v1", "org_id": "bobthecorp", "profile_version": 5,
		"issued_at": "-1h", "expires_at": "696h", "governed": false,
		"mode_floor":       map[string]any{"default": "hard_fail"},
		"verdict_required": false, "exceptions": map[string]any{"max_lifetime_days": 30},
		"evidence": map[string]any{"required": false, "sinks": []any{}},
		"budgets":  map[string]any{"per_resource_ms": 200, "per_run_s": 120}}
}
