// Command releasegate refuses a release build. .goreleaser.yml runs it as a
// build post hook on every binary it builds. Unlike the before hooks, which
// `--skip=before` drops, goreleaser cannot skip build hooks. Run from the repo
// root:
//
//	go run ./tools/releasegate [-snapshot] <binary>
//
// Always:
//   - the binary has no build tag (conformance, ctftest and orgpin builds
//     never ship publicly);
//
// Unless -snapshot (goreleaser --snapshot never publishes):
//   - the binary was built from the checked-out HEAD with no local change and
//     the tree is still clean, so the checks below speak for the binary;
//   - keys/hashicorp-security.asc holds the key with the
//     pinned fingerprint and the binary embeds those bytes, and
//     internal/trust/org_pin.json is absent (only the org pipeline
//     writes it);
//   - TestReleaseGuard passes with COMPLIANCETF_RELEASE_GUARD=1, so a build
//     serving anything but the compliance lifecycle, or whose keyring has no
//     bundle key to verify the embedded CIS bundle, does not ship.
package main

import (
	"bytes"
	"debug/buildinfo"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"slices"
	"strings"

	"github.com/compliancetf/terraform-provider-aws/internal/upstream"
)

const (
	keyPath    = "keys/hashicorp-security.asc"
	orgPinPath = "internal/trust/org_pin.json"
)

// checkTags allows no build tag at all: public releases are untagged, so
// conformance, ctftest, orgpin and any later tag are refused.
func checkTags(bi *debug.BuildInfo) error {
	if bi == nil {
		return errors.New("no build info")
	}
	for _, s := range bi.Settings {
		if s.Key == "-tags" && s.Value != "" {
			return fmt.Errorf("built with -tags=%s; public releases are built without build tags (conformance, ctftest and orgpin builds never ship)", s.Value)
		}
	}
	return nil
}

// guardVars is all of the caller's environment go test may see.
var guardVars = []string{"PATH", "HOME", "TMPDIR", "GOROOT", "GOPATH", "GOCACHE", "GOMODCACHE", "GOPROXY"}

// guardFixed pins what decides how the guard test compiles: no go env file
// (it could restore GOFLAGS), no workspace, no flags, the go.mod toolchain.
var guardFixed = []string{"GOENV=off", "GOWORK=off", "GOFLAGS=", "GOTOOLCHAIN=local", "COMPLIANCETF_RELEASE_GUARD=1"}

// guardEnv is the complete environment of the guard test: an allowlist of
// the caller's variables (no release secret reaches it) plus guardFixed.
func guardEnv(env []string) []string {
	out := []string{}
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		if slices.Contains(guardVars, k) {
			out = append(out, kv)
		}
	}
	return append(out, guardFixed...)
}

func checkBinary(path string) (*debug.BuildInfo, error) {
	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := checkTags(bi); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return bi, nil
}

// checkVCS binds the tree checks to the binary: it was built from head with
// no local change (Go stamps vcs.modified from git status, untracked files
// included), and the tree is still clean (status is git status --porcelain).
func checkVCS(bi *debug.BuildInfo, head, status string) error {
	vcs := map[string]string{}
	for _, s := range bi.Settings {
		vcs[s.Key] = s.Value
	}
	switch {
	case vcs["vcs.revision"] != head:
		return fmt.Errorf("binary built from revision %q, checkout is at %s", vcs["vcs.revision"], head)
	case vcs["vcs.modified"] != "false":
		return fmt.Errorf("binary vcs.modified=%q: build from a clean commit", vcs["vcs.modified"])
	case status != "":
		return fmt.Errorf("working tree changed after the build:\n%s", status)
	}
	return nil
}

// checkEmbedsKey requires the key bytes inside the binary (go:embed stores
// them verbatim).
func checkEmbedsKey(bin, key []byte) error {
	if len(key) == 0 || !bytes.Contains(bin, key) {
		return fmt.Errorf("binary does not embed %s", keyPath)
	}
	return nil
}

func vcsCmd(args ...string) (string, error) {
	out, err := exec.Command("git", args...).Output() //nolint:gosec // args are constants in run
	if err != nil {
		return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return string(out), nil
}

func checkTree(root, fingerprint string) error {
	key, err := os.ReadFile(filepath.Join(root, keyPath))
	if err == nil {
		_, err = upstream.LoadKey(key, fingerprint)
	}
	if err != nil {
		return fmt.Errorf("HashiCorp release key %s: %w (the binary must embed it; see keys/README)", keyPath, err)
	}
	if _, err := os.Lstat(filepath.Join(root, orgPinPath)); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%s is present: org-pinned builds come only from the org pipeline", orgPinPath)
	}
	return nil
}

var guardPass = regexp.MustCompile(`(?m)^--- PASS: TestReleaseGuard `)

// guardPassed requires the PASS line: a skipped, renamed or excluded test
// exits 0 too.
func guardPassed(out []byte) bool { return guardPass.Match(out) }

func checkEvaluator() error {
	cmd := exec.Command("go", "test", "-count=1", "-v", "-run", "^TestReleaseGuard$", ".")
	cmd.Env = guardEnv(os.Environ())
	out, err := cmd.CombinedOutput()
	if err != nil || !guardPassed(out) {
		return fmt.Errorf("TestReleaseGuard did not pass (%v):\n%s", err, bytes.TrimSpace(out))
	}
	return nil
}

func run(args []string) error {
	fs := flag.NewFlagSet("releasegate", flag.ContinueOnError)
	snapshot := fs.Bool("snapshot", false, "snapshot build: check the binary only")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: releasegate [-snapshot] <binary>")
	}
	bin := fs.Arg(0)
	bi, err := checkBinary(bin)
	if err != nil || *snapshot {
		return err
	}
	head, err := vcsCmd("rev-parse", "HEAD")
	if err != nil {
		return err
	}
	status, err := vcsCmd("status", "--porcelain")
	if err != nil {
		return err
	}
	if err := checkVCS(bi, strings.TrimSpace(head), status); err != nil {
		return fmt.Errorf("%s: %w", bin, err)
	}
	if err := checkTree(".", upstream.HashiCorpFingerprint); err != nil {
		return err
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(bin)
	if err != nil {
		return err
	}
	if err := checkEmbedsKey(data, key); err != nil {
		return fmt.Errorf("%s: %w", bin, err)
	}
	return checkEvaluator()
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "releasegate:", err)
		os.Exit(1)
	}
}
