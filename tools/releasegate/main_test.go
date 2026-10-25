package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"

	"github.com/compliancetf/terraform-provider-aws/internal/upstream"
)

func info(tags string) *debug.BuildInfo {
	bi := &debug.BuildInfo{Settings: []debug.BuildSetting{{Key: "GOOS", Value: "linux"}}}
	if tags != "" {
		bi.Settings = append(bi.Settings, debug.BuildSetting{Key: "-tags", Value: tags})
	}
	return bi
}

// TestCheckTags: a release binary is built with no
// build tag at all, so test-only (conformance, ctftest), org-only (orgpin)
// and any future tag are refused.
func TestCheckTags(t *testing.T) {
	for _, tags := range []string{"conformance", "ctftest", "orgpin", "record", "netgo,ctftest", "orgpin,netgo", "netgo", "ctftestx"} {
		if err := checkTags(info(tags)); err == nil {
			t.Errorf("-tags=%s passed", tags)
		}
	}
	if err := checkTags(info("")); err != nil {
		t.Errorf("untagged build refused: %v", err)
	}
	if checkTags(nil) == nil {
		t.Error("missing build info passed")
	}
}

// TestCheckTagsBinary reads the -tags of a real binary: this test binary.
func TestCheckTagsBinary(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// make test builds with -tags ctftest, plain go test without: the gate
	// must read the same answer from the file as from the running binary.
	bi, _ := debug.ReadBuildInfo()
	_, err = checkBinary(exe)
	if got, want := err == nil, checkTags(bi) == nil; got != want {
		t.Errorf("checkBinary(%s) ok=%v, build info says ok=%v", exe, got, want)
	}
	if _, err := checkBinary(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("missing binary passed")
	}
}

func armoredKey(t *testing.T) ([]byte, string) {
	t.Helper()
	e, err := openpgp.NewEntity("bobthecorp", "", "release@bobthecorp.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Serialize(w); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), upstream.Fingerprint(e)
}

// TestCheckTree: the HashiCorp key must be committed
// with the pinned fingerprint, and no org pin may sit in a public tree.
func TestCheckTree(t *testing.T) {
	key, fp := armoredKey(t)
	setup := func(t *testing.T, key []byte, orgPin bool) string {
		root := t.TempDir()
		for _, d := range []string{"keys", "internal/trust"} {
			if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if key != nil {
			if err := os.WriteFile(filepath.Join(root, keyPath), key, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if orgPin {
			if err := os.WriteFile(filepath.Join(root, orgPinPath), []byte(`{}`), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return root
	}
	if err := checkTree(setup(t, key, false), fp); err != nil {
		t.Errorf("good tree refused: %v", err)
	}
	for name, c := range map[string]struct {
		root, fp, want string
	}{
		"no key":          {setup(t, nil, false), fp, "HashiCorp release key"},
		"wrong key":       {setup(t, key, false), upstream.HashiCorpFingerprint, "HashiCorp release key"},
		"not a key":       {setup(t, []byte("placeholder"), false), fp, "HashiCorp release key"},
		"org pin present": {setup(t, key, true), fp, "org_pin.json"},
	} {
		err := checkTree(c.root, c.fp)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v, want %q", name, err, c.want)
		}
	}
}

// TestGuardPassed: only a PASS line of TestReleaseGuard counts; a
// skip, a renamed test or no tests at all fail.
func TestGuardPassed(t *testing.T) {
	for out, want := range map[string]bool{
		"=== RUN   TestReleaseGuard\n--- PASS: TestReleaseGuard (0.00s)\nPASS\n":                                    true,
		"=== RUN   TestReleaseGuard\n--- SKIP: TestReleaseGuard (0.00s)\nPASS\n":                                    false,
		"--- PASS: TestReleaseGuardX (0.00s)\nPASS\n":                                                               false,
		"testing: warning: no tests to run\nPASS\n":                                                                 false,
		"=== RUN   TestReleaseGuard\n    main_test.go:49: main.go serves hook.Noop, not the compliance lifecycle\n": false,
	} {
		if got := guardPassed([]byte(out)); got != want {
			t.Errorf("guardPassed(%q) = %v, want %v", out, got, want)
		}
	}
}

// TestCheckVCS: a release binary must be built from the checked-out HEAD
// with no local change, so the tree checks speak for the shipped binary.
func TestCheckVCS(t *testing.T) {
	head := strings.Repeat("a", 40)
	vcs := func(rev, modified string) *debug.BuildInfo {
		bi := info("")
		for k, v := range map[string]string{"vcs.revision": rev, "vcs.modified": modified} {
			if v != "" {
				bi.Settings = append(bi.Settings, debug.BuildSetting{Key: k, Value: v})
			}
		}
		return bi
	}
	if err := checkVCS(vcs(head, "false"), head, ""); err != nil {
		t.Errorf("clean build refused: %v", err)
	}
	for name, c := range map[string]struct {
		bi     *debug.BuildInfo
		status string
	}{
		"modified build":   {vcs(head, "true"), ""},
		"other revision":   {vcs(strings.Repeat("b", 40), "false"), ""},
		"no vcs info":      {vcs("", ""), ""},
		"no modified flag": {vcs(head, ""), ""},
		"dirty tree now":   {vcs(head, "false"), " M keys/hashicorp-security.asc\n"},
	} {
		if checkVCS(c.bi, head, c.status) == nil {
			t.Errorf("%s passed", name)
		}
	}
}

// TestCheckEmbedsKey: the binary itself must carry the key bytes.
func TestCheckEmbedsKey(t *testing.T) {
	key := []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\nbobthecorp\n-----END PGP PUBLIC KEY BLOCK-----\n")
	if err := checkEmbedsKey(append(append([]byte("\x7fELF..."), key...), 0, 1), key); err != nil {
		t.Errorf("embedded key not found: %v", err)
	}
	if checkEmbedsKey([]byte("\x7fELF no key here"), key) == nil {
		t.Error("binary without the key passed")
	}
	if checkEmbedsKey(key, nil) == nil {
		t.Error("empty key passed")
	}
}

// TestGuardEnv: the guard test runs without the release secrets.
func TestGuardEnv(t *testing.T) {
	env := guardEnv([]string{"PATH=/bin", "GITHUB_TOKEN=x", "GH_TOKEN=x", "GPG_FINGERPRINT=y", "ACTIONS_RUNTIME_TOKEN=z",
		"COSIGN_PASSWORD=c", "AWS_SECRET_ACCESS_KEY=a", "HOME=/h", "GOFLAGS=-tags=conformance", "GOWORK=/w", "GOAUTH=x",
		"GOOGLE_APPLICATION_CREDENTIALS=/g", "GOCACHE=/c", "COMPLIANCETF_RELEASE_GUARD=0"})
	want := []string{"PATH=/bin", "HOME=/h", "GOCACHE=/c", "GOENV=off", "GOWORK=off", "GOFLAGS=", "GOTOOLCHAIN=local", "COMPLIANCETF_RELEASE_GUARD=1"}
	if strings.Join(env, " ") != strings.Join(want, " ") {
		t.Errorf("guardEnv = %v, want %v", env, want)
	}
}

// TestGuardEnvEffective runs go env under guardEnv, as checkEvaluator runs
// go test: a go env file and inherited GOFLAGS/GOWORK must not take effect.
func TestGuardEnvEffective(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "go.env")
	if err := os.WriteFile(cfg, []byte("GOFLAGS=-tags=conformance\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "env", "GOFLAGS", "GOWORK", "GOENV")
	cmd.Env = guardEnv(append(os.Environ(), "GOENV="+cfg, "GOFLAGS=-tags=ctftest", "GOWORK="+cfg))
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "\noff\n\n" { // GOFLAGS empty, GOWORK off, no env file
		t.Errorf("go env GOFLAGS GOWORK GOENV = %q, want GOFLAGS empty, GOWORK off, GOENV off (printed empty)", out)
	}
}
