//go:build ctftest

package lifecycle

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/baseline"
)

// TestConfigureBaselineKey: Configure reads COMPLIANCETF_BASELINE_KEY_FILE
// once. Unset: no read key. A usable key: Configure keeps those bytes (the
// same slice baseline.Load gets) even when the file changes afterwards. An
// unusable key without a baseline file warns and keeps no read key; with
// a baseline file it fails Configure as before.
func TestConfigureBaselineKey(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "baseline.key")
	if err := os.WriteFile(good, []byte(strings.Repeat("ab", 32)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "short.key")
	if err := os.WriteFile(bad, []byte("abab\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const noDigest = ": evidence records carry no read_digest"
	run := func(t *testing.T, keyFile string, block map[string]string, profiles map[string]json.RawMessage) (*Configured, []string, error) {
		t.Helper()
		if block == nil {
			block = map[string]string{}
		}
		return runConfigure(t, configureCase{Block: block, Profiles: profiles, Env: map[string]string{baseline.EnvKeyFile: keyFile, baseline.EnvFile: ""}})
	}
	t.Run("unset", func(t *testing.T) {
		cfg, warns, err := run(t, "", nil, nil)
		if err != nil || cfg.readKey != nil || slices.ContainsFunc(warns, func(w string) bool { return strings.HasSuffix(w, noDigest) }) {
			t.Fatalf("err %v, key %x, warnings %q", err, cfg.readKey, warns)
		}
	})
	t.Run("usable key, read once", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("the baseline key file loads only on unix (internal/verdict file_other.go)")
		}
		cfg, _, err := run(t, good, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(good, []byte(strings.Repeat("cd", 32)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(cfg.readKey, bytes.Repeat([]byte{0xab}, 32)) {
			t.Fatalf("key %x, want the bytes read at Configure", cfg.readKey)
		}
	})
	t.Run("unusable key without a baseline file", func(t *testing.T) {
		cfg, warns, err := run(t, bad, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		want := baseline.ErrKeyUnusable.Error() + noDigest
		if cfg.readKey != nil || !slices.Contains(warns, want) {
			t.Fatalf("key %x, warnings %q, want %q", cfg.readKey, warns, want)
		}
	})
	t.Run("unusable key with a baseline file", func(t *testing.T) {
		block := map[string]string{"org_id": "bobthecorp", "baseline_file": filepath.Join(dir, "baseline.json")}
		profiles := map[string]json.RawMessage{"env": json.RawMessage(`{"baseline": {}}`)}
		_, _, err := run(t, bad, block, profiles)
		if !errors.Is(err, baseline.ErrKeyUnusable) || !strings.HasSuffix(err.Error(), ": grandfather cannot be evaluated") {
			t.Fatalf("err %v, want the unusable key error failing Configure", err)
		}
	})
}
