//go:build conformance

package conformance

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestLifecycle runs lifecycle/<name> with the 0B lifecycle:
// destroy under hard_fail, unknown-then-known, replace-unknown, apply_post,
// refresh drift and envelope_mutation. NewState byte equality is the tap
// check every scenario runs.
func TestLifecycle(t *testing.T) { runTrustDir(t, "lifecycle") }

// TestDataSource runs datasource/<name> with the lifecycle: data
// source enforcement is advisory by default and deny is opt-in, raise only,
// from the provider HCL or the signed profile.
func TestDataSource(t *testing.T) { runTrustDir(t, "datasource") }

// TestAntirollback runs antirollback/<name> on an empty
// COMPLIANCETF_STATE_DIR: missing, expired and older-still-valid profiles and
// bundles fail Configure, and so does a governed run without a floor.
func TestAntirollback(t *testing.T) { runTrustDir(t, "antirollback") }

func runTrustDir(t *testing.T, dir string) {
	c, banner, err := detectCell(*tfBin)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("cell %s: %s", c.Name, banner)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatalf("no scenarios in %s", dir)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		t.Run(e.Name(), func(t *testing.T) { runScenario(t, c, filepath.Join(dir, e.Name()), "", writeTrust, nil) })
	}
}

// trustFixture is a scenario's trust.json: each present member is merged
// over its base payload (null deletes a field), signed with the ctftest key
// of its purpose and written to the work dir as profile.dsse.json,
// floor.dsse.json or bundle.tar.gz (with the scenario's controls.json, else
// defaultControls, and its iam-actions.json if present). An issued_at or expires_at given as a Go duration is
// relative to now, so the signed artifacts are fresh on every run.
type trustFixture struct {
	Profile map[string]any `json:"profile"`
	Floor   map[string]any `json:"floor"`
	Bundle  map[string]any `json:"bundle"`
}

func writeTrust(t *testing.T, work string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(work, "trust.json"))
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	var f trustFixture
	if err == nil {
		err = strictUnmarshal(b, &f)
	}
	if err != nil {
		t.Fatalf("trust.json: %v", err)
	}
	if _, err := os.Stat(filepath.Join(work, "iam-actions.json")); err == nil && f.Bundle == nil {
		t.Fatal("iam-actions.json: the scenario ships a catalog but trust.json has no bundle to sign it into")
	}
	now := time.Now().UTC().Truncate(time.Second)
	if f.Bundle != nil {
		src := filepath.Join(work, "bundle-src")
		controls, err := os.ReadFile(filepath.Join(work, "controls.json"))
		if errors.Is(err, fs.ErrNotExist) {
			controls, err = []byte(defaultControls), nil
		}
		if err == nil {
			err = os.MkdirAll(src, 0o700)
		}
		if err == nil {
			err = os.WriteFile(filepath.Join(src, "controls.json"), controls, 0o600)
		}
		// A scenario iam-actions.json goes into the signed bundle as its
		// IAM action catalog.
		if cat, rerr := os.ReadFile(filepath.Join(work, "iam-actions.json")); err == nil && rerr == nil {
			err = os.WriteFile(filepath.Join(src, "iam-actions.json"), cat, 0o600)
		} else if err == nil && !errors.Is(rerr, fs.ErrNotExist) {
			err = rerr
		}
		if err == nil {
			err = os.WriteFile(filepath.Join(src, "manifest.json"), payload(t, now, baseManifest(), f.Bundle), 0o600)
		}
		if err != nil {
			t.Fatal(err)
		}
		ctfbundle(t, "build", "-src", src, "-key", "test:bundle", "-out", filepath.Join(work, "bundle.tar.gz"))
	}
	for _, p := range []struct {
		kind string
		base map[string]any
		over map[string]any
	}{{"profile", baseProfile(), f.Profile}, {"floor", baseFloor(), f.Floor}} {
		if p.over == nil {
			continue
		}
		in := filepath.Join(work, p.kind+".json")
		if err := os.WriteFile(in, payload(t, now, p.base, p.over), 0o600); err != nil {
			t.Fatal(err)
		}
		ctfbundle(t, "sign", "-type", p.kind, "-in", in, "-key", "test:"+p.kind, "-out", filepath.Join(work, p.kind+".dsse.json"))
	}
}

// defaultControls deny a fake_thing size above 10 on create and update.
const defaultControls = `[{"id": "fake_thing_size_max", "version": "1.0.0", "kind": "resource", "resource_type": "fake_thing",
  "reads": ["size"], "presence_mode": "effective", "on": ["create", "update"],
  "expr": "resource.size != null && resource.size <= 10", "action": "deny", "severity": "high",
  "message": "fake_thing size must be at most 10.", "fix": "Set size to 10 or less.", "exemption_coverable": []}]`

func ctfbundle(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.CommandContext(t.Context(), filepath.Join(binDir, "ctfbundle"), args...).CombinedOutput(); err != nil {
		t.Fatalf("ctfbundle %v: %v\n%s", args, err, out)
	}
}

func payload(t *testing.T, now time.Time, base, over map[string]any) []byte {
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

func baseManifest() map[string]any {
	return map[string]any{"format": "compliancetf.bundle-manifest/v2", "bundle_id": "bobthecorp-fake", "bundle_version": 3,
		"label": "2026.10.8", "org_id": "bobthecorp", "profile": "fake",
		"catalog":              map[string]any{"snapshot_id": "snap_20261008_000000_000000", "schema_version": "1"},
		"provider":             map[string]any{"address": providerSource, "version_range": ">= 2.0.0, < 3.0.0"},
		"upstream":             map[string]any{"source": "hashicorp/aws", "version_range": ">= 6.0.0, < 7.0.0"},
		"schema_compat_digest": "sha256:" + hex.EncodeToString(make([]byte, 32)),
		"issued_at":            "-1h", "expires_at": "720h", "min_bundle_version": 0, "min_profile_version": 0}
}

func baseProfile() map[string]any {
	return map[string]any{"format": "compliancetf.profile/v1", "org_id": "bobthecorp", "profile_version": 5,
		"issued_at": "-1h", "expires_at": "696h", "governed": false,
		"mode_floor":       map[string]any{"default": "hard_fail"},
		"verdict_required": false, "exceptions": map[string]any{"max_lifetime_days": 30},
		"evidence": map[string]any{"required": false, "sinks": []any{}},
		"budgets":  map[string]any{"per_resource_ms": 200, "per_run_s": 120}}
}

func baseFloor() map[string]any {
	return map[string]any{"format": "compliancetf.floor/v1", "org_id": "bobthecorp", "min_profile_version": 0,
		"bundles": map[string]any{}, "min_wrapper_version": "", "keyring_digest": ctftestKeyringDigest(),
		"epoch": 1, "revocation_epoch": 0, "retired_keys": []string{}, "issued_at": "-1h", "expires_at": "23h"}
}

// ctftestKeyringDigest is the keyring digest of the ctftest proxy build,
// computed as internal/trust/embed_ctftest.go does (this test binary is not
// built with ctftest, so trust.KeyringDigest would name the release keyring).
func ctftestKeyringDigest() string {
	h := sha256.New()
	h.Write([]byte("compliancetf.keyring-digest/ctftest\x00"))
	for _, name := range []string{"keyring.json", "keyring_test.json"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "internal", "trust", name))
		if err != nil {
			panic(err) // the repo is the test's working tree
		}
		h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(b))))
		h.Write(b)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}
