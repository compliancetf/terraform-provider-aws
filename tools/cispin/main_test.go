package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testSchema = `{"provider_schemas": {"registry.terraform.io/hashicorp/aws": {"resource_schemas": {
  "aws_x": {"version": 0, "block": {"attributes": {
    "enc":   {"type": "bool", "optional": true},
    "mode":  {"type": "string", "optional": true, "computed": true},
    "rules": {"type": ["set", ["object", {"port": "number", "cidrs": ["list", "string"]}]], "optional": true, "computed": true}
  }, "block_types": {"cfg": {"nesting_mode": "list", "block": {"attributes": {
    "name": {"type": "string", "optional": true},
    "on":   {"type": "bool", "optional": true, "computed": true}
  }}}}}}}}}}`

func control(id, presence string, reads ...string) map[string]any {
	return map[string]any{
		"id": id, "version": "1.0.0", "kind": "resource", "resource_type": "aws_x",
		"reads": reads, "presence_mode": presence, "on": []string{"create", "update"},
		"expr": "true", "action": "deny", "severity": "high", "message": "m", "fix": "f",
	}
}

const testManifest = `{
  "provider": {"address": "registry.compliance.tf/compliancetf/aws", "version_range": "%s"},
  "upstream": {"source": "hashicorp/aws", "version_range": ">= 6.0.0, < 7.0.0"},
  "schema_compat_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
  "issued_at": "2026-10-06T00:00:00Z"
}
`

// setup writes cispin inputs to a temp dir: the repo pins.json, a provenance
// of provVersion, the test schema, controls and a manifest with the given
// provider range.
func setup(t *testing.T, provVersion, providerRange string, controls ...map[string]any) config {
	t.Helper()
	dir := t.TempDir()
	cfg := config{
		pins: "../../pins.json", provenance: filepath.Join(dir, "prov.json"), schema: filepath.Join(dir, "schema.json"),
		controls: filepath.Join(dir, "controls.json"), manifest: filepath.Join(dir, "manifest.json"), tsv: filepath.Join(dir, "compat.tsv"),
	}
	cj, err := json.Marshal(controls)
	if err != nil {
		t.Fatal(err)
	}
	for p, data := range map[string]string{
		cfg.provenance: `{"version": "` + provVersion + `"}`,
		cfg.schema:     testSchema,
		cfg.controls:   string(cj),
		cfg.manifest:   strings.Replace(testManifest, "%s", providerRange, 1),
	} {
		if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return cfg
}

func pinned(t *testing.T) string {
	t.Helper()
	v, err := pinnedVersion("../../pins.json")
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// TestRun: the type table lists each read once, sorted, with the computed
// flag of its top-level attribute; the manifest digest is sha256 of the first
// three columns, written in place; a second run changes nothing.
func TestRun(t *testing.T) {
	cfg := setup(t, pinned(t), ">= 6.0.0, < 7.0.0",
		control("ctl_a", "effective", "enc"),
		control("ctl_b", "configured", "mode", "rules", "rules.port"),
		control("ctl_c", "configured", "cfg", "cfg.name", "cfg.on", "enc"))
	changed, err := run(cfg)
	if err != nil || !changed {
		t.Fatalf("run: changed %v, err %v", changed, err)
	}
	want := "aws_x\tcfg\t[\"list\",[\"object\",{\"name\":\"string\",\"on\":\"bool\"}]]\tcomputed\n" +
		"aws_x\tcfg.name\t\"string\"\t-\n" +
		"aws_x\tcfg.on\t\"bool\"\tcomputed\n" +
		"aws_x\tenc\t\"bool\"\t-\n" +
		"aws_x\tmode\t\"string\"\tcomputed\n" +
		"aws_x\trules\t[\"set\",[\"object\",{\"cidrs\":[\"list\",\"string\"],\"port\":\"number\"}]]\tcomputed\n" +
		"aws_x\trules.port\t\"number\"\tcomputed\n"
	tsv, _ := os.ReadFile(cfg.tsv)
	if string(tsv) != want {
		t.Fatalf("type table:\n%s\nwant:\n%s", tsv, want)
	}
	var pre []string
	for _, l := range strings.Split(strings.TrimSuffix(want, "\n"), "\n") {
		pre = append(pre, l[:strings.LastIndex(l, "\t")])
	}
	sum := sha256.Sum256([]byte(strings.Join(pre, "\n")))
	m, _ := os.ReadFile(cfg.manifest)
	wantM := strings.Replace(strings.Replace(testManifest, "%s", ">= 6.0.0, < 7.0.0", 1),
		"sha256:"+strings.Repeat("0", 64), "sha256:"+hex.EncodeToString(sum[:]), 1)
	if string(m) != wantM {
		t.Errorf("manifest:\n%s\nwant:\n%s", m, wantM)
	}
	if changed, err := run(cfg); err != nil || changed {
		t.Errorf("second run: changed %v, err %v; want unchanged", changed, err)
	}
	if tsv2, _ := os.ReadFile(cfg.tsv); string(tsv2) != want {
		t.Error("second run rewrote the type table")
	}
}

// TestRunOwnerDecisions: inputs that need the owner fail and write nothing.
func TestRunOwnerDecisions(t *testing.T) {
	v := pinned(t)
	for name, tc := range map[string]struct {
		cfg   config
		want  string
		owner bool // reported as an owner decision (cispin: owner decision:)
	}{
		"stale schema":       {setup(t, "1.2.3", ">= 6.0.0, < 7.0.0", control("ctl_a", "effective", "enc")), "run scripts/capture-aws-schema.sh " + v, false},
		"outside range":      {setup(t, v, ">= 99.0.0, < 100.0.0", control("ctl_a", "effective", "enc")), `provider version_range ">= 99.0.0, < 100.0.0" does not admit ` + v, true},
		"read gone":          {setup(t, v, ">= 6.0.0, < 7.0.0", control("ctl_a", "effective", "gone")), "read aws_x.gone is not in the upstream schema", true},
		"computed block":     {setup(t, v, ">= 6.0.0, < 7.0.0", control("ctl_a", "effective", "cfg")), "ctl_a: read aws_x.cfg is Computed", true},
		"nested computed":    {setup(t, v, ">= 6.0.0, < 7.0.0", control("ctl_a", "effective", "cfg.on")), "ctl_a: read aws_x.cfg.on is Computed", true},
		"computed effective": {setup(t, v, ">= 6.0.0, < 7.0.0", control("ctl_a", "effective", "rules.port")), "ctl_a: read aws_x.rules.port is Computed: set presence_mode configured", true},
	} {
		t.Run(name, func(t *testing.T) {
			before, _ := os.ReadFile(tc.cfg.manifest)
			_, err := run(tc.cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v, want %q", err, tc.want)
			}
			var od ownerDecision
			if errors.As(err, &od) != tc.owner {
				t.Errorf("owner decision %v, want %v", !tc.owner, tc.owner)
			}
			if after, _ := os.ReadFile(tc.cfg.manifest); string(after) != string(before) {
				t.Error("manifest written")
			}
			if _, err := os.Stat(tc.cfg.tsv); !os.IsNotExist(err) {
				t.Errorf("type table written: %v", err)
			}
		})
	}
}

func TestInRange(t *testing.T) {
	for _, tc := range []struct {
		v, r string
		ok   bool
	}{
		{"6.67.0", ">= 6.0.0, < 7.0.0", true},
		{"6.0.0", ">= 6.0.0, < 7.0.0", true},
		{"7.0.0", ">= 6.0.0, < 7.0.0", false},
		{"5.99.0", ">= 6.0.0, < 7.0.0", false},
		{"6.67.0", ">= 6.67.0", true},
		{"6.67.0", "", false},
		{"6.67.0", ">= ", false},
		{"6.67.0", "~> 6.0", false},
		{"6.67.0", ">= 6.0.0-beta.1", false},
	} {
		if got := inRange(tc.v, tc.r); got != tc.ok {
			t.Errorf("inRange(%q, %q) = %v, want %v", tc.v, tc.r, got, tc.ok)
		}
	}
}

func TestSetDigest(t *testing.T) {
	d := "sha256:" + strings.Repeat("ab", 32)
	for _, bad := range []string{`{}`, `{"schema_compat_digest": "sha256:00", "x": 1}`,
		`{"schema_compat_digest": "sha256:` + strings.Repeat("0", 64) + `", "schema_compat_digest": "sha256:` + strings.Repeat("0", 64) + `"}`} {
		if _, err := setDigest([]byte(bad), d); err == nil {
			t.Errorf("setDigest(%s): no error", bad)
		}
	}
}

// TestRunBrokenManifestNotOwnerDecision: a manifest that does not parse fails
// as a broken input, not as an owner decision (the upstream watch workflow
// opens a draft PR only for owner decisions).
func TestRunBrokenManifestNotOwnerDecision(t *testing.T) {
	cfg := setup(t, pinned(t), ">= 6.0.0, < 7.0.0", control("ctl_a", "effective", "enc"))
	if err := os.WriteFile(cfg.manifest, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := run(cfg)
	var od ownerDecision
	if err == nil || errors.As(err, &od) {
		t.Fatalf("err %v: want a failure that is not an owner decision", err)
	}
}
