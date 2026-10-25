package bundlegen

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
)

// TestMergeBumps: an authored version_bump applies to every target of its
// id; bumps.yaml and an authored bump on one key must be identical
// (E_BUMP_CONFLICT otherwise); a bump for an id without authored controls
// is E_INPUT.
func TestMergeBumps(t *testing.T) {
	controls := map[string][]bundle.Control{"ctf_two": {
		testControl("ctf_two", "aws_db_instance", "true", bundle.PresenceEffective),
		testControl("ctf_two", "aws_rds_cluster", "true", bundle.PresenceEffective),
	}}
	major := Bump{Level: "major", From: "1.0.0"}
	k1, k2 := "ctf_two/resource/aws_db_instance", "ctf_two/resource/aws_rds_cluster"
	other := Bumps{"ctf_other/resource/aws_s3_bucket": {Level: "patch", From: "1.2.3"}}

	got, err := MergeBumps(other, map[string]Bump{"ctf_two": major}, controls)
	if err != nil {
		t.Fatal(err)
	}
	want := Bumps{k1: major, k2: major, "ctf_other/resource/aws_s3_bucket": other["ctf_other/resource/aws_s3_bucket"]}
	if !maps.Equal(got, want) || len(other) != 1 {
		t.Fatalf("merged %v, want %v; input changed: %v", got, want, other)
	}
	if got, err := MergeBumps(Bumps{k1: major}, map[string]Bump{"ctf_two": major}, controls); err != nil || !maps.Equal(got, Bumps{k1: major, k2: major}) {
		t.Fatalf("identical: %v %v", got, err)
	}
	for name, b := range map[string]Bump{"level": {Level: "minor", From: "1.0.0"}, "from": {Level: "major", From: "2.0.0"}} {
		if _, err := MergeBumps(Bumps{k2: b}, map[string]Bump{"ctf_two": major}, controls); errCode(err) != "E_BUMP_CONFLICT" || !strings.Contains(err.Error(), k2) {
			t.Errorf("%s differs: %v", name, err)
		}
	}
	// non-name values never reach the message
	if _, err := MergeBumps(Bumps{k1: {Level: "BOBTHECORP SECRET", From: "x y"}}, map[string]Bump{"ctf_two": major}, controls); errCode(err) != "E_BUMP_CONFLICT" ||
		strings.Contains(err.Error(), "BOBTHECORP") || strings.Contains(err.Error(), "x y") {
		t.Errorf("value-free: %v", err)
	}
	if _, err := MergeBumps(nil, map[string]Bump{"ctf_none": major}, controls); errCode(err) != "E_INPUT" {
		t.Errorf("no controls: %v", err)
	}
}

// TestLockGenerateAuthoredBump: Generate applies an authored version_bump
// like a bumps.yaml entry, and fails E_BUMP_CONFLICT when bumps.yaml names
// the same key with another bump.
func TestLockGenerateAuthoredBump(t *testing.T) {
	const id = "rds_bobthecorp_storage_encrypted"
	in := loadInputs(t, inputs, true)
	in.Lock = baseLock(t)
	for i := range in.Authored[id] {
		e := "resource.storage_encrypted != false"
		in.Authored[id][i].Expr = &e
	}
	in.AuthoredBumps = map[string]Bump{id: {Level: "major", From: "1.0.0"}}
	lock, err := ParseLock(generate(t, in)[LockFile])
	if err != nil {
		t.Fatal(err)
	}
	if v := lock[rdsKey].Version; v != "2.0.0" {
		t.Fatalf("%s: %s, want 2.0.0", rdsKey, v)
	}
	if in.Bumps, err = LoadBumps(filepath.Join(lockDir, "bumps.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(in, testOpts); err != nil {
		t.Fatalf("identical bumps.yaml entry: %v", err)
	}
	in.AuthoredBumps[id] = Bump{Level: "minor", From: "1.0.0"}
	if out, err := Generate(in, testOpts); errCode(err) != "E_BUMP_CONFLICT" || out != nil {
		t.Fatalf("conflicting bumps: %v", err)
	}
}

// TestGenerateVerify: Generate writes every bundle's cases with the schema
// field set, replays authored fixtures, and returns no output when verify
// reports a finding or a fixture does not convert.
func TestGenerateVerify(t *testing.T) {
	const id = "rds_bobthecorp_storage_encrypted"
	files := generate(t, loadInputs(t, inputs, true))
	k, ok := files["cis-aws/cases/"+id+"/resource.aws_db_instance.pass.json"]
	if !ok {
		t.Fatal("no authored pass case in cis-aws")
	}
	var c Case
	if err := decodeStrict(k, &c); err != nil {
		t.Fatal(err)
	}
	if c.Schema != testOpts.CaseSchema || c.Expect.UnknownPaths == nil || c.Control.Message == id {
		t.Errorf("case schema %q, unknown_paths %v, control message %q", c.Schema, c.Expect.UnknownPaths, c.Control.Message)
	}

	cases := map[string]struct {
		edit func(in *Inputs, o *Options)
		code string
	}{
		"flipped expect": {func(in *Inputs, _ *Options) {
			fx := slices.Clone(in.AuthoredFixtures[id])
			for i := range fx {
				fx[i].Expect.State = map[engine.State]engine.State{engine.Pass: engine.Fail, engine.Fail: engine.Pass}[fx[i].Expect.State]
			}
			in.AuthoredFixtures[id] = fx
		}, "E_FIXTURE_MISMATCH"},
		"no fixtures": {func(in *Inputs, _ *Options) { in.AuthoredFixtures = nil }, "E_FIXTURE_MISSING"},
		"provider not a string": {func(in *Inputs, _ *Options) {
			fx := slices.Clone(in.AuthoredFixtures[id])
			fx[0].Bindings.Provider = map[string]any{"account_id": 111111111111}
			in.AuthoredFixtures[id] = fx
		}, "E_FIXTURE"},
		"provider key": {func(in *Inputs, _ *Options) {
			fx := slices.Clone(in.AuthoredFixtures[id])
			fx[0].Bindings.Provider = map[string]any{"profile": "bobthecorp"}
			in.AuthoredFixtures[id] = fx
		}, "E_FIXTURE"},
		"no case schema":       {func(_ *Inputs, o *Options) { o.CaseSchema = "" }, "E_INPUT"},
		"absolute case schema": {func(_ *Inputs, o *Options) { o.CaseSchema = "/schemas/aws.json" }, "E_INPUT"},
		"dotdot case schema":   {func(_ *Inputs, o *Options) { o.CaseSchema = "../schemas/aws.json" }, "E_INPUT"},
		"unclean case schema":  {func(_ *Inputs, o *Options) { o.CaseSchema = "schemas/./aws.json" }, "E_INPUT"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			in, opts := loadInputs(t, inputs, true), testOpts
			tc.edit(&in, &opts)
			out, err := Generate(in, opts)
			if errCode(err) != tc.code || out != nil {
				t.Fatalf("err = %v, want %s and no output", err, tc.code)
			}
		})
	}
}

// TestReadOutputDir: a written output reads back byte-identical and verifies
// clean; a symlink in it fails E_SPECIAL_FILE.
func TestReadOutputDir(t *testing.T) {
	in := loadInputs(t, inputs, true)
	files := generate(t, in)
	dir := filepath.Join(t.TempDir(), "out")
	if err := (&Output{Files: files}).WriteDir(dir); err != nil {
		t.Fatal(err)
	}
	out, err := ReadOutputDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if bad := diffFiles(out.Files, files); bad != nil {
		t.Fatalf("read back differs: %v", bad)
	}
	rep, err := Verify(out, in.Schemas, VerifyEngine())
	if err != nil || len(rep.Findings) > 0 {
		t.Fatalf("verify: %v %v", rep.Findings, err)
	}
	if err := os.Symlink(filepath.Join(dir, "coverage.md"), filepath.Join(dir, "all", "link.md")); err != nil {
		t.Skip(err)
	}
	if _, err := ReadOutputDir(dir); errCode(err) != "E_SPECIAL_FILE" {
		t.Fatalf("symlink: %v", err)
	}
	// A symlinked output dir itself is refused, not followed.
	if err := os.Remove(filepath.Join(dir, "all", "link.md")); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "out-link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadOutputDir(link); errCode(err) != "E_SPECIAL_FILE" {
		t.Fatalf("symlinked root: %v", err)
	}
	if _, err := ReadOutputDir(dir); err != nil {
		t.Fatalf("real root: %v", err)
	}
}
