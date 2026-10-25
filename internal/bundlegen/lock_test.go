package bundlegen

import (
	"errors"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
)

const lockDir = "testdata/lock"

const (
	rdsKey = "rds_bobthecorp_storage_encrypted/resource/aws_db_instance"
	s3Key  = "s3_bobthecorp_versioning_on/resource/aws_s3_bucket_versioning"
	iamKey = "iam_bobthecorp_no_kms_wildcard/resource/aws_iam_policy"
)

// lockControls are the synthetic authored controls in ControlKey order.
func lockControls(t *testing.T) []bundle.Control {
	t.Helper()
	in := loadInputs(t, inputs, true)
	var cs []bundle.Control
	for _, id := range slices.Sorted(maps.Keys(in.Authored)) {
		cs = append(cs, in.Authored[id]...)
	}
	return cs
}

func baseLock(t *testing.T) Lock {
	t.Helper()
	l, err := LoadLock(filepath.Join(lockDir, LockFile))
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func versionOf(cs []bundle.Control, key string) string {
	for i := range cs {
		if keyOf(&cs[i]).String() == key {
			return cs[i].Version
		}
	}
	return ""
}

func errCode(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// TestLock: unchanged digests keep the version; a changed expr,
// reads or action/on/presence_mode needs a bump whose from is the locked
// version (E_VERSION_BUMP_MISSING otherwise); patch only when no digest
// changed (E_VERSION_BUMP_LEVEL); stale bumps are inert; removed controls
// keep their lock entry.
func TestLock(t *testing.T) {
	setRDS := func(f func(*bundle.Control)) func([]bundle.Control) {
		return func(cs []bundle.Control) {
			for i := range cs {
				if keyOf(&cs[i]).String() == rdsKey {
					f(&cs[i])
				}
			}
		}
	}
	newExpr := func(c *bundle.Control) { e := "resource.storage_encrypted == true && true"; c.Expr = &e }
	cases := []struct {
		name    string
		edit    func([]bundle.Control)
		bumps   Bumps
		code    string // expected error code, "" for success
		msg     string // substring of the error
		version string // rds version on success
	}{
		{name: "unchanged", edit: func([]bundle.Control) {}, version: "1.0.0"},
		{name: "expr changed without bump", edit: setRDS(newExpr), code: "E_VERSION_BUMP_MISSING", msg: rdsKey + ": expr changed since 1.0.0"},
		{name: "expr changed major", edit: setRDS(newExpr), bumps: Bumps{rdsKey: {"major", "1.0.0"}}, version: "2.0.0"},
		{name: "expr changed minor", edit: setRDS(newExpr), bumps: Bumps{rdsKey: {"minor", "1.0.0"}}, version: "1.1.0"},
		{name: "expr changed empty level", edit: setRDS(newExpr), bumps: Bumps{rdsKey: {"", "1.0.0"}}, code: "E_BUMP"},
		{name: "expr changed typo level", edit: setRDS(newExpr), bumps: Bumps{rdsKey: {"majr", "1.0.0"}}, code: "E_BUMP"},
		{name: "expr changed patch", edit: setRDS(newExpr), bumps: Bumps{rdsKey: {"patch", "1.0.0"}}, code: "E_VERSION_BUMP_LEVEL", msg: "patch is for message"},
		{name: "expr changed stale bump", edit: setRDS(newExpr), bumps: Bumps{rdsKey: {"major", "0.9.0"}}, code: "E_VERSION_BUMP_MISSING"},
		{name: "reads changed", edit: setRDS(func(c *bundle.Control) { c.Reads = append(c.Reads, "kms_key_id") }), code: "E_VERSION_BUMP_MISSING", msg: "reads changed"},
		{name: "reads duplicated", edit: setRDS(func(c *bundle.Control) { c.Reads = []string{"storage_encrypted", "storage_encrypted"} }), version: "1.0.0"},
		{name: "action warn to deny", edit: setRDS(func(c *bundle.Control) { c.Action = bundle.ActionWarn }), code: "E_VERSION_BUMP_MISSING", msg: "action/on/presence_mode changed"},
		{name: "on changed", edit: setRDS(func(c *bundle.Control) { c.On = []bundle.On{bundle.OnCreate} }), code: "E_VERSION_BUMP_MISSING"},
		{name: "on reordered", edit: setRDS(func(c *bundle.Control) { c.On = []bundle.On{bundle.OnUpdate, bundle.OnCreate} }), version: "1.0.0"},
		{name: "presence_mode changed", edit: setRDS(func(c *bundle.Control) { c.PresenceMode = bundle.PresenceConfigured }), code: "E_VERSION_BUMP_MISSING"},
		{name: "message only", edit: setRDS(func(c *bundle.Control) { c.Message = "new text"; c.Fix = "new fix" }), version: "1.0.0"},
		{name: "message with patch", edit: setRDS(func(c *bundle.Control) { c.Message = "new text" }), bumps: Bumps{rdsKey: {"patch", "1.0.0"}}, version: "1.0.1"},
		{name: "coverable and severity are not locked", edit: setRDS(func(c *bundle.Control) {
			c.ExemptionCoverable = []bundle.ExemptionKind{"grant"}
			c.Severity = bundle.SeverityHigh
		}), version: "1.0.0"},
		{name: "stale bump unchanged", edit: func([]bundle.Control) {}, bumps: Bumps{rdsKey: {"major", "0.9.0"}}, version: "1.0.0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cs := lockControls(t)
			tc.edit(cs)
			got, lock, err := ApplyLock(baseLock(t), tc.bumps, cs)
			if tc.code != "" {
				if errCode(err) != tc.code || !strings.Contains(err.Error(), tc.msg) {
					t.Fatalf("err %v, want %s containing %q", err, tc.code, tc.msg)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if v := versionOf(got, rdsKey); v != tc.version || lock[rdsKey].Version != v {
				t.Fatalf("rds version %q (lock %q), want %q", v, lock[rdsKey].Version, tc.version)
			}
			if v := versionOf(got, s3Key); v != "1.0.0" {
				t.Fatalf("untouched control moved to %q", v)
			}
			// The bumped lock read back with the same bumps is a fixed point.
			again, lock2, err := ApplyLock(lock, tc.bumps, cs)
			if err != nil || versionOf(again, rdsKey) != tc.version || !maps.Equal(lock, lock2) {
				t.Fatalf("rerun with the new lock: %v, version %q", err, versionOf(again, rdsKey))
			}
		})
	}
}

// TestLockFresh: a nil lock starts every control at 1.0.0 whatever version
// the authored control carries, bumps for unknown keys are inert, and a
// removed control keeps its entry (no version reuse on re-add).
func TestLockFresh(t *testing.T) {
	cs := lockControls(t)
	for i := range cs {
		cs[i].Version = "7.0.0"
	}
	got, lock, err := ApplyLock(nil, Bumps{rdsKey: {"major", "1.0.0"}}, cs)
	if err != nil {
		t.Fatal(err)
	}
	for i := range got {
		if got[i].Version != "1.0.0" {
			t.Fatalf("%s: %s, want 1.0.0", got[i].ID, got[i].Version)
		}
	}
	if !maps.Equal(lock, baseLock(t)) {
		t.Fatal("fresh lock differs from testdata/lock/content-lock.json")
	}

	kept := slices.DeleteFunc(slices.Clone(cs), func(c bundle.Control) bool { return keyOf(&c).String() == iamKey })
	_, next, err := ApplyLock(lock, nil, kept)
	if err != nil || next[iamKey] != lock[iamKey] {
		t.Fatalf("removed control: %v, entry %+v", err, next[iamKey])
	}
	if _, _, err := ApplyLock(nil, nil, append(cs, cs[0])); errCode(err) != "E_LOCK" {
		t.Fatalf("duplicate key: %v", err)
	}
}

// TestLockGenerate: Generate applies --lock and --bumps (testdata/lock),
// stamps the versions into controls.json and emits the new
// content-lock.json; without the bump the same change fails.
func TestLockGenerate(t *testing.T) {
	in := loadInputs(t, inputs, true)
	in.Lock = baseLock(t)
	var err error
	if in.Bumps, err = LoadBumps(filepath.Join(lockDir, "bumps.yaml")); err != nil {
		t.Fatal(err)
	}
	// The rds bump is major: change its expr. The s3 bump is a patch with
	// no digest change.
	for i := range in.Authored["rds_bobthecorp_storage_encrypted"] {
		e := "resource.storage_encrypted != false"
		in.Authored["rds_bobthecorp_storage_encrypted"][i].Expr = &e
	}
	files := generate(t, in)
	lock, err := ParseLock(files[LockFile])
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{rdsKey: "2.0.0", s3Key: "1.0.1", iamKey: "1.0.0"}
	for k, v := range want {
		if lock[k].Version != v {
			t.Fatalf("%s: lock %s, want %s", k, lock[k].Version, v)
		}
	}
	cs, err := bundle.DecodeControls(files["soc2-aws/controls.json"])
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range want {
		if got := versionOf(cs, k); got != v {
			t.Fatalf("controls.json %s: %s, want %s", k, got, v)
		}
	}
	// Without the bump the same change fails.
	in.Bumps = nil
	if _, err := Generate(in, testOpts); errCode(err) != "E_VERSION_BUMP_MISSING" {
		t.Fatalf("no bump: %v", err)
	}
}

// TestLockOrder: ApplyLock's first error does not depend on the order of
// distinct ControlKeys in the input.
func TestLockOrder(t *testing.T) {
	cs := lockControls(t)
	rev := slices.Clone(cs)
	slices.Reverse(rev)
	if len(cs) < 3 || keyOf(&cs[0]) == keyOf(&rev[0]) {
		t.Fatal("need at least three distinct keys in a different order")
	}

	// Every control misses a bump: the error names the first key in
	// ControlKey order (iam) whatever the input order (s3 first in rev).
	base := baseLock(t)
	for _, in := range [][]bundle.Control{cs, rev} {
		in = slices.Clone(in)
		for i := range in {
			e := *in[i].Expr + " && true"
			in[i].Expr = &e
		}
		_, _, err := ApplyLock(base, nil, in)
		if errCode(err) != "E_VERSION_BUMP_MISSING" || !strings.Contains(err.Error(), iamKey) {
			t.Fatalf("first input key %s: %v", keyOf(&in[0]), err)
		}
	}
}

// TestParseLockBumps: malformed lock and bumps inputs fail E_LOCK / E_BUMP.
func TestParseLockBumps(t *testing.T) {
	good := `{"a/resource/t": {"expr_digest": "` + "sha256:" + strings.Repeat("0", 64) + `", "reads_digest": "sha256:` + strings.Repeat("1", 64) + `", "semantics_digest": "sha256:` + strings.Repeat("2", 64) + `", "version": "1.2.3"}}`
	if _, err := ParseLock([]byte(good)); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{
		"not object":     `[]`,
		"null":           `null`,
		"trailing":       good + `{}`,
		"trailing delim": `{}]`,
		"duplicate key":  strings.Replace(good, `{"a/resource/t"`, `{"a/resource/t": {}, "a/resource/t"`, 1),
		"unknown field":  strings.Replace(good, `"version"`, `"extra": 1, "version"`, 1),
		"case digest":    strings.Replace(good, `"version"`, `"EXPR_DIGEST": "sha256:`+strings.Repeat("f", 64)+`", "version"`, 1),
		"case version":   strings.Replace(good, `"version": "1.2.3"`, `"Version": "9.9.9", "version": "1.2.3"`, 1),
		"case only":      strings.Replace(good, `"expr_digest"`, `"Expr_Digest"`, 1),
		"entry not obj":  `{"a/resource/t": 1}`,
		"bad key":        strings.Replace(good, "a/resource/t", "a/resource", 1),
		"empty part":     strings.Replace(good, "a/resource/t", "a//t", 1),
		"bad version":    strings.Replace(good, "1.2.3", "1.2", 1),
		"bad digest":     strings.Replace(good, "sha256:"+strings.Repeat("0", 64), "sha256:00", 1),
		"missing digest": strings.Replace(good, `"semantics_digest": "sha256:`+strings.Repeat("2", 64)+`", `, "", 1),
	} {
		if _, err := ParseLock([]byte(data)); errCode(err) != "E_LOCK" {
			t.Errorf("%s: %v, want E_LOCK", name, err)
		}
	}

	if b, err := ParseBumps([]byte("# none\n")); err != nil || len(b) != 0 {
		t.Fatalf("empty bumps: %v %v", b, err)
	}
	for name, data := range map[string]string{
		"bad level":      "a/resource/t: {level: huge, from: 1.0.0}\n",
		"missing from":   "a/resource/t: {level: major}\n",
		"bad from":       "a/resource/t: {level: major, from: v1}\n",
		"unknown field":  "a/resource/t: {level: major, from: 1.0.0, why: x}\n",
		"bad key":        "a: {level: major, from: 1.0.0}\n",
		"duplicate":      "a/resource/t: {level: major, from: 1.0.0}\na/resource/t: {level: minor, from: 1.0.0}\n",
		"multi document": "a/resource/t: {level: major, from: 1.0.0}\n---\nb/resource/t: {level: major, from: 1.0.0}\n",
	} {
		if _, err := ParseBumps([]byte(data)); errCode(err) != "E_BUMP" {
			t.Errorf("%s: %v, want E_BUMP", name, err)
		}
	}

	if _, err := LoadLock(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Fatal("missing lock file must fail")
	}
	if _, err := bumpVersion("9223372036854775807.0.0", "major"); err == nil {
		t.Fatal("overflow must fail")
	}
	if _, err := bumpVersion("1.0.0", ""); err == nil {
		t.Fatal("unknown level must fail")
	}
}

// TestLockGraph: a graph control has no expr, so its graph
// object is digested into expr_digest. A changed graph needs a bump, an
// unchanged one keeps the version, and the lock member set and the digests
// of non-graph controls do not change.
func TestLockGraph(t *testing.T) {
	ce := "companion.status == \"Enabled\""
	graph := func() bundle.Control {
		return bundle.Control{
			ID: "s3_bucket_versioning_companion", Kind: bundle.KindGraph, ResourceType: "aws_s3_bucket",
			Action: bundle.ActionDeny, Severity: bundle.SeverityHigh, Message: "m",
			Graph: &bundle.Graph{
				Rule: bundle.GraphCompanionPresent, CompanionType: "aws_s3_bucket_versioning",
				LinkAttr: "bucket", TargetAttrs: []string{"id", "bucket"}, CompanionExpr: &ce,
			},
		}
	}
	const key = "s3_bucket_versioning_companion/graph/aws_s3_bucket"
	_, prev, err := ApplyLock(baseLock(t), nil, append(lockControls(t), graph()))
	if err != nil {
		t.Fatal(err)
	}
	if prev[key].Version != "1.0.0" || prev[key].ExprDigest == bundle.DigestRaw(nil) {
		t.Fatalf("graph entry %+v: want 1.0.0 with a graph expr_digest", prev[key])
	}
	base := baseLock(t)
	for k, e := range base {
		if prev[k] != e {
			t.Errorf("%s: entry %+v, was %+v", k, prev[k], e)
		}
	}
	other := "companion.status == \"Suspended\""
	for _, tc := range []struct {
		name    string
		edit    func(*bundle.Graph)
		bumps   Bumps
		version string // "" for E_VERSION_BUMP_MISSING
	}{
		{"unchanged", func(*bundle.Graph) {}, nil, "1.0.0"},
		{"rule changed", func(g *bundle.Graph) { g.Rule = bundle.GraphCompanionAbsentForbidden }, nil, ""},
		{"rule changed major", func(g *bundle.Graph) { g.Rule = bundle.GraphCompanionAbsentForbidden }, Bumps{key: {"major", "1.0.0"}}, "2.0.0"},
		{"companion_type changed", func(g *bundle.Graph) { g.CompanionType = "aws_s3_bucket_logging" }, nil, ""},
		{"link_attr changed", func(g *bundle.Graph) { g.LinkAttr = "id" }, nil, ""},
		{"target_attrs reordered", func(g *bundle.Graph) { g.TargetAttrs = []string{"bucket", "id"} }, nil, ""},
		{"companion_expr changed", func(g *bundle.Graph) { g.CompanionExpr = &other }, nil, ""},
		{"companion_expr removed", func(g *bundle.Graph) { g.CompanionExpr = nil }, nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := graph()
			tc.edit(g.Graph)
			got, _, err := ApplyLock(prev, tc.bumps, append(lockControls(t), g))
			if tc.version == "" {
				if errCode(err) != "E_VERSION_BUMP_MISSING" || !strings.Contains(err.Error(), key+": expr changed") {
					t.Fatalf("err %v, want E_VERSION_BUMP_MISSING for %s", err, key)
				}
				return
			}
			if err != nil || versionOf(got, key) != tc.version {
				t.Fatalf("err %v, version %q, want %q", err, versionOf(got, key), tc.version)
			}
		})
	}
}
