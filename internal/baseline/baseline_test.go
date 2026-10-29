package baseline

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
	"github.com/compliancetf/terraform-provider-aws/internal/verdict"
	"github.com/compliancetf/terraform-provider-aws/internal/verdict/verdicttest"
)

var (
	now     = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	content = "sha256:" + strings.Repeat("c", 64)
	keyHex  = strings.Repeat("ab", 32)
	expr    = "self.acl == 'private'"
	ctl     = bundle.Control{ID: "s3_acl_private", Version: "2.1.0", Kind: bundle.KindResource, ResourceType: "aws_s3_bucket",
		Reads: []string{"acl", "versioning.enabled"}, Expr: &expr, Action: bundle.ActionDeny, Severity: bundle.SeverityHigh,
		Message: "m", ExemptionCoverable: []bundle.ExemptionKind{bundle.CoverBaseline}}
	objType = tftypes.Object{AttributeTypes: map[string]tftypes.Type{"id": tftypes.String, "acl": tftypes.String, "secret": tftypes.String,
		"versioning": tftypes.Object{AttributeTypes: map[string]tftypes.Type{"enabled": tftypes.Bool}}}}
	schema = &tfprotov5.Schema{Block: &tfprotov5.SchemaBlock{
		Attributes: []*tfprotov5.SchemaAttribute{{Name: "id"}, {Name: "acl"}, {Name: "secret", Sensitive: true}},
		BlockTypes: []*tfprotov5.SchemaNestedBlock{{TypeName: "versioning", Nesting: tfprotov5.SchemaNestedBlockNestingModeSingle,
			Block: &tfprotov5.SchemaBlock{Attributes: []*tfprotov5.SchemaAttribute{{Name: "enabled"}}}}}}}
)

func bucket(acl any, id string) tftypes.Value {
	return tftypes.NewValue(objType, map[string]tftypes.Value{"id": tftypes.NewValue(tftypes.String, id),
		"acl": tftypes.NewValue(tftypes.String, acl), "secret": tftypes.NewValue(tftypes.String, "s3cr3t"),
		"versioning": tftypes.NewValue(objType.AttributeTypes["versioning"], map[string]tftypes.Value{"enabled": tftypes.NewValue(tftypes.Bool, false)})})
}

type fixture struct {
	dir                string
	prof               *profile.Profile
	blKey, rcKey       verdicttest.Key
	entry              Entry
	keyPath, filePath  string
	revs               trust.Revocations
	coverableBaselines bool
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the baseline key file loads only on unix (internal/verdict file_other.go)")
	}
	f := &fixture{dir: t.TempDir(), revs: trust.NoRevocations(), coverableBaselines: true}
	f.blKey, f.rcKey = verdicttest.NewKey(t, now.Add(-24*time.Hour)), verdicttest.NewKey(t, now.Add(-24*time.Hour))
	f.blKey.Signer.Use, f.rcKey.Signer.Use = verdict.UseBaseline, verdict.UseReceipt
	f.prof = &profile.Profile{OrgID: "bobthecorp", Baseline: &profile.Baseline{PublicKeys: []profile.SignerKey{f.blKey.Signer}, MaxDays: 90},
		BreakGlass: &profile.BreakGlass{ReceiptKeys: []profile.SignerKey{f.rcKey.Signer}}}
	raw, err := os.ReadFile("testdata/entry.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &f.entry); err != nil {
		t.Fatal(err)
	}
	key, _ := hex.DecodeString(keyHex)
	d, ok := ReadDigest(key, ctl.Reads, bucket("public-read", "bkt-1"))
	m, err := digestJSON(&ctl)
	if !ok || err != nil {
		t.Fatal("fixture digests")
	}
	f.entry.ReadDigest, f.entry.ControlManifestDigest, f.entry.Expires = d, m, now.Add(30*24*time.Hour).Format(time.RFC3339)
	f.keyPath, f.filePath = filepath.Join(f.dir, "baseline.key"), filepath.Join(f.dir, "baseline.json")
	if err := os.WriteFile(f.keyPath, []byte(keyHex+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

// sign returns v signed by k: v's signature member is replaced.
func sign(t *testing.T, k verdicttest.Key, v any) json.RawMessage {
	t.Helper()
	b, _ := json.Marshal(v)
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	delete(m, "signature")
	sig, _ := json.Marshal(verdicttest.Signature(t, k.Priv, k.Signer.KID, m))
	m["signature"] = sig
	out, _ := json.Marshal(m)
	return out
}

// load signs the statement and the document with entries and loads them.
func (f *fixture) load(t *testing.T, mutate func(*Document)) (*Set, error) {
	t.Helper()
	e := f.entry
	e.ApproverStatement = Statement{Format: StatementFormat, OrgID: "bobthecorp", Role: RoleApprover, Subject: e.Approver, Workspace: e.Workspace,
		Scope: e.Scope, RunID: "run-obs-1", PlanDigest: "sha256:" + strings.Repeat("d", 64), ContentDigest: content, IssuedAt: now.Add(-time.Hour).Format(time.RFC3339)}
	var st Statement
	if err := json.Unmarshal(sign(t, f.rcKey, e.ApproverStatement), &st); err != nil {
		t.Fatal(err)
	}
	e.ApproverStatement = st
	doc := Document{Format: Format, OrgID: "bobthecorp", IssuedAt: now.Add(-time.Hour).Format(time.RFC3339), ContentDigest: content, Entries: []Entry{e}}
	if mutate != nil {
		mutate(&doc)
	}
	if err := os.WriteFile(f.filePath, sign(t, f.blKey, doc), 0o644); err != nil {
		t.Fatal(err)
	}
	key, keyErr := ReadKey(f.keyPath)
	return Load(LoadInput{Path: f.filePath, Key: key, KeyErr: keyErr, Profile: f.prof, Revocations: f.revs,
		Coverable: func(string) bool { return f.coverableBaselines }, Now: now})
}

func (f *fixture) instance(t *testing.T, s *Set) Instance {
	t.Helper()
	d := s.digests[0]
	return Instance{OrgID: "bobthecorp", Workspace: "prod", Address: "aws_s3_bucket.logs", Action: "no-op", Refreshed: "true",
		Listed: []string{d}, Matched: []string{d}, AccountID: "111111111111", Region: "us-east-1", Type: "aws_s3_bucket",
		IdentityKind: "id", Prior: bucket("public-read", "bkt-1"), Planned: bucket("public-read", "bkt-1"), Schema: schema, Now: now}
}

func revocations(t *testing.T, epoch int64, body string) trust.Revocations {
	t.Helper()
	r, err := trust.ParseRevocations(fmt.Appendf(nil, `{"format":"compliancetf.revocations/v1","epoch":%d,"revoked_keys":[%s],"revoked_bundles":[],"revoked_controls":[]}`, epoch, body))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestMatch covers the acceptance cases: each mutation of a matching
// instance either keeps or loses the grandfathering.
func TestMatch(t *testing.T) {
	type tc struct {
		name   string
		mutate func(*fixture, *Instance, *bundle.Control)
		want   bool
		reason string
	}
	cases := []tc{
		{"match", func(*fixture, *Instance, *bundle.Control) {}, true, ""},
		{"value changed", func(_ *fixture, in *Instance, _ *bundle.Control) {
			in.Prior, in.Planned = bucket("private-x", "bkt-1"), bucket("private-x", "bkt-1")
		}, false, ""},
		{"planned read differs", func(_ *fixture, in *Instance, _ *bundle.Control) { in.Planned = bucket("private", "bkt-1") }, false, ""},
		{"major bump", func(_ *fixture, _ *Instance, c *bundle.Control) { c.Version = "3.0.0" }, false,
			"baseline entry for s3_acl_private approved at major 2, bundle has 3: re-baseline"},
		{"control input changed", func(_ *fixture, _ *Instance, c *bundle.Control) { c.Message = "changed" }, false, ""},
		{"expired", func(_ *fixture, in *Instance, _ *bundle.Control) { in.Now = now.Add(31 * 24 * time.Hour) }, false, ""},
		{"unknown", func(_ *fixture, in *Instance, _ *bundle.Control) {
			in.Planned = bucket(tftypes.UnknownValue, "bkt-1")
		}, false, ""},
		{"not refreshed", func(_ *fixture, in *Instance, _ *bundle.Control) { in.Refreshed = "false" }, false, ""},
		{"not listed for the instance", func(_ *fixture, in *Instance, _ *bundle.Control) { in.Listed = nil }, false, ""},
		{"not listed at the top level", func(_ *fixture, in *Instance, _ *bundle.Control) { in.Matched = nil }, false, ""},
		{"unattested move", func(_ *fixture, in *Instance, _ *bundle.Control) { in.Address = "aws_s3_bucket.moved" }, false, ""},
		{"attested move", func(_ *fixture, in *Instance, _ *bundle.Control) {
			in.Address, in.PreviousAddress, in.Action = "aws_s3_bucket.moved", "aws_s3_bucket.logs", "move"
		}, true, ""},
		{"import", func(_ *fixture, in *Instance, _ *bundle.Control) { in.Action = "import" }, false, ""},
		{"identity changed", func(_ *fixture, in *Instance, _ *bundle.Control) { in.Prior = bucket("public-read", "bkt-2") }, false, ""},
		{"identity kind differs", func(_ *fixture, in *Instance, _ *bundle.Control) {
			in.IdentityKind, in.PriorIdentity = "identity", json.RawMessage(`{"id":"bkt-1"}`)
		}, false, ""},
		{"other scope", func(_ *fixture, in *Instance, _ *bundle.Control) { in.Region = "eu-west-1" }, false, ""},
		{"other workspace", func(_ *fixture, in *Instance, _ *bundle.Control) { in.Workspace = "dev" }, false, ""},
		{"other org", func(_ *fixture, in *Instance, _ *bundle.Control) { in.OrgID = "other" }, false, ""},
		{"no schema", func(_ *fixture, in *Instance, _ *bundle.Control) { in.Schema = nil }, false, ""},
		{"sensitive read", func(_ *fixture, _ *Instance, c *bundle.Control) { c.Reads = []string{"acl", "secret"} }, false, ""},
		{"not coverable", func(f *fixture, _ *Instance, _ *bundle.Control) { f.coverableBaselines = false }, false, ""},
		{"floor advance only", func(f *fixture, _ *Instance, _ *bundle.Control) { f.revs = revocations(t, 7, "") }, true, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			c2, in := ctl, Instance{}
			c.mutate(f, &in, &c2) // fixture-level mutations first
			s, err := f.load(t, nil)
			if err != nil {
				t.Fatal(err)
			}
			base := f.instance(t, s)
			c.mutate(f, &base, &c2)
			got := s.Grandfathered(&c2, base)
			if got.Grandfathered != c.want || got.Reason != c.reason || got.Grandfathered && got.Entry != s.digests[0] {
				t.Errorf("got %+v, want %v %q", got, c.want, c.reason)
			}
		})
	}
}

// TestRevoked: a revocation of the baseline signing key at the current
// epoch fails Configure; a revoked control at its major stops matching with
// the normative reason.
func TestRevoked(t *testing.T) {
	f := newFixture(t)
	f.revs = revocations(t, 4, `{"kid":"`+f.blKey.Signer.KID+`","revoked_at":"2026-10-01T00:00:00Z"}`)
	if _, err := f.load(t, nil); err == nil || !strings.Contains(err.Error(), "kid revoked") {
		t.Fatalf("revoked baseline key: %v", err)
	}
	f = newFixture(t)
	r, err := trust.ParseRevocations([]byte(`{"format":"compliancetf.revocations/v1","epoch":5,"revoked_keys":[],"revoked_bundles":[],"revoked_controls":[{"id":"s3_acl_private","version":2}]}`))
	if err != nil {
		t.Fatal(err)
	}
	f.revs = r
	s, err := f.load(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := s.Grandfathered(&ctl, f.instance(t, s))
	if want := "baseline entry " + s.digests[0] + " revoked at epoch 5"; got.Grandfathered || got.Reason != want {
		t.Fatalf("got %+v, want %q", got, want)
	}
}

// TestLoad: every document-level failure fails Configure; no file is a no-op.
func TestLoad(t *testing.T) {
	if s, err := Load(LoadInput{}); s != nil || err != nil {
		t.Fatalf("no file: %v %v", s, err)
	}
	f := newFixture(t)
	if _, err := f.load(t, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(LoadInput{Path: f.filePath, Profile: f.prof, Revocations: f.revs, Now: now}); err == nil || err.Error() != ErrNoKey {
		t.Fatalf("missing key: %v", err)
	}
	cases := map[string]func(*fixture, *Document){
		"wrong org": func(_ *fixture, d *Document) { d.OrgID = "other" },
		"beyond max_days": func(_ *fixture, d *Document) {
			d.Entries[0].Expires = now.Add(100 * 24 * time.Hour).Format(time.RFC3339)
		},
		"no approver":                  func(_ *fixture, d *Document) { d.Entries[0].Approver = "" },
		"approver mismatch":            func(_ *fixture, d *Document) { d.Entries[0].Approver = "mallory@bobthecorp.example" },
		"statement scope":              func(_ *fixture, d *Document) { d.Entries[0].Scope.Region = "eu-west-1" },
		"statement role":               func(_ *fixture, d *Document) { d.Entries[0].ApproverStatement.Role = "admin" },
		"statement content":            func(_ *fixture, d *Document) { d.ContentDigest = "sha256:" + strings.Repeat("e", 64) },
		"bad major":                    func(_ *fixture, d *Document) { d.Entries[0].ControlMajor = "v2" },
		"empty identity":               func(_ *fixture, d *Document) { d.Entries[0].Identity = map[string]string{"id": ""} },
		"wrong format":                 func(_ *fixture, d *Document) { d.Format = "compliancetf.baseline/v2" },
		"issued before the key window": func(_ *fixture, d *Document) { d.IssuedAt = now.Add(-48 * time.Hour).Format(time.RFC3339) },
		"issued in the future":         func(_ *fixture, d *Document) { d.IssuedAt = now.Add(time.Hour).Format(time.RFC3339) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			if _, err := f.load(t, func(d *Document) { mutate(f, d) }); err == nil {
				t.Fatal("loaded")
			}
		})
	}
	t.Run("profile without baseline keys", func(t *testing.T) {
		f := newFixture(t)
		f.prof.Baseline = nil
		if _, err := f.load(t, nil); err == nil || !strings.Contains(err.Error(), "lists no baseline keys") {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("signed by a verdict key", func(t *testing.T) {
		f := newFixture(t)
		f.blKey.Signer.Use = verdict.UseVerdict
		f.prof.Baseline.PublicKeys[0].Use = verdict.UseVerdict
		if _, err := f.load(t, nil); err == nil || !strings.Contains(err.Error(), "baseline signature invalid") {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("tampered after signing", func(t *testing.T) {
		f := newFixture(t)
		if _, err := f.load(t, nil); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(f.filePath)
		b = []byte(strings.Replace(string(b), "aws_s3_bucket.logs", "aws_s3_bucket.other", 1))
		_ = os.WriteFile(f.filePath, b, 0o644)
		key, _ := ReadKey(f.keyPath)
		if _, err := Load(LoadInput{Path: f.filePath, Key: key, Profile: f.prof, Revocations: f.revs, Now: now}); err == nil {
			t.Fatal("tampered baseline loaded")
		}
	})
	t.Run("key bytes from the caller", func(t *testing.T) {
		// Load never reads the key file: the set matches with the bytes
		// Configure read once, even after the file is rotated.
		f := newFixture(t)
		if _, err := f.load(t, nil); err != nil {
			t.Fatal(err)
		}
		key, err := ReadKey(f.keyPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f.keyPath, []byte(strings.Repeat("cd", 32)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		s, err := Load(LoadInput{Path: f.filePath, Key: key, Profile: f.prof, Revocations: f.revs, Now: now})
		if err != nil || !bytes.Equal(s.key, key) {
			t.Fatalf("err %v, set key %x, want %x", err, s.key, key)
		}
	})
	t.Run("key file readable by others", func(t *testing.T) {
		f := newFixture(t)
		if err := os.Chmod(f.keyPath, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := f.load(t, nil); !errors.Is(err, ErrKeyUnusable) || !strings.HasSuffix(err.Error(), ": grandfather cannot be evaluated") || strings.Contains(err.Error(), f.dir) {
			t.Fatalf("err %v", err)
		}
	})
}

// TestReadDigest: keyed, survives an unrelated attribute change, fails on a
// read change, an unknown read or a path into a non-object.
func TestReadDigest(t *testing.T) {
	key, _ := hex.DecodeString(keyHex)
	a, _ := ReadDigest(key, ctl.Reads, bucket("private", "bkt-1"))
	b, _ := ReadDigest(key, ctl.Reads, bucket("private", "bkt-2"))
	c, _ := ReadDigest(key, ctl.Reads, bucket("public-read", "bkt-1"))
	other, _ := ReadDigest([]byte(strings.Repeat("x", 32)), ctl.Reads, bucket("private", "bkt-1"))
	if a == "" || a != b || a == c || a == other {
		t.Fatalf("digests %s %s %s %s", a, b, c, other)
	}
	if _, ok := ReadDigest(key, ctl.Reads, bucket(tftypes.UnknownValue, "bkt-1")); ok {
		t.Fatal("unknown read digested")
	}
	if _, ok := ReadDigest(key, []string{"acl.x"}, bucket("private", "bkt-1")); ok {
		t.Fatal("path into a string digested")
	}
	if d, ok := ReadDigest(key, []string{"acl"}, bucket(nil, "bkt-1")); !ok || d == a {
		t.Fatal("null read")
	}
}

// TestNumberText pins the instance_key format v1 number vectors.
func TestNumberText(t *testing.T) {
	for in, want := range map[string]string{"0.1": "0.1", "1e21": "1000000000000000000000", "-0": "0", "9223372036854775808": "9223372036854775808",
		"18446744073709551617": "18446744073709551617", "1234567.5": "1.2345675e+06", "0.00001": "1e-05",
		"10e1000": "", "1e-1001": "", "1e-999": "1e-999", strings.Repeat("9", 202) + "e-1202": ""} {
		n, _, err := big.ParseFloat(in, 10, 4096, big.ToNearestEven)
		if err != nil {
			t.Fatal(err)
		}
		if got, ok := numberText(n); got != want || ok != (want != "") {
			t.Errorf("%s: %q %v, want %q", in, got, ok, want)
		}
	}
}

// TestHashTree: sets are order independent, lists are not, a null map
// value stays null, and numbers, bools and nested containers hash.
func TestHashTree(t *testing.T) {
	k := []byte(strings.Repeat("k", 32))
	str := func(s ...string) []tftypes.Value {
		out := []tftypes.Value{}
		for _, x := range s {
			out = append(out, tftypes.NewValue(tftypes.String, x))
		}
		return out
	}
	set := func(s ...string) tftypes.Value {
		return tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, str(s...))
	}
	list := func(s ...string) tftypes.Value {
		return tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, str(s...))
	}
	j := func(v tftypes.Value) string {
		h, ok := hashTree(k, v)
		b, _ := json.Marshal(h)
		if !ok {
			return "!"
		}
		return string(b)
	}
	if j(set("a", "b")) != j(set("b", "a")) || j(list("a", "b")) == j(list("b", "a")) {
		t.Fatal("set or list order")
	}
	m := tftypes.NewValue(tftypes.Map{ElementType: tftypes.Number}, map[string]tftypes.Value{
		"n": tftypes.NewValue(tftypes.Number, big.NewFloat(1.5)), "z": tftypes.NewValue(tftypes.Number, nil)})
	if got := j(m); !strings.HasPrefix(got, `{"n":"`) || !strings.HasSuffix(got, `"z":null}`) {
		t.Fatalf("map %s", got)
	}
	if j(tftypes.NewValue(tftypes.Bool, true)) == j(tftypes.NewValue(tftypes.Bool, false)) {
		t.Fatal("bool")
	}
	if j(tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, []tftypes.Value{tftypes.NewValue(tftypes.String, tftypes.UnknownValue)})) != "!" {
		t.Fatal("unknown element hashed")
	}
}

// TestIdentity: kind identity drops null members and needs one; an
// identity schema mismatch or a non-string member never matches.
func TestIdentity(t *testing.T) {
	id, ok := instanceIdentity(Instance{IdentityKind: "identity", PriorIdentity: json.RawMessage(`{"bucket":"b","region":null}`)})
	if !ok || len(id) != 1 || id["bucket"] != "b" {
		t.Fatalf("%v %v", id, ok)
	}
	for _, raw := range []string{`{"region":null}`, `{"n":1}`, `[]`, ``} {
		if _, ok := instanceIdentity(Instance{IdentityKind: "identity", PriorIdentity: json.RawMessage(raw)}); ok {
			t.Errorf("%s: identity accepted", raw)
		}
	}
	if _, ok := instanceIdentity(Instance{IdentityKind: "none"}); ok {
		t.Error("kind none accepted")
	}
}

// TestSensitiveRead: a read of a sensitive attribute, of a block holding
// one, or that the schema cannot resolve is not grandfatherable.
func TestSensitiveRead(t *testing.T) {
	s := &tfprotov5.Schema{Block: &tfprotov5.SchemaBlock{
		Attributes: []*tfprotov5.SchemaAttribute{{Name: "acl"}},
		BlockTypes: []*tfprotov5.SchemaNestedBlock{
			{TypeName: "auth", Nesting: tfprotov5.SchemaNestedBlockNestingModeSingle, Block: &tfprotov5.SchemaBlock{Attributes: []*tfprotov5.SchemaAttribute{{Name: "token", Sensitive: true}, {Name: "user"}}}},
			{TypeName: "rule", Nesting: tfprotov5.SchemaNestedBlockNestingModeList, Block: &tfprotov5.SchemaBlock{Attributes: []*tfprotov5.SchemaAttribute{{Name: "x"}}}}}}}
	for read, want := range map[string]bool{"acl": false, "auth.user": false, "auth.token": true, "auth": true, "rule": false, "rule.x": true, "nope": true} {
		if got := sensitiveRead(s, read); got != want {
			t.Errorf("%s: %v", read, got)
		}
	}
}

// TestGrandfatherable: plan baseline eligibility needs a known
// schema and no schema-sensitive read.
func TestGrandfatherable(t *testing.T) {
	s := &tfprotov5.Schema{Block: &tfprotov5.SchemaBlock{Attributes: []*tfprotov5.SchemaAttribute{
		{Name: "acl", Type: tftypes.String}, {Name: "secret", Type: tftypes.String, Sensitive: true}}}}
	for name, tc := range map[string]struct {
		reads  []string
		schema *tfprotov5.Schema
		want   bool
	}{
		"plain read":     {[]string{"acl"}, s, true},
		"sensitive read": {[]string{"acl", "secret"}, s, false},
		"unresolvable":   {[]string{"missing"}, s, false},
		"no schema":      {[]string{}, nil, false},
	} {
		if got := Grandfatherable(&bundle.Control{ID: "c", Reads: tc.reads}, tc.schema); got != tc.want {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
	if Grandfatherable(nil, s) {
		t.Error("nil control grandfatherable")
	}
}
