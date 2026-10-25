package celeng

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/lib"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

// memoRun evaluates b on comp and on a fresh Compiled of the same controls:
// a memo hit must give the decision a fresh evaluation gives.
func memoRun(t *testing.T, comp *Compiled, cs []bundle.Control, b Bindings) Result {
	t.Helper()
	got := comp.Evaluate(context.Background(), b, nil)
	fresh, _, err := New(testOpts).Load(cs, awsSubset(t), Content{})
	if err != nil {
		t.Fatal(err)
	}
	want := fresh.Evaluate(context.Background(), b, nil)
	if len(got) != 1 || len(want) != 1 {
		t.Fatalf("results %v / %v", got, want)
	}
	if got[0].State != want[0].State || got[0].ErrClass != want[0].ErrClass {
		t.Fatalf("memo changed the decision: %s/%s (memoized %v), fresh %s/%s",
			got[0].State, got[0].ErrClass, got[0].Memoized, want[0].State, want[0].ErrClass)
	}
	return got[0]
}

func load(t *testing.T, cs ...bundle.Control) *Compiled {
	t.Helper()
	comp, _, err := New(testOpts).Load(cs, awsSubset(t), Content{})
	if err != nil {
		t.Fatal(err)
	}
	return comp
}

func TestPrefilterHitAndMiss(t *testing.T) {
	cs := []bundle.Control{dbControl("owner", `resource.tags.owner == "bob" && resource.storage_encrypted`, "tags.owner", "storage_encrypted")}
	comp := load(t, cs...)
	enc := `{"storage_encrypted": true, "tags": {"owner": "bob"}, "identifier": "a"}`
	if r := memoRun(t, comp, cs, dbBindings(t, enc)); r.State != engine.Pass || r.Memoized {
		t.Fatalf("first: %+v", r)
	}
	// An unread attribute differs: still a hit.
	if r := memoRun(t, comp, cs, dbBindings(t, `{"storage_encrypted": true, "tags": {"owner": "bob", "team": "x"}, "identifier": "b"}`)); !r.Memoized {
		t.Fatalf("unread change: want hit, got %+v", r)
	}
	// A read value differs: miss, then its own entry.
	if r := memoRun(t, comp, cs, dbBindings(t, `{"storage_encrypted": false, "tags": {"owner": "bob"}}`)); r.Memoized || r.State != engine.Fail {
		t.Fatalf("read change: %+v", r)
	}
	if r := memoRun(t, comp, cs, dbBindings(t, `{"storage_encrypted": false, "tags": {"owner": "bob"}}`)); !r.Memoized || r.State != engine.Fail {
		t.Fatalf("fail stored: %+v", r)
	}
	// Absent map key: evaluate, never stored.
	b := dbBindings(t, `{"storage_encrypted": true, "tags": {"team": "x"}}`)
	for range 2 {
		if r := memoRun(t, comp, cs, b); r.Memoized {
			t.Fatalf("absent key: %+v", r)
		}
	}
}

func TestPrefilterVersionBump(t *testing.T) {
	c := dbControl("enc", "resource.storage_encrypted", "storage_encrypted")
	b := dbBindings(t, `{"storage_encrypted": true}`)
	comp := load(t, c)
	comp.Evaluate(context.Background(), b, nil)
	bumped := c
	bumped.Version = "1.0.1"
	k1, ok1 := comp.memoKey(&comp.progs(t, c.Kind, c.ResourceType)[0], b)
	k2, ok2 := comp.memoKey(&program{c: &bumped, ch: comp.progs(t, c.Kind, c.ResourceType)[0].ch}, b)
	if !ok1 || !ok2 || k1 == k2 {
		t.Fatalf("version bump must change the key: %v %v", ok1, ok2)
	}
}

func TestPrefilterDigestChange(t *testing.T) {
	c := dbControl("enc", "resource.storage_encrypted", "storage_encrypted")
	b := dbBindings(t, `{"storage_encrypted": true}`)
	comp := load(t, c)
	p := &comp.progs(t, c.Kind, c.ResourceType)[0]
	k1, _ := comp.memoKey(p, b)
	comp.digest = "sha256:other"
	k2, _ := comp.memoKey(p, b)
	if k1 == k2 {
		t.Fatal("digest change must change the key")
	}
}

func TestPrefilterUnknownNeverStored(t *testing.T) {
	cs := []bundle.Control{dbControl("kms", "resource.kms_key_id != null", "kms_key_id")}
	comp := load(t, cs...)
	b := dbBindings(t, `{"kms_key_id": {"$unknown": true}}`)
	for range 2 {
		if r := memoRun(t, comp, cs, b); r.State != engine.Unknown || r.Memoized {
			t.Fatalf("unknown: %+v", r)
		}
	}
	nf := []bundle.Control{dbControl("nf", "resource.tags.owner == 'x'", "tags.owner")}
	comp = load(t, nf...)
	b = dbBindings(t, `{"tags": {"team": "x"}}`) // no_such_attribute at runtime
	if r := memoRun(t, comp, nf, b); r.State != engine.NotEvaluable {
		t.Fatalf("missing key: %+v", r)
	}
	if n := comp.memo.len(); n != 0 {
		t.Fatalf("memo holds %d entries after unknown and not_evaluable", n)
	}
}

// TestPrefilterUnknownSibling: an unknown anywhere under the top-level
// attribute of a read disables the memo (container rule note).
func TestPrefilterUnknownSibling(t *testing.T) {
	cs := []bundle.Control{dbControl("owner", `resource.tags.owner == "bob"`, "tags.owner")}
	comp := load(t, cs...)
	memoRun(t, comp, cs, dbBindings(t, `{"tags": {"owner": "bob", "team": "x"}}`))
	if r := memoRun(t, comp, cs, dbBindings(t, `{"tags": {"owner": "bob", "team": {"$unknown": true}}}`)); r.Memoized {
		t.Fatalf("unknown sibling under tags: %+v", r)
	}
	// The converted map omits the unknown key, so it equals the stored map;
	// cel-go makes size() of it unknown. A hit here would turn unknown into pass.
	cs = []bundle.Control{dbControl("one_tag", `size(resource.tags) == 1`, "tags")}
	comp = load(t, cs...)
	if r := memoRun(t, comp, cs, dbBindings(t, `{"tags": {"owner": "bob"}}`)); r.State != engine.Pass {
		t.Fatalf("stored: %+v", r)
	}
	if r := memoRun(t, comp, cs, dbBindings(t, `{"tags": {"owner": "bob", "team": {"$unknown": true}}}`)); r.Memoized {
		t.Fatalf("omitted unknown key: %+v", r)
	}
	s := awsSubset(t)
	md := *testControl(bundle.KindResource, bundle.PresenceEffective, `resource.metadata_options.all(m, m.http_tokens == "required")`, "metadata_options")
	md.ID, md.Version, md.ResourceType, md.Action = "imdsv2", "1.0.0", "aws_instance", bundle.ActionDeny
	cs = []bundle.Control{md}
	comp = load(t, cs...)
	typ := s.ResourceSchemas["aws_instance"].Block.ValueType()
	bind := func(js string) Bindings {
		return Bindings{Kind: bundle.KindResource, Type: "aws_instance", Op: "create", EnvKnown: true,
			Resource: jsonValue(t, typ, json.RawMessage(js))}
	}
	memoRun(t, comp, cs, bind(`{"metadata_options": [{"http_tokens": "required", "http_endpoint": "enabled"}]}`))
	if r := memoRun(t, comp, cs, bind(`{"metadata_options": [{"http_tokens": "required", "http_endpoint": {"$unknown": true}}]}`)); r.Memoized {
		t.Fatalf("unknown sibling in a list element: %+v", r)
	}
}

func TestPrefilterEnvOpProvider(t *testing.T) {
	cs := []bundle.Control{dbControl("ctx", `op == "create" && env == "prod" && provider.region == "eu-west-1"`)}
	comp := load(t, cs...)
	b := dbBindings(t, `{}`)
	b.Provider = ProviderInfo{Region: "eu-west-1", RegionKnown: true, AccountID: "111111111111", AccountKnown: true, Partition: "aws", PartitionKnown: true}
	if r := memoRun(t, comp, cs, b); r.State != engine.Pass || r.Memoized {
		t.Fatalf("first: %+v", r)
	}
	for name, mod := range map[string]func(*Bindings){
		"op":       func(b *Bindings) { b.Op = "update" },
		"env":      func(b *Bindings) { b.Env = "dev" },
		"region":   func(b *Bindings) { b.Provider.Region = "us-east-1" },
		"env_unkn": func(b *Bindings) { b.EnvKnown = false },
		"acct_unk": func(b *Bindings) { b.Provider.AccountKnown = false },
		"part":     func(b *Bindings) { b.Provider.Partition = "aws-cn" },
		"part_unk": func(b *Bindings) { b.Provider.PartitionKnown = false },
	} {
		bb := b
		mod(&bb)
		if r := memoRun(t, comp, cs, bb); r.Memoized {
			t.Fatalf("%s change must miss: %+v", name, r)
		}
	}
	if r := memoRun(t, comp, cs, b); !r.Memoized {
		t.Fatalf("same context: want hit, got %+v", r)
	}
}

// TestPrefilterTargets: one id and version on two resource types with equal
// projected inputs never share an entry.
func TestPrefilterTargets(t *testing.T) {
	db := dbControl("owner", `resource.tags.owner == "bob"`, "tags.owner")
	inst := dbControl("owner", `resource.tags.owner != "bob"`, "tags.owner")
	inst.ResourceType = "aws_instance"
	cs := []bundle.Control{db, inst}
	comp := load(t, cs...)
	tags := `{"tags": {"owner": "bob"}}`
	b := dbBindings(t, tags)
	ib := Bindings{Kind: bundle.KindResource, Type: "aws_instance", Op: "create", Env: "prod", EnvKnown: true,
		Resource: jsonValue(t, awsSubset(t).ResourceSchemas["aws_instance"].Block.ValueType(), json.RawMessage(tags))}
	r1 := comp.Evaluate(context.Background(), b, nil)
	r2 := comp.Evaluate(context.Background(), ib, nil)
	if r1[0].State != engine.Pass || r2[0].State != engine.Fail || r2[0].Memoized {
		t.Fatalf("targets: %+v %+v", r1, r2)
	}
	// Same expr too: the key alone must separate the targets.
	inst.Expr = db.Expr
	pd := &comp.progs(t, db.Kind, db.ResourceType)[0]
	kd, _ := comp.memoKey(pd, b)
	ki, _ := comp.memoKey(&program{c: &inst, ch: pd.ch}, b)
	if kd == ki {
		t.Fatal("resource_type must be in the key")
	}
}

// TestPrefilterVariables: equal values under config and resource do not collide.
func TestPrefilterVariables(t *testing.T) {
	c := dbControl("enc", "resource.storage_encrypted", "storage_encrypted")
	comp := load(t, c)
	b := dbBindings(t, `{"storage_encrypted": true}`)
	b.Config = b.Resource
	pr := comp.progs(t, c.Kind, c.ResourceType)[0]
	ch := *pr.ch // same expr digest: only the variable name differs
	ch.Reads, ch.Vars = []Read{{Var: varConfig, Path: "storage_encrypted"}}, []string{varConfig}
	kr, ok1 := comp.memoKey(&pr, b)
	kc, ok2 := comp.memoKey(&program{c: pr.c, ch: &ch}, b)
	if !ok1 || !ok2 || kr == kc {
		t.Fatalf("config and resource projections collide: %v %v", ok1, ok2)
	}
}

func TestPrefilterCap(t *testing.T) {
	m := newMemo(2)
	for i := range 3 {
		m.put(memoKeyT{byte(i)}, engine.Pass)
	}
	if n := m.len(); n != 1 {
		t.Fatalf("cap: %d entries, want 1 after clear", n)
	}
	m.put(memoKeyT{9}, engine.Unknown)
	if _, ok := m.get(memoKeyT{9}); ok {
		t.Fatal("unknown stored")
	}
}

// memoKey is the key Evaluate computes for p under b.
func (c *Compiled) memoKey(p *program, b Bindings) (memoKeyT, bool) {
	_, vals, _, _ := c.activation(b, time.Time{})
	return c.key(p, b, vals)
}

func (c *Compiled) progs(t *testing.T, k bundle.Kind, typ string) []program {
	t.Helper()
	get := c.programs[target{k, typ}]
	if get == nil {
		t.Fatalf("no programs for %s %s", k, typ)
	}
	return get()
}

// swapSet loads testdata/bundles/swap-graph/<name>.tar.gz (signed,
// identical except graph.json; the signature is checked in internal/bundle)
// as a control set.
func swapSet(t *testing.T, name string) (*bundle.ControlSet, *bundle.Bundle) {
	t.Helper()
	raw, err := os.ReadFile("../../../testdata/bundles/swap-graph/" + name + ".tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	b, err := bundle.ReadArchive(raw, func(env []byte, _ string) (trust.Verified, error) {
		var e struct{ Payload []byte }
		err := json.Unmarshal(env, &e)
		return trust.Verified{Payload: e.Payload}, err
	})
	if err != nil {
		t.Fatal(err)
	}
	set, _, err := bundle.NewControlSet("bobthecorp", time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC), trust.NoRevocations(), b)
	if err != nil {
		t.Fatal(err)
	}
	return set, b
}

// swapCompiled loads swap-graph bundle name and compiles it with its content
// digest.
func swapCompiled(t *testing.T, name string) (*Compiled, []bundle.Control, string) {
	t.Helper()
	set, b := swapSet(t, name)
	digest := set.ContentDigest(map[string][]string{b.Controls[0].ID: {"grant"}})
	comp, _, err := New(testOpts).Load(b.Controls, awsSubset(t), Content{Digest: digest, IAMCatalog: b.IAMCatalog})
	if err != nil {
		t.Fatal(err)
	}
	return comp, b.Controls, digest
}

// TestPrefilterSwap: bundles a and b differ only in graph.json. Under b,
// neither a memo entry nor an IAM document cache entry from a is reused.
func TestPrefilterSwap(t *testing.T) {
	a, cs, da := swapCompiled(t, "a")
	b, _, db := swapCompiled(t, "b")
	if da == db || a.digest != da || b.digest != db {
		t.Fatalf("Load must key the memo by the content digest: %s %s, %s %s", a.digest, da, b.digest, db)
	}
	// A policy no other run parses (the Sid is unique), so the first parse is a cache miss.
	in := dbBindings(t, `{"kms_key_id": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"swap`+strconv.FormatInt(time.Now().UnixNano(), 10)+`\",\"Effect\":\"Deny\",\"Action\":\"kms:decrypt\",\"Resource\":\"*\"}]}"}`)
	eval := func(c *Compiled) (Result, int) {
		before := lib.DocDecodes()
		rs := c.Evaluate(context.Background(), in, nil)
		if len(rs) != 1 || rs[0].State != engine.Pass {
			t.Fatalf("results %+v", rs)
		}
		return rs[0], lib.DocDecodes() - before
	}
	if r, n := eval(a); r.Memoized || n != 1 {
		t.Fatalf("a first: %+v, %d parses", r, n)
	}
	if r, _ := eval(a); !r.Memoized {
		t.Fatalf("a again: want a memo hit, got %+v", r)
	}
	// Same content, fresh memo: the document cache hits.
	a2, _, _ := swapCompiled(t, "a")
	if r, n := eval(a2); r.Memoized || n != 0 {
		t.Fatalf("a reloaded: %+v, %d parses", r, n)
	}
	// b shares a's memo here: a's entry still misses, and the parse repeats.
	b.memo = a.memo
	if r, n := eval(b); r.Memoized || n != 1 {
		t.Fatalf("b: %+v, %d parses; nothing from a may be reused", r, n)
	}
	p := &a.progs(t, cs[0].Kind, cs[0].ResourceType)[0]
	ka, _ := a.memoKey(p, in)
	kb, _ := b.memoKey(p, in)
	if ka == kb {
		t.Fatal("memo keys under a and b must differ")
	}
}
