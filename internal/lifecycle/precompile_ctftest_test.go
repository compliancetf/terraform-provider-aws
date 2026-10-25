//go:build ctftest

package lifecycle

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// countingSchemas counts upstream schema lookups; celeng looks the schema up
// once per control it compiles.
type countingSchemas struct {
	dbSchemas
	n *atomic.Int32
}

func (s countingSchemas) Resource(typ string) (*tfprotov5.Schema, bool) {
	s.n.Add(1)
	return s.dbSchemas.Resource(typ)
}

// TestPrecompileAtConfigure: Configure compiles every embedded control
// against its upstream schemas, so the first Evaluate after it compiles
// nothing and its per-resource budget covers evaluation only.
func TestPrecompileAtConfigure(t *testing.T) {
	offlineEnv(t)
	n := &atomic.Int32{}
	l := New(Options{ProviderVersion: "6.40.0"})
	t.Cleanup(func() { _ = l.Close() }) //nolint:errcheck // test cleanup
	if _, err := l.Configure(context.Background(), tftypes.NewValue(BlockType(), nil), "1.14.0", countingSchemas{n: n}); err != nil {
		t.Fatal(err)
	}
	if got, want := int(n.Load()), len(l.Configured().Controls.All()); got != want {
		t.Fatalf("Configure looked up %d schemas, want one per control (%d)", got, want)
	}
	before := n.Load()
	res, err := l.Evaluate(context.Background(), createPlan(t))
	if err != nil {
		t.Fatal(err)
	}
	if after := n.Load(); after != before {
		t.Errorf("first Evaluate compiled: %d schema lookups after Configure", after-before)
	}
	for _, d := range res.Diagnostics { // dbSchemas lacks some reads: no_such_attribute, never timeout
		if strings.Contains(d.Summary, "(timeout)") {
			t.Errorf("first Evaluate ran out of budget: %s", d.Summary)
		}
	}
}

// offlineEnv is an offline Configure environment with every input unset
// and fresh state, cache and evidence dirs.
func offlineEnv(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	for _, k := range []string{"COMPLIANCETF_ENFORCEMENT_MODE", "COMPLIANCETF_ORG_ID", "COMPLIANCETF_GOVERNED", "COMPLIANCETF_TOKEN",
		"COMPLIANCETF_PROFILE_PATH", "COMPLIANCETF_FLOOR_PATH", "COMPLIANCETF_ENVIRONMENT", "COMPLIANCETF_WORKSPACE",
		"COMPLIANCETF_BUNDLE_PATH", "COMPLIANCETF_EXCEPTIONS_FILE", "COMPLIANCETF_MIN_BUNDLE_VERSION", "COMPLIANCETF_MIN_PROFILE_VERSION"} {
		t.Setenv(k, "")
	}
	t.Setenv("COMPLIANCETF_BREAK_GLASS", "")
	os.Unsetenv("COMPLIANCETF_BREAK_GLASS") //nolint:errcheck,usetesting // any value fails Configure; t.Setenv restores it
	t.Setenv("COMPLIANCETF_OFFLINE", "true")
	t.Setenv("COMPLIANCETF_STATE_DIR", filepath.Join(dir, "state"))
	t.Setenv("COMPLIANCETF_CACHE_DIR", filepath.Join(dir, "cache"))
	t.Setenv("COMPLIANCETF_EVIDENCE_DIR", filepath.Join(dir, "evidence"))
}

// TestReconfigureDropsPrograms: a re-Configure drops every
// program compiled for the snapshot before, and plan after it never runs
// one of them: it compiles nothing against the old schemas.
func TestReconfigureDropsPrograms(t *testing.T) {
	offlineEnv(t)
	l := New(Options{ProviderVersion: "6.40.0"})
	t.Cleanup(func() { _ = l.Close() }) //nolint:errcheck // test cleanup
	a, b := &atomic.Int32{}, &atomic.Int32{}
	for _, s := range []countingSchemas{{n: a}, {n: b}} {
		if _, err := l.Configure(context.Background(), tftypes.NewValue(BlockType(), nil), "1.14.0", s); err != nil {
			t.Fatal(err)
		}
		if _, err := l.Evaluate(context.Background(), createPlan(t)); err != nil {
			t.Fatal(err)
		}
	}
	before := a.Load()
	if _, err := l.Evaluate(context.Background(), createPlan(t)); err != nil {
		t.Fatal(err)
	}
	if a.Load() != before {
		t.Errorf("plan after re-Configure looked up the first Configure's schemas")
	}
	cur := l.Configured().compiler
	n := 0
	l.progs.Range(func(k, _ any) bool {
		n++
		if k.(progKey).compiler != cur {
			t.Errorf("program of an earlier Configure kept: %+v", k)
		}
		return true
	})
	if n == 0 {
		t.Error("no program cached for the current Configure")
	}
}
