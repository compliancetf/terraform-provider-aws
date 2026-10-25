//go:build ctftest

package bench

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/bundle/bundletest"
	"github.com/compliancetf/terraform-provider-aws/internal/bundlegen"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/enginetest"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/lib"
	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/iampolicy"
	"github.com/compliancetf/terraform-provider-aws/internal/lifecycle"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
	"github.com/compliancetf/terraform-provider-aws/internal/trust/testkeys"
)

var instancesFile = flag.String("instances", "", "go run ./test/bench/gen output to evaluate (make bench-gate writes it)")

const (
	repo = "../.."
	// maxNotEvaluablePct caps not_evaluable results (plan and apply_pre, from
	// the evidence of the measured passes): the crosscheck probes of the
	// reference bundle are written for one input each and some fail on
	// generated nulls (about 9% on seed 1). Above the cap the benchmark would
	// time error paths, not evaluation.
	maxNotEvaluablePct = 10
	// now is inside the issued_at..expires_at window of release-iam.tar.gz.
	benchNow = "2026-10-06T06:00:00Z"
)

// BenchmarkP99 drives the generated instances through the plan and
// apply_pre stages of a Lifecycle configured with the reference bundle
// (testdata/bench/reference-bundle.json, signed with the ctftest bundle key
// into an air-gap archive with the catalog-iam catalog) and reports the p99 per
// resource as p99-ns/resource. Every iteration is one measured pass on cold
// caches (see pass); ns/op includes its Configure. cmd/benchgate gates the
// median over -count runs against test/bench/baseline/<runner-class>.json;
// make bench-gate runs both.
func BenchmarkP99(b *testing.B) {
	schemas, archive, rs := fixture(b)
	var d []time.Duration
	states := map[string]int{}
	controls := 0
	for b.Loop() {
		t, st, n := pass(b, schemas, archive, rs, 0)
		d, controls = append(d, t...), n
		for k, v := range st {
			states[k] += v
		}
	}
	total := 0
	for _, v := range states {
		total += v
	}
	if total == 0 || states["not_evaluable"]*100 >= total*maxNotEvaluablePct {
		b.Fatalf("results by state %v: want under %d%% not_evaluable", states, maxNotEvaluablePct)
	}
	b.ReportMetric(float64(P99(d)), "p99-ns/resource")
	b.ReportMetric(float64(len(rs)), "resources")
	b.ReportMetric(float64(controls), "controls")
	b.ReportMetric(float64(states["not_evaluable"])*100/float64(total), "not-evaluable-%")
}

// TestP99Seeded is the seeded regression self-check: a pass that sleeps 2x
// the clean p99 inside the timed region of every resource must record every
// sample at or above that delay, so its p99 is over 1.20x the clean one
// whatever the machine load. make bench-gate runs it before the benchmark.
func TestP99Seeded(t *testing.T) {
	schemas, archive, rs := fixture(t)
	rs = rs[:100]
	clean, _, _ := pass(t, schemas, archive, rs, 0)
	delay := 2 * P99(clean)
	seeded, _, _ := pass(t, schemas, archive, rs, delay)
	for i, s := range seeded {
		if s < delay {
			t.Fatalf("sample %d: %v, under the injected %v: the timer misses the evaluation", i, s, delay)
		}
	}
	if c, s := P99(clean), P99(seeded); int64(s)*100 <= int64(c)*120 {
		t.Errorf("seeded p99 %v is not over 1.20x the clean %v", s, c)
	}
}

// fixture loads the schema subset, the -instances document and the signed
// reference bundle archive.
func fixture(tb testing.TB) (bundlegen.Schemas, []byte, []resource) {
	tb.Helper()
	if *instancesFile == "" {
		tb.Fatal("-instances not set: run make bench-gate")
	}
	schemas, err := bundlegen.LoadSchemas(repo + "/testdata/schemas/aws-subset.json")
	if err != nil {
		tb.Fatal(err)
	}
	archive, err := os.ReadFile(repo + "/testdata/bundles/release-iam.tar.gz")
	if err != nil {
		tb.Fatal(err)
	}
	cat, err := os.ReadFile(repo + "/testdata/controls/catalog-iam/" + iampolicy.CatalogFile)
	if err != nil {
		tb.Fatal(err)
	}
	for name, body := range map[string][]byte{bundle.ControlsFile: withoutCIS(tb), bundle.IAMActionsFile: cat} {
		if archive, err = bundletest.WithFile(archive, name, body, testkeys.Bundle()); err != nil {
			tb.Fatal(err)
		}
	}
	return schemas, archive, load(tb, *instancesFile, schemas)
}

// pass is one measured pass on cold caches: a fresh Lifecycle (Configure
// compiles and plans every program, its decision memo is empty) and an
// empty process document cache, so every resource is evaluated, not
// replayed from the memo or the IAM/JSON document cache of an earlier pass.
// It runs plan then apply_pre on every instance once, sleeping delay inside
// each timed region, closes the Lifecycle and returns the per-resource
// times, the evidence results by state and the control count.
func pass(tb testing.TB, schemas bundlegen.Schemas, archive []byte, rs []resource, delay time.Duration) ([]time.Duration, map[string]int, int) {
	tb.Helper()
	l, evidence := configure(tb, schemas, archive)
	lib.ResetDocCache()
	d := make([]time.Duration, len(rs))
	for i := range rs {
		d[i] = evaluate(tb, l, &rs[i], delay)
	}
	n := controlCount(l, rs)
	if err := l.Close(); err != nil {
		tb.Fatal(err)
	}
	return d, resultStates(tb, evidence), n
}

// resultStates counts the results of every evidence record under dir by
// state.
func resultStates(tb testing.TB, dir string) map[string]int {
	tb.Helper()
	out := map[string]int{}
	err := filepath.WalkDir(dir, func(path string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() || filepath.Ext(path) != ".jsonl" {
			return err
		}
		raw, err := os.ReadFile(path) //nolint:gosec // temp dir of this test
		if err != nil {
			return err
		}
		for line := range bytes.Lines(raw) {
			var rec struct{ Results []struct{ State string } }
			if err := json.Unmarshal(line, &rec); err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
			for _, r := range rec.Results {
				out[r.State]++
			}
		}
		return nil
	})
	if err != nil {
		tb.Fatal(err)
	}
	return out
}

// configure returns a Lifecycle for org bobthecorp, offline, on temp dirs,
// with archive as its air-gap bundle and a signed profile, and its evidence
// dir. The caller closes it.
func configure(tb testing.TB, schemas bundlegen.Schemas, archive []byte) (*lifecycle.Lifecycle, string) {
	tb.Helper()
	now, err := time.Parse(time.RFC3339, benchNow)
	if err != nil {
		tb.Fatal(err)
	}
	dir := tb.TempDir()
	path, prof := filepath.Join(dir, "reference.tar.gz"), filepath.Join(dir, "profile.json")
	for f, body := range map[string][]byte{path: archive, prof: signedProfile(tb, now)} {
		if err := os.WriteFile(f, body, 0o600); err != nil {
			tb.Fatal(err)
		}
	}
	for _, k := range []string{"COMPLIANCETF_ENFORCEMENT_MODE", "COMPLIANCETF_GOVERNED", "COMPLIANCETF_TOKEN",
		"COMPLIANCETF_ENVIRONMENT", "COMPLIANCETF_FLOOR_PATH", "COMPLIANCETF_WORKSPACE",
		"COMPLIANCETF_EXCEPTIONS_FILE", "COMPLIANCETF_MIN_BUNDLE_VERSION", "COMPLIANCETF_MIN_PROFILE_VERSION"} {
		tb.Setenv(k, "")
	}
	tb.Setenv("COMPLIANCETF_BREAK_GLASS", "")
	os.Unsetenv("COMPLIANCETF_BREAK_GLASS") //nolint:errcheck,usetesting // any value, even empty, fails Configure; tb.Setenv above restores it
	tb.Setenv("COMPLIANCETF_OFFLINE", "true")
	tb.Setenv("COMPLIANCETF_ORG_ID", "bobthecorp")
	tb.Setenv("COMPLIANCETF_PROFILE_PATH", prof)
	tb.Setenv("COMPLIANCETF_BUNDLE_PATH", path)
	tb.Setenv("COMPLIANCETF_STATE_DIR", filepath.Join(dir, "state"))
	tb.Setenv("COMPLIANCETF_CACHE_DIR", filepath.Join(dir, "cache"))
	evidence := filepath.Join(dir, "evidence")
	tb.Setenv("COMPLIANCETF_EVIDENCE_DIR", evidence)
	l := lifecycle.New(lifecycle.Options{ProviderVersion: "6.40.0", Now: func() time.Time { return now }})
	if _, err := l.Configure(context.Background(), tftypes.NewValue(lifecycle.BlockType(), nil), "1.14.0", schemas); err != nil {
		tb.Fatal(err)
	}
	return l, evidence
}

// signedProfile is a hard_fail profile for bobthecorp, signed with the
// ctftest profile key, whose scope binds the trusted env prod: without it
// every env-dependent control is not_evaluable/scope_untrusted.
func signedProfile(tb testing.TB, now time.Time) []byte {
	tb.Helper()
	payload, err := json.Marshal(map[string]any{
		"format": "compliancetf.profile/v1", "org_id": "bobthecorp", "profile_version": 1,
		"issued_at": now.Add(-time.Hour).Format(time.RFC3339), "expires_at": now.Add(20 * 24 * time.Hour).Format(time.RFC3339),
		"governed": false, "mode_floor": map[string]string{"default": "hard_fail"}, "verdict_required": false,
		"scope":      map[string]string{"environment": "prod"},
		"exceptions": map[string]any{"max_lifetime_days": 180, "self_service": []string{}},
		"evidence":   map[string]any{"required": false, "sinks": []string{}},
		"budgets":    map[string]int{"per_resource_ms": 50, "per_run_s": 600},
	})
	if err != nil {
		tb.Fatal(err)
	}
	key := testkeys.Profile()
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		tb.Fatal(err)
	}
	env, err := json.Marshal(map[string]any{
		"payloadType": trust.PayloadProfile,
		"payload":     base64.StdEncoding.EncodeToString(payload),
		"signatures": []map[string]string{{"keyid": trust.KIDFromSPKI(spki),
			"sig": base64.StdEncoding.EncodeToString(ed25519.Sign(key, trust.PAE(trust.PayloadProfile, payload)))}},
	})
	if err != nil {
		tb.Fatal(err)
	}
	return env
}

// withoutCIS is the reference bundle without the controls whose key the
// embedded CIS bundle holds: Configure always loads that bundle and rejects a
// duplicate key, and the reference bundle took those controls from it
// unchanged, so the two bundles together evaluate the reference bundle.
func withoutCIS(tb testing.TB) []byte {
	tb.Helper()
	key := func(c map[string]any) string { return fmt.Sprint(c["id"], "|", c["kind"], "|", c["resource_type"]) }
	read := func(path string) []map[string]any {
		var cs []map[string]any
		raw, err := os.ReadFile(repo + path) //nolint:gosec // repo fixture
		if err == nil {
			err = json.Unmarshal(raw, &cs)
		}
		if err != nil {
			tb.Fatal(err)
		}
		return cs
	}
	cis := map[string]bool{}
	for _, c := range read("/internal/embedded/cis/controls.json") {
		cis[key(c)] = true
	}
	ref := read("/testdata/bench/reference-bundle.json")
	out := slices.DeleteFunc(slices.Clone(ref), func(c map[string]any) bool { return cis[key(c)] })
	if len(out) == len(ref) || len(ref)-len(out) != len(cis) {
		tb.Fatalf("reference bundle holds %d of the %d embedded CIS controls, want all", len(ref)-len(out), len(cis))
	}
	raw, err := json.Marshal(out)
	if err != nil {
		tb.Fatal(err)
	}
	return raw
}

// resource is one generated instance; values are msgpack, as Core sends them.
type resource struct {
	typ                    string
	op                     hook.Op
	ty                     tftypes.Type
	config, prior, planned []byte
}

// load reads a compliancetf.bench-instances/v1 document; JSON null is a
// null object.
func load(tb testing.TB, path string, schemas bundlegen.Schemas) []resource {
	tb.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // operator-supplied fixture path
	if err != nil {
		tb.Fatal(err)
	}
	var doc struct {
		Format    string
		Instances []struct {
			ResourceType           string `json:"resource_type"`
			Op                     hook.Op
			Config, Prior, Planned json.RawMessage
		}
	}
	if err := json.Unmarshal(raw, &doc); err != nil || doc.Format != "compliancetf.bench-instances/v1" || len(doc.Instances) == 0 {
		tb.Fatalf("%s: format %q, %d instances (%v)", path, doc.Format, len(doc.Instances), err)
	}
	mp := func(ty tftypes.Type, raw json.RawMessage) []byte {
		if string(raw) == "null" {
			raw = nil
		}
		dv, err := tfprotov5.NewDynamicValue(ty, enginetest.Value(tb, ty, raw))
		if err != nil {
			tb.Fatal(err)
		}
		return dv.MsgPack
	}
	out := make([]resource, len(doc.Instances))
	for i, in := range doc.Instances {
		sc, ok := schemas.Resource(in.ResourceType)
		if !ok {
			tb.Fatalf("instance %d: %s is not in the schema", i, in.ResourceType)
		}
		ty := sc.ValueType()
		out[i] = resource{typ: in.ResourceType, op: in.Op, ty: ty,
			config: mp(ty, in.Config), prior: mp(ty, in.Prior), planned: mp(ty, in.Planned)}
	}
	return out
}

// controlCount is the number of (type, op, control) evaluations the
// instance types can reach on create and update.
func controlCount(l *lifecycle.Lifecycle, rs []resource) int {
	n, seen := 0, map[string]bool{}
	for _, r := range rs {
		if !seen[r.typ] {
			seen[r.typ] = true
			n += len(l.Configured().Controls.For(r.typ, bundle.OnCreate)) + len(l.Configured().Controls.For(r.typ, bundle.OnUpdate))
		}
	}
	return n
}

// evaluate runs plan then apply_pre on r, sleeps delay, and returns the
// elapsed time of all three.
func evaluate(tb testing.TB, l *lifecycle.Lifecycle, r *resource, delay time.Duration) time.Duration {
	val := func(mp []byte) *hook.Value {
		return hook.NewValue(mp, nil, func() (tftypes.Type, error) { return r.ty, nil })
	}
	start := time.Now()
	req := &hook.Request{Stage: hook.StagePlan, Kind: hook.KindResource, TypeName: r.typ, Op: r.op,
		Config: val(r.config), Prior: val(r.prior), Planned: val(r.planned)}
	res, err := l.Evaluate(context.Background(), req)
	if err != nil {
		tb.Fatalf("plan %s: %v", r.typ, err)
	}
	env := &hook.EnvelopeHeader{V: 1}
	env.CTF.Op, env.CTF.ControlVersionsDigest = r.op, res.ControlVersionsDigest
	req = &hook.Request{Stage: hook.StageApplyPre, Kind: hook.KindResource, TypeName: r.typ, Op: r.op,
		Config: val(r.config), Prior: val(r.prior), Planned: val(r.planned), Envelope: env}
	if _, err := l.Evaluate(context.Background(), req); err != nil {
		tb.Fatalf("apply_pre %s: %v", r.typ, err)
	}
	time.Sleep(delay)
	return time.Since(start)
}
