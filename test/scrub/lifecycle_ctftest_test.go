//go:build ctftest

package scrub

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/bundle/bundletest"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/evidence"
	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/lifecycle"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
	"github.com/compliancetf/terraform-provider-aws/internal/trust/testkeys"
	"github.com/compliancetf/terraform-provider-aws/test/scrub/scrubtest"
)

const scrubWorkspace = "bobthecorp-scrub"

// signedProfile is a soft_fail profile for org bobthecorp with a 60 s
// per-resource budget (so no case can time out on a loaded machine), the
// scrub workspace in its scope and the cover cases self-service, signed
// with the ctftest profile key.
func signedProfile(t *testing.T, now time.Time) []byte {
	t.Helper()
	var self []string
	for _, c := range cases {
		if c.cover {
			self = append(self, c.id())
		}
	}
	payload, err := json.Marshal(map[string]any{
		"format": "compliancetf.profile/v1", "org_id": "bobthecorp", "profile_version": 5,
		"issued_at": now.Add(-time.Hour).Format(time.RFC3339), "expires_at": now.Add(20 * 24 * time.Hour).Format(time.RFC3339),
		"governed": false, "mode_floor": map[string]string{"default": "soft_fail"}, "verdict_required": false,
		"scope":      map[string]string{"workspace": scrubWorkspace},
		"exceptions": map[string]any{"max_lifetime_days": 180, "self_service": self},
		"evidence":   map[string]any{"required": false, "sinks": []string{}},
		"budgets":    map[string]int{"per_resource_ms": 60000, "per_run_s": 600},
	})
	if err != nil {
		t.Fatal(err)
	}
	key := testkeys.Profile()
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	env, err := json.Marshal(map[string]any{
		"payloadType": trust.PayloadProfile,
		"payload":     base64.StdEncoding.EncodeToString(payload),
		"signatures": []map[string]string{{"keyid": trust.KIDFromSPKI(spki),
			"sig": base64.StdEncoding.EncodeToString(ed25519.Sign(key, trust.PAE(trust.PayloadProfile, payload)))}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// sidecar applies an exception to scrub_fail (its match reads the marked
// tags) and leaves one pending on scrub_unknown_map_key (its match reads
// the tags map with an unknown value under a marker key). Reasons and
// tickets carry markers; neither is ever recorded.
func sidecar(now time.Time) string {
	exp := now.Add(30 * 24 * time.Hour).Format("2006-01-02")
	return fmt.Sprintf(`exception "scrub-applied" {
  controls  = ["scrub_fail"]
  match     = "size(resource.tags) == 1"
  workspace = %[1]q
  reason    = %[2]q
  ticket    = %[3]q
  expires   = %[4]q
}
exception "scrub-pending" {
  controls  = ["scrub_unknown_map_key"]
  match     = "size(resource.tags) > 0"
  workspace = %[1]q
  reason    = %[5]q
  expires   = %[4]q
}
`, scrubWorkspace, scrubtest.Marker(53), scrubtest.Marker(54), exp, scrubtest.Marker(55))
}

// stageWant is the diagnostic summary a case's own control gives at one
// stage under soft_fail ("" none) and the evidence exception it records
// (source/status, "" none).
func stageWant(c scrubCase, stage hook.Stage) (summary, exception string) {
	id := "[" + c.id() + "] "
	switch {
	case c.name == "fail":
		return "", "self_service/applied"
	case c.state == engine.Pass:
		return "", ""
	case c.state == engine.Fail:
		return id + "Scrub control.", ""
	case c.state == engine.Unknown && stage == hook.StagePlan:
		return id + "pending: re-checked at apply", ""
	case c.state == engine.Unknown:
		return "", "" // soft_fail carries an unknown at apply_pre silently
	}
	return id + "not evaluable (" + string(c.class) + ")", ""
}

// TestScrubLifecycle runs every case through a configured Lifecycle (the
// release-iam test bundle with its controls.json replaced by the scrub
// controls and re-signed with the ctftest bundle key, a signed soft_fail
// profile with a 60 s budget, and a self-service sidecar) at plan and
// apply_pre. Each stage must give the case's own diagnostic and evidence
// result (state, class, paths, exception) and no timeout anywhere; then
// the Configure warnings, every diagnostic and returned error, every file
// under the evidence, state and cache dirs and the captured logs and
// stderr are scanned. Evidence records the exception label, digest,
// expiry, workspace, source and status by design (spec 10.1), never the
// reason or ticket.
func TestScrubLifecycle(t *testing.T) {
	logs := scrubtest.CaptureLogs(t)
	s := schemas(t)
	now := time.Now().UTC().Truncate(time.Second)
	archive, err := os.ReadFile(filepath.Join(testdata, "bundles", "release-iam.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	archive, err = bundletest.WithFile(archive, bundle.ControlsFile, controlsJSON(t), testkeys.Bundle())
	if err != nil {
		t.Fatal(err)
	}
	dir, in := t.TempDir(), t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(in, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, k := range []string{"COMPLIANCETF_ENFORCEMENT_MODE", "COMPLIANCETF_GOVERNED", "COMPLIANCETF_TOKEN",
		"COMPLIANCETF_FLOOR_PATH", "COMPLIANCETF_ENVIRONMENT", "COMPLIANCETF_WORKSPACE",
		"COMPLIANCETF_MIN_BUNDLE_VERSION", "COMPLIANCETF_MIN_PROFILE_VERSION"} {
		t.Setenv(k, "")
	}
	t.Setenv("COMPLIANCETF_BREAK_GLASS", "")
	os.Unsetenv("COMPLIANCETF_BREAK_GLASS") //nolint:errcheck,usetesting // any value fails Configure; t.Setenv restores it
	t.Setenv("COMPLIANCETF_OFFLINE", "true")
	t.Setenv("COMPLIANCETF_ORG_ID", "bobthecorp")
	outDirs := map[string]string{}
	for _, d := range []string{"state", "cache", "evidence"} {
		outDirs[d] = filepath.Join(dir, d)
		t.Setenv("COMPLIANCETF_"+strings.ToUpper(d)+"_DIR", outDirs[d])
	}
	t.Setenv("COMPLIANCETF_BUNDLE_PATH", write("scrub.tar.gz", archive))
	t.Setenv("COMPLIANCETF_PROFILE_PATH", write("profile.dsse.json", signedProfile(t, now)))
	t.Setenv("COMPLIANCETF_EXCEPTIONS_FILE", write("compliance-exceptions.hcl", []byte(sidecar(now))))

	l := lifecycle.New(lifecycle.Options{ProviderVersion: "6.40.0", Now: func() time.Time { return now }})
	warns, err := l.Configure(context.Background(), tftypes.NewValue(lifecycle.BlockType(), nil), "1.14.0", s)
	noLoadMarker(t, "Configure warnings", strings.Join(warns, "\n"))
	mustLoad(t, "Configure", err)
	cfg := l.Configured()
	if cfg.Sidecar == nil {
		t.Fatal("no sidecar loaded")
	}
	n := 0
	for _, c := range cfg.Controls.All() {
		if strings.HasPrefix(c.ID, "scrub_") {
			n++
		}
	}
	if n != len(cases) { // beside the embedded CIS baseline
		t.Fatalf("%d scrub controls loaded, want %d", n, len(cases))
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			typ, v := c.value(t, s)
			mp := msgpack(t, typ, v)
			null := msgpack(t, typ, tftypes.NewValue(typ, nil))
			val := func(b []byte) *hook.Value {
				return hook.NewValue(b, nil, func() (tftypes.Type, error) { return typ, nil })
			}
			req := &hook.Request{Stage: hook.StagePlan, Kind: hook.KindResource, TypeName: c.typ, Op: hook.OpCreate,
				Config: val(mp), Prior: val(null), Planned: val(mp)}
			for _, stage := range []hook.Stage{hook.StagePlan, hook.StageApplyPre} {
				res, err := l.Evaluate(context.Background(), req)
				scrubtest.Must(t, string(stage)+" error", err)
				checkDiags(t, c, stage, res.Diagnostics)
				env := &hook.EnvelopeHeader{V: 1}
				env.CTF.Op, env.CTF.ControlVersionsDigest = hook.OpCreate, res.ControlVersionsDigest
				req = &hook.Request{Stage: hook.StageApplyPre, Kind: hook.KindResource, TypeName: c.typ, Op: hook.OpCreate,
					Config: val(mp), Prior: val(null), Planned: val(mp), Envelope: env}
			}
		})
	}
	scrubtest.Must(t, "Close", l.Close())
	checkEvidence(t, outDirs["evidence"])
	// Layout: offline, the bundle comes from COMPLIANCETF_BUNDLE_PATH and
	// nothing is cached; state holds the trust state and its lock.
	files := map[string][]string{}
	for name, d := range outDirs {
		files[name] = scanDir(t, name, d)
	}
	if len(files["cache"]) != 0 || !slices.Equal(files["state"], []string{"trust-state.json", "trust-state.lock"}) ||
		len(files["evidence"]) == 0 || slices.ContainsFunc(files["evidence"], func(f string) bool { return filepath.Ext(f) != ".jsonl" }) {
		t.Errorf("output layout %v, want no cache file, the trust state and lock, and evidence .jsonl only", files)
	}
	cacheSkips(t, archive)
	versionRange(t, archive, write, outDirs)
	scopeRejected(t, archive, write)
	out := logs()
	scrubtest.NoMarker(t, "log", out)
	if !strings.Contains(out, "exception scrub-pending pending: selector unknown") {
		t.Error("the pending sidecar entry wrote no log line")
	}
}

// cacheSkips configures again over a bundle cache under a marked path that
// holds archives it cannot use: garbage, a valid archive under another
// digest's name, and a symlink to a marked file (whose own name is no
// archive name and is not counted). The bundle_loaded record carries the
// bundle sources and the skip count and reasons only; the evidence, the
// Configure warnings and the trust state never carry a marker.
func cacheSkips(t *testing.T, archive []byte) {
	t.Helper()
	root := t.TempDir()
	bdir := filepath.Join(root, scrubtest.Marker(57), "cache", "bundles")
	if err := os.MkdirAll(bdir, 0o700); err != nil {
		t.Fatal(err)
	}
	name := func(c string) string { return filepath.Join(bdir, "sha256-"+strings.Repeat(c, 64)+".tar.gz") }
	marked := filepath.Join(bdir, scrubtest.Marker(58)+".tar.gz")
	for p, b := range map[string][]byte{name("0"): []byte(scrubtest.Marker(59)), name("1"): archive, marked: []byte(scrubtest.Marker(60))} {
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(marked, name("2")); err != nil {
		t.Fatal(err)
	}
	evDir, stDir := filepath.Join(root, "evidence"), filepath.Join(root, "state")
	for k, v := range map[string]string{"CACHE": filepath.Dir(bdir), "EVIDENCE": evDir, "STATE": stDir} {
		t.Setenv("COMPLIANCETF_"+k+"_DIR", v)
	}
	l := lifecycle.New(lifecycle.Options{ProviderVersion: "6.40.0"})
	warns, err := l.Configure(context.Background(), tftypes.NewValue(lifecycle.BlockType(), nil), "1.14.0", schemas(t))
	noLoadMarker(t, "Configure warnings (cache skips)", strings.Join(warns, "\n"))
	mustLoad(t, "Configure (cache skips)", err)
	scrubtest.Must(t, "Close (cache skips)", l.Close())
	scanDir(t, "evidence (cache skips)", evDir)
	scanDir(t, "state (cache skips)", stDir)
	var loaded *evidence.Record
	for _, f := range scanDir(t, "evidence (cache skips)", evDir) {
		raw, err := os.ReadFile(filepath.Join(evDir, f))
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
			var r evidence.Record
			if err := json.Unmarshal(line, &r); err != nil {
				t.Fatal(err)
			}
			if r.Kind == evidence.KindConfigure && r.Event == "bundle_loaded" {
				loaded = &r
			}
		}
	}
	if loaded == nil {
		t.Fatal("no bundle_loaded record")
	}
	var sources []string
	for _, bs := range loaded.BundleSources {
		sources = append(sources, bs.Source)
	}
	slices.Sort(sources)
	want := evidence.CacheSkipped{Count: 3, Reasons: []string{"digest_mismatch", "not_regular", "unverified"}}
	if !slices.Equal(sources, []string{"embedded", "local"}) || loaded.CacheSkipped == nil ||
		loaded.CacheSkipped.Count != want.Count || !slices.Equal(loaded.CacheSkipped.Reasons, want.Reasons) {
		t.Errorf("bundle_loaded sources %v, cache_skipped %+v; want [embedded local], %+v", sources, loaded.CacheSkipped, want)
	}
}

// versionRange re-signs the scrub bundle with a marker in its manifest
// provider.version_range: Configure must fail on the range
// without printing it, then the output dirs are scanned again.
func versionRange(t *testing.T, archive []byte, write func(string, []byte) string, outDirs map[string]string) {
	t.Helper()
	bad, err := bundletest.WithManifest(archive, testkeys.Bundle(), func(m *bundle.Manifest) error {
		m.Provider.VersionRange = ">= 2.0.0, < " + scrubtest.Marker(56)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("COMPLIANCETF_BUNDLE_PATH", write("scrub-range.tar.gz", bad))
	l := lifecycle.New(lifecycle.Options{ProviderVersion: "6.40.0"})
	warns, err := l.Configure(context.Background(), tftypes.NewValue(lifecycle.BlockType(), nil), "1.14.0", schemas(t))
	noLoadMarker(t, "Configure warnings (version_range)", strings.Join(warns, "\n"))
	if err == nil {
		t.Fatal("Configure with a marked version_range: no error")
	}
	scrubtest.NoMarker(t, "Configure error (version_range)", err.Error())
	if !strings.Contains(err.Error(), "outside the provider version range of bundle") {
		t.Errorf("Configure with a marked version_range: %s, want the range error", scrubtest.Mask(err.Error()))
	}
	for name, d := range outDirs {
		scanDir(t, name, d)
	}
}

// scopeRejected configures with the scrub sidecar, then on the same
// Lifecycle with a sidecar that carries a baseline block and a floor
// attribute, each with its own evidence and state dir. The
// second Configure fails with self_service_scope and its chain attests it
// with one value-free configure record, event exception_self_service_scope,
// and no bundle_loaded. The first snapshot is dropped: a plan after the
// rejection fails closed and writes no eval line into the rejection chain,
// and the rejection accepts nothing into its trust state. Markers sit in
// the label, the reason, the ticket and every scoped value; neither the
// error, the warnings nor any evidence or state file carries one.
func scopeRejected(t *testing.T, archive []byte, write func(string, []byte) string) {
	t.Helper()
	now := time.Now().UTC()
	exp := now.Add(30 * 24 * time.Hour).Format("2006-01-02")
	side := fmt.Sprintf(`exception %[1]q {
  controls  = ["scrub_fail"]
  match     = "size(resource.tags) == 1"
  workspace = %[2]q
  reason    = %[3]q
  ticket    = %[4]q
  expires   = %[5]q
  baseline {
    digest = %[6]q
  }
}
floor = %[6]q
`, scrubtest.Marker(92), scrubWorkspace, scrubtest.Marker(93), scrubtest.Marker(94), exp, scrubtest.Marker(95))
	t.Setenv("COMPLIANCETF_BUNDLE_PATH", write("scrub-scope.tar.gz", archive))
	dirs := func() (ev, st string) {
		root := t.TempDir()
		ev, st = filepath.Join(root, "evidence"), filepath.Join(root, "state")
		t.Setenv("COMPLIANCETF_EVIDENCE_DIR", ev)
		t.Setenv("COMPLIANCETF_STATE_DIR", st)
		return ev, st
	}
	dirs()
	t.Setenv("COMPLIANCETF_EXCEPTIONS_FILE", write("scope-good-exceptions.hcl", []byte(sidecar(now))))
	l := lifecycle.New(lifecycle.Options{ProviderVersion: "6.40.0"})
	warns, err := l.Configure(context.Background(), tftypes.NewValue(lifecycle.BlockType(), nil), "1.14.0", schemas(t))
	noLoadMarker(t, "Configure warnings (scope, first)", strings.Join(warns, "\n"))
	mustLoad(t, "Configure (scope, first)", err)

	evDir, stDir := dirs()
	t.Setenv("COMPLIANCETF_EXCEPTIONS_FILE", write("scope-exceptions.hcl", []byte(side)))
	warns, err = l.Configure(context.Background(), tftypes.NewValue(lifecycle.BlockType(), nil), "1.14.0", schemas(t))
	noLoadMarker(t, "Configure warnings (scope)", strings.Join(warns, "\n"))
	if err == nil || !strings.Contains(err.Error(), "self_service_scope: baseline at ") {
		t.Fatalf("Configure with a scoped sidecar: %v, want self_service_scope", err)
	}
	scrubtest.NoMarker(t, "Configure error (scope)", err.Error())
	if l.Configured() != nil {
		t.Error("a scope rejection kept a Configured snapshot")
	}
	c := cases[0]
	typ, v := c.value(t, schemas(t))
	val := func(b []byte) *hook.Value {
		return hook.NewValue(b, nil, func() (tftypes.Type, error) { return typ, nil })
	}
	mp := val(msgpack(t, typ, v))
	if _, err := l.Evaluate(context.Background(), &hook.Request{Stage: hook.StagePlan, Kind: hook.KindResource, TypeName: c.typ,
		Op: hook.OpCreate, Config: mp, Prior: val(msgpack(t, typ, tftypes.NewValue(typ, nil))), Planned: mp}); err == nil {
		t.Error("plan after a scope rejection: no error, want not configured")
	}
	scrubtest.Must(t, "Close (scope)", l.Close())
	if files := scanDir(t, "state (scope)", stDir); slices.Contains(files, "trust-state.json") {
		t.Errorf("state after a scope rejection %v, want no trust state accepted", files)
	}
	var kinds, events []string
	for _, f := range scanDir(t, "evidence (scope)", evDir) {
		raw, err := os.ReadFile(filepath.Join(evDir, f))
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
			var r evidence.Record
			if err := json.Unmarshal(line, &r); err != nil {
				t.Fatal(err)
			}
			kinds = append(kinds, string(r.Kind))
			if r.Kind == evidence.KindConfigure {
				events = append(events, r.Event)
				if r.Digests == nil || len(r.Digests.Bundles) == 0 || len(r.Digests.Exceptions) != 0 {
					t.Errorf("scope record digests %+v, want the loaded bundles and no exceptions digest", r.Digests)
				}
			}
		}
	}
	if !slices.Equal(events, []string{"exception_self_service_scope"}) || !slices.Equal(kinds, []string{"chain_start", "configure", "chain_end"}) {
		t.Errorf("rejection chain kinds %v, configure events %v; want chain_start, configure, chain_end and only exception_self_service_scope", kinds, events)
	}
}

// checkDiags asserts the case's own diagnostic at stage, rejects any
// timeout and scans every diagnostic.
func checkDiags(t *testing.T, c scrubCase, stage hook.Stage, diags []hook.Diagnostic) {
	t.Helper()
	out := fmt.Sprintf("%+v", diags)
	scrubtest.NoMarker(t, string(stage)+" diagnostics", out)
	if strings.Contains(out, "not evaluable (timeout)") {
		t.Errorf("%s: unexpected timeout: %s", stage, scrubtest.Mask(out))
	}
	want, _ := stageWant(c, stage)
	var own []string
	for _, d := range diags {
		if strings.HasPrefix(d.Summary, "["+c.id()+"] ") {
			own = append(own, d.Summary)
		}
	}
	if (want == "" && len(own) > 0) || (want != "" && !slices.Contains(own, want)) {
		t.Errorf("%s: own diagnostics %q, want %q", stage, scrubtest.Mask(fmt.Sprint(own)), want)
	}
}

// checkEvidence reads the eval records in call order (case by case, plan
// then apply_pre) and checks each case's own result.
func checkEvidence(t *testing.T, dir string) {
	t.Helper()
	var evals []evidence.Record
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(p) != ".jsonl" {
			return err
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		sc := bufio.NewScanner(bytes.NewReader(raw))
		sc.Buffer(nil, 1<<20)
		for sc.Scan() {
			var r evidence.Record
			if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
				return err
			}
			if r.Kind == evidence.KindEval {
				evals = append(evals, r)
			}
		}
		return sc.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(evals) != 2*len(cases) {
		t.Fatalf("%d eval records, want one per stage call (%d)", len(evals), 2*len(cases))
	}
	for i, c := range cases {
		for j, stage := range []hook.Stage{hook.StagePlan, hook.StageApplyPre} {
			r := evals[2*i+j]
			k := slices.IndexFunc(r.Results, func(x evidence.Result) bool { return x.Control == c.id() })
			if r.Stage != string(stage) || r.Resource == nil || r.Resource.Type != c.typ || k < 0 {
				t.Errorf("%s %s: record %d is %s %v without its result", c.name, stage, 2*i+j, r.Stage, r.Resource)
				continue
			}
			x := r.Results[k]
			paths := c.paths
			if c.state != engine.Unknown && c.state != engine.Pass {
				paths = c.reads // fail and not_evaluable record the declared reads
				if c.evPaths != nil {
					paths = c.evPaths // cut at a schema map attribute
				}
			}
			if paths == nil {
				paths = []string{}
			}
			_, exc := stageWant(c, stage)
			got := ""
			if x.Exception != nil {
				got = x.Exception.Source + "/" + x.Exception.Status
			}
			if x.State != c.state.String() || x.Err != string(c.class) || !slices.Equal(x.Paths, paths) || got != exc {
				t.Errorf("%s %s: evidence %s/%s %v exception %q, want %s/%s %v exception %q", c.name, stage,
					x.State, x.Err, scrubtest.Mask(fmt.Sprint(x.Paths)), got, c.state, c.class, paths, exc)
			}
		}
	}
}

// scanDir scans every regular file under dir, fails on any other file
// kind (symlink, device, socket, FIFO) and returns the relative paths.
func scanDir(t *testing.T, name, dir string) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if !d.Type().IsRegular() {
			t.Errorf("%s: %s is a %s, want a regular file", name, p, d.Type())
			return nil
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		files = append(files, filepath.ToSlash(rel))
		scrubtest.NoMarker(t, name+"/"+rel, string(raw))
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return files
}

func msgpack(t *testing.T, typ tftypes.Type, v tftypes.Value) []byte {
	t.Helper()
	dv, err := tfprotov5.NewDynamicValue(typ, v)
	if err != nil {
		t.Fatal(err)
	}
	return dv.MsgPack
}
