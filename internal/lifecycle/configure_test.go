//go:build ctftest

package lifecycle

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/evidence"
	"github.com/compliancetf/terraform-provider-aws/internal/fetch"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
	"github.com/compliancetf/terraform-provider-aws/internal/trust/testkeys"
)

var configureNow = time.Date(2026, 10, 6, 6, 0, 0, 0, time.UTC)

// configureCase is one testdata/configure golden. Profiles and the floor are
// payload overrides (null deletes a key) signed at run time with the ctftest
// keys, so a case states only what it changes.
type configureCase struct {
	Block           map[string]string          `json:"block"`
	Env             map[string]string          `json:"env"`
	Profiles        map[string]json.RawMessage `json:"profiles"` // env, hcl, cache/v<n>
	Floor           json.RawMessage            `json:"floor"`
	State           map[string]int64           `json:"state_profiles"`  // org -> accepted profile version
	Cache           []string                   `json:"cache_bundles"`   // testdata/bundles/<name>.tar.gz
	Service         map[string]string          `json:"service_bundles"` // bundle_id -> testdata/bundles/<name>; also serves the floor
	ProviderVersion string                     `json:"provider_version"`
	UpstreamVersion *string                    `json:"upstream_version"` // nil: 6.40.0
	Want            struct {
		Error          string   `json:"error"`
		RunMode        string   `json:"run_mode"`
		Fallback       string   `json:"fallback"`
		Governed       bool     `json:"governed"`
		ProfileVersion int64    `json:"profile_version"`
		FloorEpoch     int64    `json:"floor_epoch"`
		Bundles        []string `json:"bundles"`
		Warnings       []string `json:"warnings"`
		Events         []string `json:"events"`  // configure evidence events; checked when set
		Sources        []string `json:"sources"` // sorted bundle_sources of bundle_loaded; checked when set
	} `json:"want"`
}

var fallbackNames = []string{"free_tier", "profile_applied", "hard_fail_floor"}

func TestConfigure(t *testing.T) {
	files, _ := filepath.Glob("testdata/configure/*.json")
	if len(files) == 0 {
		t.Fatal("no configure goldens")
	}
	for _, f := range files {
		t.Run(strings.TrimSuffix(filepath.Base(f), ".json"), func(t *testing.T) { checkConfigureGolden(t, f) })
	}
}

// TestFloorPendingPersistsHighWater: a floor whose revocation bundle is
// withheld fails Configure but its (generation, epoch) is persisted, so a
// replayed older floor is refused on the next run.
func TestFloorPendingPersistsHighWater(t *testing.T) {
	var c configureCase
	raw, err := os.ReadFile("testdata/configure/floor-revocation-pending.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	stateDir := t.TempDir()
	c.Env = map[string]string{"COMPLIANCETF_STATE_DIR": stateDir}
	if _, _, err := runConfigure(t, c); !errors.Is(err, trust.ErrFloorRevocationPending) {
		t.Fatalf("configure: %v", err)
	}
	s, err := trust.LoadState(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if m := s.Floors["bobthecorp"]; m.Epoch != 1 {
		t.Fatalf("pending floor mark %+v not persisted", s.Floors)
	}
}

// TestStubsConfigure runs the goldens: grandfather is accepted with
// its warning, a set COMPLIANCETF_BREAK_GLASS fails Configure; and:
// each verdict, baseline or break_glass profile setting this version cannot honor is a warning;
// and: a baseline file without its key file fails Configure.
func TestStubsConfigure(t *testing.T) {
	for _, n := range []string{"grandfather-no-baseline", "break-glass-set", "phase3-settings-warn", "baseline-no-key"} {
		t.Run(n, func(t *testing.T) { checkConfigureGolden(t, "testdata/configure/"+n+".json") })
	}
}

func checkConfigureGolden(t *testing.T, f string) {
	t.Helper()
	var c configureCase
	raw, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	cfg, warns, err := runConfigure(t, c)
	w := c.Want
	if w.Error != "" {
		if err == nil || !strings.Contains(err.Error(), w.Error) {
			t.Fatalf("error %v, want %q", err, w.Error)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{"run_mode": cfg.Table.RunMode.String(), "fallback": fallbackNames[cfg.Resolution.Fallback],
		"governed": cfg.Resolution.Governed, "profile_version": int64(0), "floor_epoch": int64(0)}
	if p := cfg.Resolution.Profile; p != nil {
		got["profile_version"] = p.ProfileVersion
	}
	if cfg.Floor != nil {
		got["floor_epoch"] = cfg.Floor.Epoch
	}
	want := map[string]any{"run_mode": w.RunMode, "fallback": w.Fallback, "governed": w.Governed,
		"profile_version": w.ProfileVersion, "floor_epoch": w.FloorEpoch}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
	// The trust state records exactly the bundles of the control set.
	s, err := trust.LoadState(os.Getenv("COMPLIANCETF_STATE_DIR"))
	if err != nil {
		t.Fatal(err)
	}
	var loaded []string
	for id, v := range s.Bundles {
		loaded = append(loaded, fmt.Sprintf("%s@%d", id, v))
	}
	slices.Sort(loaded)
	if !slices.Equal(loaded, w.Bundles) {
		t.Errorf("bundles %v, want %v", loaded, w.Bundles)
	}
	var sources []string
	for _, bs := range cfg.Sources {
		sources = append(sources, bs.Source)
	}
	slices.Sort(sources)
	if w.Sources != nil && !slices.Equal(sources, w.Sources) {
		t.Errorf("bundle sources %v, want %v", sources, w.Sources)
	}
	if w.Events != nil && !slices.Equal(cfg.Events, w.Events) {
		t.Errorf("events %v, want %v", cfg.Events, w.Events)
	}
	all := strings.Join(warns, "\n")
	for _, s := range w.Warnings {
		if !strings.Contains(all, s) {
			t.Errorf("warning %q missing in:\n%s", s, all)
		}
	}
}

func runConfigure(t *testing.T, c configureCase) (*Configured, []string, error) {
	t.Helper()
	dir := t.TempDir()
	for _, k := range []string{"COMPLIANCETF_ENFORCEMENT_MODE", "COMPLIANCETF_ORG_ID", "COMPLIANCETF_GOVERNED", "COMPLIANCETF_TOKEN",
		"COMPLIANCETF_OFFLINE", "COMPLIANCETF_PROFILE_PATH", "COMPLIANCETF_FLOOR_PATH", "COMPLIANCETF_ENVIRONMENT",
		"COMPLIANCETF_WORKSPACE", "COMPLIANCETF_BUNDLE_PATH", "COMPLIANCETF_EXCEPTIONS_FILE", "COMPLIANCETF_MIN_BUNDLE_VERSION",
		"COMPLIANCETF_MIN_PROFILE_VERSION"} {
		t.Setenv(k, "")
	}
	t.Setenv("COMPLIANCETF_BREAK_GLASS", "")
	os.Unsetenv("COMPLIANCETF_BREAK_GLASS") //nolint:errcheck,usetesting // any value, even empty, fails Configure; t.Setenv above restores it
	grandfatherWarned.Store(false)          // the warning is once per process
	t.Setenv("COMPLIANCETF_STATE_DIR", filepath.Join(dir, "state"))
	t.Setenv("COMPLIANCETF_CACHE_DIR", filepath.Join(dir, "cache"))
	t.Setenv("COMPLIANCETF_EVIDENCE_DIR", filepath.Join(dir, "evidence"))
	for k, v := range c.Env {
		t.Setenv(k, v)
	}
	for where, over := range c.Profiles {
		path := filepath.Join(dir, where+".dsse.json")
		switch {
		case where == "env":
			t.Setenv("COMPLIANCETF_PROFILE_PATH", path)
		case where == "hcl":
			c.Block["profile_path"] = path
		case strings.HasPrefix(where, "cache/"):
			path = filepath.Join(dir, "cache", "profiles", "bobthecorp", strings.TrimPrefix(where, "cache/")+".dsse.json")
		}
		writeFile(t, path, signed(t, trust.PayloadProfile, merge(t, baseProfile(), over), testkeys.Profile()))
	}
	if c.State != nil {
		if _, err := trust.UpdateState(filepath.Join(dir, "state"), trust.State{Profiles: c.State}); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range c.Cache {
		raw, err := os.ReadFile("../../testdata/bundles/" + name + ".tar.gz")
		if err != nil {
			t.Fatal(err)
		}
		b, err := bundle.ReadArchive(raw, func(env []byte, pt string) (trust.Verified, error) {
			return trust.Verify(env, pt, trust.NoRevocations())
		})
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(dir, "cache", "bundles", "sha256-"+strings.TrimPrefix(b.Digest, "sha256:")+".tar.gz"), raw)
	}
	var floorEnv []byte
	if c.Floor != nil {
		path := filepath.Join(dir, "floor.dsse.json")
		floorEnv = signed(t, trust.PayloadFloor, merge(t, baseFloor(), c.Floor), testkeys.Floor())
		writeFile(t, path, floorEnv)
		t.Setenv("COMPLIANCETF_FLOOR_PATH", path)
	}
	if c.Service != nil {
		serve(t, c.Service, floorEnv)
	}
	block := tftypes.NewValue(BlockType(), nil)
	if c.Block != nil {
		vals := map[string]tftypes.Value{}
		for _, a := range blockAttrs {
			var v any
			if s, ok := c.Block[a]; ok {
				v = s
			}
			vals[a] = tftypes.NewValue(tftypes.String, v)
		}
		block = tftypes.NewValue(BlockType(), vals)
	}
	if c.ProviderVersion == "" {
		c.ProviderVersion = "6.40.0"
	}
	upstream := "6.40.0"
	if c.UpstreamVersion != nil {
		upstream = *c.UpstreamVersion
	}
	l := New(Options{ProviderVersion: c.ProviderVersion, WrapperName: "compliancetf/aws", UpstreamName: "hashicorp/aws", UpstreamVersion: upstream, Now: func() time.Time { return configureNow }})
	warns, err := l.Configure(context.Background(), block, "1.14.0", nil)
	if cerr := l.Close(); cerr != nil {
		t.Fatal(cerr)
	}
	// A successful Configure writes one schema-valid configure record per
	// event, bundle_loaded first; a failed one writes none.
	var events []string
	var loaded *evidence.Record
	for _, r := range readChain(t, filepath.Join(dir, "evidence")) {
		if r.Kind == evidence.KindConfigure {
			events = append(events, r.Event)
			if r.Event == "bundle_loaded" {
				loaded = &r
			} else if r.BundleSources != nil || r.CacheSkipped != nil {
				t.Errorf("%s record carries bundle_sources or cache_skipped", r.Event)
			}
		}
	}
	var want []string
	if cfg := l.Configured(); err == nil && cfg != nil {
		want = cfg.Events
		if len(want) == 0 || want[0] != "bundle_loaded" {
			t.Errorf("events %v: want bundle_loaded first", want)
		}
		// bundle_loaded names the source of every loaded bundle, in digest
		// order, and the skipped cache archives.
		var digests []string
		if loaded != nil {
			for _, bs := range loaded.BundleSources {
				digests = append(digests, bs.Digest)
			}
		}
		if loaded == nil || !slices.Equal(digests, cfg.Bundles) || loaded.CacheSkipped == nil || loaded.CacheSkipped.Count != cfg.Skipped.Count {
			t.Errorf("bundle_loaded %+v: want the sources of %v and the cache skips", loaded, cfg.Bundles)
		}
		if (cfg.Resolution.OrgID != "" && cfg.Resolution.Profile == nil) != slices.Contains(want, "profile_missing") {
			t.Errorf("events %v: profile_missing must match an org without a profile", want)
		}
	}
	if !slices.Equal(events, want) {
		t.Errorf("configure events %v, want %v", events, want)
	}
	return l.Configured(), warns, err
}

func baseProfile() map[string]any {
	return map[string]any{"format": "compliancetf.profile/v1", "org_id": "bobthecorp", "profile_version": 5,
		"issued_at": "2026-10-01T00:00:00Z", "expires_at": "2026-10-30T00:00:00Z", "governed": false,
		"mode_floor":       map[string]any{"default": "soft_fail", "environments": map[string]string{"prod": "hard_fail"}},
		"verdict_required": false, "exceptions": map[string]any{"max_lifetime_days": 30},
		"evidence": map[string]any{"required": false, "sinks": []any{}},
		"budgets":  map[string]any{"per_resource_ms": 200, "per_run_s": 120}}
}

func baseFloor() map[string]any {
	return map[string]any{"format": "compliancetf.floor/v1", "org_id": "bobthecorp", "min_profile_version": 0,
		"bundles": map[string]int64{}, "min_wrapper_version": "", "keyring_digest": trust.KeyringDigest(),
		"epoch": 1, "revocation_epoch": 0, "retired_keys": []string{},
		"issued_at": "2026-10-06T00:00:00Z", "expires_at": "2026-10-07T00:00:00Z"}
}

func merge(t *testing.T, base map[string]any, over json.RawMessage) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(over, &m); err != nil {
		t.Fatal(err)
	}
	for k, v := range m {
		if v == nil {
			delete(base, k)
		} else {
			base[k] = v
		}
	}
	b, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// signed is a one-signature DSSE envelope: ES256 over SHA-256(PAE), Ed25519
// over the raw PAE.
func signed(t *testing.T, payloadType string, payload []byte, key crypto.Signer) []byte {
	t.Helper()
	pae := trust.PAE(payloadType, payload)
	var sig []byte
	var err error
	if _, ok := key.(ed25519.PrivateKey); ok {
		sig, err = key.Sign(rand.Reader, pae, crypto.Hash(0))
	} else {
		sum := sha256.Sum256(pae)
		sig, err = key.Sign(rand.Reader, sum[:], crypto.SHA256)
	}
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]any{"payloadType": payloadType, "payload": base64.StdEncoding.EncodeToString(payload),
		"signatures": []map[string]string{{"keyid": trust.KIDFromSPKI(der), "sig": base64.StdEncoding.EncodeToString(sig)}}})
	return b
}

func writeFile(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(fmt.Errorf("write %s: %w", path, err))
	}
}

// serve is the bundle service: GET .../bundles/<id> returns the named
// archive, GET .../floor the signed floor; anything else is 503.
func serve(t *testing.T, bundles map[string]string, floor []byte) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/v1/orgs/bobthecorp/bundles/")
		switch {
		case r.URL.Path == "/v1/orgs/bobthecorp/floor" && floor != nil:
			w.Header().Set("Content-Type", "application/json")
			w.Write(floor) //nolint:errcheck,gosec // test server
		case bundles[id] != "":
			raw, err := os.ReadFile("../../testdata/bundles/" + bundles[id] + ".tar.gz")
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/gzip")
			w.Write(raw) //nolint:errcheck,gosec // test server
		default:
			http.Error(w, "unavailable", http.StatusServiceUnavailable) // transient: profile falls back
		}
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(fetch.SetTestEndpoint(srv.URL, srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs))
}
