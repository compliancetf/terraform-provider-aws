//go:build conformance

// Package verdict runs verdict end-to-end conformance: real Terraform or
// OpenTofu (-tf) plans and applies
// through the proxy (built with -tags conformance,ctftest) in front of
// test/fakeupstream, under a signed profile and bundle and a verdict signed
// with keys generated in code (internal/verdict/verdicttest).
//
//	go test -count=1 -tags conformance ./test/conformance/verdict/... -tf "$(which terraform)"
//
// The shared harness and gate stand-in are test/conformance/harness.
package verdict

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/verdict/verdicttest"
	"github.com/compliancetf/terraform-provider-aws/test/conformance/harness"
)

func TestMain(m *testing.M) { harness.Main(m, "ctf-verdict-conformance-") }

// defaultControls deny a fake_thing size above 10 on create and update (a
// bundle holds at least one control).
const defaultControls = `[{"id": "fake_thing_size_max", "version": "1.0.0", "kind": "resource", "resource_type": "fake_thing",
  "reads": ["size"], "presence_mode": "effective", "on": ["create", "update"],
  "expr": "resource.size != null && resource.size <= 10", "action": "deny", "severity": "high",
  "message": "fake_thing size must be at most 10.", "fix": "Set size to 10 or less.", "exemption_coverable": []}]`

// runOpt configures a run's trust inputs. Profile is merged last (over
// the Keys and Required fields; null deletes a field), Floor over the base
// floor (nil: no floor file), Bundle over the base manifest.
type runOpt struct {
	Controls string            // controls.json of the signed bundle; "" defaultControls
	Keys     []verdicttest.Key // profile verdict.public_keys
	Required bool              // profile verdict_required
	Profile  map[string]any
	Floor    map[string]any
	Bundle   map[string]any
	State    string // a seeded terraform.tfstate; "" none
}

// run is one scenario (harness.Run) with this suite's helpers.
type run struct{ *harness.Run }

type (
	result = harness.Result
	gate   = harness.Gate
)

// newRun writes mainTF (and opt.State) into a fresh work dir, signs the
// bundle and profile (and floor) with the ctftest keys and sets the
// lifecycle environment: empty state, cache and evidence dirs, offline.
func newRun(t *testing.T, mainTF string, opt runOpt) *run {
	t.Helper()
	r := &run{harness.NewRun(t)}
	work := r.Work
	files := map[string]string{"main.tf": mainTF}
	if opt.State != "" {
		files["terraform.tfstate"] = opt.State
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(work, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	src := filepath.Join(work, "bundle-src")
	controls := opt.Controls
	if controls == "" {
		controls = defaultControls
	}
	if err := os.MkdirAll(src, 0o700); err != nil {
		t.Fatal(err)
	}
	srcFiles := map[string][]byte{"controls.json": []byte(controls), "manifest.json": harness.Payload(t, now, harness.BaseManifest(), opt.Bundle)}
	if strings.Contains(controls, `"kind": "graph"`) {
		srcFiles["graph.json"] = []byte(`{"edges":[]}`) // graph controls load only with a signed graph.json
	}
	for name, body := range srcFiles {
		if err := os.WriteFile(filepath.Join(src, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	harness.Ctfbundle(t, "build", "-src", src, "-key", "test:bundle", "-out", filepath.Join(work, "bundle.tar.gz"))
	prof := harness.BaseProfile()
	prof["verdict_required"] = opt.Required
	if len(opt.Keys) > 0 {
		keys := make([]any, len(opt.Keys))
		for i, k := range opt.Keys {
			keys[i] = k.Signer
		}
		prof["verdict"] = map[string]any{"public_keys": keys}
	}
	signed := []struct {
		kind       string
		base, over map[string]any
	}{{"profile", prof, opt.Profile}}
	if opt.Floor != nil {
		signed = append(signed, struct {
			kind       string
			base, over map[string]any
		}{"floor", baseFloor(), opt.Floor})
	}
	for _, p := range signed {
		in := filepath.Join(work, p.kind+".json")
		if err := os.WriteFile(in, harness.Payload(t, now, p.base, p.over), 0o600); err != nil {
			t.Fatal(err)
		}
		harness.Ctfbundle(t, "sign", "-type", p.kind, "-in", in, "-key", "test:"+p.kind, "-out", filepath.Join(work, p.kind+".dsse.json"))
	}
	for _, d := range []string{"STATE", "CACHE", "EVIDENCE"} {
		r.Env = append(r.Env, "COMPLIANCETF_"+d+"_DIR="+filepath.Join(work, strings.ToLower(d)))
	}
	r.Env = append(r.Env, "COMPLIANCETF_OFFLINE=true", "COMPLIANCETF_ORG_ID=bobthecorp",
		"COMPLIANCETF_PROFILE_PATH="+filepath.Join(work, "profile.dsse.json"),
		"COMPLIANCETF_BUNDLE_PATH="+filepath.Join(work, "bundle.tar.gz"),
		"COMPLIANCETF_CONFORMANCE_TAP="+filepath.Join(work, "tap.jsonl"),
		"COMPLIANCETF_CONFORMANCE_ENVELOPE="+filepath.Join(work, "envelope.json"))
	if opt.Floor != nil {
		r.Env = append(r.Env, "COMPLIANCETF_FLOOR_PATH="+filepath.Join(work, "floor.dsse.json"))
	}
	return r
}

// loaded is the binding the provider loaded, read from the evidence
// records after any Configure (harness.Loaded).
func (r *run) loaded() verdicttest.Binding {
	r.T.Helper()
	return harness.Loaded(r.T, filepath.Join(r.Work, "evidence"))
}

// envelope sets the envelope edit the conformance proxy applies to every
// ApplyResourceChange (internal/proxy/tap_conformance.go); "" removes it.
func (r *run) envelope(edit string) {
	r.T.Helper()
	p := filepath.Join(r.Work, "envelope.json")
	err := os.Remove(p)
	if errors.Is(err, fs.ErrNotExist) {
		err = nil
	}
	if err == nil && edit != "" {
		err = os.WriteFile(p, []byte(edit), 0o600)
	}
	if err != nil {
		r.T.Fatal(err)
	}
}

func baseFloor() map[string]any {
	return map[string]any{"format": "compliancetf.floor/v1", "org_id": "bobthecorp", "min_profile_version": 0,
		"bundles": map[string]any{}, "min_wrapper_version": "", "keyring_digest": ctftestKeyringDigest(),
		"epoch": 1, "revocation_epoch": 0, "retired_keys": []string{}, "issued_at": "-1h", "expires_at": "23h"}
}

// ctftestKeyringDigest is the keyring digest of the ctftest proxy build, as
// internal/trust/embed_ctftest.go computes it (this test binary is not
// built with ctftest).
func ctftestKeyringDigest() string {
	h := sha256.New()
	h.Write([]byte("compliancetf.keyring-digest/ctftest\x00"))
	for _, name := range []string{"keyring.json", "keyring_test.json"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "..", "internal", "trust", name))
		if err != nil {
			panic(err) // the repo is the test's working tree
		}
		h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(b))))
		h.Write(b)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}
