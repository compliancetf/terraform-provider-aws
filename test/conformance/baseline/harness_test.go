//go:build conformance

// Package baseline runs grandfather baseline end-to-end conformance:
// real Terraform or OpenTofu (-tf) plans and
// applies through the proxy (built with -tags conformance,ctftest) in front
// of test/fakeupstream, under a signed bundle and profiles, a baseline
// generated from the inventory join and signed, and a verdict, all with
// keys generated in code.
//
//	go test -count=1 -tags conformance ./test/conformance/baseline/... -tf "$(which terraform)"
//
// The shared harness and gate stand-in are test/conformance/harness.
package baseline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/verdict/verdicttest"
	"github.com/compliancetf/terraform-provider-aws/test/conformance/harness"
)

func TestMain(m *testing.M) { harness.Main(m, "ctf-baseline-conformance-") }

// run is one scenario (harness.Run) with this suite's helpers.
type run struct{ *harness.Run }

type (
	result     = harness.Result
	gate       = harness.Gate
	plan       = harness.Plan
	schema     = harness.Schema
	planChange = harness.PlanChange
)

// newRun writes mainTF into a fresh work dir, signs the bundle of controls
// and one profile per name in profiles (merged over baseProfile), and sets
// the lifecycle environment: state, cache and evidence dirs, offline. No
// profile is selected; use r.profile.
func newRun(t *testing.T, mainTF, controls string, profiles map[string]map[string]any) *run {
	t.Helper()
	r := &run{harness.NewRun(t)}
	work := r.Work
	if err := os.WriteFile(filepath.Join(work, "main.tf"), []byte(mainTF), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	src := filepath.Join(work, "bundle-src")
	if err := os.MkdirAll(src, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{"controls.json": []byte(controls), "manifest.json": harness.Payload(t, now, harness.BaseManifest(), nil)} {
		if err := os.WriteFile(filepath.Join(src, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	harness.Ctfbundle(t, "build", "-src", src, "-key", "test:bundle", "-out", filepath.Join(work, "bundle.tar.gz"))
	for name, over := range profiles {
		in := filepath.Join(work, "profile-"+name+".json")
		if err := os.WriteFile(in, harness.Payload(t, now, harness.BaseProfile(), over), 0o600); err != nil {
			t.Fatal(err)
		}
		harness.Ctfbundle(t, "sign", "-type", "profile", "-in", in, "-key", "test:profile", "-out", filepath.Join(work, "profile-"+name+".dsse.json"))
	}
	for _, d := range []string{"STATE", "CACHE"} {
		r.Env = append(r.Env, "COMPLIANCETF_"+d+"_DIR="+filepath.Join(work, strings.ToLower(d)))
	}
	r.Env = append(r.Env, "COMPLIANCETF_OFFLINE=true", "COMPLIANCETF_ORG_ID=bobthecorp",
		"COMPLIANCETF_BUNDLE_PATH="+filepath.Join(work, "bundle.tar.gz"),
		"COMPLIANCETF_CONFORMANCE_TAP="+filepath.Join(work, "tap.jsonl"),
		"COMPLIANCETF_CONFORMANCE_ENVELOPE="+filepath.Join(work, "envelope.json"))
	return r
}

// profile selects the signed profile name and an evidence dir of its own,
// so each phase's records are read alone.
func (r *run) profile(name, evidence string) {
	r.Env = append(r.Env, "COMPLIANCETF_PROFILE_PATH="+filepath.Join(r.Work, "profile-"+name+".dsse.json"),
		"COMPLIANCETF_EVIDENCE_DIR="+r.evidenceDir(evidence))
}

func (r *run) evidenceDir(name string) string { return filepath.Join(r.Work, "evidence-"+name) }

// records calls fn with each evidence record line under the named
// evidence dir, decoded into a fresh T.
func records[T any](r *run, evidence string, fn func(T)) {
	r.T.Helper()
	harness.Records(r.T, r.evidenceDir(evidence), fn)
}

// loaded is the binding the provider loaded under the named evidence dir
// (harness.Loaded).
func (r *run) loaded(evidence string) verdicttest.Binding {
	r.T.Helper()
	return harness.Loaded(r.T, r.evidenceDir(evidence))
}

// attrs is the state attributes of the root managed instance at address.
func (r *run) attrs(address string) map[string]any {
	r.T.Helper()
	typ, name, _ := strings.Cut(address, ".")
	rs, _ := r.State()["resources"].([]any)
	for _, x := range rs {
		res, _ := x.(map[string]any)
		if res["type"] == typ && res["name"] == name && res["mode"] == "managed" {
			insts, _ := res["instances"].([]any)
			if len(insts) == 1 {
				in, _ := insts[0].(map[string]any)
				a, _ := in["attributes"].(map[string]any)
				return a
			}
		}
	}
	r.T.Fatalf("no single state instance at %s", address)
	return nil
}
