//go:build conformance

package baseline

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/verdict"
)

const bootstrapProvider = `terraform {
  required_providers {
    fake = { source = "registry.compliance.tf/compliancetf/aws" }
  }
}

provider "fake" {
  region              = "us-east-1"
  allowed_account_ids = ["111122223333"]
}

variable "crash" {
  type    = bool
  default = null
}
`

// bootstrapSeedTF: the pre-existing instances, every one violating
// fake_named_size_max (fake_replace_size_max for swap); kept also violates
// the advisory fake_named_ro, which is not baseline-coverable.
const bootstrapSeedTF = bootstrapProvider + `
resource "fake_named" "logs" {
  name  = "logs"
  size  = 20
  crash = var.crash
}

resource "fake_named" "kept" {
  name  = "kept-ro"
  size  = 30
  crash = var.crash
}

resource "fake_named" "old" {
  name = "old"
  size = 40
}

resource "fake_named" "pending" {
  name  = "pending"
  size  = 50
  crash = var.crash
}

resource "fake_named" "gone" {
  name = "gone"
  size = 60
}

resource "fake_replace" "swap" {
  name = "swap-a"
  size = 70
}
`

// bootstrapObservationTF: logs and kept unchanged (no-op); fresh created,
// swap replaced, imported imported (a no-op violating the name control),
// old moved to moved (a no-op), gone forgotten, pending's size unknown.
const bootstrapObservationTF = bootstrapProvider + `
resource "fake_named" "logs" {
  name  = "logs"
  size  = 20
  crash = var.crash
}

resource "fake_named" "kept" {
  name  = "kept-ro"
  size  = 30
  crash = var.crash
}

resource "fake_named" "fresh" {
  name = "fresh"
  size = 80
}

resource "fake_named" "pending" {
  name  = "pending"
  size  = length(fake_named.fresh.id)
  crash = var.crash
}

import {
  to = fake_named.imported
  id = "legacy-imp"
}

resource "fake_named" "imported" {
  name = "legacy-imp"
}

moved {
  from = fake_named.old
  to   = fake_named.moved
}

resource "fake_named" "moved" {
  name = "old"
  size = 40
}

removed {
  from = fake_named.gone
  lifecycle {
    destroy = false
  }
}

resource "fake_replace" "swap" {
  name = "swap-b"
  size = 70
}
`

// bootstrapControls: size denies on fake_named and fake_replace and a
// name deny on fake_named, all baseline-coverable, and fake_named_ro, an
// advisory without baseline in its coverable list; all effective, as in
// namedControls.
const bootstrapControls = `[
 {"id": "fake_named_size_max", "version": "1.0.0", "kind": "resource", "resource_type": "fake_named",
  "reads": ["size"], "presence_mode": "effective", "on": ["create", "update"],
  "expr": "resource.size != null && resource.size <= 10", "action": "deny", "severity": "high",
  "message": "fake_named size must be at most 10.", "fix": "Set size to 10 or less.", "exemption_coverable": ["baseline"]},
 {"id": "fake_named_legacy_name", "version": "1.0.0", "kind": "resource", "resource_type": "fake_named",
  "reads": ["name"], "presence_mode": "effective", "on": ["create", "update"],
  "expr": "!resource.name.startsWith('legacy-')", "action": "deny", "severity": "high",
  "message": "fake_named name must not start with legacy-.", "fix": "Rename it.", "exemption_coverable": ["baseline"]},
 {"id": "fake_named_ro", "version": "1.0.0", "kind": "resource", "resource_type": "fake_named",
  "reads": ["name"], "presence_mode": "effective", "on": ["create", "update"],
  "expr": "!resource.name.endsWith('-ro')", "action": "warn", "severity": "low",
  "message": "fake_named name should not end with -ro.", "fix": "Rename it.", "exemption_coverable": []},
 {"id": "fake_replace_size_max", "version": "1.0.0", "kind": "resource", "resource_type": "fake_replace",
  "reads": ["size"], "presence_mode": "effective", "on": ["create", "update"],
  "expr": "resource.size != null && resource.size <= 10", "action": "deny", "severity": "high",
  "message": "fake_replace size must be at most 10.", "fix": "Set size to 10 or less.", "exemption_coverable": ["baseline"]}
]`

// candidate is an artifact set's candidate.json: what gate plan left.
type candidate struct {
	Kind       string `json:"kind"` // observation or apply
	RunID      string `json:"run_id"`
	PlanDigest string `json:"plan_digest"`
	Planfile   string `json:"planfile"`
}

// artifactSet writes the artifact set of p (kind observation or apply) to
// its own dir and returns the dir.
func (r *run) artifactSet(name, kind, runID string, p *plan) string {
	r.T.Helper()
	dir := filepath.Join(r.Work, "set-"+name)
	b, err := json.Marshal(candidate{Kind: kind, RunID: runID, PlanDigest: p.Digest, Planfile: p.File})
	if err == nil {
		err = os.MkdirAll(dir, 0o700)
	}
	if err == nil {
		err = os.WriteFile(filepath.Join(dir, "candidate.json"), b, 0o600)
	}
	if err != nil {
		r.T.Fatal(err)
	}
	return dir
}

// signable is the gate sign stand-in's first check: only an apply
// candidate is signed; an observation authorizes baseline signing only
// (ctfkit exits 2).
func (r *run) signable(set string) bool {
	r.T.Helper()
	return r.candidate(set).Kind == "apply"
}

func (r *run) candidate(set string) candidate {
	r.T.Helper()
	var c candidate
	b, err := os.ReadFile(filepath.Join(set, "candidate.json"))
	if err == nil {
		err = json.Unmarshal(b, &c)
	}
	if err != nil {
		r.T.Fatal(err)
	}
	return c
}

// ctfkitApply is the `ctfkit apply` stand-in: it refuses (exit 2, before
// Terraform runs) a set whose candidate is not kind apply, and otherwise
// applies the candidate's planfile.
func (r *run) ctfkitApply(set string) result {
	r.T.Helper()
	if c := r.candidate(set); c.Kind == "apply" {
		return r.TF("apply", "-no-color", "-input=false", c.Planfile)
	}
	return result{Exit: 2, Stderr: "ctfkit apply: the artifact set is an observation; it authorizes baseline signing, never an apply\n"}
}

func (r *run) writeMain(tf string) {
	r.T.Helper()
	if err := os.WriteFile(filepath.Join(r.Work, "main.tf"), []byte(tf), 0o600); err != nil {
		r.T.Fatal(err)
	}
}

func (r *run) stateBytes() []byte {
	r.T.Helper()
	b, err := os.ReadFile(filepath.Join(r.Work, "terraform.tfstate"))
	if err != nil {
		r.T.Fatal(err)
	}
	return b
}

// TestBaselineBootstrap (E1): from a state with violations and no
// baseline, grant or receipt, an observation (a refreshed plan under the
// grandfather profile) that mutates nothing and whose artifact set gate
// sign and ctfkit apply refuse; generate selects only the pre-existing
// no-op instances, so the created, replaced, imported, moved, forgotten
// and pending ones get no entry, nor does the advisory without baseline in
// its coverable list; the signed baseline then grandfathers the observed
// instances through the next gate plan, gate sign and apply, while the
// pending instance, never observed, stays blocked.
func TestBaselineBootstrap(t *testing.T) {
	vk, bl, rc := key(t, "verdict"), key(t, verdict.UseBaseline), key(t, verdict.UseReceipt)
	trust := map[string]any{"verdict": map[string]any{"public_keys": signers(vk)},
		"baseline":    map[string]any{"public_keys": signers(bl), "max_days": 90},
		"break_glass": map[string]any{"enabled": false, "receipt_keys": signers(rc)}}
	withMode := func(m string) map[string]any {
		p := maps.Clone(trust)
		p["mode_floor"] = map[string]any{"default": m}
		return p
	}
	r := newRun(t, bootstrapSeedTF, bootstrapControls, map[string]map[string]any{"grandfather": withMode("grandfather"), "soft": withMode("soft_fail")})

	// Pre-existing violations, created under soft_fail: no baseline, grant
	// or receipt exists yet.
	r.profile("soft", "seed")
	r.Must("apply", "-no-color", "-input=false", "-auto-approve")
	if _, err := os.Stat(filepath.Join(r.Work, "baseline.json")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a baseline before the bootstrap: %v", err)
	}

	// Observation: `ctfkit baseline generate` runs gate plan itself, refresh on.
	r.writeMain(bootstrapObservationTF)
	before := r.stateBytes()
	r.profile("grandfather", "observation")
	const obsRun = "bobthecorp-obs-1"
	r.Env = append(r.Env, "COMPLIANCETF_RUN_ID="+obsRun)
	obs := r.SavePlan("observation")
	obsSet := r.artifactSet("observation", "observation", obsRun, obs)

	// It mutates nothing: state as before, no apply stage reached upstream.
	if !bytes.Equal(r.stateBytes(), before) {
		t.Fatal("the observation changed terraform.tfstate")
	}
	records(r, "observation", func(rec evRecord) {
		if strings.HasPrefix(rec.Stage, "apply") {
			t.Fatalf("observation evidence at stage %s: the observation reached apply", rec.Stage)
		}
	})

	// Its artifact set is never signed and never applied.
	if r.signable(obsSet) {
		t.Fatal("gate sign accepts the observation artifact set")
	}
	if res := r.ctfkitApply(obsSet); res.Exit != 2 {
		t.Fatalf("ctfkit apply of the observation set: exit %d, want 2", res.Exit)
	}
	if _, err := os.Stat(filepath.Join(r.Work, "gate")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a verdict was written for the observation: %v", err)
	}
	if !bytes.Equal(r.stateBytes(), before) {
		t.Fatal("the refused apply changed terraform.tfstate")
	}

	// Every excluded instance is in the observation, with its action, and
	// fails (pending: unknown) at plan, so each exclusion below is exercised.
	actions := map[string]string{}
	moved := map[string]bool{}
	imported := map[string]bool{}
	for _, c := range obs.Doc.ResourceChanges {
		if c.Mode == "managed" && c.Deposed == "" {
			actions[c.Address] = strings.Join(c.Change.Actions, ",")
			moved[c.Address], imported[c.Address] = c.PreviousAddress != "", len(c.Change.Importing) > 0
		}
	}
	for addr, want := range map[string]string{"fake_named.logs": "no-op", "fake_named.kept": "no-op", "fake_named.fresh": "create",
		"fake_replace.swap": "delete,create", "fake_named.imported": "no-op", "fake_named.moved": "no-op", "fake_named.gone": "forget",
		"fake_named.pending": "update"} {
		if actions[addr] != want {
			t.Fatalf("observation plan %s: actions %q, want %q (all %v)", addr, actions[addr], want, actions)
		}
	}
	if !moved["fake_named.moved"] || !imported["fake_named.imported"] {
		t.Fatalf("observation plan: moved %v imported %v", moved, imported)
	}
	results := map[string][]string{} // "<op> <control>" -> states
	noopFails := map[string]bool{}   // addresses with a no-op fake_named_size_max fail
	sch := r.Schemas()
	records(r, "observation", func(rec evRecord) {
		if rec.Kind != "eval" || rec.Resource == nil {
			return
		}
		for _, x := range rec.Results {
			k := rec.Resource.Op + " " + x.Control
			results[k] = append(results[k], x.State)
			if k == "no-op fake_named_size_max" && x.State == "fail" && rec.Stage == "plan" {
				noopFails[r.join(obs, sch, rec).Address] = true
			}
		}
	})
	for k, want := range map[string]string{"create fake_named_size_max": "fail", "replace fake_replace_size_max": "fail",
		"update fake_named_size_max": "unknown", "import fake_named_legacy_name": "fail", "no-op fake_named_ro": "fail"} {
		if !slices.Contains(results[k], want) {
			t.Fatalf("observation evidence %q: states %v, want a %s (all %v)", k, results[k], want, results)
		}
	}
	// logs, kept and the moved instance are the no-op size failures; gone is
	// forgotten, so the provider sees no plan for it at all.
	if got, want := slices.Sorted(maps.Keys(noopFails)), []string{"fake_named.kept", "fake_named.logs", "fake_named.moved"}; !slices.Equal(got, want) {
		t.Fatalf("observation evidence: no-op fake_named_size_max fails on %v, want %v", got, want)
	}

	controls, err := bundle.ParseControls([]byte(bootstrapControls))
	if err != nil {
		t.Fatal(err)
	}
	bkey := make([]byte, 32)
	if _, err := rand.Read(bkey); err != nil {
		t.Fatal(err)
	}
	inv := r.generate(obs, "observation", "prod", controls, bkey)
	var got []string
	for _, w := range inv.Rows {
		got = append(got, w.Address+" "+w.Control)
	}
	slices.Sort(got)
	if want := []string{"fake_named.kept fake_named_size_max", "fake_named.logs fake_named_size_max"}; !slices.Equal(got, want) {
		t.Fatalf("inventory rows %v, want %v", got, want)
	}
	gf := r.loaded("observation")
	_, digests := r.signBaseline(obs, "observation", inv, []string{"fake_named.logs", "fake_named.kept"}, bl, rc, bkey)
	if len(digests) != 2 {
		t.Fatalf("baseline entries %d, want 2", len(digests))
	}

	// The next run: back to the pre-existing configuration; an update of
	// each observed instance outside the control reads.
	r.writeMain(bootstrapSeedTF)
	next := func(name string, targets ...string) (*gate, result) {
		t.Helper()
		run := "bobthecorp-run-" + name
		r.Env = append(r.Env, "COMPLIANCETF_RUN_ID="+run)
		r.profile("grandfather", "plan-"+name)
		args := []string{"-var", "crash=false"}
		for _, a := range targets {
			args = append(args, "-target="+a)
		}
		g := r.GatePlan(name, args...)
		if len(g.Instances) != len(targets) {
			t.Fatalf("%s: verdict entries %+v, want one update per target", name, g.Instances)
		}
		for _, in := range g.Instances {
			if in.Action != "update" {
				t.Fatalf("%s: verdict entries %+v, want one update per target", name, g.Instances)
			}
		}
		set := r.artifactSet(name, "apply", run, g.Plan)
		if !r.signable(set) {
			t.Fatalf("%s: gate sign refuses an apply set", name)
		}
		r.GateSign(g, vk, gf, func(ins []verdict.Instance) {
			for i := range ins {
				ins[i].Baselines = digests
			}
		}, nil, digests...)
		r.profile("grandfather", "apply-"+name)
		return g, r.ctfkitApply(set)
	}

	// pending was observed with an unknown size: it has no entry and stays blocked.
	if _, res := next("pending", "fake_named.pending"); res.Exit == 0 ||
		!strings.Contains(strings.Join(strings.Fields(res.Stderr), " "), "fake_named size must be at most 10.") {
		t.Fatalf("fake_named.pending: exit %d, want blocked by fake_named_size_max\n--- stdout\n%s--- stderr\n%s", res.Exit, res.Stdout, res.Stderr)
	}
	if c := r.attrs("fake_named.pending")["crash"]; c != nil {
		t.Fatalf("fake_named.pending: blocked apply changed crash to %v", c)
	}

	_, res := next("observed", "fake_named.logs", "fake_named.kept")
	if res.Exit != 0 {
		t.Fatalf("grandfathered apply: exit %d\n--- stdout\n%s--- stderr\n%s", res.Exit, res.Stdout, res.Stderr)
	}
	for _, a := range []string{"fake_named.logs", "fake_named.kept"} {
		if c := r.attrs(a)["crash"]; c != false {
			t.Fatalf("%s crash %v after the grandfathered apply, want false", a, c)
		}
	}
	fails := map[string]bool{} // the violations were present at apply_pre: grandfathered, not passed
	records(r, "apply-observed", func(rec evRecord) {
		for _, x := range rec.Results {
			if rec.Stage == "apply_pre" && rec.Resource != nil && x.Control == "fake_named_size_max" && x.State == "fail" {
				id := ""
				if rec.Resource.ID != nil {
					id = *rec.Resource.ID
				}
				fails[fmt.Sprint(rec.Resource.IdentityKind, rec.Resource.Identity, id)] = true
			}
		}
	})
	if len(fails) != 2 {
		t.Fatalf("apply_pre fake_named_size_max fails on %d distinct instances %v, want 2 (logs, kept)", len(fails), fails)
	}
	postApplyWarned(t, r, res, "apply-observed", 2)
}
