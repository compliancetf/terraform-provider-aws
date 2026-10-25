//go:build conformance

package baseline

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
	"github.com/compliancetf/terraform-provider-aws/internal/verdict"
	"github.com/compliancetf/terraform-provider-aws/internal/verdict/verdicttest"
)

// namedTF: two fake_named instances whose native identity {name} differs
// from their id (bobthecorp-<name>); both violate the size control. The
// provider binds the scope from region and the one allowed account id.
const namedTF = `terraform {
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

resource "fake_named" "logs" {
  name  = "logs"
  size  = 20
  crash = var.crash
}

resource "fake_named" "other" {
  name  = "other"
  size  = 30
  crash = var.crash
}
`

// namedControls: a deny on size, baseline-coverable, effective so apply_post
// re-checks the applied state.
const namedControls = `[{"id": "fake_named_size_max", "version": "1.0.0", "kind": "resource", "resource_type": "fake_named",
  "reads": ["size"], "presence_mode": "effective", "on": ["create", "update"],
  "expr": "resource.size != null && resource.size <= 10", "action": "deny", "severity": "high",
  "message": "fake_named size must be at most 10.", "fix": "Set size to 10 or less.", "exemption_coverable": ["baseline"]}]`

func key(t *testing.T, use string) verdicttest.Key {
	k := verdicttest.NewKey(t, time.Now().Add(-24*time.Hour))
	k.Signer.Use = use
	return k
}

func signers(ks ...verdicttest.Key) []profile.SignerKey {
	out := make([]profile.SignerKey, len(ks))
	for i, k := range ks {
		out[i] = k.Signer
	}
	return out
}

// TestBaselineNativeIdentity: an observation of pre-existing
// violating instances, the inventory join and a signed baseline for
// fake_named.logs, whose identity {name: logs} differs from its id. The
// entry carries the identity object, not the id; the next run's update of
// that instance (crash only, outside the control reads) is grandfathered
// at apply under mode grandfather. Without the entry listed, and for the
// unbaselined fake_named.other, the same apply blocks before upstream.
// Plan warns the violating update as a pending baseline exemption, so this
// needs baseline plan eligibility: without it plan, and apply's re-plan, error.
func TestBaselineNativeIdentity(t *testing.T) {
	vk, bl, rc := key(t, "verdict"), key(t, verdict.UseBaseline), key(t, verdict.UseReceipt)
	trust := map[string]any{"verdict": map[string]any{"public_keys": signers(vk)},
		"baseline":    map[string]any{"public_keys": signers(bl), "max_days": 90},
		"break_glass": map[string]any{"enabled": false, "receipt_keys": signers(rc)}}
	withMode := func(m string) map[string]any {
		p := maps.Clone(trust)
		p["mode_floor"] = map[string]any{"default": m}
		return p
	}
	r := newRun(t, namedTF, namedControls, map[string]map[string]any{"grandfather": withMode("grandfather"), "soft": withMode("soft_fail")})

	// Pre-existing violations: created under soft_fail, before any baseline.
	r.profile("soft", "seed")
	r.Must("apply", "-no-color", "-input=false", "-auto-approve")
	if id := r.attrs("fake_named.logs")["id"]; id != "bobthecorp-logs" {
		t.Fatalf("fake_named.logs id %v, want bobthecorp-logs", id)
	}

	// Observation: a refreshed no-op plan under the grandfather profile.
	r.profile("grandfather", "observation")
	r.Env = append(r.Env, "COMPLIANCETF_RUN_ID=bobthecorp-obs-1") // the observation run ctfkit names
	obs := r.SavePlan("observation")
	controls, err := bundle.ParseControls([]byte(namedControls))
	if err != nil {
		t.Fatal(err)
	}
	bkey := make([]byte, 32)
	if _, err := rand.Read(bkey); err != nil {
		t.Fatal(err)
	}
	inv := r.generate(obs, "observation", "prod", controls, bkey)
	if len(inv.Rows) != 2 {
		t.Fatalf("inventory rows %+v, want one per violating instance", inv.Rows)
	}
	gf := r.loaded("observation") // the grandfather profile binding the verdicts carry
	doc, digests := r.signBaseline(obs, "observation", inv, []string{"fake_named.logs"}, bl, rc, bkey)

	if len(doc.Entries) != 1 {
		t.Fatalf("baseline entries %+v, want fake_named.logs only", doc.Entries)
	}
	e := doc.Entries[0]
	raw, err := json.Marshal(e.Identity)
	if err != nil {
		t.Fatal(err)
	}
	if e.IdentityKind != "identity" || !maps.Equal(e.Identity, map[string]string{"name": "logs"}) || strings.Contains(string(raw), "bobthecorp-logs") {
		t.Fatalf("entry identity_kind %q identity %s: want the identity object {name: logs}, not the id", e.IdentityKind, raw)
	}
	if e.Scope != (inv.Rows[0].Scope) || e.Scope.AccountID != "111122223333" || e.Scope.Region != "us-east-1" || e.Workspace != "prod" {
		t.Fatalf("entry scope %+v workspace %q, want the provider configuration's and prod", e.Scope, e.Workspace)
	}

	// The next run: under grandfather, plan (and apply's own re-plan) warns
	// the violating update as a pending baseline exemption; apply
	// decides it.
	apply := func(name, target string, listed bool) result {
		t.Helper()
		r.Env = append(r.Env, "COMPLIANCETF_RUN_ID=bobthecorp-run-"+name) // a run other than the observation
		r.profile("grandfather", "plan-"+name)
		g := r.GatePlan(name, "-target="+target, "-var", "crash=false")
		if len(g.Instances) != 1 || g.Instances[0].Action != "update" || g.Instances[0].PriorIdentityKind != verdict.KindIdentity {
			t.Fatalf("%s: verdict entries %+v, want one update of kind identity", name, g.Instances)
		}
		var top []string
		edit := func([]verdict.Instance) {}
		if listed {
			top = digests
			edit = func(ins []verdict.Instance) { ins[0].Baselines = digests }
		}
		r.GateSign(g, vk, gf, edit, nil, top...)
		r.profile("grandfather", "apply-"+name)
		return r.TF("apply", "-no-color", "-input=false", g.File)
	}
	blocked := func(res result, address string) {
		t.Helper()
		out := strings.Join(strings.Fields(res.Stderr), " ")
		if res.Exit == 0 || !strings.Contains(out, "fake_named size must be at most 10.") || !strings.Contains(out, "Stage: apply_pre") {
			t.Fatalf("%s: exit %d, want blocked by fake_named_size_max\n--- stdout\n%s--- stderr\n%s", address, res.Exit, res.Stdout, res.Stderr)
		}
		if c := r.attrs(address)["crash"]; c != nil {
			t.Fatalf("%s: blocked apply changed crash to %v", address, c)
		}
	}
	blocked(apply("other", "fake_named.other", true), "fake_named.other")   // no entry for its identity
	blocked(apply("unlisted", "fake_named.logs", false), "fake_named.logs") // entry not listed by the verdict

	res := apply("logs", "fake_named.logs", true)
	if res.Exit != 0 {
		t.Fatalf("grandfathered apply: exit %d\n--- stdout\n%s--- stderr\n%s", res.Exit, res.Stdout, res.Stderr)
	}
	if c := r.attrs("fake_named.logs")["crash"]; c != false {
		t.Fatalf("fake_named.logs crash %v after the grandfathered apply, want false", c)
	}
	var failed bool // the violation was present at apply_pre: grandfathered, not passed
	records(r, "apply-logs", func(rec evRecord) {
		for _, x := range rec.Results {
			failed = failed || rec.Stage == "apply_pre" && x.Control == "fake_named_size_max" && x.State == "fail"
		}
	})
	if !failed {
		t.Fatal("no apply_pre evidence result fail for fake_named_size_max: the apply passed without grandfathering")
	}
	postApplyWarned(t, r, res, "apply-logs", 1)
}

// postApplyWarned asserts the grandfathered apply res re-checked the
// applied state at apply_post: one fake_named_size_max result on each of n
// distinct instances, failing with decision post_apply_violation, surfaced
// as a warning (Stage: apply_post), not an error.
func postApplyWarned(t *testing.T, r *run, res result, evidence string, n int) {
	t.Helper()
	var got int
	instances := map[string]bool{}
	records(r, evidence, func(rec evRecord) {
		for _, x := range rec.Results {
			if rec.Stage == "apply_post" && x.Control == "fake_named_size_max" {
				if x.State != "fail" || x.Decision != "post_apply_violation" || rec.Resource == nil {
					t.Fatalf("apply_post fake_named_size_max: state %q decision %q resource %v, want fail post_apply_violation on an instance", x.State, x.Decision, rec.Resource)
				}
				id := ""
				if rec.Resource.ID != nil {
					id = *rec.Resource.ID
				}
				instances[fmt.Sprint(rec.Resource.IdentityKind, rec.Resource.Identity, id)] = true
				got++
			}
		}
	})
	if got != n || len(instances) != n {
		t.Fatalf("apply_post fake_named_size_max results %d on %d distinct instances %v, want %d on %d", got, len(instances), instances, n, n)
	}
	out := strings.Join(strings.Fields(res.Stdout+res.Stderr), " ")
	if strings.Contains(out, "Error:") || !strings.Contains(out, "Warning:") ||
		!strings.Contains(out, "fake_named size must be at most 10.") || !strings.Contains(out, "Stage: apply_post") {
		t.Fatalf("grandfathered apply: want an apply_post warning for fake_named_size_max and no error\n--- stdout\n%s--- stderr\n%s", res.Stdout, res.Stderr)
	}
}
