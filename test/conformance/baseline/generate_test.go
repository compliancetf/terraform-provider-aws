//go:build conformance

package baseline

// An in-repo stand-in for `ctfkit baseline generate` and `ctfkit baseline
// sign`: the inventory join of the observation's
// provider evidence records, its plan and the control set, then a signed
// compliancetf.baseline/v1 written from the inventory rows only.

import (
	"encoding/hex"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/baseline"
	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/verdict/verdicttest"
	"github.com/compliancetf/terraform-provider-aws/test/conformance/harness"
)

// inventory is inventory.json: rows bound to the observation's plan and
// content digests.
type inventory struct {
	RunID         string `json:"run_id"`
	PlanDigest    string `json:"plan_digest"`
	ContentDigest string `json:"content_digest"`
	Rows          []row  `json:"rows"`
}

// row is one observed_fail (instance, control).
type row struct {
	State                 string            `json:"state"` // observed_fail
	Address               string            `json:"address"`
	Type                  string            `json:"type"`
	IdentityKind          string            `json:"identity_kind"`
	Identity              map[string]string `json:"identity"`
	Workspace             string            `json:"workspace"`
	Scope                 baseline.Scope    `json:"scope"`
	Control               string            `json:"control"`
	ControlMajor          string            `json:"control_major"`
	ControlManifestDigest string            `json:"control_manifest_digest"`
	ReadDigest            string            `json:"read_digest"`
}

// evRecord is the part of a provider evidence record the join reads.
type evRecord struct {
	Kind     string              `json:"kind"`
	Stage    string              `json:"stage"`
	Run      struct{ ID string } `json:"run"`
	Resource *struct {
		ID           *string           `json:"id"`
		Identity     map[string]string `json:"identity"`
		IdentityKind string            `json:"identity_kind"`
		Op           string            `json:"op"`
		Type         string            `json:"type"`
	} `json:"resource"`
	Results []struct {
		Control, Version, State, Decision string
	} `json:"results"`
}

// generate joins the observation obs (its plan and the provider evidence
// under the named dir) with controls (the verified set) into inventory
// rows: each plan record of a no-op instance with a fail result of a
// control whose coverable list holds baseline joins exactly one no-op plan
// instance of its type with the same native identity, from the plan's prior
// state; workspace is the checked flag, account and region the provider
// configuration; an instance the plan moves gets no row (the provider
// records an imported one with op import). A missing or ambiguous join, an
// unknown scope or a control outside the set fails (ctfkit exits 2).
func (r *run) generate(obs *plan, evidence, workspace string, controls []bundle.Control, key []byte) inventory {
	r.T.Helper()
	inv := inventory{PlanDigest: obs.Digest, ContentDigest: r.loaded(evidence).ContentDigest, Rows: []row{}}
	scope := r.providerScope(obs)
	sch := r.Schemas()
	seen := map[string]bool{}
	records(r, evidence, func(rec evRecord) {
		if rec.Kind != "eval" || rec.Stage != "plan" || rec.Resource == nil || rec.Resource.Op != "no-op" {
			return // only pre-existing no-op instances are observed
		}
		if inv.RunID != "" && inv.RunID != rec.Run.ID {
			r.T.Fatalf("baseline generate: evidence of runs %s and %s: not one observation", inv.RunID, rec.Run.ID)
		}
		inv.RunID = rec.Run.ID
		for _, res := range rec.Results {
			if res.State != "fail" {
				continue
			}
			i := slices.IndexFunc(controls, func(c bundle.Control) bool { return c.ID == res.Control && c.Version == res.Version })
			if i < 0 {
				r.T.Fatalf("baseline generate: control %s@%s is outside the verified control set", res.Control, res.Version)
			}
			ctl := &controls[i]
			if !slices.Contains(ctl.ExemptionCoverable, bundle.ExemptionKind("baseline")) {
				continue // no row for a control that is not baseline-coverable
			}
			c := r.join(obs, sch, rec)
			if c.PreviousAddress != "" {
				continue // moved this run: not a pre-existing instance at its address
			}
			if seen[c.Address+"\x00"+ctl.ID] {
				continue // the same instance recorded again (another plan walk)
			}
			seen[c.Address+"\x00"+ctl.ID] = true
			kind, idJSON, err := harness.PriorIdentity(sch[c.Type], c)
			var identity map[string]string
			if err == nil {
				err = json.Unmarshal(idJSON, &identity)
			}
			if err != nil {
				r.T.Fatalf("baseline generate: %s: %v", c.Address, err)
			}
			// shortcut: read_digest from the plan's prior state with the
			// baseline key, until it is in the
			// provider evidence record.
			prior, _, err := harness.PlannedValue(sch[c.Type], c.Change.Before, nil)
			if err != nil {
				r.T.Fatal(err)
			}
			rd, ok := baseline.ReadDigest(key, ctl.Reads, prior)
			if !ok {
				r.T.Fatalf("baseline generate: %s has an unknown read", c.Address)
			}
			manifest, err := json.Marshal(ctl)
			var md string
			if err == nil {
				md, err = bundle.DigestJSON(manifest)
			}
			if err != nil {
				r.T.Fatal(err)
			}
			major, _, _ := strings.Cut(ctl.Version, ".")
			inv.Rows = append(inv.Rows, row{State: "observed_fail", Address: c.Address, Type: c.Type, IdentityKind: kind, Identity: identity,
				Workspace: workspace, Scope: scope, Control: ctl.ID, ControlMajor: major, ControlManifestDigest: md, ReadDigest: rd})
		}
	})
	return inv
}

// join is the one no-op plan instance of rec's type whose native identity
// equals the record's (identity object, else id).
func (r *run) join(obs *plan, sch map[string]schema, rec evRecord) planChange {
	r.T.Helper()
	var hits []planChange
	for _, c := range obs.Doc.ResourceChanges {
		if c.Mode != "managed" || c.Type != rec.Resource.Type || c.Deposed != "" || !slices.Equal(c.Change.Actions, []string{"no-op"}) {
			continue
		}
		kind, idJSON, err := harness.PriorIdentity(sch[c.Type], c)
		var identity map[string]string
		if err != nil || json.Unmarshal(idJSON, &identity) != nil {
			continue
		}
		switch {
		case kind != rec.Resource.IdentityKind:
		case kind == "identity" && maps.Equal(identity, rec.Resource.Identity):
			hits = append(hits, c)
		case kind == "id" && rec.Resource.ID != nil && identity["id"] == *rec.Resource.ID:
			hits = append(hits, c)
		}
	}
	if len(hits) != 1 {
		r.T.Fatalf("baseline generate: a %s evidence record joins %d plan instances, want 1 (missing or ambiguous join)", rec.Resource.Type, len(hits))
	}
	return hits[0]
}

// providerScope is account_id and region from the observation's provider
// configuration: one constant allowed_account_ids element and a constant
// region, else the scope is unknown.
func (r *run) providerScope(obs *plan) baseline.Scope {
	r.T.Helper()
	exprs := obs.Doc.Configuration.ProviderConfig["fake"].Expressions
	var s baseline.Scope
	var ids []string
	if json.Unmarshal(exprs["region"].ConstantValue, &s.Region) != nil || json.Unmarshal(exprs["allowed_account_ids"].ConstantValue, &ids) != nil ||
		len(ids) != 1 || s.Region == "" {
		r.T.Fatal("baseline generate: unknown scope (account_id or region)")
	}
	s.AccountID = ids[0]
	return s
}

// signBaseline is `baseline sign`: it checks the inventory is bound to the
// observation and the content digest the provider verified, then writes
// one entry per row of an approved address with an approver statement
// (receipt key rc) bound to the observation and the row's scope, signs the
// document with the baseline key bl and points the run at it and the
// baseline key file. It returns the document and each entry's digest.
func (r *run) signBaseline(obs *plan, evidence string, inv inventory, approved []string, bl, rc verdicttest.Key, key []byte) (baseline.Document, []string) {
	r.T.Helper()
	if inv.PlanDigest != obs.Digest || inv.ContentDigest != r.loaded(evidence).ContentDigest || inv.RunID == "" {
		r.T.Fatal("baseline sign: the inventory is not bound to the observation's run, plan and content digests")
	}
	now := time.Now().UTC().Truncate(time.Second)
	issued := now.Add(-time.Minute).Format(time.RFC3339)
	doc := baseline.Document{Format: baseline.Format, OrgID: "bobthecorp", IssuedAt: issued, ContentDigest: inv.ContentDigest, Entries: []baseline.Entry{}}
	var digests []string
	for _, w := range inv.Rows {
		if !slices.Contains(approved, w.Address) {
			continue
		}
		const approver = "alice@bobthecorp.example"
		st := baseline.Statement{Format: baseline.StatementFormat, OrgID: doc.OrgID, Role: baseline.RoleApprover, Subject: approver,
			Workspace: w.Workspace, Scope: w.Scope, RunID: inv.RunID, PlanDigest: inv.PlanDigest, ContentDigest: inv.ContentDigest, IssuedAt: issued}
		e := baseline.Entry{Workspace: w.Workspace, Scope: w.Scope, Type: w.Type, IdentityKind: w.IdentityKind, Identity: w.Identity,
			Address: w.Address, Control: w.Control, ControlMajor: w.ControlMajor, ControlManifestDigest: w.ControlManifestDigest,
			ReadDigest: w.ReadDigest, Approver: approver, Expires: now.Add(30 * 24 * time.Hour).Format(time.RFC3339), Ticket: "BOB-56"}
		if err := json.Unmarshal(signed(r, rc, st), &e.ApproverStatement); err != nil {
			r.T.Fatal(err)
		}
		b, err := json.Marshal(e)
		var d string
		if err == nil {
			d, err = bundle.DigestJSON(b)
		}
		if err != nil {
			r.T.Fatal(err)
		}
		doc.Entries, digests = append(doc.Entries, e), append(digests, d)
	}
	file, keyFile := filepath.Join(r.Work, "baseline.json"), filepath.Join(r.Work, "baseline.key")
	if err := os.WriteFile(file, signed(r, bl, doc), 0o600); err != nil {
		r.T.Fatal(err)
	}
	if err := os.WriteFile(keyFile, []byte(hex.EncodeToString(key)+"\n"), 0o600); err != nil {
		r.T.Fatal(err)
	}
	r.Env = append(r.Env, baseline.EnvFile+"="+file, baseline.EnvKeyFile+"="+keyFile)
	return doc, digests
}

// signed returns v signed by k (its signature member replaced).
func signed(r *run, k verdicttest.Key, v any) []byte {
	r.T.Helper()
	b, err := json.Marshal(v)
	var m map[string]json.RawMessage
	if err == nil {
		err = json.Unmarshal(b, &m)
	}
	if err != nil {
		r.T.Fatal(err)
	}
	delete(m, "signature")
	sig, err := json.Marshal(verdicttest.Signature(r.T, k.Priv, k.Signer.KID, m))
	if err != nil {
		r.T.Fatal(err)
	}
	m["signature"] = sig
	out, err := json.Marshal(m)
	if err != nil {
		r.T.Fatal(err)
	}
	return out
}
