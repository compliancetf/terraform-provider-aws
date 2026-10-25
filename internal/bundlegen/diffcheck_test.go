package bundlegen

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
)

const diffcheckDir = "testdata/diffcheck"

// diffcheckOutput translates and synthesizes every intent of in into one
// bundle "test", plus the extra controls (with their cases).
func diffcheckOutput(t *testing.T, s Schemas, in Intents, extra ...bundle.Control) *Output {
	t.Helper()
	var cs []bundle.Control
	var cases []Case
	for _, it := range in.Policies {
		sc, _ := s.Resource(it.ResourceType)
		c, ri, err := Translate(it, sc)
		if err != nil || ri != nil {
			t.Fatalf("translate %s: %v %v", it.ID, err, ri)
		}
		// the shared fields Generate fills
		c.Severity, c.Message, c.ExemptionCoverable = bundle.SeverityHigh, "Fixture control.", []bundle.ExemptionKind{}
		cs = append(cs, c)
		cases = append(cases, synth(t, s, c)...)
	}
	for _, c := range extra {
		cs = append(cs, c)
		cases = append(cases, synth(t, s, c)...)
	}
	slices.SortFunc(cs, func(a, b bundle.Control) int { return strings.Compare(a.ID, b.ID) })
	return bundleOutput(t, cs, cases)
}

func loadDiffcheckInputs(t *testing.T) (Intents, PolicyFixtures, []DiffAllow) {
	t.Helper()
	in, err := LoadIntents(filepath.Join(diffcheckDir, "intents.json"))
	if err != nil {
		t.Fatal(err)
	}
	pf, err := LoadPolicyFixtures(filepath.Join(diffcheckDir, "policy-fixtures.json"))
	if err != nil {
		t.Fatal(err)
	}
	allow, err := LoadDiffAllow(filepath.Join(diffcheckDir, "diffcheck-allow.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return in, pf, allow
}

func findingKeys(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Code+" "+f.Control+" "+f.Case+": "+f.Detail)
	}
	return out
}

// TestDiffcheck is the oracle and the he01 check. The rds sample's
// intent (non-empty username) is narrower than its content postcondition
// (username != "admin"): the replayed content fixture "admin" passes the
// control and fails the postcondition, and the synthesized null username
// fails the control and passes the postcondition. The s3 sample agrees on
// every case; a control without an intent is skipped.
func TestDiffcheck(t *testing.T) {
	s := subsetSchemas(t)
	in, pf, _ := loadDiffcheckInputs(t)
	authored := testControl("ctf_authored", "aws_db_instance", "resource.storage_encrypted == true", bundle.PresenceEffective, "storage_encrypted")
	out := diffcheckOutput(t, s, in, authored)
	rep, err := Diffcheck(out, in, pf, nil, s, verifyEngine())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"W_DIFFCHECK_SKIPPED ctf_authored : no content postcondition for the control",
		"E_DIFFCHECK_MISMATCH rds_db_instance_no_default_admin_name fail: cel fail, postcondition pass",
		"E_DIFFCHECK_MISMATCH rds_db_instance_no_default_admin_name policy.non_compliant_admin: cel pass, postcondition fail",
	}
	if got := findingKeys(rep.Findings); !slices.Equal(got, want) {
		t.Fatalf("findings:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if !rep.Failed() {
		t.Fatal("a mismatch must fail diffcheck")
	}
	for _, f := range rep.Findings {
		if f.Bundle != "test" {
			t.Fatalf("finding %v: bundle %q", f, f.Bundle)
		}
	}
	data, err := rep.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"admin"`) || strings.Contains(string(data), "dbadmin") {
		t.Fatalf("diffcheck.json carries a fixture value:\n%s", data)
	}
}

// TestDiffcheckAllow: an allow entry turns its mismatch into a warning, the
// unmatched mismatch still fails, an entry for the reverse direction does
// not mask it, and an entry matching nothing is stale.
func TestDiffcheckAllow(t *testing.T) {
	s := subsetSchemas(t)
	in, pf, allow := loadDiffcheckInputs(t)
	allow = append(allow, DiffAllow{ID: "s3_bobthecorp_versioning_on", Case: "pass", CEL: "pass", Postcondition: "fail", Reason: "stale"},
		// the reverse direction of the null-username mismatch: it must not mask it
		DiffAllow{ID: "rds_db_instance_no_default_admin_name", Case: "fail", CEL: "pass", Postcondition: "fail", Reason: "reverse"})
	rep, err := Diffcheck(diffcheckOutput(t, s, in), in, pf, allow, s, verifyEngine())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"W_DIFFCHECK_STALE rds_db_instance_no_default_admin_name fail: the allow entry matches no difference",
		"W_DIFFCHECK_STALE s3_bobthecorp_versioning_on pass: the allow entry matches no difference",
		"E_DIFFCHECK_MISMATCH rds_db_instance_no_default_admin_name fail: cel fail, postcondition pass",
		"W_DIFFCHECK_ALLOWED rds_db_instance_no_default_admin_name policy.non_compliant_admin: cel pass, postcondition fail, allowed",
	}
	if got := findingKeys(rep.Findings); !slices.Equal(got, want) {
		t.Fatalf("findings:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	allow = append(allow[:1], DiffAllow{ID: "rds_db_instance_no_default_admin_name", Case: "fail", CEL: "fail", Postcondition: "pass", Reason: "null username"})
	rep, err = Diffcheck(diffcheckOutput(t, s, in), in, pf, allow, s, verifyEngine())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Failed() {
		t.Fatalf("every mismatch is allowed, got %v", findingKeys(rep.Findings))
	}
}

// TestDiffcheckEval: a postcondition that does not parse or calls an
// unimplemented function and a policy fixture that does not decode are
// reported, not compared; a policy without fixtures is a warning.
func TestDiffcheckEval(t *testing.T) {
	s := subsetSchemas(t)
	in, pf, _ := loadDiffcheckInputs(t)
	out := diffcheckOutput(t, s, in)
	bad := in
	bad.Policies = slices.Clone(in.Policies)
	bad.Policies[0].Postcondition = "try(nosuchfunc(self.username), true)"                                                              // try would hide it at run time
	bad.Policies[1].Postcondition = "self.versioning_configuration =="                                                                  // does not parse
	bad.Policies = append(bad.Policies, Intent{ID: "ctf_nope", ResourceType: "aws_db_instance", Postcondition: "try(self.nope, true)"}) // a validate error in Terraform
	nope := testControl("ctf_nope", "aws_db_instance", "config.username != null && size(config.username) > 0", bundle.PresenceConfigured, "username")
	rep, err := Diffcheck(diffcheckOutput(t, s, in, nope), bad, pf, nil, s, verifyEngine())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"E_DIFFCHECK_EVAL ctf_nope : postcondition self reference: Unsupported attribute",
		"E_DIFFCHECK_EVAL rds_db_instance_no_default_admin_name : postcondition calls nosuchfunc, which diffcheck does not implement",
		"E_DIFFCHECK_EVAL s3_bobthecorp_versioning_on : postcondition does not parse: Missing expression",
	}
	if got := findingKeys(rep.Findings); !slices.Equal(got, want) {
		t.Fatalf("findings:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	pf.Policies = []PolicyFixture{{ID: "rds_db_instance_no_default_admin_name", ResourceType: "aws_db_instance",
		Cases: []PolicyCase{{Name: "typo", Resource: []byte(`{"usernam": "x"}`)}, {Name: "ok", Resource: []byte(`{"username": "x"}`)}}}}
	in.Policies[0].Postcondition = "try(length(self.username) > 0, false)"                                                        // agrees on every case
	pf.Policies = append(pf.Policies, PolicyFixture{ID: "s3_bobthecorp_versioning_on", ResourceType: "aws_s3_bucket_versioning"}) // no cases
	rep, err = Diffcheck(out, in, pf, nil, s, verifyEngine())
	if err != nil {
		t.Fatal(err)
	}
	want = []string{
		"E_DIFFCHECK_EVAL rds_db_instance_no_default_admin_name policy.typo: the policy fixture does not decode against the schema",
		"W_DIFFCHECK_NO_POLICY_FIXTURES s3_bobthecorp_versioning_on : no policy fixtures; only bundle cases are compared",
	}
	if got := findingKeys(rep.Findings); !slices.Equal(got, want) {
		t.Fatalf("findings:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// TestDiffcheckKind: policy fixtures for a non-resource control (data
// sources still load-gated, so a deletion guard) are not replayed, with a
// detail naming the kind.
func TestDiffcheckKind(t *testing.T) {
	s := subsetSchemas(t)
	ds := testControl("ctf_ds", "aws_db_instance", "prior.storage_encrypted == true", bundle.PresenceEffective, "storage_encrypted")
	ds.Kind, ds.On, ds.PresenceMode = bundle.KindDeletionGuard, []bundle.On{bundle.OnDelete}, ""
	in := Intents{Policies: []Intent{{ID: "ctf_ds", ResourceType: "aws_db_instance", Postcondition: "true"}}}
	pf := PolicyFixtures{Policies: []PolicyFixture{{ID: "ctf_ds", ResourceType: "aws_db_instance", Cases: []PolicyCase{{Name: "x", Resource: []byte(`{}`)}}}}}
	rep, err := Diffcheck(bundleOutput(t, []bundle.Control{ds}, nil), in, pf, nil, s, verifyEngine())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"E_DIFFCHECK_NO_COMPARISON ctf_ds : the control has a postcondition but no bundle case or policy fixture was compared",
		"W_DIFFCHECK_NO_POLICY_FIXTURES ctf_ds : policy fixtures are resource values; a deletion_guard control does not replay them",
	}
	if got := findingKeys(rep.Findings); !slices.Equal(got, want) || !rep.Failed() {
		t.Fatalf("findings (failed %v):\n%s\nwant:\n%s", rep.Failed(), strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// TestDiffcheckNoComparison: a resource control with a postcondition, no
// bundle case and no policy fixture compares nothing and fails; one with
// bundle cases but no policy fixture only warns.
func TestDiffcheckNoComparison(t *testing.T) {
	s := subsetSchemas(t)
	c := testControl("ctf_bare", "aws_db_instance", "resource.storage_encrypted == true", bundle.PresenceEffective, "storage_encrypted")
	in := Intents{Policies: []Intent{{ID: "ctf_bare", ResourceType: "aws_db_instance", Postcondition: "self.storage_encrypted == true"}}}
	rep, err := Diffcheck(bundleOutput(t, []bundle.Control{c}, nil), in, PolicyFixtures{}, nil, s, verifyEngine())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"E_DIFFCHECK_NO_COMPARISON ctf_bare : the control has a postcondition but no bundle case or policy fixture was compared",
		"W_DIFFCHECK_NO_POLICY_FIXTURES ctf_bare : no policy fixtures; only bundle cases are compared",
	}
	if got := findingKeys(rep.Findings); !slices.Equal(got, want) || !rep.Failed() {
		t.Fatalf("findings (failed %v):\n%s\nwant:\n%s", rep.Failed(), strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	rep, err = Diffcheck(bundleOutput(t, []bundle.Control{c}, synth(t, s, c)), in, PolicyFixtures{}, nil, s, verifyEngine())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Failed() {
		t.Fatalf("bundle cases were compared, got %v", findingKeys(rep.Findings))
	}
}

// TestPostconditionReferences: references are checked against the
// resource schema before evaluation, as Terraform's validate does, so try
// and can cannot turn an invalid self path into a pass.
func TestPostconditionReferences(t *testing.T) {
	s := subsetSchemas(t)
	sc, _ := s.Resource("aws_s3_bucket_versioning")
	for src, want := range map[string]string{
		`self.bucket != ""`: "",
		`contains(["Enabled"], one(self.versioning_configuration).status)`: "",
		`self.versioning_configuration[0].status == "Enabled"`:             "",
		`length(self.versioning_configuration[*].status) == 1`:             "",
		`try(self.nope, true)`:                        "self reference: Unsupported attribute",
		`can(self.versioning_configuration[0].nope)`:  "self reference: Unsupported attribute",
		`self.versioning_configuration.status == "x"`: "self reference: Invalid operation",
		`self["bucket"] == "x"`:                       "self reference: Invalid index operation",
		`try(self.bucket.nope, true)`:                 "self reference: Unsupported attribute",
		`try(var.x, true)`:                            "references var, which diffcheck does not bind",
	} {
		p, err := parsePostcondition(src)
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		got := ""
		if err := p.validateSelf(sc.Block); err != nil {
			got = err.Error()
		}
		if got != want {
			t.Errorf("%s: got %q, want %q", src, got, want)
		}
	}
}

// TestPostconditionFuncs pins the Terraform semantics of the local
// functions and of results that are not a known bool.
func TestPostconditionFuncs(t *testing.T) {
	obj := tftypes.Object{AttributeTypes: map[string]tftypes.Type{"a": tftypes.String, "b": tftypes.String}}
	set := tftypes.Set{ElementType: tftypes.String}
	self := tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{
		"s": tftypes.String, "u": tftypes.String, "l": tftypes.List{ElementType: tftypes.String}, "set": set, "obj": obj,
	}}, map[string]tftypes.Value{
		"s":   tftypes.NewValue(tftypes.String, "bobthecorp"),
		"u":   tftypes.NewValue(tftypes.String, tftypes.UnknownValue),
		"l":   tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, []tftypes.Value{tftypes.NewValue(tftypes.String, "a")}),
		"set": tftypes.NewValue(set, []tftypes.Value{tftypes.NewValue(tftypes.String, "x"), tftypes.NewValue(tftypes.String, tftypes.UnknownValue)}),
		"obj": tftypes.NewValue(obj, tftypes.UnknownValue),
	})
	// a trailing "!" marks a fail from an evaluation error (why is set)
	for src, want := range map[string]string{
		`one([]) == null`:                  "pass",
		`one(self.l) == "a"`:               "pass",
		`one(["a", "b"]) == "a"`:           "fail!",
		`alltrue([])`:                      "pass",
		`alltrue([true, null])`:            "fail",
		`alltrue([true, self.u == "x"])`:   "unknown",
		`anytrue([])`:                      "fail",
		`anytrue([null, true])`:            "pass",
		`anytrue([false, self.u == "x"])`:  "unknown",
		`startswith(self.s, "bobthe")`:     "pass",
		`length(self.s) == 10`:             "pass",
		`length(self.l) == 1`:              "pass",
		`try(one(["a", "b"]), "x") == "x"`: "pass",
		`can(one(["a", "b"]))`:             "fail",
		`coalesce(null, "x") == "x"`:       "pass",
		`tobool("true")`:                   "pass",
		`contains(["bobthecorp"], self.s)`: "pass",
		`lower("BOB") == "bob"`:            "pass",
		`jsondecode("{\"a\":1}").a == 1`:   "pass",
		`tonumber("2") == 2`:               "pass",
		`length(tolist(["a"])) == 1`:       "pass",
		`self.u == "x"`:                    "unknown",
		`null`:                             "fail!",
		`"bobthecorp"`:                     "fail!",
		`one(self.set) == "x"`:             "unknown",
		`alltrue([self.u == "x", false])`:  "unknown",
		`alltrue([self.u == "x"]) != null`: "pass",
		`anytrue([self.u == "x", true])`:   "pass",
		`coalesce("", "x") == "x"`:         "pass",
		`coalesce(null, "")`:               "fail!",
		`coalesce(self.u, "x") == "x"`:     "unknown",
		`length(self.obj) == 2`:            "pass",
		`length(self.u) > 0`:               "unknown",
		`startswith(self.u, "")`:           "pass",
		`tobool("yes")`:                    "fail!",
	} {
		p, err := parsePostcondition(src)
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		st, why, err := p.eval(self)
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		got := st.String()
		if why != "" {
			got += "!"
		}
		if got != want {
			t.Errorf("%s: got %s, want %s", src, got, want)
		}
	}
	if engine.Pass.String() != "pass" {
		t.Fatalf("state names changed: %s", engine.Pass)
	}
}

// TestLoadDiffcheckInputs: malformed policy fixtures and allow files fail.
func TestLoadDiffcheckInputs(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for name, body := range map[string]string{
		"format.json":  `{"format": "x", "policies": []}`,
		"unknown.json": `{"format": "content.policy-fixtures/1", "policies": [], "extra": 1}`,
		"dup.json": `{"format": "content.policy-fixtures/1", "policies": [{"id": "a", "resource_type": "aws_x", "cases": [
			{"name": "c", "resource": {}}, {"name": "c", "resource": {}}]}]}`,
		"nocases.json":    `{"format": "content.policy-fixtures/1", "policies": [{"id": "a", "resource_type": "aws_x"}]}`,
		"emptycases.json": `{"format": "content.policy-fixtures/1", "policies": [{"id": "a", "resource_type": "aws_x", "cases": []}]}`,
		"scalar.json":     `{"format": "content.policy-fixtures/1", "policies": [{"id": "a", "resource_type": "aws_x", "cases": [{"name": "c", "resource": 1}]}]}`,
	} {
		if _, err := LoadPolicyFixtures(write(name, body)); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	for name, body := range map[string]string{
		"noreason.yaml":  "- {id: a, case: pass, cel: pass, postcondition: fail}\n",
		"field.yaml":     "- {id: a, case: pass, cel: pass, postcondition: fail, reason: r, extra: 1}\n",
		"dup.yaml":       "- {id: a, case: pass, cel: pass, postcondition: fail, reason: r}\n- {id: a, case: pass, cel: fail, postcondition: pass, reason: r}\n",
		"case.yaml":      "- {id: a, case: Pass, cel: pass, postcondition: fail, reason: r}\n",
		"nostate.yaml":   "- {id: a, case: pass, reason: r}\n",
		"badstate.yaml":  "- {id: a, case: pass, cel: ok, postcondition: fail, reason: r}\n",
		"samestate.yaml": "- {id: a, case: pass, cel: fail, postcondition: fail, reason: r}\n",
	} {
		if _, err := LoadDiffAllow(write(name, body)); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	if a, err := LoadDiffAllow(write("empty.yaml", "")); err != nil || len(a) != 0 {
		t.Fatalf("empty allow file: %v %v", a, err)
	}
}

// diffcheckGenInputs is the generator fixture with the rds control
// translated from an intent carrying postcondition post (its authored file
// removed), the other ids authored without an intent, and diffcheck on
// with no policy fixtures.
func diffcheckGenInputs(t *testing.T, post string) Inputs {
	t.Helper()
	const id = "rds_bobthecorp_storage_encrypted"
	in := loadInputs(t, inputs, true)
	delete(in.Authored, id)
	delete(in.AuthoredFixtures, id)
	delete(in.AuthoredBumps, id)
	in.Intents.Policies = []Intent{{ID: id, ResourceType: "aws_db_instance",
		Attributes:  []IntentAttribute{{SchemaPath: "storage_encrypted", Condition: "equals_any", Values: []json.RawMessage{json.RawMessage("true")}}},
		Explanation: "Attribute `storage_encrypted` of `aws_db_instance` must be `true`.", Postcondition: post}}
	in.PolicyFixtures = &PolicyFixtures{Format: policyFixturesFormat, Policies: []PolicyFixture{}}
	return in
}

// TestGenerateDiffcheck: Generate runs diffcheck after verify and writes
// diffcheck.json. A planted disagreement (the postcondition requires
// storage_encrypted false) moves only that id to the review queue: it is in
// no bundle, coverage counts it as pending review, and the rerun is
// deterministic; an allow entry for both directions keeps it; a
// postcondition diffcheck cannot evaluate fails the run; without policy
// fixtures diffcheck does not run.
func TestGenerateDiffcheck(t *testing.T) {
	const id = "rds_bobthecorp_storage_encrypted"
	inBundle := func(files map[string][]byte, cid string) []string {
		var ids []string
		for _, p := range slices.Sorted(maps.Keys(files)) {
			if strings.HasSuffix(p, "/"+bundle.ControlsFile) && strings.Contains(string(files[p]), `"id": "`+cid+`"`) {
				ids = append(ids, strings.TrimSuffix(p, "/"+bundle.ControlsFile))
			}
		}
		return ids
	}
	codes := func(rep *DiffcheckReport) []string {
		var out []string
		for _, f := range rep.Findings {
			out = append(out, f.Code+" "+f.Control+" "+f.Case)
		}
		return out
	}

	agree := diffcheckGenInputs(t, "self.storage_encrypted == true")
	out, err := Generate(agree, testOpts)
	if err != nil {
		t.Fatal(err)
	}
	if got := inBundle(out.Files, id); len(got) == 0 || out.Diffcheck == nil || out.Diffcheck.Failed() {
		t.Fatalf("agreeing: bundles %v, report %v", got, out.Diffcheck)
	}
	if want, _ := out.Diffcheck.JSON(); string(out.Files["diffcheck.json"]) != string(want) || !slices.Contains(codes(out.Diffcheck), "W_DIFFCHECK_NO_POLICY_FIXTURES "+id+" ") {
		t.Fatalf("agreeing diffcheck.json %s", out.Files["diffcheck.json"])
	}
	keep := inBundle(out.Files, "iam_bobthecorp_no_kms_wildcard")
	if len(keep) == 0 {
		t.Fatal("iam control in no bundle")
	}

	planted := diffcheckGenInputs(t, "self.storage_encrypted == false")
	out, err = Generate(planted, testOpts)
	if err != nil {
		t.Fatal(err)
	}
	if got := inBundle(out.Files, id); len(got) > 0 {
		t.Fatalf("mismatched id still in %v", got)
	}
	if got := inBundle(out.Files, "iam_bobthecorp_no_kms_wildcard"); !slices.Equal(got, keep) {
		t.Fatalf("other id in %v, want %v", got, keep)
	}
	if len(out.ReviewQueue) != 1 || out.ReviewQueue[0].ID != id || out.ReviewQueue[0].Reason != ReviewDiffcheck ||
		!strings.Contains(out.ReviewQueue[0].Detail, "fail: cel fail, postcondition pass") ||
		!strings.Contains(out.ReviewQueue[0].Detail, "pass: cel pass, postcondition fail") {
		t.Fatalf("review queue %+v", out.ReviewQueue)
	}
	if q := string(out.Files["review-queue.md"]); !strings.Contains(q, "E_REVIEW_PENDING "+id+" -: diffcheck: ") {
		t.Fatalf("review-queue.md:\n%s", q)
	}
	if out.Diffcheck.Failed() || slices.ContainsFunc(codes(out.Diffcheck), func(s string) bool { return strings.Contains(s, id) }) {
		t.Fatalf("report after the rerun: %v", codes(out.Diffcheck))
	}
	var cov coverageReport
	if err := json.Unmarshal(out.Files["coverage.json"], &cov); err != nil {
		t.Fatal(err)
	}
	for _, b := range []string{"all", "cis-aws"} {
		if !slices.Contains(cov.Bundles[b].PendingReview, id) {
			t.Errorf("coverage %s pending_review %v, want %s", b, cov.Bundles[b].PendingReview, id)
		}
	}
	ledger, err := os.ReadFile(filepath.Join(inputs, "ledger.json"))
	if err != nil {
		t.Fatal(err)
	}
	if l, err := UpdateLedger(planted, out.Files, ledger); err != nil ||
		!strings.Contains(string(l), `"generation_status": "pending_review",
    "id": "`+id+`"`) {
		t.Fatalf("ledger: %v\n%s", err, l)
	}
	again, err := Generate(planted, testOpts)
	if err != nil || !maps.EqualFunc(out.Files, again.Files, func(a, b []byte) bool { return string(a) == string(b) }) {
		t.Fatalf("rerun differs: %v", err)
	}

	planted.DiffAllow = []DiffAllow{
		{ID: id, Case: "pass", CEL: "pass", Postcondition: "fail", Reason: "planted"},
		{ID: id, Case: "fail", CEL: "fail", Postcondition: "pass", Reason: "planted"},
	}
	if out, err = Generate(planted, testOpts); err != nil || len(inBundle(out.Files, id)) == 0 ||
		!slices.Contains(codes(out.Diffcheck), "W_DIFFCHECK_ALLOWED "+id+" pass") {
		t.Fatalf("allowed: %v %v", err, out)
	}

	if out, err := Generate(diffcheckGenInputs(t, "self.bobthecorp_missing == true"), testOpts); errCode(err) != "E_DIFFCHECK_EVAL" || out != nil {
		t.Fatalf("eval error: %v", err)
	}

	// a mismatch plus an undecodable policy fixture of the same id: the
	// eval finding fails the run, holding the id does not hide it
	both := diffcheckGenInputs(t, "self.storage_encrypted == false")
	both.PolicyFixtures.Policies = []PolicyFixture{{ID: id, ResourceType: "aws_db_instance",
		Cases: []PolicyCase{{Name: "bobthecorp_bad", Resource: json.RawMessage(`{"storage_encrypted": "bobthecorp"}`)}}}}
	if out, err := Generate(both, testOpts); errCode(err) != "E_DIFFCHECK_EVAL" || out != nil {
		t.Fatalf("mismatch plus eval error: %v", err)
	}

	// nothing emitted: the report says nothing was compared
	none := diffcheckGenInputs(t, "self.storage_encrypted == true")
	none.Catalog.Dispositions.Controls = maps.Clone(none.Catalog.Dispositions.Controls)
	for cid, d := range none.Catalog.Dispositions.Controls {
		if isLocal(d.Disposition) {
			d.Disposition, d.Targets, d.Content = "runtime", nil, "none"
			none.Catalog.Dispositions.Controls[cid] = d
		}
	}
	none.Authored, none.AuthoredFixtures, none.AuthoredBumps = nil, nil, nil
	if out, err := Generate(none, testOpts); err != nil || out.Diffcheck == nil || !slices.Equal(codes(out.Diffcheck), []string{"W_DIFFCHECK_NOTHING_COMPARED  "}) {
		t.Fatalf("nothing emitted: %v %v", err, out)
	}

	off := diffcheckGenInputs(t, "self.storage_encrypted == false")
	off.PolicyFixtures = nil
	if out, err := Generate(off, testOpts); err != nil || out.Diffcheck != nil || out.Files["diffcheck.json"] != nil || len(inBundle(out.Files, id)) == 0 {
		t.Fatalf("diffcheck off: %v", err)
	}
}
