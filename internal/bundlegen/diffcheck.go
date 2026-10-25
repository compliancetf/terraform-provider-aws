package bundlegen

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/celeng"
	"github.com/compliancetf/terraform-provider-aws/internal/fixturejson"
	"github.com/compliancetf/terraform-provider-aws/internal/iampolicy"
)

// PolicyFixtures is the content policy fixture export (content.policy-fixtures/1):
// per policy, the resource values the content pipeline's own conformance cases use
// (acceptable_values, the literals its enforcement rejects). They exercise
// what the content enforces, which can be wider than the intent the control was
// translated from, so diffcheck replays them too.
type PolicyFixtures struct {
	Format         string          `json:"format"`
	ContentVersion string          `json:"content_version"`
	ContentCommit  string          `json:"content_commit"`
	Policies       []PolicyFixture `json:"policies"`
}

type PolicyFixture struct {
	ID           string       `json:"id"`
	ResourceType string       `json:"resource_type"`
	Cases        []PolicyCase `json:"cases"`
}

// PolicyCase is one resource value in fixture JSON (omitted is null,
// {"$unknown": true} unknown). It carries no expected state: diffcheck
// compares two evaluators, not a label.
type PolicyCase struct {
	Name     string          `json:"name"`
	Resource json.RawMessage `json:"resource"`
}

// DiffAllow is one entry of diffcheck-allow.yaml: an accepted
// difference of control ID on case Case (a bundle case name, or
// policy.<name> for a policy fixture) in one direction: CEL state CEL and
// postcondition state Postcondition, so the entry never masks the reverse
// disagreement. One entry covers every bundle with the control: a control
// key carries one digest across bundles.
type DiffAllow struct {
	ID            string `yaml:"id"`
	Case          string `yaml:"case"`
	CEL           string `yaml:"cel"`
	Postcondition string `yaml:"postcondition"`
	Reason        string `yaml:"reason"`
}

// allowKey identifies an allowed difference.
type allowKey struct{ id, kase, cel, post string }

func (a DiffAllow) key() allowKey { return allowKey{a.ID, a.Case, a.CEL, a.Postcondition} }

const policyFixturesFormat = "content.policy-fixtures/1"

// policyCasePrefix qualifies a policy fixture name in findings and allow
// entries, apart from bundle case names.
const policyCasePrefix = "policy."

// LoadPolicyFixtures reads a content policy fixture export; an unknown field,
// a non-name id or case name, a duplicate, a policy without cases (empty or
// omitted: it would replay nothing yet hide the missing-fixture warning) or
// a non-object resource fails.
func LoadPolicyFixtures(path string) (PolicyFixtures, error) {
	var pf PolicyFixtures
	data, err := readRegular(path)
	if err != nil {
		return pf, err
	}
	var raw any
	if err := json.Unmarshal(data, &raw); err != nil {
		return pf, errf("E_INPUT", "%s: %v", path, err)
	}
	if p := unknownField(raw, reflect.TypeOf(pf), ""); p != "" {
		return pf, errf("E_INPUT", "%s: unknown field %s", path, p)
	}
	if err := decodeJSON(path, data, &pf); err != nil {
		return pf, err
	}
	if pf.Format != policyFixturesFormat {
		return pf, errf("E_INPUT", "%s: format %q, want %q", path, pf.Format, policyFixturesFormat)
	}
	seen := map[string]bool{}
	for _, p := range pf.Policies {
		key := p.ID + " " + p.ResourceType
		if safeName(p.ID) != p.ID || safeName(p.ResourceType) != p.ResourceType || seen[key] {
			return pf, errf("E_INPUT", "%s: policy %s %s: want a unique name-shaped id and type", path, safeName(p.ID), safeName(p.ResourceType))
		}
		seen[key] = true
		if len(p.Cases) == 0 {
			return pf, errf("E_INPUT", "%s: policy %s %s: no cases (omit the policy instead)", path, p.ID, p.ResourceType)
		}
		names := map[string]bool{}
		for _, k := range p.Cases {
			if safeName(k.Name) != k.Name || names[k.Name] || !bytes.HasPrefix(bytes.TrimSpace(k.Resource), []byte("{")) {
				return pf, errf("E_INPUT", "%s: policy %s case %s: want a unique name and an object resource", path, p.ID, safeName(k.Name))
			}
			names[k.Name] = true
		}
	}
	return pf, nil
}

// LoadDiffAllow reads diffcheck-allow.yaml, a list of {id, case, cel,
// postcondition, reason}; every field is required, cel and postcondition
// are engine state names, and an (id, case) appears once.
func LoadDiffAllow(path string) ([]DiffAllow, error) {
	data, err := readRegular(path)
	if err != nil {
		return nil, err
	}
	var out []DiffAllow
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&out); err != nil && !errors.Is(err, io.EOF) {
		return nil, errf("E_INPUT", "%s: %s", path, yamlError(err))
	}
	if err := dec.Decode(new(yaml.Node)); !errors.Is(err, io.EOF) {
		return nil, errf("E_INPUT", "%s: one YAML document only", path)
	}
	seen := map[[2]string]bool{}
	for i, a := range out {
		k := [2]string{a.ID, a.Case}
		name := strings.TrimPrefix(a.Case, policyCasePrefix)
		var st engine.State
		if safeName(a.ID) != a.ID || safeName(name) != name || strings.TrimSpace(a.Reason) == "" || seen[k] ||
			st.UnmarshalText([]byte(a.CEL)) != nil || st.UnmarshalText([]byte(a.Postcondition)) != nil || a.CEL == a.Postcondition {
			return nil, errf("E_INPUT", "%s: entry %d: want a unique name-shaped id and case, two different states cel and postcondition, and a reason", path, i)
		}
		seen[k] = true
	}
	return out, nil
}

// DiffcheckReport is diffcheck.json. Findings are value-free (codes,
// states, case names) in bundle, control, case and code order.
type DiffcheckReport struct {
	Findings []Finding `json:"findings"`
}

// Failed reports an E_ finding; W_ findings (allowed, stale allow entries,
// skips) do not fail.
func (r DiffcheckReport) Failed() bool {
	return slices.ContainsFunc(r.Findings, func(f Finding) bool { return strings.HasPrefix(f.Code, "E_") })
}

// JSON is the canonical diffcheck.json.
func (r DiffcheckReport) JSON() ([]byte, error) { return canonicalJSON(r) }

// Diffcheck evaluates the content resource_postcondition of each generated
// control's intent on the same
// fixtures as the control and compares the states: every case of the
// bundle (resource bound to self, as the postcondition sees the planned
// value) and every content policy fixture of the same id and type (bound as
// resource and config, op create, like a synthesized case). Findings:
//   - E_DIFFCHECK_MISMATCH: the CEL state differs from the postcondition
//     state (unknown included; a postcondition that errors on the value,
//     or yields null or a non-bool, is fail: Terraform fails the apply);
//     the id goes to review;
//   - W_DIFFCHECK_ALLOWED: the same, accepted by an allow entry for that
//     id, case and direction, in every bundle with the control;
//   - E_DIFFCHECK_EVAL: the postcondition does not parse, calls a
//     function diffcheck does not implement, or has a reference Terraform's
//     static validation rejects (not self, or a self path the schema does
//     not have, inside try and can too), or a policy fixture does not
//     decode against the schema (no comparison);
//   - W_DIFFCHECK_STALE: an allow entry that matched no difference;
//   - E_DIFFCHECK_NO_COMPARISON: a control with a postcondition for which
//     no bundle case and no policy fixture was compared, so diffcheck
//     checked nothing;
//   - W_DIFFCHECK_SKIPPED: a control diffcheck cannot check by design: no
//     intent postcondition (spec: diffcheck covers the content policies that
//     carry one; authored-only ids), or a load diagnostic (verify fails
//     on it, E_LOAD_DIAG);
//   - W_DIFFCHECK_NO_POLICY_FIXTURES: a checked control without policy
//     fixtures, or one that is not a resource control (policy fixtures are
//     resource values), so only its bundle cases were compared;
//   - W_DIFFCHECK_STALE also covers an entry whose direction (cel,
//     postcondition) differs from the observed one.
//
// Policy fixtures of ids that generated no control are not replayed (the id
// is in the review queue). The error is for an output verify also rejects.
func Diffcheck(out *Output, in Intents, pf PolicyFixtures, allow []DiffAllow, s Schemas, eng *celeng.Engine) (DiffcheckReport, error) {
	ids, err := verifyClaims(out)
	if err != nil {
		return DiffcheckReport{}, err
	}
	intents, err := intentsByID(in.Policies)
	if err != nil {
		return DiffcheckReport{}, err
	}
	fixtures := map[[2]string][]PolicyCase{}
	for _, p := range pf.Policies {
		fixtures[[2]string{p.ID, p.ResourceType}] = p.Cases
	}
	allowed := map[allowKey]bool{}
	for _, a := range allow {
		allowed[a.key()] = false
	}
	rep := DiffcheckReport{Findings: []Finding{}}
	for _, id := range ids {
		fs, err := diffcheckBundle(out, id, intents, fixtures, allowed, s, eng)
		if err != nil {
			return DiffcheckReport{}, fmt.Errorf("diffcheck bundle %s: %w", id, err)
		}
		rep.Findings = append(rep.Findings, fs...)
	}
	for _, a := range allow {
		if !allowed[a.key()] {
			rep.Findings = append(rep.Findings, Finding{Code: "W_DIFFCHECK_STALE", Control: a.ID, Case: a.Case, Detail: "the allow entry matches no difference"})
		}
	}
	slices.SortStableFunc(rep.Findings, func(a, b Finding) int {
		return cmp.Or(cmp.Compare(a.Bundle, b.Bundle), cmp.Compare(a.Control, b.Control), cmp.Compare(a.Case, b.Case), cmp.Compare(a.Code, b.Code))
	})
	return rep, nil
}

func diffcheckBundle(out *Output, id string, intents map[string]Intent, fixtures map[[2]string][]PolicyCase,
	allowed map[allowKey]bool, s Schemas, eng *celeng.Engine) ([]Finding, error) {
	// the load verify does (verifyBundle), without the mutation pass
	files := bundleFiles(out.Files, id)
	cs, err := bundle.ParseControls(files[bundle.ControlsFile])
	if err != nil {
		return nil, err
	}
	content := celeng.Content{}
	if raw, ok := files[bundle.IAMActionsFile]; ok {
		if content.IAMCatalog, err = iampolicy.LoadCatalog(raw); err != nil {
			return nil, err
		}
	}
	if content.Digest, err = ContentDigest(id, files); err != nil {
		return nil, err
	}
	comp, diags, err := eng.Load(cs, s.ProviderSchema(), content)
	if err != nil {
		return nil, err
	}
	diagnosed := map[string]bool{}
	for _, d := range diags {
		diagnosed[d.ControlID] = true
	}
	cases, err := bundleCases(files)
	if err != nil {
		return nil, err
	}
	var fs []Finding
	for i := range cs {
		c := &cs[i]
		f := func(code, kase, format string, a ...any) {
			fs = append(fs, Finding{Code: code, Bundle: id, Control: c.ID, Case: kase, Detail: fmt.Sprintf(format, a...)})
		}
		it, ok := intents[c.ID]
		switch {
		case !ok || it.Postcondition == "":
			f("W_DIFFCHECK_SKIPPED", "", "no content postcondition for the control")
			continue
		case diagnosed[c.ID]:
			f("W_DIFFCHECK_SKIPPED", "", "the control has a load diagnostic")
			continue
		}
		sc, _ := s.Lookup(c.Kind, c.ResourceType)
		if sc == nil || sc.Block == nil {
			return nil, fmt.Errorf("no %s schema for %s", c.Kind, c.ResourceType)
		}
		post, err := parsePostcondition(it.Postcondition)
		if err == nil {
			err = post.validateSelf(sc.Block)
		}
		if err != nil {
			f("E_DIFFCHECK_EVAL", "", "postcondition %v", err)
			continue
		}
		compared := 0
		compare := func(name string, k Case) error {
			compared++
			b, err := caseBindings(s, c, k)
			if err != nil {
				return err
			}
			cel := evalOne(comp, b, c.ID).State
			hcl, why, err := post.eval(b.Resource)
			if err != nil {
				return err
			}
			if why != "" {
				why = " (" + why + ")"
			}
			switch {
			case cel != hcl && allowedDiff(allowed, allowKey{c.ID, name, cel.String(), hcl.String()}):
				f("W_DIFFCHECK_ALLOWED", name, "cel %s, postcondition %s%s, allowed", cel, hcl, why)
			case cel != hcl:
				f("E_DIFFCHECK_MISMATCH", name, "cel %s, postcondition %s%s", cel, hcl, why)
			}
			return nil
		}
		key := caseID(*c, "")
		for _, k := range cases[key] {
			if err := compare(strings.TrimPrefix(k.ID, key), k); err != nil {
				return nil, fmt.Errorf("case %s: %w", k.ID, err)
			}
		}
		pcs, ok := fixtures[[2]string{c.ID, c.ResourceType}]
		switch {
		case ok && c.Kind != bundle.KindResource:
			f("W_DIFFCHECK_NO_POLICY_FIXTURES", "", "policy fixtures are resource values; a %s control does not replay them", c.Kind)
			pcs = nil
		case len(pcs) == 0: // absent, or empty in an unloaded PolicyFixtures
			f("W_DIFFCHECK_NO_POLICY_FIXTURES", "", "no policy fixtures; only bundle cases are compared")
		}
		for _, pc := range pcs {
			name := policyCasePrefix + pc.Name
			if _, err := fixturejson.Value(sc.Block.ValueType(), pc.Resource); err != nil {
				f("E_DIFFCHECK_EVAL", name, "the policy fixture does not decode against the schema")
				continue
			}
			k := Case{Bindings: CaseBindings{Op: string(bundle.OnCreate), Provider: fixtureProvider, Resource: pc.Resource, Config: pc.Resource}}
			if err := compare(name, k); err != nil {
				return nil, fmt.Errorf("policy fixture %s: %w", name, err)
			}
		}
		if compared == 0 {
			f("E_DIFFCHECK_NO_COMPARISON", "", "the control has a postcondition but no bundle case or policy fixture was compared")
		}
	}
	return fs, nil
}

// allowedDiff marks and reports an allow entry for k.
func allowedDiff(allowed map[allowKey]bool, k allowKey) bool {
	if _, ok := allowed[k]; !ok {
		return false
	}
	allowed[k] = true
	return true
}
