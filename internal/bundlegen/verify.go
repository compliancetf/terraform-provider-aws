package bundlegen

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/celeng"
	"github.com/compliancetf/terraform-provider-aws/internal/fixturejson"
	"github.com/compliancetf/terraform-provider-aws/internal/iampolicy"
)

// Finding is one verify failure. Detail carries states, paths and codes,
// never fixture values.
type Finding struct {
	Code    string `json:"code"`
	Bundle  string `json:"bundle"`
	Control string `json:"control"`
	Case    string `json:"case,omitempty"`
	Detail  string `json:"detail"`
}

func (f Finding) String() string {
	return strings.Join(slices.DeleteFunc([]string{f.Code, f.Control, f.Case}, func(s string) bool { return s == "" }), " ") + ": " + f.Detail
}

// VerifyReport lists the findings in bundle, control and case order; verify
// passes when it is empty.
type VerifyReport struct {
	Findings []Finding `json:"findings"`
}

// Verify loads each bundle of out (<id>/controls.json, iam-actions.json when
// present) with eng against s, the way the provider does, and replays its
// cases (<id>/cases/, CasePath) with Compiled.Evaluate. Graph controls are
// skipped as the provider skips them: ctfkit gate decides them, and a case
// for one is an error.
// Findings:
//   - E_FIXTURE_MISSING: a control without a pass and a fail case;
//   - E_FIXTURE_CONTROL: a case's control is not the bundle's control;
//   - E_FIXTURE_MISMATCH: a result differs from expect;
//   - E_MUTATION_SURVIVED: !(expr), loaded the same way, does not flip a
//     pass case to fail or a fail case to pass, so a vacuous expression
//     cannot verify;
//   - E_MUTATION_LOAD: !(expr) does not load (the check cannot run);
//   - E_OPTIONAL_COMPUTED: an effective deny control reads an
//     Optional+Computed attribute and no case with that read unknown in
//     resource expects pass or fail;
//   - E_LOAD_DIAG: a load diagnostic on a kept control.
//
// The error is for input that does not load or decode (a bundle that the
// provider rejects, a case file that is not a case) and for an output that
// verify would pass without checking it: no bundle, or a file that is
// neither a generator report at the top level nor a bundle file
// (verifyClaims).
func Verify(out *Output, s Schemas, eng *celeng.Engine) (VerifyReport, error) {
	rep := VerifyReport{Findings: []Finding{}}
	ids, err := verifyClaims(out)
	if err != nil {
		return VerifyReport{}, err
	}
	for _, id := range ids {
		fs, err := verifyBundle(out, id, s, eng)
		if err != nil {
			return VerifyReport{}, fmt.Errorf("verify bundle %s: %w", id, err)
		}
		rep.Findings = append(rep.Findings, fs...)
	}
	return rep, nil
}

// topReports are the generator files outside any bundle directory.
var topReports = []string{"content-lock.json", "coverage.json", "coverage.md", "diffcheck.json", "review-queue.md", "review-sheet.md"}

// bundleArchive are the files of a bundle directory besides cases/.
var bundleArchive = []string{bundle.ControlsFile, bundle.GraphFile, bundle.IAMActionsFile, "build.json"}

// verifyClaims returns the bundle ids of out (<id>/controls.json) and fails
// when there is none or a file is not claimed: every file is a top-level
// report or <id>/<archive file> or <id>/cases/... of a bundle id.
func verifyClaims(out *Output) ([]string, error) {
	var ids []string
	for p := range out.Files {
		if id, ok := strings.CutSuffix(p, "/"+bundle.ControlsFile); ok && id != "" && !strings.Contains(id, "/") {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return nil, errf("E_VERIFY_EMPTY", "no <bundle>/controls.json in the output")
	}
	slices.Sort(ids)
	for _, p := range slices.Sorted(maps.Keys(out.Files)) {
		id, rest, nested := strings.Cut(p, "/")
		claimed := !nested && slices.Contains(topReports, p) ||
			nested && slices.Contains(ids, id) && (slices.Contains(bundleArchive, rest) || strings.HasPrefix(rest, "cases/"))
		if !claimed {
			return nil, errf("E_VERIFY_UNCLAIMED", "%s is not a report or a file of a verified bundle", p)
		}
	}
	return ids, nil
}

func verifyBundle(out *Output, id string, s Schemas, eng *celeng.Engine) ([]Finding, error) {
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
	comp, diags, err := eng.Load(exprControls(cs), s.ProviderSchema(), content)
	if err != nil {
		return nil, err
	}
	var fs []Finding
	for _, d := range diags {
		fs = append(fs, Finding{Code: "E_LOAD_DIAG", Bundle: id, Control: d.ControlID, Detail: d.Code})
	}
	cases, err := bundleCases(files)
	if err != nil {
		return nil, err
	}
	for i := range cs {
		c := &cs[i]
		f := func(code, kase, format string, a ...any) {
			fs = append(fs, Finding{Code: code, Bundle: id, Control: c.ID, Case: kase, Detail: fmt.Sprintf(format, a...)})
		}
		key := caseID(*c, "")
		mine := cases[key]
		delete(cases, key)
		if c.Kind == bundle.KindGraph {
			if len(mine) > 0 {
				return nil, fmt.Errorf("graph control %s has cases; the provider does not evaluate graph controls", c.ID)
			}
			continue
		}
		want, err := canonicalJSON(c)
		if err != nil {
			return nil, err
		}
		mut := *c
		if c.Expr != nil {
			m := "!(" + *c.Expr + ")"
			mut.Expr = &m
		}
		// verify-only load without the iam polarity lint
		mcomp, _, err := eng.LoadMutant([]bundle.Control{mut}, s.ProviderSchema(), content)
		if err != nil {
			f("E_MUTATION_LOAD", "", "!(expr) does not load: %v", err)
		}
		states := map[engine.State]bool{}
		deciding := map[string]bool{}
		for _, k := range mine {
			name := strings.TrimPrefix(k.ID, key)
			if got, err := canonicalJSON(k.Control); err != nil || !bytes.Equal(got, want) {
				f("E_FIXTURE_CONTROL", name, "the case control differs from the bundle control")
				continue
			}
			states[k.Expect.State] = true
			b, err := caseBindings(s, c, k)
			if err != nil {
				return nil, fmt.Errorf("case %s: %w", k.ID, err)
			}
			r := evalOne(comp, b, c.ID)
			if r.State != k.Expect.State || r.ErrClass != k.Expect.ErrClass || !slices.Equal(r.UnknownPaths, k.Expect.UnknownPaths) {
				f("E_FIXTURE_MISMATCH", name, "want %s %q %v, got %s %q %v", k.Expect.State, k.Expect.ErrClass, k.Expect.UnknownPaths,
					r.State, r.ErrClass, r.UnknownPaths)
			}
			flip := map[engine.State]engine.State{engine.Pass: engine.Fail, engine.Fail: engine.Pass}
			if to, ok := flip[k.Expect.State]; ok {
				if m := evalOne(mcomp, b, c.ID); mcomp != nil && m.State != to {
					f("E_MUTATION_SURVIVED", name, "!(expr) gives %s, want %s", m.State, to)
				}
				for _, p := range c.Reads {
					if r.State == k.Expect.State && unknownAt(k.Bindings.Resource, strings.Split(p, ".")) {
						deciding[p] = true
					}
				}
			}
		}
		if !states[engine.Pass] || !states[engine.Fail] {
			f("E_FIXTURE_MISSING", "", "want a pass and a fail case, have %d cases", len(mine))
		}
		sc, _ := s.Lookup(c.Kind, c.ResourceType)
		if c.Action == bundle.ActionDeny && c.PresenceMode == bundle.PresenceEffective && sc != nil && sc.Block != nil {
			for _, p := range c.Reads {
				if optionalComputed(sc.Block, strings.Split(p, ".")) && !deciding[p] {
					fs = append(fs, Finding{Code: "E_OPTIONAL_COMPUTED", Bundle: id, Control: c.ID,
						Detail: p + ": use presence_mode configured or add a deciding unknown fixture"})
				}
			}
		}
	}
	if len(cases) > 0 {
		return nil, fmt.Errorf("cases of %s name no control of the bundle", strings.TrimSuffix(slices.Sorted(maps.Keys(cases))[0], "."))
	}
	slices.SortStableFunc(fs, func(a, b Finding) int { return cmp.Compare(a.Control, b.Control) })
	return fs, nil
}

// bundleCases decodes the cases/ files of one bundle by case id prefix
// <control id>.<kind>.<type>., checking each file sits at its CasePath.
func bundleCases(files map[string][]byte) (map[string][]Case, error) {
	out := map[string][]Case{}
	for _, name := range slices.Sorted(maps.Keys(files)) {
		if !strings.HasPrefix(name, "cases/") {
			continue
		}
		var k Case
		if err := decodeStrict(files[name], &k); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if CasePath("", k) != "/"+name || !strings.HasPrefix(k.ID, caseID(k.Control, "")) || k.ResourceType != k.Control.ResourceType {
			return nil, fmt.Errorf("%s: case %q is not at its path <control id>/<kind>.<type>.<case>.json", name, k.ID)
		}
		key := caseID(k.Control, "")
		out[key] = append(out[key], k)
	}
	return out, nil
}

// caseBindings builds the engine input of case k, the way the replay
// runner does.
func caseBindings(s Schemas, c *bundle.Control, k Case) (celeng.Bindings, error) {
	sc, ok := s.Lookup(c.Kind, c.ResourceType)
	if !ok || sc.Block == nil {
		return celeng.Bindings{}, fmt.Errorf("no %s schema for %s", c.Kind, c.ResourceType)
	}
	typ := sc.Block.ValueType()
	b := celeng.Bindings{Kind: c.Kind, Type: c.ResourceType, Op: k.Bindings.Op}
	var err error
	for _, x := range []struct {
		name string
		dst  *tftypes.Value
		raw  json.RawMessage
	}{{"resource", &b.Resource, k.Bindings.Resource}, {"config", &b.Config, k.Bindings.Config}, {"prior", &b.Prior, k.Bindings.Prior}} {
		if *x.dst, err = fixturejson.Value(typ, x.raw); err != nil {
			return celeng.Bindings{}, fmt.Errorf("%s: %w", x.name, err)
		}
	}
	if b.Env, b.EnvKnown, err = fixturejson.String(k.Bindings.Env); err != nil {
		return celeng.Bindings{}, fmt.Errorf("env: %w", err)
	}
	str := func(key string) (string, bool) {
		v, ok := k.Bindings.Provider[key]
		return v, ok
	}
	b.Provider.Region, b.Provider.RegionKnown = str("region")
	b.Provider.AccountID, b.Provider.AccountKnown = str("account_id")
	b.Provider.Partition, b.Provider.PartitionKnown = str("partition")
	return b, nil
}

// exprControls are the controls of cs the provider evaluates with CEL: all
// but the graph controls, which carry no expr (ctfkit gate decides them).
func exprControls(cs []bundle.Control) []bundle.Control {
	return slices.DeleteFunc(slices.Clone(cs), func(c bundle.Control) bool { return c.Kind == bundle.KindGraph })
}

// evalOne evaluates control id alone.
func evalOne(comp *celeng.Compiled, b celeng.Bindings, id string) celeng.Result {
	if comp == nil {
		return celeng.Result{}
	}
	rs := comp.Evaluate(context.Background(), b, func(c *bundle.Control) bool { return c.ID == id })
	if len(rs) != 1 {
		return celeng.Result{State: engine.NotEvaluable, ErrClass: engine.ErrClass(fmt.Sprintf("%d results", len(rs)))}
	}
	return rs[0]
}

// unknownAt reports {"$unknown": true} at path, or at an ancestor of it, in
// fixture JSON raw, through any element of a block list.
func unknownAt(raw json.RawMessage, path []string) bool {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return false
	}
	var walk func(v any, path []string) bool
	walk = func(v any, path []string) bool {
		if fixturejson.IsUnknown(v) {
			return true // an unknown ancestor makes the read unknown
		}
		if len(path) == 0 {
			return false
		}
		switch x := v.(type) {
		case map[string]any:
			return walk(x[path[0]], path[1:])
		case []any:
			return slices.ContainsFunc(x, func(e any) bool { return walk(e, path) })
		}
		return false
	}
	return walk(v, path)
}

// VerifyEngine is the engine Generate and `ctf-bundlegen verify` replay
// cases with: the provider's cost limit and a minute wall-clock budget per
// resource, so a loaded machine cannot turn a case into a budget error.
func VerifyEngine() *celeng.Engine {
	return celeng.New(celeng.Options{PerResourceBudget: time.Minute})
}

// ReadOutputDir reads a generated output directory back into an Output for
// Verify. It walks and reads through a root pinned to dir, so a symlink,
// special file or swapped directory anywhere fails E_SPECIAL_FILE and no
// read escapes dir.
func ReadOutputDir(dir string) (*Output, error) {
	root, err := openDirRoot(dir, "E_INPUT")
	if err != nil {
		return nil, err
	}
	defer root.Close() //nolint:errcheck // read-only
	out := &Output{Files: map[string][]byte{}}
	if _, err := walkRootDir(root, ".", nil, "E_INPUT", func(rel string) error {
		data, err := readRootFile(root, rel)
		if err != nil {
			return err
		}
		out.Files[filepath.ToSlash(rel)] = data
		return nil
	}); err != nil {
		return nil, err
	}
	return out, nil
}
