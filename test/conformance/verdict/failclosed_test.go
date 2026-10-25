//go:build conformance

package verdict

// Fail-closed goldens:
// internal/verdict/testdata/failclosed. Under verdict_required each case
// plans without a verdict (plan never needs one) and then applies the
// planfile with no verdict, a verdict missing the instance's entry, an
// entry missing a graph control's decision, or an entry whose provisional
// exemption has no final proof. Every apply blocks before upstream: Terraform
// exits non-zero, the conformance tap records no forwarded
// ApplyResourceChange, no apply_post record is written and state is
// unchanged. The diagnostics are the golden's exact value-free texts and the
// apply_pre eval record carries the golden's decisions. internal/verdict
// TestFailClosed checks the same goldens against the situation table.

import (
	"bufio"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/verdict"
	"github.com/compliancetf/terraform-provider-aws/internal/verdict/verdicttest"
)

// failClosedTF is one fake_thing; its name is a value no diagnostic or
// evidence record may carry.
const failClosedTF = header + `
variable "size" {
  type    = number
  default = 2
}

resource "fake_thing" "a" {
  name = "` + failClosedName + `"
  size = var.size
}
`

const failClosedName = "bobthecorp-failclosed-a"

// coverableControls is defaultControls with the size control coverable by a
// grant, so its blocking failure is a pending exemption at plan.
var coverableControls = strings.Replace(defaultControls, `"exemption_coverable": []`, `"exemption_coverable": ["grant"]`, 1)

// failClosedGolden is the part of a golden this runner checks (the
// situation input is internal/verdict's).
type failClosedGolden struct {
	Plan struct {
		Warnings []string `json:"warnings"`
	} `json:"plan"`
	Apply struct {
		Errors []struct {
			Summary string `json:"summary"`
			Detail  string `json:"detail"`
		} `json:"errors"`
		Evidence struct {
			Op      string           `json:"op"`
			Results []failClosedEval `json:"results"`
		} `json:"evidence"`
	} `json:"apply"`
}

type failClosedEval struct {
	Control   string `json:"control"`
	Version   string `json:"version"`
	State     string `json:"state"`
	Decision  string `json:"decision"`
	Situation string `json:"situation"`
}

// failClosedCases set up each golden: the signed controls, the plan
// arguments and the gate's edit before signing (nil: apply with no verdict).
var failClosedCases = map[string]struct {
	controls string
	planArgs []string
	edit     func(*gate)
}{
	"plan-no-verdict":     {defaultControls, nil, nil},
	"apply-missing-entry": {defaultControls, nil, func(g *gate) { g.Instances = []verdict.Instance{} }},
	// gatePlan entries start with no decisions: the companion is missing.
	"missing-decision": {graphControls, nil, func(*gate) {}},
	"exemption-no-proof": {coverableControls, []string{"-var", "size=20"}, func(g *gate) {
		entry(g.Instances, "fake_thing.a", "").Decisions = []verdict.Decision{
			{Control: "fake_thing_size_max", Version: "1.0.0", Result: verdict.ResultProvisional, Action: "deny"}}
	}},
}

// TestFailClosed runs every fail-closed golden end to end.
func TestFailClosed(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "internal", "verdict", "testdata", "failclosed")
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	if len(files) != len(failClosedCases) {
		t.Fatalf("%d goldens in %s, want %d", len(files), dir, len(failClosedCases))
	}
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".json")
		c, ok := failClosedCases[name]
		if !ok {
			t.Fatalf("golden %s has no case", name)
		}
		t.Run(name, func(t *testing.T) {
			var want failClosedGolden
			if err := json.Unmarshal(mustRead(t, f), &want); err != nil {
				t.Fatal(err)
			}
			k := newKey(t)
			r := newRun(t, failClosedTF, runOpt{Keys: []verdicttest.Key{k}, Required: true, Controls: c.controls})
			g := r.gatePlan(c.planArgs...)
			got := slices.DeleteFunc(summaries(g.Out.Stdout+g.Out.Stderr, "Warning: "), func(s string) bool { return ambientWarnings[s] })
			if !slices.Equal(got, want.Plan.Warnings) {
				t.Fatalf("plan warnings %q, want %q\n--- stdout\n%s--- stderr\n%s", got, want.Plan.Warnings, g.Out.Stdout, g.Out.Stderr)
			}
			if c.edit != nil {
				c.edit(g)
				r.gateSign(g, k, nil)
			}
			if len(want.Apply.Errors) == 0 {
				t.Fatal("a fail-closed golden names the errors its apply blocks with")
			}
			before := r.State()
			res := r.TF("apply", "-no-color", "-input=false", g.File)
			var errs, details []string
			for _, e := range want.Apply.Errors {
				errs = append(errs, e.Summary)
				details = append(details, strings.Join(strings.Fields(e.Detail), " "))
			}
			r.blocked(res, before, errs...)
			if got := summaries(res.Stderr, "Error: "); !slices.Equal(got, errs) {
				t.Fatalf("apply errors %q, want %q\n--- stderr\n%s", got, errs, res.Stderr)
			}
			if got := errorDetails(res.Stderr); !slices.Equal(got, details) {
				t.Fatalf("apply error details %q, want %q\n--- stderr\n%s", got, details, res.Stderr)
			}
			if strings.Contains(res.Stdout+res.Stderr, failClosedName) {
				t.Fatalf("apply output carries a value:\n%s%s", res.Stdout, res.Stderr)
			}
			r.checkFailClosed(want.Apply.Evidence.Op, want.Apply.Evidence.Results)
		})
	}
}

// ambientWarnings are the plan warnings of every conformance run (dev
// overrides, offline profile), not of the case.
var ambientWarnings = map[string]bool{"Provider development overrides are in effect": true, "Compliance configuration": true}

// summaries are the diagnostic summaries Terraform printed with prefix
// ("Error: " or "Warning: "), in order.
func summaries(out, prefix string) []string {
	got := []string{}
	for line := range strings.Lines(out) {
		if s, ok := strings.CutPrefix(strings.TrimSpace(line), prefix); ok {
			got = append(got, s)
		}
	}
	return got
}

// errorDetails are the details of the "Error: " diagnostics Terraform
// printed in out, in order and whitespace folded: the paragraphs after the
// summary less the "with"/"on" source context ("" for none).
func errorDetails(out string) []string {
	got := []string{}
	var body []string
	in := false
	flush := func() {
		if !in {
			return
		}
		paras := strings.Split(strings.TrimLeft(strings.Join(body, ""), "\n"), "\n\n")
		if p := paras[0]; strings.HasPrefix(p, "  with ") || strings.HasPrefix(p, "  on ") {
			paras = paras[1:]
		}
		got = append(got, strings.Join(strings.Fields(strings.Join(paras, " ")), " "))
	}
	for line := range strings.Lines(out) {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "Error: ") || strings.HasPrefix(t, "Warning: ") {
			flush()
			in, body = strings.HasPrefix(t, "Error: "), nil
			continue
		}
		body = append(body, line)
	}
	flush()
	return got
}

// checkFailClosed fails unless upstream never applied (no tap line, no
// apply_post record) and the one apply_pre eval record is the value-free
// op and results want.
func (r *run) checkFailClosed(op string, want []failClosedEval) {
	r.T.Helper()
	if _, err := os.Stat(filepath.Join(r.Work, "tap.jsonl.failed")); err == nil {
		r.T.Fatal("conformance tap write failed")
	}
	// No tap file is the normal case: the tap writes only on a forwarded apply.
	b, err := os.ReadFile(filepath.Join(r.Work, "tap.jsonl"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		r.T.Fatal(err)
	}
	if strings.Contains(string(b), `"ApplyResourceChange"`) {
		r.T.Fatalf("a blocked apply reached upstream:\n%s", b)
	}
	var last []byte
	pre := 0
	err = filepath.WalkDir(filepath.Join(r.Work, "evidence"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".jsonl") {
			return err
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(nil, 1<<24)
		for sc.Scan() {
			var rec struct {
				Kind, Stage string
			}
			if json.Unmarshal(sc.Bytes(), &rec) != nil || rec.Kind != "eval" {
				continue
			}
			switch rec.Stage {
			case "apply_post":
				r.T.Fatalf("a blocked apply wrote an apply_post record: %s", sc.Bytes())
			case "apply_pre":
				last, pre = slices.Clone(sc.Bytes()), pre+1
			}
		}
		return sc.Err()
	})
	if err != nil || pre != 1 {
		r.T.Fatalf("%d apply_pre eval records, want 1 (err %v)", pre, err)
	}
	if strings.Contains(string(last), failClosedName) {
		r.T.Fatalf("the apply_pre record carries a value: %s", last)
	}
	var rec struct {
		Resource struct {
			Op string `json:"op"`
		} `json:"resource"`
		Results []failClosedEval `json:"results"`
	}
	if err := json.Unmarshal(last, &rec); err != nil {
		r.T.Fatal(err)
	}
	if rec.Resource.Op != op || !reflect.DeepEqual(rec.Results, want) {
		r.T.Fatalf("apply_pre record op %s results %+v, want %s %+v", rec.Resource.Op, rec.Results, op, want)
	}
}
