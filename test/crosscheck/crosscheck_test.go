package crosscheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/celeng"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/enginetest"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/lib"
	"github.com/compliancetf/terraform-provider-aws/internal/iampolicy"
)

const limitsFormat = "compliancetf.lib-limits/v1"

// Required case groups and minimum counts.
// iam-identity runs in iam_test.go.
func TestUnknown(t *testing.T)   { replayGroup(t, "unknown", 12) }
func TestScope(t *testing.T)     { replayGroup(t, "scope", 3) }
func TestMemo(t *testing.T)      { replayGroup(t, "memo", 2) }
func TestNull(t *testing.T)      { replayGroup(t, "null", 8) }
func TestNested(t *testing.T)    { replayGroup(t, "nested", 8) }
func TestSensitive(t *testing.T) { replayGroup(t, "sensitive", 3) }
func TestErrors(t *testing.T)    { replayGroup(t, "errors", 6) }
func TestLimits(t *testing.T)    { replayGroup(t, "limits", 4) }

// step is one evaluation: the celeng crosscheck case format
// (internal/engine/celeng TestEvaluateCrosscheck) plus memoized.
type step struct {
	ResourceType string `json:"resource_type"`
	Bindings     struct {
		Op, Env, Resource, Config, Prior json.RawMessage
		Provider                         map[string]json.RawMessage
	}
	Expect struct {
		State        engine.State
		ErrClass     engine.ErrClass `json:"err_class"`
		UnknownPaths []string        `json:"unknown_paths"`
		Memoized     bool
	}
}

// caseFile is one case file: a control with one step at top level, or
// (memo) controls loaded together and steps run in order on that load.
// load_diags lists the load diagnostic codes the controls must produce
// (none when absent); marker is the sensitive value a sensitive-group case
// plants.
type caseFile struct {
	ID, Schema, About, Marker string
	LoadDiags                 []string `json:"load_diags"`
	Control                   json.RawMessage
	Controls                  []json.RawMessage
	step
	Steps []step
}

// limitsFile is a compliancetf.lib-limits/v1 file.
type limitsFile struct {
	Format, About string
	Cases         []limitsCase
}

// groupFile is one decoded file of a group: exactly one of cf and lf is set.
type groupFile struct {
	path string
	cf   *caseFile
	lf   *limitsFile
}

var knownOps = []string{string(bundle.OnCreate), string(bundle.OnUpdate), string(bundle.OnDelete)}

// decodeStrict decodes one JSON document: unknown fields and trailing data
// are errors.
func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("data after the JSON document")
	}
	return nil
}

// normalize turns the single-control form into controls and steps and
// rejects a file that would contribute no case.
func (cf *caseFile) normalize() error {
	if cf.Control != nil {
		if len(cf.Controls) > 0 || len(cf.Steps) > 0 {
			return errors.New("control and controls/steps are exclusive")
		}
		cf.Controls, cf.Steps = []json.RawMessage{cf.Control}, []step{cf.step}
	}
	if len(cf.Controls) == 0 || len(cf.Steps) == 0 {
		return fmt.Errorf("%d controls, %d steps: a case file needs both", len(cf.Controls), len(cf.Steps))
	}
	for i, st := range cf.Steps {
		var op string
		if json.Unmarshal(st.Bindings.Op, &op) != nil || !slices.Contains(knownOps, op) {
			return fmt.Errorf("step %d: op %s, want one of %v", i, st.Bindings.Op, knownOps)
		}
	}
	return nil
}

// loadGroup decodes every file of dir and counts its cases. A file that
// does not decode, or contributes no case, is an error even when the group
// minimum is met by the other files.
func loadGroup(dir string, min int) ([]groupFile, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	var out []groupFile
	n := 0
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var head struct{ Format string }
		if err := json.Unmarshal(data, &head); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		g := groupFile{path: f}
		switch head.Format {
		case limitsFormat:
			g.lf = &limitsFile{}
			if err = decodeStrict(data, g.lf); err == nil && len(g.lf.Cases) == 0 {
				err = errors.New("no cases")
			}
			if err == nil {
				n += len(g.lf.Cases)
			}
		case "":
			g.cf = &caseFile{}
			if err = decodeStrict(data, g.cf); err == nil {
				err = g.cf.normalize()
			}
			if err == nil {
				n += len(g.cf.Steps)
			}
		default:
			err = fmt.Errorf("format %q", head.Format)
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		out = append(out, g)
	}
	if n < min {
		return nil, fmt.Errorf("%s: %d cases, want at least %d", dir, n, min)
	}
	return out, nil
}

// replayGroup replays every file of testdata/crosscheck/<group>: a
// lib-limits/v1 file through the CEL library, every other file through
// celeng Load and Evaluate.
func replayGroup(t *testing.T, group string, min int) {
	files, err := loadGroup(filepath.Join(root, "crosscheck", group), min)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range files {
		if g.lf != nil {
			replayLimits(t, g.path, g.lf)
			continue
		}
		replayCase(t, group, g.path, g.cf)
	}
}

func replayCase(t *testing.T, group, f string, cf *caseFile) {
	arr, err := json.Marshal(cf.Controls)
	if err != nil {
		t.Fatalf("%s: %v", f, err)
	}
	cs, err := bundle.DecodeControls(arr)
	if err != nil {
		t.Fatalf("%s: %v", f, err)
	}
	s := enginetest.AWSSubset(t, filepath.Join(root, "..", cf.Schema))
	// A minute: no case tests the deadline.
	comp, diags, err := celeng.New(celeng.Options{PerResourceBudget: time.Minute}).
		Load(cs, s, celeng.Content{Digest: "sha256:crosscheck"})
	if err != nil {
		t.Fatalf("%s: %v", f, err)
	}
	// Load errors return err above; diags are the kept controls' findings.
	var codes []string
	for _, d := range diags {
		codes = append(codes, d.Code)
	}
	slices.Sort(codes)
	want := slices.Sorted(slices.Values(cf.LoadDiags))
	if !slices.Equal(codes, want) {
		t.Fatalf("%s: load diagnostics %v, want %v", f, codes, want)
	}
	for i, st := range cf.Steps {
		t.Run(fmt.Sprintf("%s/%d", strings.TrimSuffix(filepath.Base(f), ".json"), i), func(t *testing.T) {
			sc, ok := s.ResourceSchemas[st.ResourceType]
			ci := slices.IndexFunc(cs, func(c bundle.Control) bool { return c.ResourceType == st.ResourceType })
			if !ok || ci < 0 {
				t.Fatalf("%s: resource_type %q: no schema or no control", f, st.ResourceType)
			}
			typ := sc.Block.ValueType()
			b := celeng.Bindings{Kind: cs[ci].Kind, Type: st.ResourceType,
				Resource: enginetest.Value(t, typ, st.Bindings.Resource),
				Config:   enginetest.Value(t, typ, st.Bindings.Config),
				Prior:    enginetest.Value(t, typ, st.Bindings.Prior)}
			b.Op, _ = enginetest.String(t, st.Bindings.Op)
			b.Env, b.EnvKnown = enginetest.String(t, st.Bindings.Env)
			b.Provider.Region, b.Provider.RegionKnown = enginetest.String(t, st.Bindings.Provider["region"])
			b.Provider.AccountID, b.Provider.AccountKnown = enginetest.String(t, st.Bindings.Provider["account_id"])
			b.Provider.Partition, b.Provider.PartitionKnown = enginetest.String(t, st.Bindings.Provider["partition"])
			rs := comp.Evaluate(context.Background(), b, nil)
			if len(rs) != 1 {
				t.Fatalf("%d results", len(rs))
			}
			r, want := rs[0], st.Expect
			if r.State == engine.Pass && want.State != engine.Pass {
				t.Fatalf("SAFETY: pass, want %s/%s", want.State, want.ErrClass)
			}
			if r.State != want.State || r.ErrClass != want.ErrClass || r.Memoized != want.Memoized ||
				!slices.Equal(r.UnknownPaths, want.UnknownPaths) {
				t.Fatalf("got %+v, want %+v", r, want)
			}
			sens := slices.Concat(enginetest.SensitiveStrings(sc.Block, b.Resource),
				enginetest.SensitiveStrings(sc.Block, b.Config), enginetest.SensitiveStrings(sc.Block, b.Prior))
			if group == "sensitive" && (cf.Marker == "" || !slices.Contains(sens, cf.Marker)) {
				t.Fatalf("marker %q is not among the sensitive values %d", cf.Marker, len(sens))
			}
			noLeak(t, sens, rs, diags)
		})
	}
}

// noLeak fails when a sensitive value appears in the results or the load
// diagnostics.
func noLeak(t *testing.T, sens []string, rs []celeng.Result, diags []celeng.LoadDiag) {
	t.Helper()
	out := fmt.Sprintf("%+v %+v", rs, diags)
	for _, v := range sens {
		if v != "" && strings.Contains(out, v) {
			t.Fatalf("sensitive value in the result or diagnostics: %s", out)
		}
	}
}

// limitsCase is one compliancetf.lib-limits/v1 case (the format of
// internal/engine/lib TestJSONLimitsFixtures). fn is json.path (default):
// a generated document of doc_bytes, {"a":"xx..."} or, malformed, with a
// duplicate key. fn iam.parse: a policy of statements Allow s3:* statements
// under a generated catalog of catalog_actions s3 actions.
type limitsCase struct {
	ID             string
	Fn             string
	DocBytes       int  `json:"doc_bytes"`
	Malformed      bool `json:"malformed"`
	Statements     int  `json:"statements"`
	CatalogActions int  `json:"catalog_actions"`
	RemainingUS    int  `json:"remaining_us"`
	Expect         struct {
		ErrClass engine.ErrClass `json:"err_class"`
	}
}

// fresh makes every replayed document new to the process-wide document
// cache: a cache hit needs no budget, so a repeated document would skip the
// limit checks under test.
var fresh atomic.Int64

// replayLimits replays a lib-limits/v1 file through the CEL library, with
// the remaining budget as the activation deadline (lib.DeadlineVar), the
// way celeng binds it.
func replayLimits(t *testing.T, f string, lf *limitsFile) {
	for _, tc := range lf.Cases {
		t.Run(strings.TrimSuffix(filepath.Base(f), ".json")+"/"+tc.ID, func(t *testing.T) {
			n := fresh.Add(1)
			var env *cel.Env
			var expr, doc string
			var opts []cel.ProgramOption
			var err error
			switch tc.Fn {
			case "", "json.path":
				env, err = cel.NewEnv(lib.JSON(), cel.Variable("v", cel.StringType))
				expr, doc = `json.path(v, "/a") != null`, sizedDoc(t, tc.DocBytes, tc.Malformed, n)
			case "iam.parse":
				bound, berr := lib.IAMProgram(s3Catalog(t, tc.CatalogActions), fmt.Sprintf("sha256:crosscheck-%d", n))
				if berr != nil {
					t.Fatal(berr)
				}
				env, err = cel.NewEnv(lib.IAM(), cel.Variable("v", cel.StringType))
				expr, doc, opts = `iam.parse(v).statements.size() > 0`, policy(tc.Statements), []cel.ProgramOption{bound}
			default:
				t.Fatalf("%s: fn %q", f, tc.Fn)
			}
			if err != nil {
				t.Fatal(err)
			}
			a, iss := env.Compile(expr)
			if iss.Err() != nil {
				t.Fatal(iss.Err())
			}
			prg, err := env.Program(a, opts...)
			if err != nil {
				t.Fatal(err)
			}
			out, _, err := prg.Eval(map[string]any{"v": doc,
				lib.DeadlineVar: time.Now().Add(time.Duration(tc.RemainingUS) * time.Microsecond)})
			got := engine.ErrNone
			switch {
			case errors.Is(err, lib.ErrLimit):
				got = engine.ErrLimit
			case errors.Is(err, lib.ErrInvalid):
				got = engine.ErrTypeError
			case err != nil:
				t.Fatalf("unexpected error %v", err)
			case out != types.True:
				t.Fatalf("got %v", out)
			}
			if got != tc.Expect.ErrClass {
				t.Fatalf("got %q (%v), want %q", got, err, tc.Expect.ErrClass)
			}
		})
	}
}

// sizedDoc is the lib-limits/v1 document of n bytes; nonce leads the
// filler so each call is a new document of the same length.
func sizedDoc(t *testing.T, n int, malformed bool, nonce int64) string {
	head := `{"a":"` + fmt.Sprint(nonce)
	if malformed {
		head = `{"a":1,"a":"` + fmt.Sprint(nonce)
	}
	fill := n - len(head) - 2
	if fill < 0 {
		t.Fatalf("doc_bytes %d is shorter than the %d-byte document frame", n, len(head)+2)
	}
	return head + strings.Repeat("x", fill) + `"}`
}

func policy(statements int) string {
	st := strings.TrimSuffix(strings.Repeat(`{"Effect":"Allow","Action":"s3:*","Resource":"*"},`, statements), ",")
	return `{"Version":"2012-10-17","Statement":[` + st + `]}`
}

func s3Catalog(t *testing.T, actions int) *iampolicy.Catalog {
	names := make([]string, actions)
	for i := range names {
		names[i] = fmt.Sprintf("a%05d", i)
	}
	b, err := json.Marshal(map[string]any{"format": iampolicy.CatalogFormat, "retrieved": "2026-10-01",
		"services": map[string][]string{"s3": names}, "snapshot": "sha256:" + strings.Repeat("0", 64), "source": iampolicy.CatalogSource})
	if err != nil {
		t.Fatal(err)
	}
	c, err := iampolicy.LoadCatalog(b)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestEmptyFixtureFails: a file that contributes no case fails its group
// even when the other files meet the minimum.
func TestEmptyFixtureFails(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(root, "crosscheck", "null", "N-01-null-attribute.json"))
	if err != nil {
		t.Fatal(err)
	}
	for name, empty := range map[string]string{
		"no-steps":       `{"id": "empty", "schema": "testdata/schemas/aws-subset.json", "controls": [], "steps": []}`,
		"no-cases":       `{"format": "` + limitsFormat + `", "cases": []}`,
		"trailing-data":  string(src) + `{}`,
		"op-unknown":     strings.Replace(string(src), `"op": "create"`, `"op": {"$unknown": true}`, 1),
		"unknown-format": `{"format": "compliancetf.lib-limits/v0", "cases": []}`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			for f, data := range map[string]string{"ok.json": string(src), "bad.json": empty} {
				if err := os.WriteFile(filepath.Join(dir, f), []byte(data), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := loadGroup(dir, 1); err == nil || !strings.Contains(err.Error(), "bad.json") {
				t.Fatalf("loadGroup: %v, want an error naming bad.json", err)
			}
			if err := os.Remove(filepath.Join(dir, "bad.json")); err != nil {
				t.Fatal(err)
			}
			if _, err := loadGroup(dir, 1); err != nil {
				t.Fatalf("without bad.json: %v", err)
			}
		})
	}
}

// TestSensitiveStrings: the leak scan reads sensitive attributes in nested
// blocks too, and only sensitive ones.
func TestSensitiveStrings(t *testing.T) {
	s := schema(t)
	blk := s.ResourceSchemas["aws_lb_listener"].Block
	v := enginetest.Value(t, blk.ValueType(), json.RawMessage(`{"default_action": [{"type": "authenticate-oidc",
		"authenticate_oidc": [{"issuer": "https://idp.bobthecorp.example", "client_id": "bobthecorp", "client_secret": "ctf-marker-nested-0001"}]}]}`))
	if got := enginetest.SensitiveStrings(blk, v); !slices.Equal(got, []string{"ctf-marker-nested-0001"}) {
		t.Fatalf("got %q", got)
	}
}
