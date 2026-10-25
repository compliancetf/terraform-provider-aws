package lifecycle

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/evidence"
	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

// dbType is the aws_db_instance subset the stage goldens use.
var dbType = tftypes.Object{AttributeTypes: map[string]tftypes.Type{
	"storage_encrypted":   tftypes.Bool,
	"kms_key_id":          tftypes.String,
	"engine":              tftypes.String,
	"deletion_protection": tftypes.Bool,
	"id":                  tftypes.String,
}}

// dbSchemas is the upstream schema of dbType the expr stage controls load
// against (celeng.SchemaSource).
type dbSchemas struct{}

func (dbSchemas) Resource(typ string) (*tfprotov5.Schema, bool) {
	if typ != "aws_db_instance" {
		return nil, false
	}
	b := &tfprotov5.SchemaBlock{}
	for _, n := range slices.Sorted(maps.Keys(dbType.AttributeTypes)) {
		b.Attributes = append(b.Attributes, &tfprotov5.SchemaAttribute{Name: n, Type: dbType.AttributeTypes[n], Optional: true})
	}
	return &tfprotov5.Schema{Block: b}, true
}

// DataSource serves dbType as the data source aws_db_lookup.
func (dbSchemas) DataSource(typ string) (*tfprotov5.Schema, bool) {
	if typ != "aws_db_lookup" {
		return nil, false
	}
	return dbSchemas{}.Resource("aws_db_instance")
}

func (dbSchemas) EphemeralResource(string) (*tfprotov5.Schema, bool) { return nil, false }

type stageGolden struct {
	Description  string          `json:"description"`
	Stage        hook.Stage      `json:"stage"`
	TypeName     string          `json:"type_name"` // default aws_db_instance
	Unconfigured bool            `json:"unconfigured"`
	Mode         profile.Mode    `json:"mode"`
	Op           hook.Op         `json:"op"`
	Replace      []string        `json:"requires_replace"`
	Config       json.RawMessage `json:"config"`
	Prior        json.RawMessage `json:"prior"`
	Planned      json.RawMessage `json:"planned"`
	New          json.RawMessage `json:"new"`
	// Identity is the decoded resource identity the proxy hands the hook.
	Identity map[string]any `json:"identity"`
	// Envelope is the apply_pre envelope; digest "current" is the loaded
	// VersionsDigest. Absent means the plan carried none.
	Envelope *struct {
		Op                hook.Op         `json:"op"`
		Digest            string          `json:"digest"`
		PriorIdentityKind string          `json:"prior_identity_kind"`
		PriorIdentity     json.RawMessage `json:"prior_identity"`
		Imported          bool            `json:"imported"`
	} `json:"envelope"`
	// Verdict gate goldens (TestVerdictGate): verdict_required, the recording
	// fake (absent: noVerdict), the RPC method and request, the data source
	// deferral, and whether the proxy gates the method.
	VerdictRequired bool           `json:"verdict_required"`
	Verdict         *verdictGolden `json:"verdict"`
	Method          string         `json:"method"`
	RPCRequest      string         `json:"rpc_request"`
	Deferred        bool           `json:"deferred"`
	Gated           bool           `json:"gated"`
	// TrustedEnv is read by the setup of TestTrustedEnv (env_*.json) and
	// TestTrustedEnvSelector (envsel_*.json) only.
	TrustedEnv *trustedEnvGolden `json:"trusted_env"`
	// NotEvaluable is read by TestNotEvaluableAsFail's setup only.
	NotEvaluable *notEvaluableGolden `json:"not_evaluable"`
	// Exception is read by TestExceptionStages's setup only.
	Exception *exceptionGolden `json:"exception"`
	// EvidenceRequired sets the profile's evidence.required; with
	// EvidenceUnavailable the evidence chain could not be opened.
	EvidenceRequired    bool `json:"evidence_required"`
	EvidenceUnavailable bool `json:"evidence_unavailable"`
	// DataSourcesDeny is the mode table data_sources deny switch; DenyFloor
	// its deny floor (hard_fail when an org has no acceptable profile).
	DataSourcesDeny bool         `json:"data_sources_deny"`
	DenyFloor       profile.Mode `json:"deny_floor"`
	Want            struct {
		Error       string        `json:"error"`
		NoRecord    bool          `json:"no_record"` // no eval record is written
		Diagnostics []wantDiag    `json:"diagnostics"`
		Stamp       bool          `json:"stamp"`
		Evidence    *wantEvidence `json:"evidence"`
	} `json:"want"`
}

type wantDiag struct {
	Severity  string `json:"severity"`
	Summary   string `json:"summary"`
	Detail    string `json:"detail"`
	Attribute string `json:"attribute,omitempty"`
}

// TestPlan runs stages/plan_*.json: validate and plan inputs to diagnostics
// and the envelope stamp.
func TestPlan(t *testing.T) { runStages(t, "plan_*.json") }

// TestApply runs stages/apply_*.json: apply_pre and apply_post inputs to
// diagnostics; NewState bytes are never altered.
func TestApply(t *testing.T) { runStages(t, "apply_*.json") }

// TestRefresh runs stages/refresh_*.json: the read stage on refreshed state.
func TestRefresh(t *testing.T) { runStages(t, "refresh_*.json") }

// TestImportNotInventory runs stages/import_*.json: the import stage on
// imported state writes stage import and resource.op import records, which
// the schema marks as never an inventory source (the schema mark
// is checked in internal/evidence).
func TestImportNotInventory(t *testing.T) { runStages(t, "import_*.json") }

// TestDataSource runs stages/datasource_*.json: the data_source stage on a
// read of aws_db_lookup: advisory by default, deny opt-in,
// unknown pending, a missing value not_evaluable.
func TestDataSource(t *testing.T) { runStages(t, "datasource_*.json") }

// TestDataSourceControlVersions: a data_source record's
// control_versions is the digest of the data source controls of the type,
// not the managed resource stamp of a resource control sharing the name.
func TestDataSourceControlVersions(t *testing.T) {
	expr := "resource.engine != \"mysql\""
	cs := stageControlSetDigest(t, "cd", bundle.Control{ID: "res_same_name", Version: "1.0.0", Kind: bundle.KindResource,
		ResourceType: "aws_db_lookup", Reads: []string{"engine"}, PresenceMode: bundle.PresenceEffective,
		On: []bundle.On{bundle.OnCreate}, Expr: &expr, Action: bundle.ActionWarn, Severity: "low", Message: "m"})
	want := cs.VersionsDigestOf("aws_db_lookup", bundle.KindDataSource)
	if want == cs.VersionsDigest("aws_db_lookup") {
		t.Fatal("fixture: data source and resource digests must differ")
	}
	l := New(Options{})
	l.testPerResource = 10 * time.Second
	l.cfg = &Configured{Table: profile.ModeTable{RunMode: profile.HardFail}, Controls: cs, Schemas: dbSchemas{}}
	evDir := t.TempDir()
	w, err := evidence.Open(evidence.Options{Dir: evDir, Run: evidence.Run{ID: "r1", IDSource: "compliancetf"}})
	if err != nil {
		t.Fatal(err)
	}
	l.ev = w
	ok := json.RawMessage(`{"storage_encrypted": true, "engine": "postgres", "deletion_protection": true}`)
	if _, err := l.Evaluate(context.Background(), &hook.Request{Stage: hook.StageDataSource, Kind: hook.KindDataSource,
		TypeName: "aws_db_lookup", Config: dynValue(t, ok), New: dynValue(t, ok)}); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range readChain(t, evDir) {
		if r.Stage != "data_source" {
			continue
		}
		n++
		if r.Digests == nil || r.Digests.ControlVersions == nil || *r.Digests.ControlVersions != want {
			t.Errorf("data_source control_versions = %+v, want %s", r.Digests, want)
		}
	}
	if n != 1 {
		t.Fatalf("%d data_source records, want 1", n)
	}
}

// TestJoinFields runs stages/join_*.json: the inventory join fields of the
// eval record.
func TestJoinFields(t *testing.T) { runStages(t, "join_*.json") }

// runStages runs the stage goldens matching pattern; each setup runs after
// the default Configured is in place and may replace it.
func runStages(t *testing.T, pattern string, setup ...func(*testing.T, *stageGolden, *Lifecycle)) {
	files, err := filepath.Glob(filepath.Join("testdata/stages", pattern))
	if err != nil || len(files) == 0 {
		t.Fatalf("no %s goldens: %v", pattern, err)
	}
	cs := stageControlSet(t)
	current := cs.VersionsDigest("aws_db_instance")
	for _, f := range files {
		t.Run(strings.TrimSuffix(filepath.Base(f), ".json"), func(t *testing.T) {
			raw, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			var g stageGolden
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&g); err != nil {
				t.Fatal(err)
			}
			if g.NotEvaluable != nil && len(setup) == 0 {
				t.Skip("run by TestNotEvaluableAsFail")
			}
			if (g.VerdictRequired || g.Method != "") && len(setup) == 0 {
				t.Skip("run by TestVerdictGate")
			}
			if g.TypeName == "" {
				g.TypeName = "aws_db_instance"
			}
			l := New(Options{})
			// Goldens do not test budgets; 10 s stays well under the
			// 60 s per-run budget that each admission reserves against.
			l.testPerResource = 10 * time.Second
			if !g.Unconfigured {
				l.cfg = &Configured{Table: profile.ModeTable{RunMode: g.Mode, VerdictRequired: g.VerdictRequired, DataSourcesDeny: g.DataSourcesDeny, DenyFloor: g.DenyFloor}, Controls: cs,
					Block: Block{ExceptionsFile: "compliance-exceptions.hcl"}, Schemas: dbSchemas{}}
				if g.EvidenceRequired {
					l.cfg.Resolution.Profile = &profile.Profile{Evidence: profile.Evidence{Required: true}}
				}
			}
			evDir := t.TempDir()
			if g.EvidenceUnavailable {
				l.evClass = evidence.ClassOpen
			} else {
				w, err := evidence.Open(evidence.Options{Dir: evDir, Run: evidence.Run{ID: "r1", IDSource: "compliancetf"}})
				if err != nil {
					t.Fatal(err)
				}
				l.ev = w
			}
			for _, f := range setup {
				f(t, &g, l)
			}
			req := &hook.Request{Stage: g.Stage, Kind: hook.KindResource, TypeName: g.TypeName, Op: g.Op,
				Config: dynValue(t, g.Config), Prior: dynValue(t, g.Prior), Planned: dynValue(t, g.Planned),
				Deferred: g.Deferred, Method: g.Method, Identity: g.Identity}
			if g.RPCRequest != "" {
				req.RPCRequest = []byte(g.RPCRequest)
			}
			var newMP, newBytes []byte
			if len(g.New) > 0 {
				newMP = msgpack(t, g.New)
				newBytes = bytes.Clone(newMP)
				req.New = hook.NewValue(newMP, nil, func() (tftypes.Type, error) { return dbType, nil })
			}
			for _, a := range g.Replace {
				req.RequiresReplace = append(req.RequiresReplace, tftypes.NewAttributePath().WithAttributeName(a))
			}
			if e := g.Envelope; e != nil {
				req.Envelope = &hook.EnvelopeHeader{V: 1}
				req.Envelope.CTF.Op, req.Envelope.CTF.ControlVersionsDigest = e.Op, e.Digest
				req.Envelope.CTF.PriorIdentityKind, req.Envelope.CTF.PriorIdentity = e.PriorIdentityKind, e.PriorIdentity
				req.Envelope.CTF.Imported = e.Imported
				if e.Digest == "current" {
					req.Envelope.CTF.ControlVersionsDigest = current
				}
			}
			res, err := l.Evaluate(context.Background(), req)
			// Apply after never alters NewState: the hook shares the bytes
			// the proxy returns to Core.
			if !bytes.Equal(newMP, newBytes) {
				t.Error("NewState bytes changed by Evaluate")
			}
			if cerr := l.Close(); cerr != nil {
				t.Fatal(cerr)
			}
			// Every stage call that evaluates writes one schema-valid eval record.
			recs := readChain(t, evDir)
			switch {
			case g.Want.NoRecord || g.Stage == hook.StageValidate:
				checkNoEvalRecord(t, recs)
			case err == nil && !g.EvidenceUnavailable:
				stage := stageName(Stage(g.Stage))
				checkEvalRecord(t, recs, stage, g.TypeName, g.Want.Evidence)
			}
			if g.Want.Error != "" {
				if err == nil || !strings.Contains(err.Error(), g.Want.Error) {
					t.Fatalf("error %v, want %q", err, g.Want.Error)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got := []wantDiag{}
			for _, d := range res.Diagnostics {
				w := wantDiag{Severity: "error", Summary: d.Summary, Detail: d.Detail}
				if d.Severity == hook.SeverityWarning {
					w.Severity = "warning"
				}
				if d.Attribute != nil {
					w.Attribute = d.Attribute.String()
				}
				got = append(got, w)
			}
			want := g.Want.Diagnostics
			if want == nil {
				want = []wantDiag{}
			}
			for i := range want {
				want[i].Detail = strings.ReplaceAll(want[i].Detail, "<current>", current)
			}
			gj, _ := json.MarshalIndent(got, "", "  ")
			wj, _ := json.MarshalIndent(want, "", "  ")
			if !bytes.Equal(gj, wj) {
				t.Errorf("diagnostics\n got %s\nwant %s", gj, wj)
			}
			wantStamp := ""
			if g.Want.Stamp {
				wantStamp = current
			}
			if res.ControlVersionsDigest != wantStamp {
				t.Errorf("stamp %q, want %q", res.ControlVersionsDigest, wantStamp)
			}
		})
	}
}

func TestWants(t *testing.T) {
	l := New(Options{})
	// Before Configure every kind is wanted, so Evaluate fails closed.
	for _, k := range []hook.Kind{hook.KindResource, hook.KindDataSource, hook.KindEphemeral} {
		if !l.Wants(k, "aws_s3_bucket") {
			t.Errorf("unconfigured Lifecycle must want every %s", k)
		}
	}
	l.cfg = &Configured{Controls: stageControlSet(t)}
	for _, c := range []struct {
		kind hook.Kind
		typ  string
		want bool
	}{
		{hook.KindResource, "aws_db_instance", true},
		{hook.KindResource, "aws_s3_bucket", false},
		{hook.KindDataSource, "aws_db_instance", false},
		{hook.KindDataSource, "aws_db_lookup", true},
		{hook.KindResource, "aws_db_lookup", false},
		{hook.KindEphemeral, "aws_db_instance", false},
	} {
		if got := l.Wants(c.kind, c.typ); got != c.want {
			t.Errorf("Wants(%s, %s) = %v, want %v", c.kind, c.typ, got, c.want)
		}
	}
}

func stageControlSet(t *testing.T) *bundle.ControlSet { return stageControlSetDigest(t, "ab") }

// stageControlSetDigest is the stage control set under bundle digest hex pair
// d, plus any extra controls.
func stageControlSetDigest(t *testing.T, d string, extra ...bundle.Control) *bundle.ControlSet {
	t.Helper()
	mraw, err := os.ReadFile("testdata/stages/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	m, err := bundle.DecodeManifest(mraw)
	if err != nil {
		t.Fatal(err)
	}
	craw, err := os.ReadFile("testdata/stages/controls.json")
	if err != nil {
		t.Fatal(err)
	}
	controls, err := bundle.ParseControls(craw)
	if err != nil {
		t.Fatal(err)
	}
	controls = append(controls, extra...)
	b := &bundle.Bundle{Manifest: m, Digest: "sha256:" + strings.Repeat(d, 32), Controls: controls,
		Revocations: trust.NoRevocations()}
	cs, _, err := bundle.NewControlSet("bobthecorp", time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC), trust.NoRevocations(), b)
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

// dynValue builds a hook value of dbType from golden JSON: absent means not
// present, null a null object, "<unknown>" an unknown object or attribute.
func dynValue(t *testing.T, raw json.RawMessage) *hook.Value {
	t.Helper()
	if len(raw) == 0 {
		return nil
	}
	return hook.NewValue(msgpack(t, raw), nil, func() (tftypes.Type, error) { return dbType, nil })
}

func msgpack(t *testing.T, raw json.RawMessage) []byte {
	t.Helper()
	dv, err := tfprotov5.NewDynamicValue(dbType, objValue(t, raw))
	if err != nil {
		t.Fatal(err)
	}
	return dv.MsgPack
}

func objValue(t *testing.T, raw json.RawMessage) tftypes.Value {
	t.Helper()
	switch string(raw) {
	case "null":
		return tftypes.NewValue(dbType, nil)
	case `"<unknown>"`:
		return tftypes.NewValue(dbType, tftypes.UnknownValue)
	}
	var in map[string]any
	if err := json.Unmarshal(raw, &in); err != nil {
		t.Fatal(err)
	}
	attrs := map[string]tftypes.Value{}
	for name, typ := range dbType.AttributeTypes {
		x, ok := in[name]
		delete(in, name)
		switch {
		case !ok || x == nil:
			attrs[name] = tftypes.NewValue(typ, nil)
		case x == "<unknown>":
			attrs[name] = tftypes.NewValue(typ, tftypes.UnknownValue)
		default:
			attrs[name] = tftypes.NewValue(typ, x)
		}
	}
	if len(in) != 0 {
		t.Fatalf("unknown attributes %v", in)
	}
	return tftypes.NewValue(dbType, attrs)
}
