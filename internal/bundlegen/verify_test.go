package bundlegen

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"golang.org/x/tools/txtar"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/celeng"
)

// verifyEngine has a minute budget: no case tests the deadline.
func verifyEngine() *celeng.Engine {
	return celeng.New(celeng.Options{PerResourceBudget: time.Minute})
}

func subsetSchemas(t *testing.T) Schemas {
	t.Helper()
	s, err := LoadSchemas(awsSubset)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func testControl(id, typ, expr string, mode bundle.PresenceMode, reads ...string) bundle.Control {
	return bundle.Control{ID: id, Version: "1.0.0", Kind: bundle.KindResource, ResourceType: typ, Reads: append([]string{}, reads...),
		PresenceMode: mode, On: []bundle.On{bundle.OnCreate, bundle.OnUpdate}, Expr: &expr, Action: bundle.ActionDeny,
		Severity: bundle.SeverityHigh, Message: "Fixture control.", ExemptionCoverable: []bundle.ExemptionKind{}}
}

// synth synthesizes the cases of c against the aws-subset.
func synth(t *testing.T, s Schemas, c bundle.Control) []Case {
	t.Helper()
	sc, _ := s.Resource(c.ResourceType)
	cs, err := Synthesize(c, sc)
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

// bundleOutput is one bundle "test" of cs and their cases.
func bundleOutput(t *testing.T, cs []bundle.Control, cases []Case) *Output {
	t.Helper()
	data, err := EmitControls(cs)
	if err != nil {
		t.Fatal(err)
	}
	out := &Output{Files: map[string][]byte{"test/controls.json": data}}
	if err := out.AddCases("test", cases); err != nil {
		t.Fatal(err)
	}
	return out
}

// retarget moves cases to control c, keeping bindings and expectations.
func retarget(cases []Case, c bundle.Control) []Case {
	out := slices.Clone(cases)
	for i := range out {
		name := out[i].ID[strings.LastIndex(out[i].ID, ".")+1:]
		out[i].Control, out[i].ID = c, caseID(c, name)
	}
	return out
}

// TestVerify is the oracle: a vacuous true control and an effective
// deny control reading an Optional+Computed attribute without a deciding
// unknown fixture are reported; a deciding authored unknown case and
// synthesized cases of sound controls verify clean.
func TestVerify(t *testing.T) {
	s := subsetSchemas(t)
	good := testControl("ctf_good", "aws_db_instance", "resource.storage_encrypted == true", bundle.PresenceEffective, "storage_encrypted")
	vacuous := testControl("ctf_vacuous", "aws_db_instance", "true", bundle.PresenceEffective, "storage_encrypted")
	oc := testControl("ctf_oc", "aws_instance", "resource.associate_public_ip_address == false", bundle.PresenceEffective, "associate_public_ip_address")
	decided := testControl("ctf_oc_decided", "aws_instance", `resource.instance_type == "t3.micro" && resource.associate_public_ip_address == false`,
		bundle.PresenceEffective, "associate_public_ip_address", "instance_type")
	nofail := testControl("ctf_nofail", "aws_db_instance", "resource.storage_encrypted == true", bundle.PresenceEffective, "storage_encrypted")

	var cases []Case
	cases = append(cases, synth(t, s, good)...)
	cases = append(cases, retarget(synth(t, s, good), vacuous)...)
	cases = append(cases, synth(t, s, oc)...)
	// authored deciding unknown cases: one read fails while the other is
	// unknown
	dc := synth(t, s, decided)
	if len(dc) != 4 {
		t.Fatalf("%d cases for two Optional+Computed reads plus pass and fail, want 4", len(dc))
	}
	dc = dc[:2]
	u := dc[1]
	u.ID = caseID(decided, "unknown-decides")
	u.Bindings.Resource = json.RawMessage(`{"instance_type": "BOBTHECORP_INVALID", "associate_public_ip_address": {"$unknown": true}}`)
	u.Bindings.Config = u.Bindings.Resource
	u2 := u
	u2.ID = caseID(decided, "unknown-decides-type")
	u2.Bindings.Resource = json.RawMessage(`{"instance_type": {"$unknown": true}, "associate_public_ip_address": true}`)
	u2.Bindings.Config = u2.Bindings.Resource
	cases = append(cases, append(dc, u, u2)...)
	cases = append(cases, synth(t, s, nofail)[:1]...)

	rep, err := Verify(bundleOutput(t, []bundle.Control{good, vacuous, oc, decided, nofail}, cases), s, verifyEngine())
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range rep.Findings {
		got = append(got, f.String())
	}
	want := []string{
		"E_FIXTURE_MISSING ctf_nofail: want a pass and a fail case, have 1 cases",
		"E_OPTIONAL_COMPUTED ctf_oc: associate_public_ip_address: use presence_mode configured or add a deciding unknown fixture",
		"E_LOAD_DIAG ctf_vacuous: control_reads_unused",
		"E_LOAD_DIAG ctf_vacuous: control_constant",
		`E_FIXTURE_MISMATCH ctf_vacuous fail: want fail "" [], got pass "" []`,
		"E_MUTATION_SURVIVED ctf_vacuous fail: !(expr) gives fail, want pass",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("findings\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// TestVerifyInputErrors: a case at the wrong path, a case for a control
// the bundle lacks and a stale case control fail.
func TestVerifyInputErrors(t *testing.T) {
	s := subsetSchemas(t)
	good := testControl("ctf_good", "aws_db_instance", "resource.storage_encrypted == true", bundle.PresenceEffective, "storage_encrypted")
	cases := synth(t, s, good)

	out := bundleOutput(t, []bundle.Control{good}, cases)
	out.Files["test/cases/ctf_good/moved.json"] = out.Files[CasePath("test", cases[0])]
	if _, err := Verify(out, s, verifyEngine()); err == nil || !strings.Contains(err.Error(), "moved.json") {
		t.Fatalf("moved case: %v", err)
	}

	other := testControl("ctf_other", "aws_db_instance", "resource.storage_encrypted == true", bundle.PresenceEffective, "storage_encrypted")
	if _, err := Verify(bundleOutput(t, []bundle.Control{good}, append(cases, retarget(cases, other)...)), s, verifyEngine()); err == nil ||
		!strings.Contains(err.Error(), "ctf_other") {
		t.Fatalf("orphan case: %v", err)
	}

	stale := retarget(cases, good)
	stale[0].Control.Message = "Old message."
	rep, err := Verify(bundleOutput(t, []bundle.Control{good}, stale), s, verifyEngine())
	// a stale case does not count as the pass case
	if err != nil || len(rep.Findings) != 2 || rep.Findings[0].Code != "E_FIXTURE_CONTROL" || rep.Findings[1].Code != "E_FIXTURE_MISSING" {
		t.Fatalf("stale case: %+v %v", rep.Findings, err)
	}
}

// TestVerifyClaims: verify fails, never passes, on an output it would not
// check: no bundle, cases without controls.json, a nested controls.json or
// a stray file.
func TestVerifyClaims(t *testing.T) {
	s := subsetSchemas(t)
	good := testControl("ctf_good", "aws_db_instance", "resource.storage_encrypted == true", bundle.PresenceEffective, "storage_encrypted")
	valid := func() *Output { return bundleOutput(t, []bundle.Control{good}, synth(t, s, good)) }
	casesOnly := valid()
	delete(casesOnly.Files, "test/controls.json")
	nestedOnly := &Output{Files: map[string][]byte{"a/b/controls.json": valid().Files["test/controls.json"]}}
	nested := valid()
	nested.Files["test/sub/controls.json"] = nested.Files["test/controls.json"]
	stray := valid()
	stray.Files["notes.txt"] = []byte("x")
	strayInBundle := valid()
	strayInBundle.Files["test/extra.json"] = []byte("{}")
	emptyID := valid()
	emptyID.Files["/controls.json"] = emptyID.Files["test/controls.json"]
	emptyIDOnly := &Output{Files: map[string][]byte{"/controls.json": valid().Files["test/controls.json"]}}
	reports := valid()
	reports.Files["coverage.json"] = []byte("{}")
	reports.Files["test/build.json"] = []byte("{}")
	for name, tc := range map[string]struct {
		out  *Output
		code string
	}{
		"empty":           {&Output{}, "E_VERIFY_EMPTY"},
		"cases-only":      {casesOnly, "E_VERIFY_EMPTY"},
		"nested-only":     {nestedOnly, "E_VERIFY_EMPTY"},
		"nested":          {nested, "E_VERIFY_UNCLAIMED"},
		"stray":           {stray, "E_VERIFY_UNCLAIMED"},
		"stray-in-bundle": {strayInBundle, "E_VERIFY_UNCLAIMED"},
		"empty-id":        {emptyID, "E_VERIFY_UNCLAIMED"},
		"empty-id-only":   {emptyIDOnly, "E_VERIFY_EMPTY"},
		"reports":         {reports, ""},
	} {
		t.Run(name, func(t *testing.T) {
			rep, err := Verify(tc.out, s, verifyEngine())
			var e *Error
			switch {
			case tc.code == "" && (err != nil || len(rep.Findings) != 0):
				t.Fatalf("got %+v %v", rep.Findings, err)
			case tc.code != "" && (!errors.As(err, &e) || e.Code != tc.code):
				t.Fatalf("got %v, want %s", err, tc.code)
			}
		})
	}
}

// TestVerifyDecidingMismatch: an unknown case whose expectation the engine
// does not reproduce does not count as deciding.
func TestVerifyDecidingMismatch(t *testing.T) {
	s := subsetSchemas(t)
	oc := testControl("ctf_oc", "aws_instance", "resource.associate_public_ip_address == false", bundle.PresenceEffective, "associate_public_ip_address")
	cases := synth(t, s, oc)
	u := cases[1]
	u.ID = caseID(oc, "unknown-wrong")
	u.Bindings.Resource = json.RawMessage(`{"associate_public_ip_address": {"$unknown": true}}`)
	rep, err := Verify(bundleOutput(t, []bundle.Control{oc}, append(cases, u)), s, verifyEngine())
	if err != nil {
		t.Fatal(err)
	}
	var codes []string
	for _, f := range rep.Findings {
		codes = append(codes, f.Code)
	}
	if !slices.Equal(codes, []string{"E_FIXTURE_MISMATCH", "E_MUTATION_SURVIVED", "E_OPTIONAL_COMPUTED"}) {
		t.Fatalf("findings %+v", rep.Findings)
	}
}

// TestAddCases: a nil Files map is initialized and a duplicate path is an
// error, never an overwrite.
func TestAddCases(t *testing.T) {
	s := subsetSchemas(t)
	good := testControl("ctf_good", "aws_db_instance", "resource.storage_encrypted == true", bundle.PresenceEffective, "storage_encrypted")
	cases := synth(t, s, good)
	var out Output
	if err := out.AddCases("test", cases); err != nil || len(out.Files) != len(cases) {
		t.Fatalf("%d files, %v", len(out.Files), err)
	}
	var e *Error
	if err := out.AddCases("test", cases[:1]); !errors.As(err, &e) || e.Code != "E_FIXTURE" {
		t.Fatalf("duplicate: %v", err)
	}
}

// TestUnknownCaseNames: reads a.b and a_b get distinct unknown cases, and
// a read through an Optional+Computed object attribute is Optional+Computed.
func TestUnknownCaseNames(t *testing.T) {
	oc := func(name string, typ tftypes.Type) *tfprotov5.SchemaAttribute {
		return &tfprotov5.SchemaAttribute{Name: name, Type: typ, Optional: true, Computed: true}
	}
	sc := &tfprotov5.Schema{Block: &tfprotov5.SchemaBlock{
		Attributes: []*tfprotov5.SchemaAttribute{oc("a_b", tftypes.String),
			oc("o", tftypes.Object{AttributeTypes: map[string]tftypes.Type{"x": tftypes.String}}),
			{Name: "p", Type: tftypes.Object{AttributeTypes: map[string]tftypes.Type{"x": tftypes.String}}, Optional: true}},
		BlockTypes: []*tfprotov5.SchemaNestedBlock{{TypeName: "a", Nesting: tfprotov5.SchemaNestedBlockNestingModeList, MaxItems: 1,
			Block: &tfprotov5.SchemaBlock{Attributes: []*tfprotov5.SchemaAttribute{oc("b", tftypes.String)}}}},
	}}
	c := testControl("ctf_names", "aws_fake", "resource.a_b != null && resource.a.exists(e0, e0.b != null)", bundle.PresenceEffective, "a", "a.b", "a_b")
	cs, err := Synthesize(c, sc)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, k := range cs {
		names = append(names, strings.TrimPrefix(k.ID, caseID(c, "")))
	}
	if !slices.Equal(names, []string{"pass", "fail", "unknown-a-b", "unknown-a_b"}) {
		t.Fatalf("names %q", names)
	}
	if err := (&Output{}).AddCases("test", cs); err != nil {
		t.Fatal(err)
	}
	if !optionalComputed(sc.Block, []string{"o", "x"}) || optionalComputed(sc.Block, []string{"p", "x"}) ||
		!optionalComputed(sc.Block, []string{"a", "b"}) || optionalComputed(sc.Block, []string{"a"}) {
		t.Fatal("optionalComputed")
	}
	for raw, want := range map[string]bool{
		`{"o": {"$unknown": true}}`:        true,
		`{"o": {"x": {"$unknown": true}}}`: true,
		`{"o": {"x": "bobthecorp"}}`:       false,
		`{"a": [{"$unknown": true}]}`:      true,
	} {
		path := []string{"o", "x"}
		if strings.Contains(raw, `"a"`) {
			path = []string{"a", "b"}
		}
		if unknownAt(json.RawMessage(raw), path) != want {
			t.Errorf("unknownAt %s: want %v", raw, want)
		}
	}
}

// TestSynthesizeValues pins the fixture synthesis rules on the case
// bindings.
func TestSynthesizeValues(t *testing.T) {
	s := subsetSchemas(t)
	for _, tc := range []struct {
		c                bundle.Control
		pass, fail, unkn string
	}{
		{testControl("x", "aws_db_instance", "resource.storage_encrypted == true", bundle.PresenceEffective, "storage_encrypted"),
			`{"storage_encrypted":true}`, `{"storage_encrypted":false}`, ""},
		{testControl("x", "aws_db_instance", `resource.engine in ["mysql", "postgres"]`, bundle.PresenceEffective, "engine"),
			`{"engine":"mysql"}`, `{"engine":"BOBTHECORP_INVALID"}`, `{"engine":{"$unknown":true}}`},
		{testControl("x", "aws_db_instance", "config.kms_key_id != null && size(config.kms_key_id) > 0", bundle.PresenceConfigured, "kms_key_id"),
			`{"kms_key_id":"arn:aws:kms:eu-west-1:111111111111:key/bobthecorp"}`, `{"kms_key_id":null}`, `{"kms_key_id":{"$unknown":true}}`},
		{testControl("x", "aws_s3_bucket_versioning", `resource.versioning_configuration.exists(e0, e0.status == "Enabled")`, bundle.PresenceEffective, "versioning_configuration", "versioning_configuration.status"),
			`{"versioning_configuration":[{"status":"Enabled"}]}`, `{"versioning_configuration":[]}`, ""},
		{testControl("x", "aws_s3_bucket_versioning", "size(config.versioning_configuration) >= 1", bundle.PresenceConfigured, "versioning_configuration"),
			`{"versioning_configuration":[{}]}`, `{"versioning_configuration":[]}`, ""},
	} {
		t.Run(*tc.c.Expr, func(t *testing.T) {
			cs := synth(t, s, tc.c)
			want := []string{tc.pass, tc.fail}
			if tc.unkn != "" {
				want = append(want, tc.unkn)
			}
			var got []string
			for _, k := range cs {
				got = append(got, string(k.Bindings.Resource))
				if string(k.Bindings.Config) != string(k.Bindings.Resource) {
					t.Errorf("%s: config differs from resource", k.ID)
				}
			}
			if !slices.Equal(got, want) {
				t.Fatalf("got %q, want %q", got, want)
			}
		})
	}
	bad := testControl("x", "aws_db_instance", "resource.storage_encrypted || true", bundle.PresenceEffective, "storage_encrypted")
	sc, _ := s.Resource("aws_db_instance")
	var e *Error
	if _, err := Synthesize(bad, sc); !errors.As(err, &e) || e.Code != "E_FIXTURE_SYNTH" {
		t.Fatalf("unsupported shape: %v", err)
	}
}

// TestVerifyTranslated synthesizes and verifies every control of the
// translation table (testdata/translate): synthesized cases never disagree
// with the translator, the mutant always flips, and the only finding is
// E_OPTIONAL_COMPUTED, exactly for effective deny controls with an
// Optional+Computed read.
func TestVerifyTranslated(t *testing.T) {
	files, err := filepath.Glob("testdata/translate/*.txtar")
	if err != nil {
		t.Fatal(err)
	}
	subset := subsetSchemas(t)
	n := 0
	for _, f := range files {
		ar, err := txtar.ParseFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var want translateResult
		for _, x := range ar.Files {
			if x.Name == "schema.json" {
				want.Control = nil // own schema: covered by TestTranslate
				break
			}
			if x.Name == "want.json" {
				if err := decodeStrictJSON(x.Data, &want); err != nil {
					t.Fatal(err)
				}
			}
		}
		if want.Control == nil {
			continue
		}
		n++
		c := *want.Control
		c.Severity, c.Message = bundle.SeverityHigh, "Fixture control."
		t.Run(strings.TrimSuffix(filepath.Base(f), ".txtar"), func(t *testing.T) {
			rep, err := Verify(bundleOutput(t, []bundle.Control{c}, synth(t, subset, c)), subset, verifyEngine())
			if err != nil {
				t.Fatal(err)
			}
			sc, _ := subset.Resource(c.ResourceType)
			var wantF []string
			for _, r := range c.Reads {
				if c.PresenceMode == bundle.PresenceEffective && optionalComputed(sc.Block, strings.Split(r, ".")) {
					wantF = append(wantF, "E_OPTIONAL_COMPUTED "+r)
				}
			}
			var got []string
			for _, f := range rep.Findings {
				got = append(got, f.Code+" "+strings.SplitN(f.Detail, ":", 2)[0])
			}
			if !slices.Equal(got, wantF) {
				t.Fatalf("findings %+v, want %q", rep.Findings, wantF)
			}
		})
	}
	if n < 8 {
		t.Fatalf("%d translated controls, want at least 8", n)
	}
}

// iamOutput is one bundle of the iam control expr with a pass case (no
// grant of s3:PutBucketPolicy) and a fail case (a grant), and the test
// catalog.
func iamOutput(t *testing.T, id, expr string) *Output {
	t.Helper()
	c := testControl(id, "aws_s3_bucket_policy", expr, bundle.PresenceEffective, "policy")
	pol := func(action string) json.RawMessage {
		return json.RawMessage(`{"bucket": "bobthecorp-logs", "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::222222222222:root\"},\"Action\":\"` + action + `\",\"Resource\":\"*\"}]}"}`)
	}
	var cases []Case
	for _, x := range []struct {
		name, action string
		st           engine.State
	}{{CasePass, "s3:GetObject", engine.Pass}, {CaseFail, "s3:PutBucketPolicy", engine.Fail}} {
		cases = append(cases, Case{ID: caseID(c, x.name), ResourceType: c.ResourceType, Control: c,
			Bindings: CaseBindings{Op: "create", Provider: fixtureProvider, Resource: pol(x.action)},
			Expect:   CaseExpect{State: x.st, UnknownPaths: []string{}}})
	}
	out := bundleOutput(t, []bundle.Control{c}, cases)
	cat, err := os.ReadFile("testdata/inputs/iam-actions.json")
	if err != nil {
		t.Fatal(err)
	}
	out.Files["test/iam-actions.json"] = cat
	return out
}

const iamGrantsExpr = `iam.parse(resource.policy).statements.all(s, !(s.effect == "Allow" && iam.grants(s, "s3:putbucketpolicy")))`

// TestVerifyIAMMutant: an iam.grants control's
// mutant loads through the verify-only LoadMutant (no polarity lint) and
// must flip both cases, so the control verifies clean with the mutation
// check run, and a vacuous iam.grants control is still caught.
func TestVerifyIAMMutant(t *testing.T) {
	s := subsetSchemas(t)
	rep, err := Verify(iamOutput(t, "ctf_iam", iamGrantsExpr), s, verifyEngine())
	if err != nil || len(rep.Findings) != 0 {
		t.Fatalf("iam.grants control: %+v %v", rep.Findings, err)
	}
	rep, err = Verify(iamOutput(t, "ctf_iam_vacuous", iamGrantsExpr+" || true"), s, verifyEngine())
	if err != nil {
		t.Fatal(err)
	}
	codes := map[string]bool{}
	for _, f := range rep.Findings {
		codes[f.Code] = true
	}
	if !codes["E_FIXTURE_MISMATCH"] || !codes["E_MUTATION_SURVIVED"] || codes["E_MUTATION_LOAD"] {
		t.Fatalf("vacuous iam.grants control: %+v", rep.Findings)
	}
}

// TestSynthesizeCollections: sample elements follow the element type
// (tftypes Is compares the outer kind only), the cases replay through
// verify, and an unsupported element type is E_FIXTURE_SYNTH.
func TestSynthesizeCollections(t *testing.T) {
	obj := tftypes.Object{AttributeTypes: map[string]tftypes.Type{"x": tftypes.String}}
	attrs := []*tfprotov5.SchemaAttribute{
		{Name: "ln", Type: tftypes.List{ElementType: tftypes.Number}, Required: true},
		{Name: "sb", Type: tftypes.Set{ElementType: tftypes.Bool}, Required: true},
		{Name: "mn", Type: tftypes.Map{ElementType: tftypes.Number}, Required: true},
		{Name: "lo", Type: tftypes.List{ElementType: obj}, Required: true},
	}
	sc := &tfprotov5.Schema{Block: &tfprotov5.SchemaBlock{Attributes: attrs}}
	s := Schemas{resp: &tfprotov5.GetProviderSchemaResponse{ResourceSchemas: map[string]*tfprotov5.Schema{"aws_fake": sc}}}
	for name, want := range map[string]string{"ln": `{"ln":[1]}`, "sb": `{"sb":[true]}`, "mn": `{"mn":{"bobthecorp":1}}`} {
		c := testControl("ctf_"+name, "aws_fake", "resource."+name+" != null && size(resource."+name+") > 0", bundle.PresenceEffective, name)
		cs, err := Synthesize(c, sc)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := string(cs[0].Bindings.Resource); got != want {
			t.Fatalf("%s: pass %s, want %s", name, got, want)
		}
		rep, err := Verify(bundleOutput(t, []bundle.Control{c}, cs), s, verifyEngine())
		if err != nil || len(rep.Findings) != 0 {
			t.Fatalf("%s: %+v %v", name, rep.Findings, err)
		}
	}
	c := testControl("ctf_lo", "aws_fake", "resource.lo != null", bundle.PresenceEffective, "lo")
	var e *Error
	if _, err := Synthesize(c, sc); !errors.As(err, &e) || e.Code != "E_FIXTURE_SYNTH" {
		t.Fatalf("list(object): %v", err)
	}
}
