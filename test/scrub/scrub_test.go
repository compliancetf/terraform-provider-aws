// Package scrub is the value-free output scrub test (the value-free output
// invariant): marker secrets planted in sensitive and
// non-sensitive attributes, map keys, policy documents and JSON strings, for
// every result state and error class, never reach a result, load or
// selector diagnostic, sidecar decision, memo dump or log line. The ctftest
// file adds the lifecycle streams: diagnostics, Configure warnings and the
// evidence chain.
//
// Markers are never planted in id or identity attributes: evidence records
// the cloud id and identifier attributes by design (spec 10.1).
package scrub

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/celeng"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/enginetest"
	"github.com/compliancetf/terraform-provider-aws/internal/exceptions"
	"github.com/compliancetf/terraform-provider-aws/internal/iampolicy"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
	"github.com/compliancetf/terraform-provider-aws/test/scrub/scrubtest"
)

const testdata = "../../testdata"

// exprMarkers matches the markers control expressions hold as constant map
// keys: control text, not resource data, so a load error naming the
// expression may carry them. Only load streams cut them. They are numbered
// 900 and up, planted data markers below 900 (TestScrubMarkerRanges), and a
// match must end at a non-digit, so a cut never touches a data marker. A
// data key equal to an expression key (the unknown map-key cases) is the
// same control text.
var exprMarkers = func() *regexp.Regexp {
	var alts []string
	for _, c := range cases {
		for _, m := range scrubtest.MarkerRE.FindAllString(c.expr, -1) {
			alts = append(alts, regexp.QuoteMeta(m))
		}
	}
	return regexp.MustCompile(`(?:` + strings.Join(alts, "|") + `)([^0-9]|$)`)
}()

// scrubCase is one control and one resource that drives it to a state and
// error class. Values are enginetest JSON ({"$unknown": true} is unknown);
// %[1]s... in resource are replaced by markers.
type scrubCase struct {
	name, typ, expr string
	reads           []string
	resource        string
	envUntrusted    bool
	cover           bool // self_service coverable (the lifecycle sidecar entries)
	state           engine.State
	class           engine.ErrClass
	paths           []string // exact UnknownPaths
	evPaths         []string // fail and not_evaluable evidence paths, when not reads
}

func (c scrubCase) id() string { return "scrub_" + c.name }

// big is a string over the 256 KiB json.path document limit that starts
// and ends with a marker.
var big = scrubtest.Marker(15) + strings.Repeat("x", 300<<10) + scrubtest.Marker(16)

// cases cover every state and every error class except timeout (an
// expired deadline, TestScrubEngine). aws_db_instance tags is marked sensitive by schemas(),
// aws_s3_bucket tags is not: both carry marker keys.
var cases = []scrubCase{
	{name: "pass", typ: "aws_db_instance", reads: []string{"password", "tags"},
		expr:     `resource.password != "" && size(resource.tags) > 0`,
		resource: `{"password": %[1]q, "tags": {%[2]q: %[3]q}}`, state: engine.Pass},
	{name: "fail", typ: "aws_s3_bucket", reads: []string{"tags"}, cover: true,
		expr:     `"Owner" in resource.tags`,
		resource: `{"tags": {%[4]q: %[5]q}}`, state: engine.Fail},
	// The unknown trail runs through the marker key (the read is the
	// constant index); UnknownPaths stop at the map attribute.
	{name: "unknown_sensitive_map_key", typ: "aws_db_instance", reads: []string{"tags"},
		expr:     `resource.tags["BOBTHECORP-MARKER-906"] != ""`,
		resource: `{"password": %[1]q, "tags": {"BOBTHECORP-MARKER-906": {"$unknown": true}, %[7]q: %[3]q}}`,
		state:    engine.Unknown, paths: []string{"tags"}},
	{name: "unknown_map_key", typ: "aws_s3_bucket", reads: []string{"tags"}, cover: true,
		expr:     `resource.tags["BOBTHECORP-MARKER-904"] != ""`,
		resource: `{"tags": {"BOBTHECORP-MARKER-904": {"$unknown": true}, %[5]q: %[3]q}}`,
		state:    engine.Unknown, paths: []string{"tags"}},
	// Lowercase marker keys pass the evidence path format ([a-z0-9_]), so
	// they would survive into evidence bytes. A constant index shaped like
	// an attribute name is a read step (reads.go: map key or object
	// attribute); UnknownPaths cut it at the schema map attribute,
	// so no map key leaves the engine.
	{name: "unknown_lower_sensitive_map_key", typ: "aws_db_instance", reads: []string{"tags"},
		expr:     `resource.tags["owner_key"] != ""`,
		resource: `{"tags": {"owner_key": {"$unknown": true}, "bobthecorp_marker_44": {"$unknown": true}, %[7]q: %[3]q}}`,
		state:    engine.Unknown, paths: []string{"tags"}},
	{name: "unknown_lower_map_key", typ: "aws_s3_bucket", reads: []string{"tags"},
		expr:     `resource.tags["owner_key"] != ""`,
		resource: `{"tags": {"owner_key": {"$unknown": true}, "bobthecorp_marker_45": %[5]q}}`,
		state:    engine.Unknown, paths: []string{"tags"}},
	// A declared read below a map attribute: fail and not_evaluable
	// evidence records the declared reads cut at the map.
	{name: "fail_map_key_read", typ: "aws_s3_bucket", reads: []string{"tags.owner_key"},
		expr:     `resource.tags["owner_key"] == "x"`,
		resource: `{"tags": {"owner_key": %[43]q}}`, state: engine.Fail, evPaths: []string{"tags"}},
	{name: "missing_map_key_read", typ: "aws_db_instance", reads: []string{"tags.owner_key"},
		expr:     `resource.tags["owner_key"] == "x"`,
		resource: `{"tags": {%[47]q: %[48]q}}`, state: engine.NotEvaluable, class: engine.ErrNoSuchAttribute,
		evPaths: []string{"tags"}},
	{name: "non_bool", typ: "aws_s3_bucket_policy", reads: []string{"policy"},
		expr:     `json.path(resource.policy, "/a")`,
		resource: `{"bucket": %[1]q, "policy": "{\"a\": \"%[8]s\"}"}`, state: engine.NotEvaluable, class: engine.ErrTypeError},
	{name: "json_invalid", typ: "aws_s3_bucket_policy", reads: []string{"policy"},
		expr:     `json.path(resource.policy, "/a") == "x"`,
		resource: `{"policy": "{\"a\": %[9]s"}`, state: engine.NotEvaluable, class: engine.ErrTypeError},
	{name: "json_duplicate_key", typ: "aws_s3_bucket_policy", reads: []string{"policy"},
		expr:     `json.path(resource.policy, "/a") == "x"`,
		resource: `{"policy": "{\"a\": \"%[10]s\", \"a\": \"%[11]s\"}"}`, state: engine.NotEvaluable, class: engine.ErrTypeError},
	{name: "policy_invalid", typ: "aws_s3_bucket_policy", reads: []string{"policy"},
		expr:     `iam.parse(resource.policy).statements.size() > 0`,
		resource: `{"policy": "{\"Version\": \"2012-10-17\", \"Statement\": \"%[12]s\"}"}`, state: engine.NotEvaluable, class: engine.ErrTypeError},
	{name: "cidr_invalid", typ: "aws_vpc_security_group_ingress_rule", reads: []string{"cidr_ipv4"},
		expr:     `!cidr.contains("0.0.0.0/0", resource.cidr_ipv4)`,
		resource: `{"cidr_ipv4": %[13]q}`, state: engine.NotEvaluable, class: engine.ErrTypeError},
	{name: "conversion", typ: "aws_db_instance", reads: []string{"password"},
		expr:     `int(resource.password) > 0`,
		resource: `{"password": %[14]q}`, state: engine.NotEvaluable, class: engine.ErrTypeError},
	{name: "doc_limit", typ: "aws_s3_bucket_policy", reads: []string{"policy"},
		expr:     `json.path(resource.policy, "/a") != null`,
		resource: `{"policy": "{\"a\": \"%[15]s\"}"}`, state: engine.NotEvaluable, class: engine.ErrLimit},
	{name: "cost_limit", typ: "aws_db_instance", reads: []string{"kms_key_id"},
		expr:     `[0,1,2,3,4,5,6,7,8,9].all(a, [0,1,2,3,4,5,6,7,8,9].all(b, [0,1,2,3,4,5,6,7,8,9].all(c, !resource.kms_key_id.contains("zz"))))`,
		resource: `{"kms_key_id": %[16]q}`, state: engine.NotEvaluable, class: engine.ErrLimit},
	{name: "missing_key", typ: "aws_s3_bucket", reads: []string{"tags"},
		expr:     `resource.tags["absent"] == "x"`,
		resource: `{"tags": {%[19]q: %[20]q}}`, state: engine.NotEvaluable, class: engine.ErrNoSuchAttribute},
	// An absent marker key: cel-go names the key in its error text.
	{name: "missing_sensitive_marker_key", typ: "aws_db_instance", reads: []string{"tags"},
		expr:     `resource.tags["BOBTHECORP-MARKER-940"] == "x"`,
		resource: `{"tags": {%[41]q: %[42]q}}`, state: engine.NotEvaluable, class: engine.ErrNoSuchAttribute},
	{name: "missing_marker_key", typ: "aws_s3_bucket", reads: []string{"tags"},
		expr:     `resource.tags["BOBTHECORP-MARKER-943"] == "x"`,
		resource: `{"tags": {%[41]q: %[42]q}}`, state: engine.NotEvaluable, class: engine.ErrNoSuchAttribute},
	{name: "missing_lower_marker_key", typ: "aws_db_instance", reads: []string{"tags"},
		expr:     `resource.tags["bobthecorp_marker_946"] == "x"`,
		resource: `{"tags": {%[41]q: %[42]q}}`, state: engine.NotEvaluable, class: engine.ErrNoSuchAttribute},
	{name: "index_out_of_range", typ: "aws_db_instance", reads: []string{"domain_dns_ips"},
		expr:     `resource.domain_dns_ips[3] == "x"`,
		resource: `{"domain_dns_ips": [%[21]q]}`, state: engine.NotEvaluable, class: engine.ErrNoSuchAttribute},
	{name: "principal_alias", typ: "aws_s3_bucket_policy", reads: []string{"policy"},
		expr:     `iam.parse(resource.policy).statements.all(s, !iam.principal_is(s, "arn:aws:iam::222222222222:role/bobthecorp-app"))`,
		resource: `{"policy": "{\"Version\": \"2012-10-17\", \"Statement\": [{\"Effect\": \"Allow\", \"Principal\": {\"AWS\": \"%[22]s\"}, \"Action\": \"s3:GetObject\", \"Resource\": \"arn:aws:s3:::%[23]s/*\"}]}"}`,
		state:    engine.NotEvaluable, class: engine.ErrUnresolved},
	{name: "catalog_miss", typ: "aws_s3_bucket_policy", reads: []string{"policy"},
		expr:     `iam.parse(resource.policy).statements.all(s, !iam.grants(s, "s3:putbucketpolicy"))`,
		resource: `{"policy": "{\"Version\": \"2012-10-17\", \"Statement\": [{\"Effect\": \"Allow\", \"Principal\": \"*\", \"Action\": \"s3:Bobthecorp%[24]sAction\", \"Resource\": \"*\"}]}"}`,
		state:    engine.NotEvaluable, class: engine.ErrUnresolved},
	{name: "scope_untrusted", typ: "aws_db_instance", reads: []string{"storage_encrypted"},
		expr:     `env != "prod" || resource.storage_encrypted == true`,
		resource: `{"storage_encrypted": false, "password": %[25]q, "tags": {%[26]q: %[3]q}}`, envUntrusted: true,
		state: engine.NotEvaluable, class: engine.ErrScopeUntrusted},
}

// fill fills a case's resource template: %[n] is scrubtest.Marker(n), but 15 is the
// oversized document, 16 the cost-limit string and 24 a marker without the
// BOBTHECORP- prefix (part of an IAM action name). Templates use explicit
// indexes only, so unused arguments are not reported.
func fill(tmpl string) string {
	args := make([]any, 60)
	for i := range args {
		args[i] = scrubtest.Marker(i + 1)
	}
	args[14] = big
	args[15] = scrubtest.Marker(17) + strings.Repeat("x", 20000) + scrubtest.Marker(18)
	args[23] = "MARKER-24"
	return fmt.Sprintf(tmpl, args...)
}

func controlJSON(c scrubCase) map[string]any {
	cover := []string{}
	if c.cover {
		cover = []string{"self_service"}
	}
	return map[string]any{"id": c.id(), "version": "1.0.0", "kind": "resource", "resource_type": c.typ, "reads": c.reads,
		"presence_mode": "effective", "on": []string{"create", "update"}, "expr": c.expr, "action": "deny",
		"severity": "high", "message": "Scrub control.", "exemption_coverable": cover}
}

// controlsJSON is the controls.json of every case.
func controlsJSON(t *testing.T) []byte {
	t.Helper()
	var cs []map[string]any
	for _, c := range cases {
		cs = append(cs, controlJSON(c))
	}
	b, err := json.Marshal(cs)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// schemas is the aws-subset schema with aws_db_instance tags marked
// sensitive, so a sensitive map carries marker keys.
func schemas(t *testing.T) respSchemas {
	t.Helper()
	s := enginetest.AWSSubset(t, filepath.Join(testdata, "schemas", "aws-subset.json"))
	for _, a := range s.ResourceSchemas["aws_db_instance"].Block.Attributes {
		if a.Name == "tags" {
			a.Sensitive = true
			return respSchemas{s}
		}
	}
	t.Fatal("aws_db_instance has no tags attribute")
	return respSchemas{}
}

// respSchemas is a schema response as a celeng.SchemaSource.
type respSchemas struct {
	*tfprotov5.GetProviderSchemaResponse
}

func (s respSchemas) Resource(typ string) (*tfprotov5.Schema, bool) {
	x, ok := s.ResourceSchemas[typ]
	return x, ok
}

func (s respSchemas) DataSource(typ string) (*tfprotov5.Schema, bool) {
	x, ok := s.DataSourceSchemas[typ]
	return x, ok
}

func (s respSchemas) EphemeralResource(typ string) (*tfprotov5.Schema, bool) {
	x, ok := s.EphemeralResourceSchemas[typ]
	return x, ok
}

func (c scrubCase) value(t *testing.T, s respSchemas) (tftypes.Type, tftypes.Value) {
	t.Helper()
	typ := s.ResourceSchemas[c.typ].Block.ValueType()
	raw := fill(c.resource)
	if !scrubtest.MarkerRE.MatchString(raw) {
		t.Fatalf("%s: no marker planted", c.name)
	}
	return typ, enginetest.Value(t, typ, json.RawMessage(raw))
}

func (c scrubCase) bindings(t *testing.T, s respSchemas) celeng.Bindings {
	_, v := c.value(t, s)
	b := celeng.Bindings{Kind: bundle.KindResource, Type: c.typ, Resource: v, Config: v, Op: "create",
		Env: "prod", EnvKnown: !c.envUntrusted,
		Provider: celeng.ProviderInfo{Region: "eu-west-1", AccountID: "111111111111", Partition: "aws",
			RegionKnown: true, AccountKnown: true, PartitionKnown: true}}
	if c.envUntrusted {
		b.Env = ""
	}
	return b
}

// noLoadMarker is noMarker for load streams (load diagnostics, Load and
// Configure errors and warnings), which may name control text: the
// expression markers are cut first.
func noLoadMarker(t *testing.T, stream, out string) {
	t.Helper()
	scrubtest.NoMarker(t, stream, exprMarkers.ReplaceAllString(out, "$1"))
}

// mustLoad is must for load errors.
func mustLoad(t *testing.T, stream string, err error) {
	t.Helper()
	if err != nil {
		noLoadMarker(t, stream, err.Error())
		t.Fatalf("%s: %s", stream, scrubtest.Mask(err.Error()))
	}
}

func catalog(t *testing.T) *iampolicy.Catalog {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(testdata, "crosscheck", "iam-identity", "iam-actions.json"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := iampolicy.LoadCatalog(raw)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// loadEngine loads every case control into one Compiled under budget.
func loadEngine(t *testing.T, s respSchemas, budget time.Duration) *celeng.Compiled {
	t.Helper()
	cs, err := bundle.DecodeControls(controlsJSON(t))
	mustLoad(t, "DecodeControls", err)
	content := celeng.Content{Digest: "sha256:scrub", IAMCatalog: catalog(t)}
	comp, diags, err := celeng.New(celeng.Options{PerResourceBudget: budget}).Load(cs, s.GetProviderSchemaResponse, content)
	noLoadMarker(t, "load diagnostics", fmt.Sprintf("%+v", diags))
	mustLoad(t, "Load", err)
	return comp
}

// evalCases evaluates every case twice (the second pass and fail run is a
// memo hit) and checks each case's own result.
func evalCases(t *testing.T, s respSchemas, comp *celeng.Compiled) {
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for range 2 {
				rs := comp.Evaluate(context.Background(), c.bindings(t, s), nil)
				scrubtest.NoMarker(t, "results", fmt.Sprintf("%+v", rs))
				i := slices.IndexFunc(rs, func(r celeng.Result) bool { return r.ControlID == c.id() })
				if i < 0 {
					t.Fatalf("no result for %s", c.id())
				}
				r := rs[i]
				if r.State != c.state || r.ErrClass != c.class || !slices.Equal(r.UnknownPaths, c.paths) {
					t.Fatalf("got %s/%s %v, want %s/%s %v", r.State, r.ErrClass, scrubtest.Mask(fmt.Sprint(r.UnknownPaths)), c.state, c.class, c.paths)
				}
			}
		})
	}
}

// TestScrubEngine: every case through celeng Load and Evaluate reaches its
// state and class (so the scan is not vacuous), and no result, load
// diagnostic, returned error or log line carries a marker. A deadline
// already past gives timeout for every scrub control on the same marked
// values. The memo dump is TestScrubMemo (ctftest).
func TestScrubEngine(t *testing.T) {
	logs := scrubtest.CaptureLogs(t)
	s := schemas(t)
	evalCases(t, s, loadEngine(t, s, time.Minute))

	// A deadline already past when Evaluate starts: every control is
	// timeout, deterministically, on the same marked values.
	slow := loadEngine(t, s, time.Minute)
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	timedOut := map[string]bool{}
	for _, c := range cases {
		rs := slow.Evaluate(expired, c.bindings(t, s), nil)
		scrubtest.NoMarker(t, "timeout results", fmt.Sprintf("%+v", rs))
		for _, r := range rs {
			if r.State != engine.NotEvaluable || r.ErrClass != engine.ErrTimeout {
				t.Errorf("%s past the deadline: %s/%s, want not_evaluable/timeout", r.ControlID, r.State, r.ErrClass)
			}
			timedOut[r.ControlID] = true
		}
	}
	for _, c := range cases {
		if !timedOut[c.id()] {
			t.Errorf("%s has no timeout result", c.id())
		}
	}
	scrubtest.NoMarker(t, "log", logs())
}

// TestScrubSelector: exception selectors that do not compile name a
// position or a fixed reason, never their text, and selector outcomes on
// marked values carry no marker for any class.
func TestScrubSelector(t *testing.T) {
	logs := scrubtest.CaptureLogs(t)
	for _, expr := range []string{
		`resource.password == "` + scrubtest.Marker(30) + `" &&`,
		`"` + scrubtest.Marker(31) + `"`,
		`iam.parse("` + scrubtest.Marker(32) + `").statements.size() > 0`,
		`resource["` + scrubtest.Marker(33) + `"] == "x"`,
	} {
		_, err := celeng.CompileSelector(expr)
		if err == nil {
			t.Fatalf("selector %d compiled", len(expr))
		}
		scrubtest.NoMarker(t, "selector compile error", err.Error())
	}
	s := schemas(t)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if strings.Contains(c.expr, "iam.") {
				_, err := celeng.CompileSelector(c.expr)
				if err == nil {
					t.Fatal("iam.* selector compiled")
				}
				scrubtest.NoMarker(t, "selector compile error", err.Error())
				return
			}
			sel, err := celeng.CompileSelector(c.expr)
			scrubtest.Must(t, "selector compile error", err)
			b := c.bindings(t, s)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			out := sel.Eval(ctx, s, bundle.KindResource, c.typ, &engine.Activation{Resource: b.Resource, Config: b.Config,
				Op: engine.OpCreate, Env: b.Env, EnvKnown: b.EnvKnown, Provider: b.Provider})
			scrubtest.NoMarker(t, "selector outcome", fmt.Sprintf("%+v", out))
			if out.State != c.state || out.Err != c.class || !slices.Equal(out.UnknownPaths, c.paths) {
				t.Errorf("got %s/%s, want %s/%s", out.State, out.Err, c.state, c.class)
			}
		})
	}
	scrubtest.NoMarker(t, "log", logs())
}

// TestScrubSidecar: a sidecar entry whose match errors on marked values and
// one whose match is unknown under a marker key leave decisions and log
// lines with labels and classes only.
func TestScrubSidecar(t *testing.T) {
	logs := scrubtest.CaptureLogs(t)
	const ctl = "scrub_conversion"
	src := `exception "scrub-rejected" {
  controls  = ["` + ctl + `"]
  match     = "int(resource.password) > 0"
  workspace = "bobthecorp-scrub"
  reason    = "` + scrubtest.Marker(50) + `"
  ticket    = "` + scrubtest.Marker(51) + `"
  expires   = "2027-03-31"
}
exception "scrub-pending" {
  controls  = ["` + ctl + `"]
  match     = "size(resource.tags) == 0"
  workspace = "bobthecorp-scrub"
  reason    = "` + scrubtest.Marker(52) + `"
  expires   = "2027-03-31"
}
`
	path := filepath.Join(t.TempDir(), "compliance-exceptions.hcl")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	cov, _ := exceptions.NewCoverability(map[string][]bundle.ExemptionKind{ctl: {bundle.CoverSelfService}}, nil)
	tbl := profile.ModeTable{Workspace: profile.Dim{Value: "bobthecorp-scrub", Source: "profile"},
		Exceptions:      &profile.Exceptions{MaxLifetimeDays: 180, SelfService: []string{ctl}},
		SidecarControls: []string{ctl}}
	now := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	sc, n, err := exceptions.LoadSidecar(path, exceptions.SidecarInput{Table: tbl, Now: now, Coverable: cov,
		Resolve: func(ref string) []string { return []string{ref} }})
	scrubtest.Must(t, "LoadSidecar", err)
	if sc == nil {
		t.Fatal("LoadSidecar: no sidecar")
	}
	scrubtest.NoMarker(t, "sidecar notices", fmt.Sprintf("%+v", n))
	s := schemas(t)
	typ := s.ResourceSchemas["aws_db_instance"].Block.ValueType()
	v := enginetest.Value(t, typ, json.RawMessage(fill(`{"password": %[27]q, "tags": {%[28]q: {"$unknown": true}}}`)))
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	d := sc.Lookup(ctx, &bundle.Control{ID: ctl, Kind: bundle.KindResource, ResourceType: "aws_db_instance"}, s,
		&engine.Activation{Resource: v, Config: v, Op: engine.OpCreate}, now)
	scrubtest.NoMarker(t, "sidecar decision", fmt.Sprintf("%+v %+v", d, d.Exception))
	want := []string{"exception scrub-rejected: exception_rejected: selector type_error", "exception scrub-pending pending: selector unknown"}
	if !slices.Equal(d.Log, want) || d.Applied || !d.Unresolved {
		t.Fatalf("decision log %q applied %v unresolved %v, want log %q, unresolved", scrubtest.Mask(fmt.Sprint(d.Log)), d.Applied, d.Unresolved, want)
	}
	d.WriteLog()
	if !strings.Contains(logs(), "exception_rejected") {
		t.Fatal("WriteLog wrote nothing to the captured log")
	}
	scrubtest.NoMarker(t, "log", logs())
}

// TestScrubMarkerRanges: expression markers are 900 and up, planted data
// markers below 900 except a data key that repeats an expression key, and
// the load-stream cut keeps an adjacent data marker.
func TestScrubMarkerRanges(t *testing.T) {
	num := regexp.MustCompile(`[0-9]+$`)
	var exprs []string
	for _, c := range cases {
		for _, m := range scrubtest.MarkerRE.FindAllString(c.expr, -1) {
			if n, _ := strconv.Atoi(num.FindString(m)); n < 900 {
				t.Errorf("%s: expression marker %s below 900", c.name, m)
			}
			exprs = append(exprs, m)
		}
		for _, m := range scrubtest.MarkerRE.FindAllString(fill(c.resource), -1) {
			if n, _ := strconv.Atoi(num.FindString(m)); n >= 900 && !slices.Contains(exprs, m) {
				t.Errorf("%s: data marker %s at 900 or above", c.name, m)
			}
		}
	}
	if got := exprMarkers.ReplaceAllString(exprs[0]+" "+exprs[0]+"1", "$1"); !scrubtest.MarkerRE.MatchString(got) {
		t.Errorf("load-stream cut removed a longer marker: %q", got)
	}
}

// TestScrubDetects: the scanner finds both marker forms in any case and
// inside other text, masks them, and matches nothing else.
func TestScrubDetects(t *testing.T) {
	for _, s := range []string{scrubtest.Marker(1), strings.ToLower(scrubtest.Marker(2)), "x" + scrubtest.Marker(3)[11:] + "y", "tags.bobthecorp_marker_44",
		fill(cases[0].resource)} {
		if scrubtest.MarkerRE.FindString(s) == "" || scrubtest.MarkerRE.MatchString(scrubtest.Mask(s)) {
			t.Errorf("scanner missed or did not mask %q", s)
		}
	}
	if scrubtest.MarkerRE.MatchString("no such key: absent; MARKER-x; marker_") {
		t.Error("scanner matched text without a marker")
	}
}
