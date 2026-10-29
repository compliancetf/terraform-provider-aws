package schemadiff

import (
	"bytes"
	"errors"
	"flag"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/bundlegen"
	"github.com/compliancetf/terraform-provider-aws/test/scrub/scrubtest"
)

var update = flag.Bool("update", false, "rewrite testdata/golden")

func load(t *testing.T, name string) bundlegen.Schemas {
	t.Helper()
	s, err := bundlegen.LoadSchemas(filepath.Join("testdata", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func content(t *testing.T) []bundle.Control {
	t.Helper()
	cs, err := bundlegen.LoadControls("testdata/controls.json")
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

// TestGolden covers each row of the section 9 table: the variant schema
// against base must yield its check (the golden pins the whole report).
func TestGolden(t *testing.T) {
	cs := content(t)
	base := load(t, "base")
	for _, tc := range []struct {
		name, control, read, check, result string
		base                               string // default "base"; the variant is then next
	}{
		{"base", "", "", "", Pass, ""},
		{"type-removed", "s3_bucket_logging_target_set", "", CheckTypeRemoved, Fail, ""},
		{"removed-attr", "s3_bucket_logging_target_set", "target_bucket", CheckReadMissing, Fail, ""},
		{"type-changed", "db_instance_password_length_min_14", "password_length", CheckShapeChanged, Fail, ""},
		{"maxitems-changed", "elb_listener_no_fixed_response", "default_action.type", CheckShapeChanged, Fail, ""},
		{"nesting-changed", "vpc_security_group_no_open_ingress", "ingress.cidr_blocks", CheckShapeChanged, Fail, ""},
		{"computed-only", "db_instance_password_length_min_14", "", CheckComputedOnly, Fail, ""},
		{"expr-compile", "ec2_instance_env_tag", "", CheckExprCompile, Fail, ""},
		{"deprecated", "db_instance_password_length_min_14", "password_length", CheckDeprecated, Warn, ""},
		// Panel round 1 regressions.
		{"attr-list-to-set", "ec2_instance_ebs_min_size", "ebs.size", CheckShapeChanged, Fail, ""},
		{"attr-nested-list", "ec2_instance_ebs_min_size", "ebs.size", CheckShapeChanged, Fail, ""},
		{"block-nested-maxitems", "elb_listener_has_forward", "default_action.forward", CheckShapeChanged, Fail, ""},
		{"block-attr-removed", "elb_listener_has_forward", "default_action.forward", CheckReadMissing, Fail, ""},
		{"block-additive", "", "", "", Pass, ""},
		{"computed-only-warn", "s3_bucket_logging_target_set", "target_bucket", CheckComputedOnly, Fail, ""},
		{"deprecated-segment", "elb_listener_no_fixed_response", "default_action.type", CheckDeprecated, Warn, ""},
		{"block-prior-computed-only", "elb_listener_has_forward", "default_action.forward", CheckComputedOnly, Fail, ""},
		{"stale-base-read", "s3_bucket_logging_target_set", "target_bucket", CheckReadNotInBase, Warn, "removed-attr"},
		{"stale-base-type", "s3_bucket_logging_target_set", "", CheckTypeNotInBase, Warn, "type-removed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, n := base, tc.name
			if tc.base != "" {
				b, n = load(t, tc.base), "base"
			}
			r, err := Diff(cs, b, load(t, n))
			if err != nil {
				t.Fatal(err)
			}
			if r.Result != tc.result {
				t.Errorf("result %s, want %s", r.Result, tc.result)
			}
			if r.Failed() != (tc.result == Fail) {
				t.Errorf("Failed() %v for result %s", r.Failed(), r.Result)
			}
			if tc.check != "" && !slices.ContainsFunc(r.Findings, func(f Finding) bool {
				return f.ControlID == tc.control && f.Read == tc.read && f.Check == tc.check && f.Result == tc.result
			}) {
				t.Errorf("no %s %s finding for %s %q in %+v", tc.result, tc.check, tc.control, tc.read, r.Findings)
			}
			got, err := r.JSON()
			if err != nil {
				t.Fatal(err)
			}
			golden := filepath.Join("testdata", "golden", tc.name+".report.json")
			if *update {
				if err := os.WriteFile(golden, got, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("report differs from %s (-update to rewrite):\n%s", golden, got)
			}
		})
	}
}

// TestDeterministic: shuffled content gives byte-identical reports.
func TestDeterministic(t *testing.T) {
	base, next := load(t, "base"), load(t, "deprecated")
	want := report(t, content(t), base, next)
	for i := range 20 {
		cs := content(t)
		r := rand.New(rand.NewPCG(uint64(i), 1))
		r.Shuffle(len(cs), func(a, b int) { cs[a], cs[b] = cs[b], cs[a] })
		for j := range cs {
			r.Shuffle(len(cs[j].Reads), func(a, b int) { cs[j].Reads[a], cs[j].Reads[b] = cs[j].Reads[b], cs[j].Reads[a] })
		}
		if got := report(t, cs, base, next); !bytes.Equal(got, want) {
			t.Fatalf("seed %d: report differs:\n%s\nwant:\n%s", i, got, want)
		}
	}
}

// TestValueFree: expr literals and messages never reach the report, also
// when the control fails to load against the new schema.
func TestValueFree(t *testing.T) {
	cs := content(t)
	for i := range cs {
		m := scrubtest.Marker(i)
		cs[i].Message = m
		e := *cs[i].Expr + " || \"" + m + "\" == \"" + m + "\""
		cs[i].Expr = &e
	}
	base := load(t, "base")
	for _, name := range []string{"base", "expr-compile", "computed-only", "removed-attr"} {
		got := string(report(t, cs, base, load(t, name)))
		scrubtest.NoMarker(t, name, got)
		if strings.Contains(got, "fixed-response") {
			t.Errorf("%s: expr literal in report:\n%s", name, got)
		}
	}
}

// TestComputedOnlyPrior: prior.* is stored state, exempt from the
// Computed-only rule (celeng.Load): a deletion guard and a configured
// control that read password_length only through prior get no finding when
// it becomes Computed-only (panel round 2).
func TestComputedOnlyPrior(t *testing.T) {
	r, err := Diff(content(t), load(t, "base"), load(t, "computed-only"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range r.Findings {
		if f.ControlID == "db_instance_delete_guard_password" || f.ControlID == "db_instance_identifier_or_prior_password" {
			t.Errorf("prior-only read flagged: %+v", f)
		}
	}
	if !slices.ContainsFunc(r.Findings, func(f Finding) bool {
		return f.ControlID == "db_instance_password_length_min_14" && f.Check == CheckComputedOnly
	}) {
		t.Errorf("resource.* deny read not flagged: %+v", r.Findings)
	}
}

// TestComputedOnlyPerPath: under a block read, computed_only counts only
// the attribute paths the expr reads through config. The control reads
// default_action.type through config and forward.target_group_arn only
// through prior, so target_group_arn becoming Computed-only is no finding
// for it (panel round 3); elb_listener_has_forward, reading forward through
// config, still fails (in the golden table).
func TestComputedOnlyPerPath(t *testing.T) {
	r, err := Diff(content(t), load(t, "base"), load(t, "block-prior-computed-only"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range r.Findings {
		if f.ControlID == "elb_listener_prior_forward_target" {
			t.Errorf("prior-only descendant flagged: %+v", f)
		}
	}
}

func TestUnknownKind(t *testing.T) {
	cs := content(t)
	cs[0].Kind = "nope"
	var e *bundlegen.Error
	if _, err := Diff(cs, load(t, "base"), load(t, "base")); !errors.As(err, &e) || e.Code != "E_SCHEMA_TYPE" {
		t.Fatalf("err %v, want E_SCHEMA_TYPE", err)
	}
}

func report(t *testing.T, cs []bundle.Control, base, next bundlegen.Schemas) []byte {
	t.Helper()
	r, err := Diff(cs, base, next)
	if err != nil {
		t.Fatal(err)
	}
	b, err := r.JSON()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestNilSchemaParts: a nil block, attribute or nested block schema does not
// panic (panel round 2).
func TestNilSchemaParts(t *testing.T) {
	if _, ok := resolve(nil, "a"); ok {
		t.Error("resolve(nil) ok")
	}
	b := &tfprotov5.SchemaBlock{
		Attributes: []*tfprotov5.SchemaAttribute{nil},
		BlockTypes: []*tfprotov5.SchemaNestedBlock{nil, {TypeName: "x"}},
	}
	if out := compareBlock(func(string) bool { return true }, "r", b, &tfprotov5.SchemaBlock{}); len(out) != 0 {
		t.Errorf("findings %v for nil base parts", out)
	}
}

// TestGraph: a graph control is checked on its target type
// (target_attrs) and its companion type (link_attr and the companion_expr
// reads), each finding naming
// the type it is about, instead of aborting the diff; missing types and
// attributes fail with the existing checks and a stale base warns.
func TestGraph(t *testing.T) {
	graph := func(target string, attrs []string, companion, link string) bundle.Control {
		ce := "companion." + link + " == \"" + scrubtest.Marker(0) + "\""
		return bundle.Control{
			ID: "g", Version: "1.0.0", Kind: bundle.KindGraph, ResourceType: target,
			Action: bundle.ActionDeny, Severity: bundle.SeverityHigh, Message: scrubtest.Marker(1),
			Graph: &bundle.Graph{Rule: bundle.GraphCompanionPresent, CompanionType: companion,
				LinkAttr: link, TargetAttrs: attrs, CompanionExpr: &ce},
		}
	}
	withExpr := func(c bundle.Control, expr string) bundle.Control {
		c.Graph.CompanionExpr = &expr
		return c
	}
	// companionSide: the logging type is the companion; targetSide: the target.
	companionSide := graph("aws_db_instance", []string{"identifier"}, "aws_s3_bucket_logging", "target_bucket")
	targetSide := graph("aws_s3_bucket_logging", []string{"bucket", "target_bucket"}, "aws_db_instance", "identifier")
	f := func(typ, read, check, result string) Finding {
		return Finding{"g", "graph", typ, read, check, result}
	}
	for _, tc := range []struct {
		name       string
		c          bundle.Control
		base, next string
		result     string
		want       []Finding
	}{
		{"companion pass", companionSide, "base", "base", Pass, []Finding{}},
		{"target pass", targetSide, "base", "base", Pass, []Finding{}},
		{"companion type removed", companionSide, "base", "type-removed", Fail,
			[]Finding{f("aws_s3_bucket_logging", "", CheckTypeRemoved, Fail)}},
		{"target type removed", targetSide, "base", "type-removed", Fail,
			[]Finding{f("aws_s3_bucket_logging", "", CheckTypeRemoved, Fail)}},
		{"link_attr removed", companionSide, "base", "removed-attr", Fail,
			[]Finding{f("aws_s3_bucket_logging", "target_bucket", CheckReadMissing, Fail)}},
		{"target_attr removed", targetSide, "base", "removed-attr", Fail,
			[]Finding{f("aws_s3_bucket_logging", "target_bucket", CheckReadMissing, Fail)}},
		{"unknown target type", graph("aws_nope", []string{"id"}, "aws_db_instance", "identifier"), "base", "base", Fail,
			[]Finding{f("aws_nope", "", CheckTypeRemoved, Fail)}},
		{"unknown target_attr", graph("aws_db_instance", []string{"identifier", "nope"}, "aws_s3_bucket_logging", "bucket"), "base", "base", Fail,
			[]Finding{f("aws_db_instance", "nope", CheckReadMissing, Fail)}},
		{"companion_expr read removed", withExpr(graph("aws_db_instance", []string{"identifier"}, "aws_s3_bucket_logging", "bucket"),
			"companion.target_bucket != ''"), "base", "removed-attr", Fail,
			[]Finding{f("aws_s3_bucket_logging", "target_bucket", CheckReadMissing, Fail)}},
		{"companion_expr does not compile", withExpr(graph("aws_db_instance", []string{"identifier"}, "aws_s3_bucket_logging", "bucket"),
			"companion.bucket +"), "base", "base", Fail,
			[]Finding{f("aws_s3_bucket_logging", "", CheckExprCompile, Fail)}},
		{"stale base", companionSide, "type-removed", "base", Warn,
			[]Finding{f("aws_s3_bucket_logging", "", CheckTypeNotInBase, Warn)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := Diff([]bundle.Control{tc.c}, load(t, tc.base), load(t, tc.next))
			if err != nil {
				t.Fatal(err)
			}
			if r.Result != tc.result || !slices.Equal(r.Findings, tc.want) {
				t.Fatalf("result %s findings %+v, want %s %+v", r.Result, r.Findings, tc.result, tc.want)
			}
			got, err := r.JSON()
			if err != nil {
				t.Fatal(err)
			}
			scrubtest.NoMarker(t, tc.name, string(got))
		})
	}
	// Graph controls next to expr controls: the whole content is still diffed.
	r, err := Diff(append(content(t), companionSide), load(t, "base"), load(t, "base"))
	if err != nil || r.Result != Pass {
		t.Fatalf("mixed content: %v, result %s %+v", err, r.Result, r.Findings)
	}
	bad := companionSide
	bad.Graph = nil
	var e *bundlegen.Error
	if _, err := Diff([]bundle.Control{bad}, load(t, "base"), load(t, "base")); !errors.As(err, &e) || e.Code != "E_SCHEMA_TYPE" {
		t.Fatalf("graph without graph: err %v, want E_SCHEMA_TYPE", err)
	}
}
