package bundlegen

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
)

// graphTypes are the attribute types of the graph test schema; a test
// retypes one to see whether the digest and the release check notice.
type graphTypes struct {
	id, bucket, region, link, status, owner string
	noCompanion                             bool
}

var baseGraphTypes = graphTypes{id: "string", bucket: "string", region: "string", link: "string", status: "string", owner: "string"}

func graphSchemas(t *testing.T, g graphTypes) Schemas {
	t.Helper()
	companion := fmt.Sprintf(`, "aws_s3_bucket_versioning": {"block": {"attributes": {
		"bucket": {"type": %q, "required": true},
		"region": {"type": "string", "optional": true},
		"expected_bucket_owner": {"type": %q, "optional": true}},
		"block_types": {"versioning_configuration": {"nesting_mode": "list", "block": {"attributes": {
			"status": {"type": %q, "required": true},
			"mfa_delete": {"type": "string", "optional": true}}}}}}}`, g.link, g.owner, g.status)
	if g.noCompanion {
		companion = ""
	}
	s, err := LoadSchemas(writeSchema(t, fmt.Sprintf(`{"aws_s3_bucket": {"block": {"attributes": {
		"id": {"type": %q, "computed": true},
		"bucket": {"type": %q, "optional": true},
		"region": {"type": %q, "optional": true}}}}%s}`, g.id, g.bucket, g.region, companion)))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func graphControl(rule bundle.GraphRule, expr string) bundle.Control {
	g := &bundle.Graph{Rule: rule, CompanionType: "aws_s3_bucket_versioning", LinkAttr: "bucket", TargetAttrs: []string{"id", "bucket"}}
	if expr != "" {
		g.CompanionExpr = &expr
	}
	return bundle.Control{ID: "s3_bucket_versioning_kept", Version: "1.0.0", Kind: bundle.KindGraph, ResourceType: "aws_s3_bucket",
		Graph: g, Action: bundle.ActionWarn, Severity: bundle.SeverityMedium, Message: "m", ExemptionCoverable: []bundle.ExemptionKind{}}
}

const versioningExpr = "companion.versioning_configuration[0].status == 'Enabled'"

// TestGraphReads: a graph control reads its target_attrs on the target,
// its link_attr on the companion and the companion_expr reads on the
// companion, whatever the rule.
func TestGraphReads(t *testing.T) {
	s := graphSchemas(t, baseGraphTypes)
	want := []SchemaRead{
		{bundle.KindResource, "aws_s3_bucket", "bucket"},
		{bundle.KindResource, "aws_s3_bucket", "id"},
		{bundle.KindResource, "aws_s3_bucket_versioning", "bucket"},
		{bundle.KindResource, "aws_s3_bucket_versioning", "versioning_configuration.status"},
	}
	for _, rule := range []bundle.GraphRule{bundle.GraphCompanionPresent, bundle.GraphCompanionAbsentForbidden} {
		c := graphControl(rule, versioningExpr)
		got, err := GraphReads(&c, s)
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("%s: GraphReads = %v, %v; want %v", rule, got, err, want)
		}
		c = graphControl(rule, "")
		if got, err := GraphReads(&c, s); err != nil || !slices.Equal(got, want[:3]) {
			t.Errorf("%s without companion_expr: GraphReads = %v, %v; want %v", rule, got, err, want[:3])
		}
	}
}

// TestGraphSchemaCompat: the digest of a graph control pins every read
// GraphReads names and nothing else; the supported-release check fails
// E_SUPPORTED_SCHEMA on a retyped read or a missing companion type and
// passes on an unchanged schema or a retyped attribute it does not read.
func TestGraphSchemaCompat(t *testing.T) {
	pin := graphSchemas(t, baseGraphTypes)
	for _, rule := range []bundle.GraphRule{bundle.GraphCompanionPresent, bundle.GraphCompanionAbsentForbidden} {
		cs := []bundle.Control{graphControl(rule, versioningExpr)}
		base, err := SchemaCompatDigest(cs, pin)
		if err != nil {
			t.Fatalf("%s: %v", rule, err)
		}
		if err := checkSupported(cs, pin, map[string]Schemas{"6.66.0": pin}, []string{"6.66.0"}); err != nil {
			t.Errorf("%s unchanged: %v", rule, err)
		}
		for _, tc := range []struct {
			name string
			mod  func(*graphTypes)
			read bool
		}{
			{"target_attrs id", func(g *graphTypes) { g.id = "number" }, true},
			{"target_attrs bucket", func(g *graphTypes) { g.bucket = "number" }, true},
			{"link_attr", func(g *graphTypes) { g.link = "number" }, true},
			{"companion_expr read", func(g *graphTypes) { g.status = "bool" }, true},
			{"target attribute not read", func(g *graphTypes) { g.region = "number" }, false},
			{"companion attribute not read", func(g *graphTypes) { g.owner = "number" }, false},
		} {
			g := baseGraphTypes
			tc.mod(&g)
			s := graphSchemas(t, g)
			d, err := SchemaCompatDigest(cs, s)
			if err != nil {
				t.Fatalf("%s %s: %v", rule, tc.name, err)
			}
			if (d != base) != tc.read {
				t.Errorf("%s %s: digest changed %v, want %v", rule, tc.name, d != base, tc.read)
			}
			err = checkSupported(cs, pin, map[string]Schemas{"6.66.0": s}, []string{"6.66.0"})
			if tc.read && errCode(err) != "E_SUPPORTED_SCHEMA" {
				t.Errorf("%s %s: err = %v, want E_SUPPORTED_SCHEMA", rule, tc.name, err)
			}
			if !tc.read && err != nil {
				t.Errorf("%s %s: err = %v, want nil", rule, tc.name, err)
			}
		}
		s := graphSchemas(t, graphTypes{id: "string", bucket: "string", region: "string", noCompanion: true})
		if _, err := SchemaCompatDigest(cs, s); errCode(err) != "E_SCHEMA_TYPE" || !strings.Contains(err.Error(), "aws_s3_bucket_versioning") {
			t.Errorf("%s no companion: err = %v, want E_SCHEMA_TYPE naming the companion", rule, err)
		}
		if err := checkSupported(cs, pin, map[string]Schemas{"6.66.0": s}, []string{"6.66.0"}); errCode(err) != "E_SUPPORTED_SCHEMA" {
			t.Errorf("%s no companion in a supported release: err = %v, want E_SUPPORTED_SCHEMA", rule, err)
		}
	}
}

// TestGraphReadGone: a read missing from a supported release has signature
// "" there, unlike any type in the pin, so sameReadTypes fails E_SCHEMA_TYPE
// even without the CheckSchema that runs before it.
func TestGraphReadGone(t *testing.T) {
	pin := graphSchemas(t, baseGraphTypes)
	s, err := LoadSchemas(writeSchema(t, `{"aws_s3_bucket": {"block": {"attributes": {
		"id": {"type": "string", "computed": true}, "bucket": {"type": "string", "optional": true}}}},
		"aws_s3_bucket_versioning": {"block": {"attributes": {"region": {"type": "string", "optional": true}}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	cs := []bundle.Control{graphControl(bundle.GraphCompanionPresent, "")}
	if err := sameReadTypes(cs, s, pin); errCode(err) != "E_SCHEMA_TYPE" || !strings.Contains(err.Error(), "aws_s3_bucket_versioning.bucket") {
		t.Errorf("link_attr gone: err = %v, want E_SCHEMA_TYPE naming aws_s3_bucket_versioning.bucket", err)
	}
	if err := checkSupported(cs, pin, map[string]Schemas{"6.66.0": s}, []string{"6.66.0"}); errCode(err) != "E_SUPPORTED_SCHEMA" {
		t.Errorf("link_attr gone in a supported release: err = %v, want E_SUPPORTED_SCHEMA", err)
	}
}

// TestGraphSchemaCompatFailsClosed: a companion_expr whose reads cannot be
// bounded, or a graph control without graph, fails E_SCHEMA_TYPE.
func TestGraphSchemaCompatFailsClosed(t *testing.T) {
	s := graphSchemas(t, baseGraphTypes)
	c := graphControl(bundle.GraphCompanionPresent, "dyn(companion.versioning_configuration)[0].status == 'Enabled'")
	if _, err := SchemaCompatLines([]bundle.Control{c}, s); errCode(err) != "E_SCHEMA_TYPE" || !strings.Contains(err.Error(), "control_dynamic_access") {
		t.Errorf("dynamic companion_expr: err = %v, want E_SCHEMA_TYPE control_dynamic_access", err)
	}
	c = graphControl(bundle.GraphCompanionPresent, "companion.versioning_configuration[0].missing == 'x'")
	if _, err := SchemaCompatLines([]bundle.Control{c}, s); errCode(err) != "E_SCHEMA_TYPE" {
		t.Errorf("companion_expr read not in the schema: err = %v, want E_SCHEMA_TYPE", err)
	}
	c.Graph = nil
	if _, err := SchemaCompatLines([]bundle.Control{c}, s); errCode(err) != "E_SCHEMA_TYPE" {
		t.Errorf("no graph: err = %v, want E_SCHEMA_TYPE", err)
	}
	// DecodeControls rejects reads on a graph control; one built in memory
	// must not have them dropped unpinned either.
	c = graphControl(bundle.GraphCompanionPresent, "")
	c.Reads = []string{"region"}
	if _, err := SchemaCompatLines([]bundle.Control{c}, s); errCode(err) != "E_SCHEMA_TYPE" || !strings.Contains(err.Error(), "reads") {
		t.Errorf("graph control with reads: err = %v, want E_SCHEMA_TYPE", err)
	}
	if err := checkSupported([]bundle.Control{c}, s, map[string]Schemas{"6.66.0": s}, []string{"6.66.0"}); errCode(err) != "E_SUPPORTED_SCHEMA" {
		t.Errorf("graph control with reads in the release check: err = %v, want E_SUPPORTED_SCHEMA", err)
	}
	// Nor a stray expr, which checkSupported keeps out of celeng.Load.
	c = graphControl(bundle.GraphCompanionPresent, "")
	expr := "resource.region == 'x'"
	c.Expr = &expr
	if _, err := SchemaCompatLines([]bundle.Control{c}, s); errCode(err) != "E_SCHEMA_TYPE" || !strings.Contains(err.Error(), "expr") {
		t.Errorf("graph control with expr: err = %v, want E_SCHEMA_TYPE", err)
	}
	if err := checkSupported([]bundle.Control{c}, s, map[string]Schemas{"6.66.0": s}, []string{"6.66.0"}); errCode(err) != "E_SUPPORTED_SCHEMA" {
		t.Errorf("graph control with expr in the release check: err = %v, want E_SUPPORTED_SCHEMA", err)
	}
}
