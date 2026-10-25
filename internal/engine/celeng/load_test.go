package celeng

import (
	"crypto/sha256"
	"encoding/hex"
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

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/enginetest"
)

// TestLoadDiagValueFree: load errors and warnings never quote control
// expression text, string literals, map keys or quoted field names; they name
// the control, an error class and only attribute-shaped paths.
func TestLoadDiagValueFree(t *testing.T) {
	s := awsSubset(t)
	ctl := func(typ, expr string, reads ...string) bundle.Control {
		c := *testControl(bundle.KindResource, bundle.PresenceEffective, expr, reads...)
		c.ResourceType, c.Action = typ, bundle.ActionWarn
		return c
	}
	for _, tc := range []struct {
		name, code string
		c          bundle.Control
	}{
		{"parse error", "control_expr", ctl("aws_db_instance", `resource.arn == "zq9-secret" &&`, "arn")},
		{"type error", "control_expr", ctl("aws_db_instance", `"zq9-secret" + 1 == true`)},
		{"non-attribute index", "control_dynamic_access", ctl("aws_db_instance", `resource["zq9 key"] == "x"`)},
		{"quoted field not covered", "control_reads_missing", ctl("aws_db_instance", "resource.`zq9-field` == 1")},
		{"map key not in block", "control_dynamic_access", ctl("aws_instance", `resource.root_block_device.all(d, d["zq9-Key"])`, "root_block_device")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, diags, err := Load([]bundle.Control{tc.c}, s)
			var text []string
			codes := []string{diagCode(err)}
			if err != nil {
				text = append(text, err.Error())
			}
			for _, d := range diags {
				text = append(text, d.Error())
				codes = append(codes, d.Code)
			}
			if !slices.Contains(codes, tc.code) {
				t.Fatalf("codes %q, want %s", codes, tc.code)
			}
			for _, s := range text {
				if strings.Contains(s, "zq9") {
					t.Errorf("diagnostic echoes control text: %q", s)
				}
			}
		})
	}
}

type zq9Stringer struct{}

func (zq9Stringer) String() string { return "zq9 stringer" }

type zq9Name string

// TestDetailfValueFree: every detailf argument, whatever its type,
// is echoed only when attribute-shaped; anything else is the placeholder.
func TestDetailfValueFree(t *testing.T) {
	for _, a := range []any{"zq9 str", zq9Name("zq9-named"), zq9Stringer{}, errors.New("zq9 err"),
		[]byte("zq9 bytes"), []string{"ok", "zq9 elem"}, map[string]string{"zq9": "x"}, struct{ S string }{"zq9"}} {
		if got := detailf("read %s; %q; %v", a, a, a); strings.Contains(got, "zq9") {
			t.Errorf("detailf(%T) echoes the value: %q", a, got)
		}
	}
	type attr string
	if got := detailf("%s %s %s %s", "resource.arn", attr("config.tags"), []string{"a.b", "c"}, []byte("prior.x")); got != "resource.arn config.tags a.b, c prior.x" {
		t.Errorf("attribute-shaped args: %q", got)
	}
}

// loadWant is the TestLoadSchema oracle for testdata/bundles/invalid fixtures
// that strict decode and Compile accept: the Load error id and detail, or ""
// when the bundle loads.
var loadWant = map[string]struct{ code, detail string }{
	"control_computed_only":   {"control_computed_only", "deny control reads computed-only attributes [resource.arn]; ship it as a warn control decided post-apply"},
	"computed_only":           {"control_computed_only", "deny control reads computed-only attributes [config.status]; ship it as a warn control decided post-apply"},
	"computed_only_effective": {"control_computed_only", "deny control reads computed-only attributes [resource.arn]; ship it as a warn control decided post-apply"},
	"iam_identity_direct":     {"control_iam_identity_direct", "principals and resources of an iam.parse statement are read only through iam.principal_is / iam.resource_is"},
	// Load cannot see a generator verify proof; E_OPTIONAL_COMPUTED is the generator's check.
	"optional_computed": {},
}

func TestLoadSchemaFixtures(t *testing.T) {
	s := withPhase2Types(awsSubset(t))
	root := filepath.Join("..", "..", "..", "testdata", "bundles")
	for name, want := range loadWant {
		t.Run(name, func(t *testing.T) {
			cs := decodeFixture(t, filepath.Join(root, "invalid", name+".json"))
			checked, _, err := Load(cs, s)
			if diagCode(err) != want.code {
				t.Fatalf("want %q, got %v", want.code, err)
			}
			if err != nil {
				if d := err.(*LoadDiag); d.Detail != want.detail || d.ControlID != cs[0].ID || checked != nil {
					t.Fatalf("got %+v, checked %v", d, checked)
				}
			} else if len(checked) != len(cs) {
				t.Fatalf("checked %d of %d", len(checked), len(cs))
			}
		})
	}
	valid, _ := filepath.Glob(filepath.Join(root, "valid", "*.json"))
	for _, f := range valid {
		if _, _, err := Load(decodeFixture(t, f), s); err != nil {
			t.Errorf("%s: %v", filepath.Base(f), err)
		}
	}
}

func TestLoadSchema(t *testing.T) {
	s := withPhase2Types(awsSubset(t))
	ctl := func(k bundle.Kind, pm bundle.PresenceMode, typ string, a bundle.Action, expr string, reads ...string) bundle.Control {
		c := *testControl(k, pm, expr, reads...)
		c.ResourceType, c.Action = typ, a
		return c
	}
	const db, ec2, eph = "aws_db_instance", "aws_instance", "aws_secretsmanager_secret_version"
	eff, cfg := bundle.PresenceEffective, bundle.PresenceConfigured
	res, deny, warn := bundle.KindResource, bundle.ActionDeny, bundle.ActionWarn
	computed := func(p string) string {
		return "deny control reads computed-only attributes [" + p + "]; ship it as a warn control decided post-apply"
	}
	cases := []struct {
		name      string
		c         bundle.Control
		code, det string
		warnings  []string // "code: detail"
	}{
		{"warn reads computed-only", ctl(res, eff, db, warn, "resource.arn != ''", "arn"), "", "", nil},
		// prior is stored state, never plan-time unknown: prior.* reads are
		// exempt from the Computed-only rule.
		{"deletion guard prior computed-only", ctl(bundle.KindDeletionGuard, "", db, deny, "prior.arn == ''", "arn"), "", "", nil},
		{"prior read in resource control", ctl(res, eff, db, deny, "resource.storage_encrypted || prior.status == 'x'", "status", "storage_encrypted"), "", "", nil},
		{"all offending paths sorted", ctl(res, eff, db, deny, "resource.status == '' && resource.arn == '' && prior.arn == ''", "arn", "status"), "control_computed_only", computed("resource.arn, resource.status"), nil},
		{"type missing", ctl(res, eff, "aws_bobthecorp_widget", deny, "resource.arn == ''", "arn"), "", "", []string{"control_schema_type_missing: resource type aws_bobthecorp_widget not in upstream resource schema"}},
		{"path missing kept", ctl(res, eff, db, deny, "resource.no_such == true", "no_such"), "", "", []string{"control_schema_path_missing: read resource.no_such not in schema for aws_db_instance"}},
		{"path missing does not hide computed-only", ctl(res, eff, db, deny, "resource.no_such == true && resource.arn == ''", "arn", "no_such"), "control_computed_only", computed("resource.arn"), []string{"control_schema_path_missing: read resource.no_such not in schema for aws_db_instance"}},
		{"block path is non-computed", ctl(res, eff, ec2, deny, "size(resource.root_block_device) == 1", "root_block_device"), "", "", nil},
		{"optional computed in block", ctl(res, eff, ec2, deny, "resource.root_block_device.all(d, d.encrypted)", "root_block_device.encrypted"), "", "", nil},
		{"computed-only in block", ctl(res, eff, ec2, deny, "resource.root_block_device.all(d, d.volume_id != '')", "root_block_device.volume_id"), "control_computed_only", computed("resource.root_block_device.volume_id"), nil},
		{"computed-only by string key in block", ctl(res, eff, ec2, deny, `resource.root_block_device.all(d, d["volume_id"] != '')`, "root_block_device"), "control_computed_only", computed("resource.root_block_device.volume_id"), nil},
		{"computed-only by string key after index", ctl(res, eff, ec2, deny, `resource.root_block_device[0]["volume_id"] != ''`, "root_block_device"), "control_computed_only", computed("resource.root_block_device.volume_id"), nil},
		// the indexed element flows on whole, so the block's
		// Computed-only attributes are read.
		{"non-constant index, computed-only", ctl(res, eff, ec2, deny, `resource.root_block_device[size(resource.root_block_device) - 1].volume_id != ''`, "root_block_device"), "control_computed_only", computed("resource.root_block_device"), nil},
		{"non-constant index rejected", ctl(res, eff, ec2, warn, `resource.root_block_device[size(resource.root_block_device) - 1].volume_id != ''`, "root_block_device"), "control_dynamic_access", "non-constant index into resource.root_block_device", nil},
		{"optional computed by string key in block", ctl(res, eff, ec2, deny, `resource.root_block_device.all(d, d["encrypted"])`, "root_block_device"), "", "", nil},
		{"computed-only through map identity", ctl(res, eff, ec2, deny, `resource.root_block_device.map(d, d).all(d, d["volume_id"] != '')`, "root_block_device"), "control_computed_only", computed("resource.root_block_device"), nil},
		{"computed-only through filter", ctl(res, eff, ec2, deny, `resource.root_block_device.filter(d, true).all(d, d.volume_id != '')`, "root_block_device"), "control_computed_only", computed("resource.root_block_device"), nil},
		{"select below filter, warn", ctl(res, eff, ec2, warn, `resource.root_block_device.filter(d, true).all(d, d.encrypted)`, "root_block_device"), "control_dynamic_access", "field or index selected from a computed value of data; select through a path instead", nil},
		{"block compared whole", ctl(res, eff, ec2, deny, `resource.root_block_device != []`, "root_block_device"), "control_computed_only", computed("resource.root_block_device"), nil},
		// a comparison that may hold objects and key iteration of a
		// computed map are rejected during reads analysis; Computed-only is
		// still the reported reason when it applies.
		{"computed compare, computed-only", ctl(res, eff, db, deny, `dyn(resource.tags) != {} && resource.arn == ''`, "arn", "tags"), "control_computed_only", computed("resource.arn"), nil},
		{"computed compare, warn", ctl(res, eff, db, warn, `dyn(resource.tags) != {} && resource.arn == ''`, "arn", "tags"), "control_dynamic_access", "comparison of a computed value of data that may hold objects; compare its attributes instead", nil},
		{"computed map iteration, computed-only", ctl(res, eff, db, deny, `dyn(resource.tags).exists(k, k == "x") && resource.arn == ''`, "arn", "tags"), "control_computed_only", computed("resource.arn"), nil},
		{"computed map iteration, warn", ctl(res, eff, db, warn, `dyn(resource.tags).exists(k, k == "x") && resource.arn == ''`, "arn", "tags"), "control_dynamic_access", "key test or key enumeration on a computed value of data; use a path", nil},
		{"computed block iteration, computed-only", ctl(res, eff, ec2, deny, `dyn(resource.root_block_device[0]).exists(k, k == "x")`, "root_block_device"), "control_computed_only", computed("resource.root_block_device"), nil},
		// rejections the reads walk used to return at once are
		// deferred too, so the reads after them still reach the
		// Computed-only rule.
		{"dynamic index, computed-only", ctl(res, eff, db, deny, `resource.tags[resource.arn] == "x"`, "arn", "tags"), "control_computed_only", computed("resource.arn"), nil},
		{"dynamic index, warn", ctl(res, eff, db, warn, `resource.tags[resource.arn] == "x"`, "arn", "tags"), "control_dynamic_access", "non-constant index into resource.tags", nil},
		{"root key not an attribute, computed-only", ctl(res, eff, db, deny, `resource["a.b"] == "x" && resource.arn == ""`, "arn"), "control_computed_only", computed("resource.arn"), nil},
		{"whole variable, computed-only", ctl(res, eff, db, deny, `size(resource) > 0 && resource.arn == ""`, "arn"), "control_computed_only", computed("resource.arn"), nil},
		{"whole variable, warn", ctl(res, eff, db, warn, `size(resource) > 0 && resource.arn == ""`, "arn"), "control_dynamic_access", "resource is used whole; read its attributes instead", nil},
		{"iterate whole variable, computed-only", ctl(res, eff, db, deny, `resource.exists(k, k == "a") && resource.arn == ""`, "arn"), "control_computed_only", computed("resource.arn"), nil},
		{"shadowing, computed-only", ctl(res, eff, db, deny, `["x"].all(resource, resource != "") && resource.arn == ""`, "arn"), "control_computed_only", computed("resource.arn"), nil},
		{"shadowing, warn", ctl(res, eff, db, warn, `["x"].all(resource, resource != "") && resource.arn == ""`, "arn"), "control_dynamic_access", "iteration variable resource shadows a bound variable", nil},
		{"shadowed read is not a read", ctl(res, eff, db, deny, `[{"arn": ""}].all(resource, .resource.arn == "")`, "arn"), "control_dynamic_access", "iteration variable resource shadows a bound variable", nil},
		{"deferred then immediate, computed-only", ctl(res, eff, db, deny, `dyn(resource.tags) != {} && resource.tags[resource.identifier] == "x" && resource.arn == ""`, "arn", "identifier", "tags"), "control_computed_only", computed("resource.arn"), nil},
		{"block compared whole, warn", ctl(res, eff, ec2, warn, `resource.root_block_device != []`, "root_block_device"), "control_dynamic_access", "whole use of a value holding objects at resource.root_block_device; select its attributes instead", nil},
		{"string key missing in block", ctl(res, eff, ec2, deny, `resource.root_block_device.all(d, d["nope"])`, "root_block_device"), "", "", []string{"control_schema_path_missing: read resource.root_block_device.nope not in schema for aws_instance"}},
		{"path missing in block", ctl(res, eff, ec2, deny, "resource.root_block_device.all(d, d.nope)", "root_block_device.nope"), "", "", []string{"control_schema_path_missing: read resource.root_block_device.nope not in schema for aws_instance"}},
		{"attribute value steps", ctl(res, eff, db, deny, "resource.tags.owner == 'bobthecorp'", "tags"), "", "", nil},
		{"object attribute steps", ctl(res, eff, "aws_security_group", deny, "resource.ingress.all(r, r.from_port != 22)", "ingress"), "", "", nil},
		{"configured optional computed", ctl(res, cfg, db, deny, "config.storage_encrypted == true", "storage_encrypted"), "", "", nil},
		{"declared unused computed-only", ctl(res, eff, db, deny, "resource.storage_encrypted == true", "arn", "storage_encrypted"), "", "", []string{"control_reads_unused: read arn is not used by expr"}},
		// Data source and ephemeral kind rules.
		{"data source result computed-only", ctl(bundle.KindDataSource, eff, "aws_ami", deny, "resource.image_id != ''", "image_id"), "", "", nil},
		{"data source config computed-only", ctl(bundle.KindDataSource, cfg, "aws_ami", deny, "config.image_id != ''", "image_id"), "control_computed_only", computed("config.image_id"), nil},
		{"data source path missing", ctl(bundle.KindDataSource, eff, "aws_ami", warn, "resource.no_such == true", "no_such"), "control_schema_path_missing", "read resource.no_such not in schema for aws_ami", nil},
		{"ephemeral input", ctl(bundle.KindEphemeral, "", eph, deny, "config.secret_id != ''", "secret_id"), "", "", nil},
		{"ephemeral optional computed", ctl(bundle.KindEphemeral, "", eph, deny, "config.version_stage == 'AWSCURRENT'", "version_stage"), "", "", nil},
		{"ephemeral reads result, warn", ctl(bundle.KindEphemeral, "", eph, warn, "config.secret_string != '' && config.secret_id != ''", "secret_id", "secret_string"), "control_ephemeral_result", "ephemeral control reads result attribute config.secret_string", nil},
		{"ephemeral path missing", ctl(bundle.KindEphemeral, "", eph, warn, "config.no_such == true", "no_such"), "control_schema_path_missing", "read config.no_such not in schema for aws_secretsmanager_secret_version", nil},
		{"data source optional", ctl(bundle.KindDataSource, cfg, "aws_ami", deny, "config.most_recent == true", "most_recent"), "", "", nil},
		{"data source type is not a resource", ctl(bundle.KindDataSource, eff, db, warn, "resource.arn == ''", "arn"), "control_data_source_unknown", "targets unknown data source aws_db_instance", nil},
		{"ephemeral type missing", ctl(bundle.KindEphemeral, "", "aws_bobthecorp_secret", warn, "config.name != ''", "name"), "control_ephemeral_unknown", "targets unknown ephemeral resource aws_bobthecorp_secret", nil},

		{"deny reads resource computed-only", ctl(res, eff, db, deny, "resource.arn == ''", "arn"), "control_computed_only", computed("resource.arn"), nil},
		{"prior block computed-only", ctl(bundle.KindDeletionGuard, "", ec2, deny, "prior.root_block_device.all(d, d.volume_id != '')", "root_block_device.volume_id"), "", "", nil},
		{"prior path missing kept", ctl(bundle.KindDeletionGuard, "", db, deny, "prior.no_such == true", "no_such"), "", "", []string{"control_schema_path_missing: read prior.no_such not in schema for aws_db_instance"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			checked, diags, err := Load([]bundle.Control{tc.c}, s)
			if diagCode(err) != tc.code {
				t.Fatalf("want %q, got %v", tc.code, err)
			}
			if err != nil && err.(*LoadDiag).Detail != tc.det {
				t.Fatalf("detail %q, want %q", err.(*LoadDiag).Detail, tc.det)
			}
			if err == nil && len(checked) != 1 {
				t.Fatalf("checked %v", checked)
			}
			var got []string
			for _, d := range diags {
				got = append(got, d.Code+": "+d.Detail)
			}
			if !slices.Equal(got, tc.warnings) {
				t.Fatalf("warnings %q, want %q", got, tc.warnings)
			}
		})
	}

	t.Run("reject keeps earlier warnings", func(t *testing.T) {
		cs := []bundle.Control{cases[4].c, cases[3].c}
		cs[1].ID = "second"
		checked, diags, err := Load(cs, s)
		if diagCode(err) != "control_computed_only" || checked != nil || len(diags) != 1 || diags[0].Code != "control_schema_type_missing" {
			t.Fatalf("checked %v diags %v err %v", checked, diags, err)
		}
	})
}

// TestLoadKeyPresence: a key test, key enumeration or whole-value use of an
// object or block value cannot tell a field missing from the schema from an
// unset one. A constant attribute key is a read of that path;
// everything else on an object is rejected.
func TestLoadKeyPresence(t *testing.T) {
	s := awsSubset(t)
	const sg, ec2, s3 = "aws_security_group", "aws_instance", "aws_s3_bucket"
	cases := []struct {
		typ, expr, read string
		code            string
		warning         string
	}{
		// Inside an attribute's type the read is checked at evaluation (E-10).
		{sg, `resource.ingress.all(r, !("no_such" in r))`, "ingress", "", ""},
		{ec2, `resource.root_block_device.all(d, "volume_id" in d)`, "root_block_device", "control_computed_only", ""},
		{sg, `resource.ingress.all(r, "protocol" in r)`, "ingress", "", ""},
		{ec2, `resource.root_block_device.all(d, !("nope" in d))`, "root_block_device", "", "read resource.root_block_device.nope not in schema for aws_instance"},
		{sg, `resource.ingress.all(r, !r.exists(k, k == "no_such"))`, "ingress", "control_dynamic_access", ""},
		{sg, `resource.ingress.all(r, r.all(k, k != "no_such"))`, "ingress", "control_dynamic_access", ""},
		{sg, `resource.ingress.all(r, size(r.filter(k, k == "no_such")) == 0)`, "ingress", "control_dynamic_access", ""},
		{sg, `resource.ingress.all(r, r.exists_one(k, true))`, "ingress", "control_dynamic_access", ""},
		{sg, `resource.ingress.all(r, size(r) == 4)`, "ingress", "control_dynamic_access", ""},
		{sg, `resource.ingress.all(r, r.size() == 4)`, "ingress", "control_dynamic_access", ""},
		{sg, `resource.ingress.all(r, !(op in r))`, "ingress", "control_dynamic_access", ""},
		{sg, `resource.ingress.all(r, !("a.b" in r))`, "ingress", "control_dynamic_access", ""},
		{sg, `resource.ingress.all(r, r != {"protocol": "tcp"})`, "ingress", "control_dynamic_access", ""},
		{sg, `resource.ingress.map(r, r).all(r, !("no_such" in r))`, "ingress", "control_dynamic_access", ""},
		{sg, `resource.ingress.all(r, !("no_such" in dyn(r)))`, "ingress", "control_dynamic_access", ""},
		{ec2, `resource.metadata_options.all(m, m.all(k, k != "x"))`, "metadata_options", "control_dynamic_access", ""},
		{ec2, `resource.root_block_device[0].all(k, k != "x")`, "root_block_device", "control_dynamic_access", ""},
		// Lists, maps and strings keep their meaning.
		{sg, `resource.ingress.all(r, r != null)`, "ingress", "", ""},
		{sg, `size(resource.ingress) > 0`, "ingress", "", ""},
		{sg, `resource.ingress.map(r, r.from_port) == [443]`, "ingress", "", ""},
		{sg, `resource.ingress.map(r, r.from_port) == [{"a": 1}]`, "ingress", "control_dynamic_access", ""},
		{sg, `resource.ingress.all(r, !("0.0.0.0/0" in r.cidr_blocks))`, "ingress", "", ""},
		{s3, `"Owner" in resource.tags`, "tags", "", ""},
		{s3, `resource.tags.exists(k, k == "Owner") && size(resource.tags) > 0`, "tags", "", ""},
		{s3, `!("bobthecorp" in resource.cors_rule.map(c, c.max_age_seconds))`, "cors_rule", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.expr, func(t *testing.T) {
			c := *testControl(bundle.KindResource, bundle.PresenceEffective, tc.expr, tc.read)
			c.ResourceType, c.Action = tc.typ, bundle.ActionDeny
			_, diags, err := Load([]bundle.Control{c}, s)
			if diagCode(err) != tc.code {
				t.Fatalf("want %q, got %v", tc.code, err)
			}
			var warn string
			for _, d := range diags {
				warn += d.Detail
			}
			if err == nil && warn != tc.warning {
				t.Fatalf("warnings %q, want %q", warn, tc.warning)
			}
		})
	}
}

func TestLoadSchemaUpstream(t *testing.T) {
	c := []bundle.Control{*testControl(bundle.KindDataSource, bundle.PresenceConfigured, "config.arn == ''", "arn")}
	c[0].ResourceType, c[0].Action = "aws_ami", bundle.ActionDeny
	ok := func() *tfprotov5.GetProviderSchemaResponse { return awsSubset(t) }
	cases := map[string]func(s *tfprotov5.GetProviderSchemaResponse) *tfprotov5.GetProviderSchemaResponse{
		"nil response": func(*tfprotov5.GetProviderSchemaResponse) *tfprotov5.GetProviderSchemaResponse { return nil },
		"nil resource map": func(s *tfprotov5.GetProviderSchemaResponse) *tfprotov5.GetProviderSchemaResponse {
			s.ResourceSchemas = nil
			return s
		},
		"nil kind map": func(s *tfprotov5.GetProviderSchemaResponse) *tfprotov5.GetProviderSchemaResponse {
			s.DataSourceSchemas = nil
			return s
		},
		"nil schema": func(s *tfprotov5.GetProviderSchemaResponse) *tfprotov5.GetProviderSchemaResponse {
			s.DataSourceSchemas["aws_ami"] = nil
			return s
		},
		"nil block": func(s *tfprotov5.GetProviderSchemaResponse) *tfprotov5.GetProviderSchemaResponse {
			s.DataSourceSchemas["aws_ami"].Block = nil
			return s
		},
		"error diagnostic": func(s *tfprotov5.GetProviderSchemaResponse) *tfprotov5.GetProviderSchemaResponse {
			s.Diagnostics = []*tfprotov5.Diagnostic{{Severity: tfprotov5.DiagnosticSeverityError, Summary: "upstream schema failed"}}
			return s
		},
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			checked, diags, err := Load(c, mut(ok()))
			if err == nil || checked != nil || diags != nil || !strings.HasPrefix(diagCode(err), "unexpected") {
				t.Fatalf("want plain error, got %v %v %v", checked, diags, err)
			}
		})
	}
	// A nil nested block schema on the read path is a plain error; nil
	// entries elsewhere are skipped.
	nested := []bundle.Control{*testControl(bundle.KindResource, bundle.PresenceEffective, "resource.root_block_device.all(d, d.encrypted)", "root_block_device.encrypted")}
	nested[0].ResourceType, nested[0].Action = "aws_instance", bundle.ActionDeny
	s := ok()
	b := s.ResourceSchemas["aws_instance"].Block
	b.Attributes = append([]*tfprotov5.SchemaAttribute{nil}, b.Attributes...)
	b.BlockTypes = append([]*tfprotov5.SchemaNestedBlock{nil}, b.BlockTypes...)
	if _, _, err := Load(nested, s); err != nil {
		t.Fatalf("nil entries: %v", err)
	}
	for _, nb := range b.BlockTypes {
		if nb != nil && nb.TypeName == "root_block_device" {
			nb.Block = nil
		}
	}
	if _, _, err := Load(nested, s); !strings.HasPrefix(diagCode(err), "unexpected") {
		t.Fatalf("nil nested block: %v", err)
	}

	s = ok()
	s.Diagnostics = []*tfprotov5.Diagnostic{{Severity: tfprotov5.DiagnosticSeverityWarning, Summary: "deprecated"}}
	if _, _, err := Load(c, s); diagCode(err) != "control_computed_only" {
		t.Fatalf("warning diagnostic: %v", err)
	}
}

// withPhase2Types adds the data source and ephemeral types the shared
// fixtures name and aws-subset.json (pinned to its capture) lacks.
func withPhase2Types(s *tfprotov5.GetProviderSchemaResponse) *tfprotov5.GetProviderSchemaResponse {
	str := tftypes.String
	s.DataSourceSchemas["aws_s3_bucket"] = &tfprotov5.Schema{Block: &tfprotov5.SchemaBlock{Attributes: []*tfprotov5.SchemaAttribute{
		{Name: "bucket", Type: str, Required: true},
		{Name: "bucket_regional_domain_name", Type: str, Computed: true},
	}}}
	if s.EphemeralResourceSchemas == nil {
		s.EphemeralResourceSchemas = map[string]*tfprotov5.Schema{}
	}
	s.EphemeralResourceSchemas["aws_secretsmanager_secret_version"] = &tfprotov5.Schema{Block: &tfprotov5.SchemaBlock{Attributes: []*tfprotov5.SchemaAttribute{
		{Name: "secret_id", Type: str, Required: true},
		{Name: "secret_string", Type: str, Computed: true, Sensitive: true},
		{Name: "version_stage", Type: str, Optional: true, Computed: true},
	}}}
	return s
}

// awsSubset reads testdata/schemas/aws-subset.json (enginetest.AWSSubset).
func awsSubset(t *testing.T) *tfprotov5.GetProviderSchemaResponse {
	return enginetest.AWSSubset(t, filepath.Join("..", "..", "..", "testdata", "schemas", "aws-subset.json"))
}

// TestAWSSubsetCaptured pins aws-subset.json to its capture
// (scripts/capture-aws-schema.sh): 28 types, digest recorded in
// aws-subset.provenance.json (a hand edit fails here), and the version
// pins.json pins once it pins one.
func TestAWSSubsetCaptured(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "testdata", "schemas")
	data, err := os.ReadFile(filepath.Join(dir, "aws-subset.json"))
	if err != nil {
		t.Fatal(err)
	}
	var prov struct {
		Version string `json:"version"`
		Subset  string `json:"subset_sha256"`
	}
	raw, err := os.ReadFile(filepath.Join(dir, "aws-subset.provenance.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &prov); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if got := "sha256:" + hex.EncodeToString(sum[:]); prov.Version == "" || got != prov.Subset {
		t.Fatalf("aws-subset.json %s, provenance %q records %s: run make schema-subset", got, prov.Version, prov.Subset)
	}
	var pins struct {
		Version string `json:"version"`
	}
	raw, err = os.ReadFile(filepath.Join("..", "..", "..", "pins.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &pins); err != nil {
		t.Fatal(err)
	}
	if pins.Version != "" && pins.Version != prov.Version {
		t.Fatalf("aws-subset.json is hashicorp/aws %s, pins.json pins %s: run make schema-subset", prov.Version, pins.Version)
	}
	// Missing names fail in the consumers (awsSubset, sgFamily, the
	// crosscheck IAM schema); the count catches additions.
	s := awsSubset(t)
	if n := len(s.ResourceSchemas) + len(s.DataSourceSchemas) + len(s.EphemeralResourceSchemas); n != 28 {
		t.Fatalf("aws-subset.json has %d types, want 28", n)
	}
}

// TestLoadKeyPresenceShapes covers shapes aws-subset lacks: map(object),
// tuple, list(object) attributes and a NestingMap block. missing is whether
// evaluation reports no_such_attribute instead of running the control.
func TestLoadKeyPresenceShapes(t *testing.T) {
	obj := tftypes.Object{AttributeTypes: map[string]tftypes.Type{"port": tftypes.Number}}
	b := &tfprotov5.SchemaBlock{
		Attributes: []*tfprotov5.SchemaAttribute{
			{Name: "rules", Type: tftypes.Map{ElementType: obj}, Optional: true},
			{Name: "tup", Type: tftypes.Tuple{ElementTypes: []tftypes.Type{obj}}, Optional: true},
			{Name: "objs", Type: tftypes.List{ElementType: obj}, Optional: true},
			{Name: "dyn", Type: tftypes.DynamicPseudoType, Optional: true},
			{Name: "mdyn", Type: tftypes.Map{ElementType: tftypes.DynamicPseudoType}, Optional: true},
			{Name: "tdyn", Type: tftypes.Tuple{ElementTypes: []tftypes.Type{tftypes.DynamicPseudoType}}, Optional: true},
			{Name: "ltup", Type: tftypes.List{ElementType: tftypes.Tuple{ElementTypes: []tftypes.Type{obj}}}, Optional: true},
			{Name: "nest", Type: tftypes.List{ElementType: tftypes.Object{AttributeTypes: map[string]tftypes.Type{"meta": obj}}}, Optional: true},
		},
		BlockTypes: []*tfprotov5.SchemaNestedBlock{{TypeName: "mrules", Nesting: tfprotov5.SchemaNestedBlockNestingModeMap,
			Block: &tfprotov5.SchemaBlock{Attributes: []*tfprotov5.SchemaAttribute{{Name: "port", Type: tftypes.Number, Optional: true}}}}},
	}
	s := &tfprotov5.GetProviderSchemaResponse{ResourceSchemas: map[string]*tfprotov5.Schema{"aws_bobthecorp_widget": {Block: b}}}
	cases := []struct {
		expr, read, code string
		missing          bool
	}{
		{`!has(resource.rules["k"].x)`, "rules", "", true},
		{`!has(resource.rules.k.x)`, "rules", "", true},
		{`!("x" in resource.rules.k)`, "rules", "", true},
		{`"port" in resource.rules.k`, "rules", "", false},
		{`resource.objs != [{"port": 22, "x": true}]`, "objs", "control_dynamic_access", false},
		{`!({"port": 22, "x": true} in resource.objs)`, "objs", "control_dynamic_access", false},
		{`resource.tup[0].all(k, k != "x")`, "tup", "control_dynamic_access", false},
		{`resource.rules.all(k, k != "")`, "rules", "", false},
		{`resource.mrules.all(k, k != "")`, "mrules", "", false},
		{`resource.mrules.k.port == 22`, "mrules", "", true}, // resolve has no map-block key step: conservative
		{`resource.mrules.k.all(f, f != "x")`, "mrules", "control_dynamic_access", false},
		// Two-variable comprehensions are not in the env (no ext.TwoVarComprehensions).
		{`resource.mrules.exists(k, v, !("no_such" in v))`, "mrules", "control_expr", false},
		{`resource.mrules.exists(k, v, "x" in v)`, "mrules", "control_expr", false},
		// A dynamic value may be an object with no schema: no key tests,
		// key enumeration or deep comparison; scalar use and selects stay.
		{`!("x" in resource.dyn)`, "dyn", "control_dynamic_access", false},
		{`!("x" in resource.dyn.a)`, "dyn", "control_dynamic_access", false},
		{`resource.dyn.exists(k, k == "x")`, "dyn", "control_dynamic_access", false},
		{`size(resource.dyn) == 0`, "dyn", "control_dynamic_access", false},
		{`resource.dyn != {"a": 1}`, "dyn", "control_dynamic_access", false},
		{`resource.dyn != resource.dyn.b`, "dyn", "control_dynamic_access", false},
		{`resource.dyn == "x"`, "dyn", "", false},
		{`resource.dyn.a == "x"`, "dyn", "", false},
		{`resource.mdyn != {"k": {"a": 1}}`, "mdyn", "control_dynamic_access", false},
		{`resource.mdyn.k == "x"`, "mdyn", "", false},
		{`!has(resource.dyn.a)`, "dyn", "control_dynamic_access", false},
		// Tuples are opaque: any element may be an object or dynamic.
		{`resource.tdyn != [{"a": 1}]`, "tdyn", "control_dynamic_access", false},
		{`!({"a": 1} in resource.tdyn)`, "tdyn", "control_dynamic_access", false},
		{`!("a" in resource.tdyn)`, "tdyn", "", true},
		{`resource.ltup != [[{"port": 1}]]`, "ltup", "control_dynamic_access", false},
		{`!([{"port": 1}] in resource.ltup)`, "ltup", "control_dynamic_access", false},
		{`resource.ltup.all(t, t[0].all(k, k != "x"))`, "ltup", "control_dynamic_access", false},
		{`!has(resource.mdyn.k)`, "mdyn", "", false},
		{`resource.objs.all(o, !has(o.x))`, "objs", "", true},
		// An element step before a select must not hide the object below it.
		{`!("x" in resource.nest[0].meta)`, "nest", "", true},
		{`resource.nest.all(r, !("x" in r.meta))`, "nest", "", true},
		{`size(resource.nest[0].meta) == 1`, "nest", "control_dynamic_access", false},
		{`resource.nest.all(r, r.meta.all(k, k != "x"))`, "nest", "control_dynamic_access", false},
		{`resource.nest[0].meta != {"port": 1}`, "nest", "control_dynamic_access", false},
		{`resource.nest.all(r, [r.meta].all(m, !("x" in m)))`, "nest", "control_dynamic_access", false},
		{`resource.ltup.all(t, t.all(o, !("x" in o)))`, "ltup", "control_dynamic_access", false},
	}
	for _, tc := range cases {
		t.Run(tc.expr, func(t *testing.T) {
			c := *testControl(bundle.KindResource, bundle.PresenceEffective, tc.expr, tc.read)
			c.ResourceType, c.Action = "aws_bobthecorp_widget", bundle.ActionDeny
			checked, _, err := Load([]bundle.Control{c}, s)
			if diagCode(err) != tc.code {
				t.Fatalf("want %q, got %v", tc.code, err)
			}
			if err != nil {
				return
			}
			reads, err := schemaReads(b, checked[0])
			if err != nil || missingRead(b, reads) != tc.missing {
				t.Fatalf("reads %v err %v, want missing %v", reads, err, tc.missing)
			}
		})
	}
}

// TestLoadNestedRejectionLinear: the reads walk goes
// on past a rejection, so each nesting level of a computed value must not
// walk its operand again (fromData is memoized per node). Every shape is at
// about the deepest nesting the parser accepts (ParserRecursionLimit 64);
// without the memo the size shape alone takes minutes.
func TestLoadNestedRejectionLinear(t *testing.T) {
	s := awsSubset(t)
	nest := func(open, mid, closing string, n int) string {
		return strings.Repeat(open, n) + mid + strings.Repeat(closing, n)
	}
	exprs := map[string]string{
		"size":     nest("size(dyn(", "resource.tags", "))", 28) + " > 0",
		"in":       nest(`"k" in dyn(`, "resource.tags", ")", 28),
		"compare":  nest("dyn(", "resource.tags", ") == {}", 60),
		"select":   nest("dyn(", "resource.tags", ").a", 60) + " == 1",
		"iterate":  nest("dyn(", "resource.tags", ").exists(k, true)", 60),
		"body":     nest("dyn(resource.tags).exists(k, ", "true", ")", 60),
		"cmp size": nest("dyn(size(dyn(", "resource.tags", "))) == 0", 20),
		// rejections returned at once before are deferred too.
		"index":     nest("resource.tags[", `"k"`, "]", 60) + ` == "x"`,
		"dyn index": nest("dyn(", `resource.tags[resource.tags["k"]]`, ").a", 60) + " == 1",
		"whole":     nest("size(dyn(", "resource", "))", 28) + " > 0",
		"shadow":    nest(`["x"].all(resource, `, `resource != ""`, ")", 60),
		"over":      nest("dyn(", "resource", ").exists(k, true)", 60),
	}
	for name, expr := range exprs {
		t.Run(name, func(t *testing.T) {
			c := *testControl(bundle.KindResource, bundle.PresenceEffective, expr, "tags")
			c.ResourceType, c.Action = "aws_db_instance", bundle.ActionDeny
			done := make(chan error, 1)
			go func() {
				_, _, err := Load([]bundle.Control{c}, s)
				done <- err
			}()
			select {
			case err := <-done:
				if diagCode(err) != "control_dynamic_access" {
					t.Fatalf("got %v, want control_dynamic_access", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("reads analysis did not finish in 5s")
			}
		})
	}
}
