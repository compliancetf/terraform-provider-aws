package bundle

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const fixtures = "testdata/controls"

type wantErr struct{ code, msg string }

// invalidWant is the oracle for testdata/controls/invalid: every fixture must
// be listed and rejected with this error code and message.
var invalidWant = map[string]wantErr{
	"predicate_and_expr":      {"control_predicate", "predicate is the legacy v0.1 form; write the check as a CEL expr"},
	"predicate_v01":           {"control_predicate", "predicate is the legacy v0.1 form; write the check as a CEL expr"},
	"expr_missing":            {"control_expr", "expr is required"},
	"kind_unknown":            {"control_kind", `kind "module": want resource, data_source, ephemeral, deletion_guard or graph`},
	"kind_missing":            {"control_kind", `kind "": want resource, data_source, ephemeral, deletion_guard or graph`},
	"id_v01":                  {"control_id", `control[0]: id "CIS-RDS-001" does not match`},
	"id_short":                {"control_id", `id "ab" does not match`},
	"version_prerelease":      {"control_version", `version "1.0.0-rc1": want MAJOR.MINOR.PATCH`},
	"version_leading_v":       {"control_version", `version "v1.0.0": want MAJOR.MINOR.PATCH`},
	"resource_type_bad":       {"control_resource_type", `resource_type "AWS-DB"`},
	"reads_empty":             {"control_reads", "reads must not be empty"},
	"reads_wildcard":          {"control_reads", `read "storage_encrypted.*" does not match`},
	"reads_unsorted":          {"control_reads", "reads must be sorted and unique"},
	"reads_duplicate":         {"control_reads", "reads must be sorted and unique"},
	"presence_missing":        {"control_presence", `presence_mode "": want effective or configured`},
	"presence_unknown":        {"control_presence", `presence_mode "planned": want effective or configured`},
	"presence_on_guard":       {"control_presence", "deletion_guard must not set presence_mode"},
	"on_missing":              {"control_on", "on must be a non-empty subset of create, update"},
	"on_resource_delete":      {"control_on", "on must be a non-empty subset of create, update"},
	"on_guard_create":         {"control_on", `deletion guard must set on = ["delete"]`},
	"on_duplicate":            {"control_on", "on must be a non-empty subset of create, update"},
	"expr_null":               {"control_decode", "expr: null is not allowed"},
	"tool_refs_null":          {"control_decode", "tool_refs: null is not allowed"},
	"presence_empty_on_guard": {"control_presence", "deletion_guard must not set presence_mode"},
	"key_case":                {"control_decode", `key "ACTION" must match`},
	"key_kelvin":              {"control_decode", "key \"\u212aind\" must match"}, // Kelvin sign folds to k in encoding/json
	"duplicate_member":        {"control_decode", `duplicate key "action"`},
	"duplicate_member_nested": {"control_decode", `tool_refs: duplicate key "checkov"`},
	"action_block":            {"control_action", `action "block": want deny or warn`},
	"severity_unknown":        {"control_severity", `severity "urgent": want critical, high, medium, low or info`},
	"message_missing":         {"control_message", "message must be 1-256 bytes without a newline"},
	"message_newline":         {"control_message", "message must be 1-256 bytes without a newline"},
	"message_too_long":        {"control_message", "message must be 1-256 bytes without a newline"},
	"fix_too_long":            {"control_fix", "fix must be at most 512 bytes"},
	"framework_ref_bad":       {"control_framework_refs", `framework_ref "CC6.1" does not match`},
	"tool_refs_unknown":       {"control_tool_refs", `tool_refs key "snyk" is not a known tool`},
	"tool_refs_empty_ref":     {"control_tool_refs", `tool_refs "checkov" has an empty ref`},
	"coverable_bool":          {"control_coverable", "exemption_coverable must be a list of exemption kinds"},
	"coverable_unknown_kind":  {"control_coverable", `exemption kind "waiver"`},
	"coverable_unsorted":      {"control_coverable", "exemption_coverable must be sorted and unique"},
	"coverable_duplicate":     {"control_coverable", "exemption_coverable must be sorted and unique"},
	"unknown_field":           {"control_decode", `unknown field "attribute_path"`},
	"duplicate":               {"control_duplicate", "duplicate control key (rds_db_instance_encryption_at_rest_enabled, resource, aws_db_instance)"},
	"not_array":               {"controls_decode", "controls: "},
	"empty":                   {"controls_empty", "controls: no controls"},
	// Graph controls.
	"graph_missing":                {"control_graph", "graph is required"},
	"graph_expr":                   {"control_graph", "graph control must not set expr"},
	"graph_reads":                  {"control_graph", "graph control must not set reads"},
	"graph_on":                     {"control_graph", "graph control must not set on"},
	"graph_presence":               {"control_graph", "graph control must not set presence_mode"},
	"graph_rule_unknown":           {"control_graph", `graph.rule "companion_linked": want companion_present or companion_absent_forbidden`},
	"graph_companion_type_bad":     {"control_graph", `graph.companion_type "AWS-PAB" does not match`},
	"graph_link_attr_bad":          {"control_graph", `graph.link_attr "bucket.*" does not match`},
	"graph_target_attrs_empty":     {"control_graph", "graph.target_attrs must not be empty"},
	"graph_target_attrs_duplicate": {"control_graph", "graph.target_attrs must be unique"},
	"graph_companion_expr_null":    {"control_decode", "graph: companion_expr: null is not allowed"},
	"graph_companion_expr_empty":   {"control_graph", "graph.companion_expr must be 1-4096 bytes"},
	"graph_unknown_field":          {"control_decode", `unknown field "companion_type_alias"`},
	"graph_on_resource":            {"control_graph", "resource must not set graph"},
}

// schemaMisses lists invalid fixtures whose rule JSON Schema cannot express
// (ordering, uniqueness of control keys, duplicate object members that JSON
// parsing collapses).
// The decoder is the authority for these.
var schemaMisses = map[string]bool{
	"reads_unsorted": true, "coverable_unsorted": true, "duplicate": true, "duplicate_member": true,
	"duplicate_member_nested": true,
}

func fixtureNames(t *testing.T, dir string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(fixtures, dir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no fixtures in %s: %v", dir, err)
	}
	return files
}

func TestControlValid(t *testing.T) {
	for _, f := range fixtureNames(t, "valid") {
		t.Run(filepath.Base(f), func(t *testing.T) {
			data, _ := os.ReadFile(f)
			cs, err := ParseControls(data)
			if err != nil {
				t.Fatal(err)
			}
			if len(cs) == 0 {
				t.Fatal("no controls")
			}
		})
	}
}

func TestControlDecodedFields(t *testing.T) {
	data, _ := os.ReadFile(filepath.Join(fixtures, "valid", "sg_ingress_conditional.json"))
	cs, err := ParseControls(data)
	if err != nil {
		t.Fatal(err)
	}
	c := cs[0]
	if c.Kind != KindResource || c.PresenceMode != PresenceConfigured || c.Action != ActionWarn || c.Severity != SeverityCritical {
		t.Errorf("enums: %+v", c)
	}
	if c.Expr == nil || *c.Expr != `config.ingress.all(i, i.from_port != 22 || !("0.0.0.0/0" in i.cidr_blocks))` {
		t.Errorf("expr: %v", c.Expr)
	}
	if len(c.On) != 2 || c.On[0] != OnCreate || c.On[1] != OnUpdate || c.ExemptionCoverable == nil || len(c.ExemptionCoverable) != 0 {
		t.Errorf("on/coverable: %v %v", c.On, c.ExemptionCoverable)
	}

	data, _ = os.ReadFile(filepath.Join(fixtures, "valid", "rds_encryption.json"))
	cs, _ = ParseControls(data)
	if got := cs[0].ExemptionCoverable; len(got) != 2 || got[0] != CoverBaseline || got[1] != CoverGrant {
		t.Errorf("coverable: %v", got)
	}
	if cs[0].ToolRefs["checkov"][0] != "CKV_AWS_16" {
		t.Errorf("tool_refs: %v", cs[0].ToolRefs)
	}
}

func TestControlInvalid(t *testing.T) {
	seen := map[string]bool{}
	for _, f := range fixtureNames(t, "invalid") {
		name := strings.TrimSuffix(filepath.Base(f), ".json")
		seen[name] = true
		t.Run(name, func(t *testing.T) {
			want, ok := invalidWant[name]
			if !ok {
				t.Fatalf("fixture %s has no expected error in invalidWant", name)
			}
			data, _ := os.ReadFile(f)
			_, err := ParseControls(data)
			var e *Error
			if !errors.As(err, &e) {
				t.Fatalf("want *Error %s, got %v", want.code, err)
			}
			if e.Code != want.code || !strings.Contains(err.Error(), want.msg) {
				t.Errorf("got %q (%s), want code %s containing %q", err, e.Code, want.code, want.msg)
			}
		})
	}
	for name := range invalidWant {
		if !seen[name] {
			t.Errorf("invalidWant lists %s but the fixture is missing", name)
		}
	}
}

func controlSchema(t testing.TB) func([]byte) error {
	sch, err := jsonschema.NewCompiler().Compile("../../schema/bundle-control-2.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	return func(data []byte) error {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
		if err != nil {
			return err
		}
		return sch.Validate(doc)
	}
}

func TestControlSchema(t *testing.T) {
	validate := controlSchema(t)
	check := func(f string) error {
		data, _ := os.ReadFile(f)
		return validate(data)
	}
	for _, f := range fixtureNames(t, "valid") {
		if err := check(f); err != nil {
			t.Errorf("%s: schema rejects a valid fixture: %v", f, err)
		}
	}
	for _, f := range fixtureNames(t, "invalid") {
		name := strings.TrimSuffix(filepath.Base(f), ".json")
		if err := check(f); (err == nil) != schemaMisses[name] {
			t.Errorf("%s: schema error = %v, schemaMisses = %v", name, err, schemaMisses[name])
		}
	}
}

// FuzzControlSchema guards the other direction: whatever the decoder accepts,
// the schema must accept too. Seeds are every fixture.
func FuzzControlSchema(f *testing.F) {
	for _, dir := range []string{fixtures + "/valid", fixtures + "/invalid", bundleFixtures + "/valid", bundleFixtures + "/invalid"} {
		files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
		for _, file := range files {
			data, _ := os.ReadFile(file)
			f.Add(data)
		}
	}
	validate := controlSchema(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		if _, err := DecodeControls(data); err != nil {
			return
		}
		if err := validate(data); err != nil {
			t.Fatalf("decoder accepts, schema rejects: %v\n%s", err, data)
		}
	})
}
