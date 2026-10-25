package bundle

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// bundleFixtures is the shared fixture oracle:
// celeng TestLoad reads the same directories for its schema-aware ids.
const bundleFixtures = "../../testdata/bundles"

// decodeWant is the DecodeControls oracle for testdata/bundles/invalid. Every
// fixture must be listed. A later celeng load error id that strict decode
// accepts is listed with an empty code.
var decodeWant = map[string]wantErr{
	"control_duplicate":            {"control_duplicate", "duplicate control key (s3_bucket_versioning_enabled, resource, aws_s3_bucket)"},
	"data_source_presence_missing": {"control_presence", `presence_mode "": want effective or configured`},
	"data_source_presence_unknown": {"control_presence", `presence_mode "planned": want effective or configured`},
	"data_source_on":               {"control_on", "data_source must not set on"},
	"data_source_on_empty":         {"control_on", "data_source must not set on"},
	"ephemeral_presence":           {"control_presence", "ephemeral must not set presence_mode"},
	"ephemeral_on":                 {"control_on", "ephemeral must not set on"},
	"guard_presence":               {"control_presence", "deletion_guard must not set presence_mode"},
	"guard_on_create":              {"control_on", `deletion guard must set on = ["delete"]`},
	"resource_on_delete":           {"control_on", "on must be a non-empty subset of create, update"},
	"resource_on_missing":          {"control_on", "on must be a non-empty subset of create, update"},
	"resource_presence_missing":    {"control_presence", `presence_mode "": want effective or configured`},
	"kind_unknown":                 {"control_kind", `kind "module": want resource, data_source, ephemeral, deletion_guard or graph`},
	"expr_empty":                   {"control_expr", "expr must be 1-4096 bytes"},
	"expr_too_long":                {"control_expr", "expr must be 1-4096 bytes"},
	"expr_missing":                 {"control_expr", "expr is required"},
	"expr_and_predicate":           {"control_predicate", "predicate is the legacy v0.1 form"},
	"unknown_field":                {"control_decode", `unknown field "expression"`},
	"coverable_bool":               {"control_coverable", "exemption_coverable must be a list of exemption kinds"},
	"coverable_unknown_kind":       {"control_coverable", `exemption kind "waiver"`},
	"coverable_unsorted":           {"control_coverable", "exemption_coverable must be sorted and unique"},
	// celeng load errors: strict decode accepts these.
	"control_vars":                       {},
	"control_reads_missing":              {},
	"control_dynamic_access":             {},
	"control_iam_unconditional_polarity": {},
	"iam_identity_direct":                {},
	"control_computed_only":              {},
	"computed_only":                      {},
	"computed_only_effective":            {},
	// optional_computed loads in celeng too: E_OPTIONAL_COMPUTED is the
	// generator verify, not a load error.
	"optional_computed": {},
}

func TestDecode(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join(bundleFixtures, "invalid", "*.json"))
	if len(files) == 0 {
		t.Fatal("no fixtures in testdata/bundles/invalid")
	}
	validate := controlSchema(t)
	seen := map[string]bool{}
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".json")
		seen[name] = true
		t.Run(name, func(t *testing.T) {
			want, ok := decodeWant[name]
			if !ok {
				t.Fatalf("fixture %s has no entry in decodeWant", name)
			}
			data, _ := os.ReadFile(f)
			_, err := DecodeControls(data)
			if want.code == "" {
				if err != nil {
					t.Fatalf("strict decode must accept %s (a celeng load error), got %v", name, err)
				}
				return
			}
			var e *Error
			if !errors.As(err, &e) {
				t.Fatalf("want *Error %s, got %v", want.code, err)
			}
			if e.Code != want.code || !strings.Contains(err.Error(), want.msg) {
				t.Errorf("got %q (%s), want code %s containing %q", err, e.Code, want.code, want.msg)
			}
			// Control-key uniqueness and list order are the decode rules the
			// schema cannot express.
			if err := validate(data); (err == nil) != (name == "control_duplicate" || name == "coverable_unsorted") {
				t.Errorf("schema error = %v", err)
			}
		})
	}
	for name := range decodeWant {
		if !seen[name] {
			t.Errorf("decodeWant lists %s but the fixture is missing", name)
		}
	}
}

func TestDecodeValid(t *testing.T) {
	decode := func(t *testing.T, name string) []Control {
		t.Helper()
		data := mustRead(t, name)
		cs, err := DecodeControls(data)
		if err != nil {
			t.Fatal(err)
		}
		if err := controlSchema(t)(data); err != nil {
			t.Errorf("schema rejects %s: %v", name, err)
		}
		return cs
	}
	t.Run("multi_target", func(t *testing.T) {
		cs := decode(t, "multi_target")
		keys := map[[3]string]bool{}
		for _, c := range cs {
			keys[[3]string{c.ID, string(c.Kind), c.ResourceType}] = true
		}
		if len(cs) != 5 || len(keys) != 5 {
			t.Errorf("want 5 distinct control keys, got %d controls, %d keys", len(cs), len(keys))
		}
		if cs[4].Kind != KindEphemeral || cs[4].PresenceMode != "" || cs[4].On != nil {
			t.Errorf("ephemeral: %+v", cs[4])
		}
		// The provider load path takes every kind.
		if _, err := ParseControls(mustRead(t, "multi_target")); err != nil {
			t.Errorf("ParseControls must accept every kind: %v", err)
		}
	})
	t.Run("configured", func(t *testing.T) {
		c := decode(t, "configured")[0]
		if c.PresenceMode != PresenceConfigured || c.Expr == nil || *c.Expr != "config.storage_encrypted == true" {
			t.Errorf("configured: %+v", c)
		}
		if _, err := ParseControls(mustRead(t, "configured")); err != nil {
			t.Errorf("ParseControls must accept a resource expr control: %v", err)
		}
	})
	for name, mode := range map[string]PresenceMode{"data_source_configured": PresenceConfigured, "data_source_effective": PresenceEffective} {
		t.Run(name, func(t *testing.T) {
			c := decode(t, name)[0]
			if c.Kind != KindDataSource || c.PresenceMode != mode || c.On != nil {
				t.Errorf("%s: %+v", name, c)
			}
		})
	}
}

func mustRead(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(bundleFixtures, "valid", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}
