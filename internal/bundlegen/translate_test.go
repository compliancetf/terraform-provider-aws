package bundlegen

import (
	"bytes"
	"context"
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
	"github.com/compliancetf/terraform-provider-aws/internal/engine/enginetest"
)

const awsSubset = "../../testdata/schemas/aws-subset.json"

// translateResult is want.json of a translate case: exactly one field set.
type translateResult struct {
	Control *bundle.Control `json:"control,omitempty"`
	Review  *ReviewItem     `json:"review,omitempty"`
	Error   string          `json:"error,omitempty"` // the E_* code
}

// TestTranslate replays testdata/translate/*.txtar (the translation
// table oracle): intent.json is one intent, schema.json an
// optional provider schema (default the aws-subset), want.json the result.
func TestTranslate(t *testing.T) {
	files, err := filepath.Glob("testdata/translate/*.txtar")
	if err != nil || len(files) < 20 {
		t.Fatalf("%d translate cases, %v", len(files), err)
	}
	subset, err := LoadSchemas(awsSubset)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		t.Run(strings.TrimSuffix(filepath.Base(f), ".txtar"), func(t *testing.T) {
			ar, err := txtar.ParseFile(f)
			if err != nil {
				t.Fatal(err)
			}
			sections := map[string][]byte{}
			for _, x := range ar.Files {
				sections[x.Name] = x.Data
			}
			schemas := subset
			if data, ok := sections["schema.json"]; ok {
				p := filepath.Join(t.TempDir(), "schema.json")
				if err := os.WriteFile(p, data, 0o600); err != nil {
					t.Fatal(err)
				}
				if schemas, err = LoadSchemas(p); err != nil {
					t.Fatal(err)
				}
			}
			var it Intent
			if err := decodeStrictJSON(sections["intent.json"], &it); err != nil {
				t.Fatalf("intent.json: %v", err)
			}
			s, _ := schemas.Resource(it.ResourceType)
			got := runTranslate(t, it, s)
			gotJSON, err := canonicalJSON(got)
			if err != nil {
				t.Fatal(err)
			}
			if *update {
				for i := range ar.Files {
					if ar.Files[i].Name == "want.json" {
						ar.Files[i].Data = gotJSON
					}
				}
				if err := os.WriteFile(f, txtar.Format(ar), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			var want translateResult
			if err := decodeStrictJSON(sections["want.json"], &want); err != nil {
				t.Fatalf("want.json: %v", err)
			}
			wantJSON, err := canonicalJSON(want)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(gotJSON, wantJSON) {
				t.Errorf("got\n%s\nwant\n%s", gotJSON, wantJSON)
			}
		})
	}
}

// runTranslate calls Translate and checks its contract: on success exactly
// one of control and review.
func runTranslate(t *testing.T, it Intent, s *tfprotov5.Schema) translateResult {
	t.Helper()
	c, r, err := Translate(it, s)
	var e *Error
	switch {
	case errors.As(err, &e):
		return translateResult{Error: e.Code}
	case err != nil:
		t.Fatalf("untyped error %v", err)
	case r != nil && c.Expr != nil, r == nil && c.Expr == nil:
		t.Fatalf("want exactly one of control and review, got %+v and %+v", c, r)
	case r != nil:
		return translateResult{Review: r}
	}
	return translateResult{Control: &c}
}

func decodeStrictJSON(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// TestTranslateContentSample translates the intents of the 20 content-sample
// controls (testdata/controls/content-sample) and replays each
// sample's cases through the translated control. A refused intent must get
// the reason in sampleReview; a translated one must reproduce every case
// except the ones sampleDiff lists, each explained there.
func TestTranslateContentSample(t *testing.T) {
	its, err := LoadIntents("testdata/translate/content-sample-intents.json")
	if err != nil {
		t.Fatal(err)
	}
	schemas, err := LoadSchemas(awsSubset)
	if err != nil {
		t.Fatal(err)
	}
	if len(its.Policies) != 20 {
		t.Fatalf("%d intents, want 20", len(its.Policies))
	}
	for _, it := range its.Policies {
		t.Run(it.ID, func(t *testing.T) {
			s, ok := schemas.Resource(it.ResourceType)
			if !ok {
				t.Fatalf("%s not in the aws-subset", it.ResourceType)
			}
			got := runTranslate(t, it, s)
			if want, ok := sampleReview[it.ID]; ok || got.Review != nil {
				if got.Review == nil || got.Review.Reason != want {
					t.Fatalf("got %+v, want review %q", got, want)
				}
				return
			}
			if got.Control == nil {
				t.Fatalf("got %+v", got)
			}
			var differ []string
			for _, tc := range sampleCases(t, it.ID) {
				st := evalCase(t, got.Control, s, tc.Resource)
				if st == engine.Pass && tc.Expect.State != engine.Pass && !slices.Contains(sampleLooser[it.ID], tc.ID) {
					t.Errorf("SAFETY: %s passes, sample says %s", tc.ID, tc.Expect.State)
				}
				if st != tc.Expect.State {
					differ = append(differ, tc.ID+":"+st.String())
				}
			}
			if want := sampleDiff[it.ID]; !slices.Equal(differ, want) {
				t.Errorf("cases that differ from the sample: %q, want %q", differ, want)
			}
		})
	}
}

type sampleCase struct {
	ID       string
	Resource map[string]json.RawMessage
	Expect   struct{ State engine.State }
}

func sampleCases(t *testing.T, id string) []sampleCase {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("../../testdata/controls/content-sample", id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var f struct{ Cases []sampleCase }
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	return f.Cases
}

// evalCase binds the fixture as resource for an effective control and as
// config for a configured one.
func evalCase(t *testing.T, c *bundle.Control, s *tfprotov5.Schema, attrs map[string]json.RawMessage) engine.State {
	t.Helper()
	raw, err := json.Marshal(attrs)
	if err != nil {
		t.Fatal(err)
	}
	v := enginetest.Value(t, s.Block.ValueType(), raw)
	resp := &tfprotov5.GetProviderSchemaResponse{ResourceSchemas: map[string]*tfprotov5.Schema{c.ResourceType: s}}
	comp, _, err := celeng.New(celeng.Options{PerResourceBudget: 10 * time.Second}).Load([]bundle.Control{*c}, resp, celeng.Content{Digest: "sha256:translate"})
	if err != nil {
		t.Fatal(err)
	}
	b := celeng.Bindings{Kind: c.Kind, Type: c.ResourceType, Op: "create", Env: "prod", EnvKnown: true}
	if c.PresenceMode == bundle.PresenceConfigured {
		b.Config = v
	} else {
		b.Resource = v
	}
	rs := comp.Evaluate(context.Background(), b, nil)
	if len(rs) != 1 {
		t.Fatalf("%d results", len(rs))
	}
	return rs[0].State
}

var (
	// sampleReview: intents the translator refuses; the sample controls
	// are their authored overrides.
	sampleReview = map[string]ReviewReason{
		// exists on a block encodes a prohibition here (the sample control is
		// size(network_interface) == 0): the table's size(b) >= 1
		// would invert it.
		"bobthecorp_sample_instance_no_inline_eni": ReviewBlockExists,
		// not_empty on a number; the control excludes listed ports.
		"bobthecorp_sample_db_port_not_listed": ReviewType,
		// rule is a set block without max_items = 1; the proposal is the
		// sample's all() over rule.
		"bobthecorp_sample_bucket_sse_kms_key":          ReviewUnboundedBlock,
		"bobthecorp_sample_bucket_policy_names_account": ReviewCondition,
		// port_range_excludes is not in the translation table.
		"bobthecorp_sample_ingress_listed_ports_closed": ReviewCondition,
	}
	// sampleDiff: sample cases whose state differs, as "<case>:<state>".
	sampleDiff = map[string][]string{
		// fail-closed equals_any: an absent block or a null value fails;
		// the sample coalesces both to the AWS default true.
		"bobthecorp_sample_instance_root_volume_deleted": {"P-02-default-null:fail", "P-03-no-block:fail"},
		// the intent (not_empty) is narrower than the enforcement
		// (username != the reserved name): review sheet and diffcheck.
		"bobthecorp_sample_db_username_not_reserved": {"F-01-reserved:pass"},
	}
	// sampleLooser: differing cases where the translated control passes
	// and the sample fails. Only intent-narrower-than-enforcement cases.
	sampleLooser = map[string][]string{
		"bobthecorp_sample_db_username_not_reserved": {"F-01-reserved"},
	}
)

// TestLoadIntentsUnknownField: a field the intents format does not define
// is E_INTENT with its path, never silently dropped (owner).
func TestLoadIntentsUnknownField(t *testing.T) {
	for _, tc := range []struct{ name, policy, want string }{
		{"where", `{"id": "a_b_c", "resource_type": "aws_kms_key", "attributes": [{"schema_path": "enable_key_rotation", "condition": "equals_any", "values": [true], "values_from_ref": null, "where": {"name": "secret-value"}}]}`,
			"policies[0].attributes[0].where"},
		{"quantifier", `{"id": "a_b_c", "resource_type": "aws_kms_key", "quantifier": "any", "attributes": []}`, "policies[0].quantifier"},
		{"non-name key", `{"id": "a_b_c", "Secret Value!": 1}`, "policies[0].<non-name>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "intents.json")
			doc := `{"format": "content.provider-intents/1", "policies": [` + tc.policy + `]}`
			if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadIntents(p)
			var e *Error
			if !errors.As(err, &e) || e.Code != "E_INTENT" || !strings.HasSuffix(e.Msg, "unknown field "+tc.want) {
				t.Fatalf("got %v, want E_INTENT unknown field %s", err, tc.want)
			}
			if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "Secret") {
				t.Fatalf("error carries input text: %v", err)
			}
		})
	}
}

// TestTranslateIncompleteSchema: a nested block without a body or an
// attribute without a type is a refusal, never a panic (panel round 1).
func TestTranslateIncompleteSchema(t *testing.T) {
	it := Intent{ID: "bobthecorp_thing_check", ResourceType: "aws_bobthecorp_thing",
		Attributes: []IntentAttribute{{SchemaPath: "a", Condition: "not_empty"}}}
	for name, b := range map[string]*tfprotov5.SchemaBlock{
		"nil block": {BlockTypes: []*tfprotov5.SchemaNestedBlock{{TypeName: "a", Nesting: tfprotov5.SchemaNestedBlockNestingModeList}}},
		"nil type":  {Attributes: []*tfprotov5.SchemaAttribute{{Name: "a", Optional: true}}},
		// panel round 2: nil entries next to a valid attribute
		"nil attribute": {Attributes: []*tfprotov5.SchemaAttribute{nil, {Name: "a", Type: tftypes.String, Optional: true}}},
		"nil nested block": {Attributes: []*tfprotov5.SchemaAttribute{{Name: "a", Type: tftypes.String, Optional: true}},
			BlockTypes: []*tfprotov5.SchemaNestedBlock{nil}},
	} {
		t.Run(name, func(t *testing.T) {
			if it.Attributes[0].SchemaPath = "a"; name == "nil block" {
				it.Attributes[0].SchemaPath = "a.x"
			}
			got := runTranslate(t, it, &tfprotov5.Schema{Block: b})
			if got.Review == nil || got.Review.Reason != ReviewType {
				t.Fatalf("got %+v, want a type review", got)
			}
		})
	}
}

// TestTranslateMalformedPathValueFree: the E_INTENT for a malformed path
// names the segment index, never the input text (panel round 2).
func TestTranslateMalformedPathValueFree(t *testing.T) {
	it := Intent{ID: "bobthecorp_sample_key_rotation_on", ResourceType: "aws_kms_key",
		Attributes: []IntentAttribute{{SchemaPath: "enable_key_rotation.Secret-Value", Condition: "equals_any"}}}
	s := &tfprotov5.Schema{Block: &tfprotov5.SchemaBlock{}}
	_, _, err := Translate(it, s)
	var e *Error
	if !errors.As(err, &e) || e.Code != "E_INTENT" || !strings.Contains(e.Msg, "segment 1") || strings.Contains(e.Msg, "Secret") {
		t.Fatalf("got %v", err)
	}
}
