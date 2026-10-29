// Package crosscheck replays language-neutral control fixtures through the
// CEL engine.
package crosscheck

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/celeng"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/enginetest"
	"github.com/compliancetf/terraform-provider-aws/internal/iampolicy"
)

const root = "../../testdata"

// controlFile is one testdata/controls control with its fixtures. A string
// attribute given a JSON object or array value is the compact JSON text of
// that value; other attributes take the fixture JSON as is (enginetest.Value);
// {"$unknown": true} is unknown. About says how the control was written.
type controlFile struct {
	About   string
	Control json.RawMessage
	Cases   []struct {
		ID       string
		Resource map[string]json.RawMessage
		// AccountUnknown leaves provider.account_id unknown; otherwise it
		// is the own account 111111111111.
		AccountUnknown bool `json:"account_unknown"`
		// Partition is provider.partition, "aws" when empty; "$unknown"
		// leaves it unknown.
		Partition string
		Expect    struct {
			State    engine.State
			ErrClass engine.ErrClass `json:"err_class"`
		}
	}
}

// TestIAMControls runs the seven catalog IAM controls (the inline KMS control
// once per inline policy type) against their positive and negative fixtures
// under the catalog-iam catalog.
func TestIAMControls(t *testing.T) {
	if n, _ := runControls(t, filepath.Join(root, "controls", "catalog-iam"), true); n != 7 {
		t.Fatalf("%d catalog IAM controls, want 7", n)
	}
}

// TestIAMIdentity runs the iam-identity group (IAM identity resolution):
// role name, unique id, path wildcard, unknown queried ARN and
// catalog miss are not_evaluable / unresolved; canonical matches decide.
func TestIAMIdentity(t *testing.T) {
	if n, cases := runControls(t, filepath.Join(root, "crosscheck", "iam-identity"), true); n != 4 || cases < 6 {
		t.Fatalf("%d iam-identity controls with %d cases, want 4 with at least 6", n, cases)
	}
}

// runControls replays every control file of dir under dir's catalog and
// returns the number of control files and of cases. withCatalog loads dir's
// catalog file, which must exist; otherwise controls load with no IAM
// catalog. Files named in skip are not controls.
func runControls(t *testing.T, dir string, withCatalog bool, skip ...string) (n, cases int) {
	s := schema(t)
	var cat *iampolicy.Catalog
	if withCatalog {
		cat = catalog(t, filepath.Join(dir, iampolicy.CatalogFile))
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if base := filepath.Base(f); base == iampolicy.CatalogFile || slices.Contains(skip, base) {
			continue
		}
		n++
		var cf controlFile
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if err := decodeStrict(data, &cf); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if len(cf.Cases) == 0 {
			t.Fatalf("%s: no cases", f)
		}
		cs, err := bundle.DecodeControls(append(append([]byte("["), cf.Control...), ']'))
		if err != nil || len(cs) != 1 {
			t.Fatalf("%s: %d controls, %v", f, len(cs), err)
		}
		comp, diags, err := celeng.New(celeng.Options{PerResourceBudget: 10 * time.Second}).
			Load(cs, s, celeng.Content{Digest: "sha256:catalog-iam", IAMCatalog: cat})
		if err != nil || len(diags) > 0 {
			t.Fatalf("%s: %v, load diagnostics %+v", f, err, diags)
		}
		sc, ok := s.ResourceSchemas[cs[0].ResourceType]
		if !ok {
			t.Fatalf("%s: resource_type %q not in the schema", f, cs[0].ResourceType)
		}
		cases += len(cf.Cases)
		pass, fail := false, false
		for _, tc := range cf.Cases {
			t.Run(cs[0].ID+"/"+tc.ID, func(t *testing.T) {
				typ, ok := sc.Block.ValueType().(tftypes.Object)
				if !ok {
					t.Fatalf("%s: %s schema is not an object", f, cs[0].ResourceType)
				}
				b := celeng.Bindings{Kind: cs[0].Kind, Type: cs[0].ResourceType, Op: "create", Env: "prod", EnvKnown: true,
					Resource: object(t, typ, tc.Resource),
					Provider: celeng.ProviderInfo{Region: "eu-west-1", RegionKnown: true, AccountID: "111111111111", AccountKnown: !tc.AccountUnknown,
						Partition: cmp.Or(tc.Partition, "aws"), PartitionKnown: tc.Partition != "$unknown"}}
				rs := comp.Evaluate(context.Background(), b, nil)
				if len(rs) != 1 {
					t.Fatalf("%d results", len(rs))
				}
				if rs[0].State == engine.Pass && tc.Expect.State != engine.Pass {
					t.Fatalf("SAFETY: pass, want %s/%s", tc.Expect.State, tc.Expect.ErrClass)
				}
				if rs[0].State != tc.Expect.State || rs[0].ErrClass != tc.Expect.ErrClass {
					t.Fatalf("got %s/%s, want %s/%s", rs[0].State, rs[0].ErrClass, tc.Expect.State, tc.Expect.ErrClass)
				}
				noLeak(t, enginetest.SensitiveStrings(sc.Block, b.Resource), rs, diags)
			})
			pass = pass || tc.Expect.State == engine.Pass
			fail = fail || tc.Expect.State == engine.Fail
		}
		if !pass || !fail {
			t.Errorf("%s: needs a positive and a negative fixture", f)
		}
	}
	return n, cases
}

func catalog(t *testing.T, path string) *iampolicy.Catalog {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	c, err := iampolicy.LoadCatalog(b)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func object(t *testing.T, typ tftypes.Object, attrs map[string]json.RawMessage) tftypes.Value {
	t.Helper()
	vals := map[string]tftypes.Value{}
	for k, at := range typ.AttributeTypes {
		raw, ok := attrs[k]
		delete(attrs, k)
		var s string
		switch {
		case !ok:
			vals[k] = tftypes.NewValue(at, nil)
		case !at.Is(tftypes.String):
			vals[k] = enginetest.Value(t, at, raw)
		case string(raw) == `{"$unknown": true}` || string(raw) == `{"$unknown":true}`:
			vals[k] = tftypes.NewValue(at, tftypes.UnknownValue)
		case json.Unmarshal(raw, &s) == nil:
			vals[k] = tftypes.NewValue(at, s)
		default:
			var buf bytes.Buffer
			if err := json.Compact(&buf, raw); err != nil {
				t.Fatal(err)
			}
			vals[k] = tftypes.NewValue(at, buf.String())
		}
	}
	if len(attrs) > 0 {
		t.Fatalf("attributes not in the schema: %v", attrs)
	}
	return tftypes.NewValue(typ, vals)
}

func schema(t *testing.T) *tfprotov5.GetProviderSchemaResponse {
	return enginetest.AWSSubset(t, filepath.Join(root, "schemas", "aws-subset.json"))
}
