package exceptions

import (
	"bytes"
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
	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
)

type sidecarGolden struct {
	Description string `json:"description"`
	HCL         string `json:"hcl"`
	Table       struct {
		Workspace               *string  `json:"workspace"`
		NoSelfService           bool     `json:"no_self_service"`
		MaxLifetimeDays         *int64   `json:"max_lifetime_days"`
		ForbidEnvironmentScoped []string `json:"forbid_environment_scoped"`
	} `json:"table"`
	LoadError  string   `json:"load_error"`
	NilSidecar bool     `json:"nil_sidecar"`
	Warnings   []string `json:"warnings"`
	Events     []string `json:"events"`
	Lookups    []struct {
		Control  string            `json:"control"`
		Resource map[string]any    `json:"resource"`
		Want     *sidecarWantMatch `json:"want"`
	} `json:"lookups"`
}

type sidecarWantMatch struct {
	Applied    bool   `json:"applied,omitempty"`
	Unresolved bool   `json:"unresolved,omitempty"`
	Status     string `json:"status,omitempty"`
	ID         string `json:"id,omitempty"`
	Expires    string `json:"expires,omitempty"`
	Workspace  string `json:"workspace,omitempty"`
}

var sidecarType = tftypes.Object{AttributeTypes: map[string]tftypes.Type{
	"identifier": tftypes.String, "storage_encrypted": tftypes.Bool}}

// testSchemas is a celeng.SchemaSource of resource schemas by type.
type testSchemas map[string]*tfprotov5.Schema

func (s testSchemas) Resource(typ string) (*tfprotov5.Schema, bool) { sc, ok := s[typ]; return sc, ok }
func (testSchemas) DataSource(string) (*tfprotov5.Schema, bool)     { return nil, false }
func (testSchemas) EphemeralResource(string) (*tfprotov5.Schema, bool) {
	return nil, false
}

// schemaOf is an upstream schema of optional attributes of typ.
func schemaOf(typ tftypes.Object) *tfprotov5.Schema {
	b := &tfprotov5.SchemaBlock{}
	for _, n := range slices.Sorted(maps.Keys(typ.AttributeTypes)) {
		b.Attributes = append(b.Attributes, &tfprotov5.SchemaAttribute{Name: n, Type: typ.AttributeTypes[n], Optional: true})
	}
	return &tfprotov5.Schema{Block: b}
}

// dbSchemas holds the aws_db_instance subset of the goldens.
var dbSchemas = testSchemas{"aws_db_instance": schemaOf(sidecarType)}

// ctl is an aws_db_instance resource control.
func ctl(id string) *bundle.Control {
	return &bundle.Control{ID: id, Kind: bundle.KindResource, ResourceType: "aws_db_instance"}
}

// act is the activation of a planned resource (config and prior null).
func act(resource tftypes.Value) *engine.Activation {
	return &engine.Activation{Resource: resource, Op: engine.OpCreate}
}

// sidecarAliases is the control set the goldens resolve against.
var sidecarAliases = map[string][]string{
	"rds_db_instance_encryption_at_rest_enabled": {"rds_db_instance_encryption_at_rest_enabled"},
	"rds_instance_kms_key_configured":            {"rds_instance_kms_key_configured"},
	"CKV_AWS_16":                                 {"rds_db_instance_encryption_at_rest_enabled"},
}

// foldAliases is bundle.ControlSet.ResolveFold over sidecarAliases: keys
// match under case folding and every match is unioned.
func foldAliases(ref string) []string {
	var out []string
	for k, ids := range sidecarAliases {
		if strings.EqualFold(k, ref) {
			for _, id := range ids {
				if !slices.Contains(out, id) {
					out = append(out, id)
				}
			}
		}
	}
	slices.Sort(out)
	return out
}

// TestExceptionSidecar runs testdata/*.json against their .hcl sidecars: the
// profile self_service gate, workspace scope, absolute expiry within
// max_lifetime_days, aliases, unresolved ids and the unknown selector.
func TestExceptionSidecar(t *testing.T) {
	files, err := filepath.Glob("testdata/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no sidecar goldens: %v", err)
	}
	now := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	for _, f := range files {
		t.Run(strings.TrimSuffix(filepath.Base(f), ".json"), func(t *testing.T) {
			var g sidecarGolden
			raw, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&g); err != nil {
				t.Fatal(err)
			}
			if g.HCL == "" {
				g.HCL = strings.TrimSuffix(filepath.Base(f), ".json") + ".hcl"
			}
			path := filepath.Join("testdata", g.HCL)
			tbl := profile.ModeTable{
				Workspace:   profile.Dim{Value: "bobthecorp-reporting-prod", Source: "profile"},
				Environment: profile.Dim{Value: "prod", Source: "profile"},
				Exceptions: &profile.Exceptions{MaxLifetimeDays: 180,
					SelfService:             []string{"rds_db_instance_encryption_at_rest_enabled"},
					ForbidEnvironmentScoped: g.Table.ForbidEnvironmentScoped},
				SidecarControls: []string{"rds_db_instance_encryption_at_rest_enabled"},
			}
			if w := g.Table.Workspace; w != nil {
				tbl.Workspace = profile.Dim{}
				if *w != "" {
					tbl.Workspace = profile.Dim{Value: *w, Source: "profile"}
				}
			}
			if m := g.Table.MaxLifetimeDays; m != nil {
				tbl.Exceptions.MaxLifetimeDays = *m
			}
			if g.Table.NoSelfService {
				tbl.Exceptions, tbl.SidecarControls = nil, nil
			}
			cov, _ := NewCoverability(map[string][]bundle.ExemptionKind{ // coverable for self_service
				"rds_db_instance_encryption_at_rest_enabled": {bundle.CoverSelfService}}, nil)
			sc, n, err := LoadSidecar(path, SidecarInput{Table: tbl, Now: now, Coverable: cov,
				Resolve: func(ref string) []string { return sidecarAliases[ref] }, ResolveFold: foldAliases})
			if g.LoadError != "" {
				if err == nil || !strings.Contains(err.Error(), g.LoadError) {
					t.Fatalf("load error %v, want %q", err, g.LoadError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if (sc == nil) != g.NilSidecar {
				t.Fatalf("sidecar %v, want nil %v", sc, g.NilSidecar)
			}
			if !slices.Equal(n.Warnings, g.Warnings) || !slices.Equal(n.Events, g.Events) {
				t.Errorf("notices %q %q, want %q %q", n.Warnings, n.Events, g.Warnings, g.Events)
			}
			for i, lk := range g.Lookups {
				if lk.Control == "" {
					lk.Control = "rds_db_instance_encryption_at_rest_enabled"
				}
				d := sc.Lookup(verdictCtx(t), ctl(lk.Control), dbSchemas, act(resourceValue(lk.Resource)), now)
				var got *sidecarWantMatch
				if d.Exception != nil || d.Unresolved {
					got = &sidecarWantMatch{Applied: d.Applied, Unresolved: d.Unresolved}
				}
				if e := d.Exception; e != nil {
					got.Status = e.Status
					if d.Applied {
						got.ID, got.Expires, got.Workspace = e.ID, e.Expires, *e.Workspace
					}
					if e.Source != "self_service" || !slices.Contains(sc.Digests(), e.Digest) {
						t.Errorf("lookup %d: source %s digest %s", i, e.Source, e.Digest)
					}
				}
				gj, _ := json.Marshal(got)
				wj, _ := json.Marshal(lk.Want)
				if !bytes.Equal(gj, wj) {
					t.Errorf("lookup %d: got %s, want %s", i, gj, wj)
				}
			}
		})
	}
}

// resourceValue builds the golden resource; "<unknown>" is an unknown string.
func resourceValue(m map[string]any) tftypes.Value {
	attrs := map[string]tftypes.Value{}
	for k, typ := range sidecarType.AttributeTypes {
		v, ok := m[k]
		switch {
		case !ok:
			attrs[k] = tftypes.NewValue(typ, nil)
		case v == "<unknown>":
			attrs[k] = tftypes.NewValue(typ, tftypes.UnknownValue)
		default:
			attrs[k] = tftypes.NewValue(typ, v)
		}
	}
	return tftypes.NewValue(sidecarType, attrs)
}
