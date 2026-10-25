package proxy

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func TestSchemaBlockToType(t *testing.T) {
	block := &tfprotov5.SchemaBlock{
		Attributes: []*tfprotov5.SchemaAttribute{
			{Name: "region", Type: tftypes.String},
			{Name: "max_retries", Type: tftypes.Number},
			{Name: "skip_metadata_api_check", Type: tftypes.Bool},
		},
	}

	typ := SchemaBlockToType(block)
	obj, ok := typ.(tftypes.Object)
	if !ok {
		t.Fatalf("expected tftypes.Object, got %T", typ)
	}

	if len(obj.AttributeTypes) != 3 {
		t.Fatalf("expected 3 attributes, got %d", len(obj.AttributeTypes))
	}

	if !obj.AttributeTypes["region"].Is(tftypes.String) {
		t.Errorf("expected region to be String, got %s", obj.AttributeTypes["region"])
	}
	if !obj.AttributeTypes["max_retries"].Is(tftypes.Number) {
		t.Errorf("expected max_retries to be Number, got %s", obj.AttributeTypes["max_retries"])
	}
	if !obj.AttributeTypes["skip_metadata_api_check"].Is(tftypes.Bool) {
		t.Errorf("expected skip_metadata_api_check to be Bool, got %s", obj.AttributeTypes["skip_metadata_api_check"])
	}
}

func TestSchemaBlockToType_WithNestedBlock(t *testing.T) {
	block := &tfprotov5.SchemaBlock{
		Attributes: []*tfprotov5.SchemaAttribute{
			{Name: "region", Type: tftypes.String},
		},
		BlockTypes: []*tfprotov5.SchemaNestedBlock{
			{
				TypeName: "compliance",
				Nesting:  tfprotov5.SchemaNestedBlockNestingModeSingle,
				Block: &tfprotov5.SchemaBlock{
					Attributes: []*tfprotov5.SchemaAttribute{
						{Name: "enforcement_mode", Type: tftypes.String, Optional: true},
						{Name: "control_profile", Type: tftypes.String, Optional: true},
					},
				},
			},
		},
	}

	typ := SchemaBlockToType(block)
	obj, ok := typ.(tftypes.Object)
	if !ok {
		t.Fatalf("expected tftypes.Object, got %T", typ)
	}

	if len(obj.AttributeTypes) != 2 {
		t.Fatalf("expected 2 keys (region + compliance), got %d", len(obj.AttributeTypes))
	}

	compType, ok := obj.AttributeTypes["compliance"]
	if !ok {
		t.Fatal("expected 'compliance' key in type")
	}

	compObj, ok := compType.(tftypes.Object)
	if !ok {
		t.Fatalf("expected compliance to be Object, got %T", compType)
	}

	if !compObj.AttributeTypes["enforcement_mode"].Is(tftypes.String) {
		t.Errorf("expected enforcement_mode to be String")
	}
	if !compObj.AttributeTypes["control_profile"].Is(tftypes.String) {
		t.Errorf("expected control_profile to be String")
	}
}

func TestSchemaBlockToType_ListNestedBlock(t *testing.T) {
	block := &tfprotov5.SchemaBlock{
		Attributes: []*tfprotov5.SchemaAttribute{
			{Name: "name", Type: tftypes.String},
		},
		BlockTypes: []*tfprotov5.SchemaNestedBlock{
			{
				TypeName: "ingress",
				Nesting:  tfprotov5.SchemaNestedBlockNestingModeList,
				Block: &tfprotov5.SchemaBlock{
					Attributes: []*tfprotov5.SchemaAttribute{
						{Name: "from_port", Type: tftypes.Number},
					},
				},
			},
		},
	}

	typ := SchemaBlockToType(block)
	obj := typ.(tftypes.Object)

	ingressType, ok := obj.AttributeTypes["ingress"]
	if !ok {
		t.Fatal("expected 'ingress' key")
	}

	listType, ok := ingressType.(tftypes.List)
	if !ok {
		t.Fatalf("expected List, got %T", ingressType)
	}

	elemObj, ok := listType.ElementType.(tftypes.Object)
	if !ok {
		t.Fatalf("expected List element to be Object, got %T", listType.ElementType)
	}

	if !elemObj.AttributeTypes["from_port"].Is(tftypes.Number) {
		t.Errorf("expected from_port to be Number")
	}
}

func TestComplianceSchema(t *testing.T) {
	block := ComplianceBlockSchema()
	if block == nil {
		t.Fatal("expected non-nil compliance block")
	}
	if block.TypeName != "compliance" {
		t.Errorf("expected TypeName 'compliance', got %q", block.TypeName)
	}
	if block.Nesting != tfprotov5.SchemaNestedBlockNestingModeSingle {
		t.Errorf("expected SINGLE nesting, got %s", block.Nesting)
	}

	// Block v2: control_bundle_url and
	// audit_log_path are removed.
	expectedAttrs := map[string]bool{
		"enforcement_mode":     false,
		"control_profile":      false,
		"org_id":               false,
		"control_bundle_path":  false,
		"profile_path":         false,
		"exceptions_file":      false,
		"exception_grants_dir": false,
		"environment":          false,
		"evidence_dir":         false,
		"data_sources":         false,
		"baseline_file":        false,
	}

	for _, attr := range block.Block.Attributes {
		if _, ok := expectedAttrs[attr.Name]; ok {
			expectedAttrs[attr.Name] = true
		} else {
			t.Errorf("unexpected attribute %q", attr.Name)
		}
		if !attr.Optional {
			t.Errorf("expected attribute %q to be Optional", attr.Name)
		}
		if !attr.Type.Is(tftypes.String) {
			t.Errorf("expected attribute %q to be String, got %s", attr.Name, attr.Type)
		}
	}

	for name, found := range expectedAttrs {
		if !found {
			t.Errorf("missing expected attribute %q", name)
		}
	}
}

func TestUnionProviderSchema(t *testing.T) {
	upstream := &tfprotov5.Schema{
		Block: &tfprotov5.SchemaBlock{
			Attributes: []*tfprotov5.SchemaAttribute{
				{Name: "region", Type: tftypes.String, Optional: true},
				{Name: "profile", Type: tftypes.String, Optional: true},
			},
		},
	}

	unioned := UnionProviderSchema(upstream)
	if unioned == nil {
		t.Fatal("expected non-nil unioned schema")
	}

	// Verify original attributes are preserved
	attrNames := make(map[string]bool)
	for _, attr := range unioned.Block.Attributes {
		attrNames[attr.Name] = true
	}
	if !attrNames["region"] {
		t.Error("expected 'region' attribute preserved")
	}
	if !attrNames["profile"] {
		t.Error("expected 'profile' attribute preserved")
	}

	// Verify compliance block is added
	var complianceBlock *tfprotov5.SchemaNestedBlock
	for _, block := range unioned.Block.BlockTypes {
		if block.TypeName == "compliance" {
			complianceBlock = block
			break
		}
	}
	if complianceBlock == nil {
		t.Fatal("expected compliance nested block in unioned schema")
	}

	// Verify original upstream schema is NOT mutated
	if len(upstream.Block.BlockTypes) != 0 {
		t.Error("upstream schema should not be mutated by UnionProviderSchema")
	}
}

func TestCombinedProviderType(t *testing.T) {
	upstream := &tfprotov5.Schema{
		Block: &tfprotov5.SchemaBlock{
			Attributes: []*tfprotov5.SchemaAttribute{
				{Name: "region", Type: tftypes.String, Optional: true},
			},
		},
	}

	combined := CombinedProviderType(upstream)
	obj, ok := combined.(tftypes.Object)
	if !ok {
		t.Fatalf("expected Object, got %T", combined)
	}

	if _, ok := obj.AttributeTypes["region"]; !ok {
		t.Error("expected 'region' in combined type")
	}
	if _, ok := obj.AttributeTypes["compliance"]; !ok {
		t.Error("expected 'compliance' in combined type")
	}
}

func TestUpstreamProviderType(t *testing.T) {
	upstream := &tfprotov5.Schema{
		Block: &tfprotov5.SchemaBlock{
			Attributes: []*tfprotov5.SchemaAttribute{
				{Name: "region", Type: tftypes.String, Optional: true},
			},
		},
	}

	upType := UpstreamProviderType(upstream)
	obj, ok := upType.(tftypes.Object)
	if !ok {
		t.Fatalf("expected Object, got %T", upType)
	}

	if _, ok := obj.AttributeTypes["region"]; !ok {
		t.Error("expected 'region' in upstream type")
	}
	if _, ok := obj.AttributeTypes["compliance"]; ok {
		t.Error("should not have 'compliance' in upstream type")
	}
}
