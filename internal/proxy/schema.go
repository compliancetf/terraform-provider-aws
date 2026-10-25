package proxy

import (
	"maps"
	"slices"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/lifecycle"
)

// SchemaBlockToType recursively converts a tfprotov5.SchemaBlock into a tftypes.Type.
// It handles attributes (using their Type field directly) and nested blocks
// (SINGLE/GROUP→Object, LIST→List{Object}, SET→Set{Object}, MAP→Map{Object}).
func SchemaBlockToType(block *tfprotov5.SchemaBlock) tftypes.Type {
	if block == nil {
		return tftypes.Object{AttributeTypes: map[string]tftypes.Type{}}
	}

	attrTypes := make(map[string]tftypes.Type, len(block.Attributes)+len(block.BlockTypes))

	for _, attr := range block.Attributes {
		if attr == nil {
			continue
		}
		attrTypes[attr.Name] = attr.Type
	}

	for _, nb := range block.BlockTypes {
		if nb == nil {
			continue
		}
		innerType := SchemaBlockToType(nb.Block)

		switch nb.Nesting {
		case tfprotov5.SchemaNestedBlockNestingModeSingle,
			tfprotov5.SchemaNestedBlockNestingModeGroup:
			attrTypes[nb.TypeName] = innerType
		case tfprotov5.SchemaNestedBlockNestingModeList:
			attrTypes[nb.TypeName] = tftypes.List{ElementType: innerType}
		case tfprotov5.SchemaNestedBlockNestingModeSet:
			attrTypes[nb.TypeName] = tftypes.Set{ElementType: innerType}
		case tfprotov5.SchemaNestedBlockNestingModeMap:
			attrTypes[nb.TypeName] = tftypes.Map{ElementType: innerType}
		}
	}

	return tftypes.Object{AttributeTypes: attrTypes}
}

// ComplianceBlockSchema returns the SchemaNestedBlock definition for the
// `compliance {}` block that gets injected into the provider schema: the
// optional attributes of lifecycle.BlockType (block v2), sorted by name.
func ComplianceBlockSchema() *tfprotov5.SchemaNestedBlock {
	attrs := lifecycle.BlockType().AttributeTypes
	block := &tfprotov5.SchemaBlock{}
	for _, name := range slices.Sorted(maps.Keys(attrs)) {
		block.Attributes = append(block.Attributes, &tfprotov5.SchemaAttribute{Name: name, Type: attrs[name], Optional: true})
	}
	return &tfprotov5.SchemaNestedBlock{TypeName: "compliance", Nesting: tfprotov5.SchemaNestedBlockNestingModeSingle, Block: block}
}

// ComplianceBlockType returns the tftypes.Type for the compliance nested block.
func ComplianceBlockType() tftypes.Type {
	return lifecycle.BlockType()
}

// UnionProviderSchema returns a copy of the upstream schema with the compliance
// nested block appended. The original upstream schema is not mutated.
func UnionProviderSchema(upstream *tfprotov5.Schema) *tfprotov5.Schema {
	if upstream == nil || upstream.Block == nil {
		return &tfprotov5.Schema{
			Block: &tfprotov5.SchemaBlock{
				BlockTypes: []*tfprotov5.SchemaNestedBlock{ComplianceBlockSchema()},
			},
		}
	}

	// Copy attributes slice
	attrs := make([]*tfprotov5.SchemaAttribute, len(upstream.Block.Attributes))
	copy(attrs, upstream.Block.Attributes)

	// Copy existing block types and append compliance
	blocks := make([]*tfprotov5.SchemaNestedBlock, len(upstream.Block.BlockTypes), len(upstream.Block.BlockTypes)+1)
	copy(blocks, upstream.Block.BlockTypes)
	blocks = append(blocks, ComplianceBlockSchema())

	return &tfprotov5.Schema{
		Version: upstream.Version,
		Block: &tfprotov5.SchemaBlock{
			Version:         upstream.Block.Version,
			Attributes:      attrs,
			BlockTypes:      blocks,
			Description:     upstream.Block.Description,
			DescriptionKind: upstream.Block.DescriptionKind,
			Deprecated:      upstream.Block.Deprecated,
		},
	}
}

// CombinedProviderType returns the tftypes.Type for the combined (upstream + compliance) provider schema.
func CombinedProviderType(upstream *tfprotov5.Schema) tftypes.Type {
	return SchemaBlockToType(UnionProviderSchema(upstream).Block)
}

// UpstreamProviderType returns the tftypes.Type for the upstream-only provider schema.
func UpstreamProviderType(upstream *tfprotov5.Schema) tftypes.Type {
	if upstream == nil || upstream.Block == nil {
		return tftypes.Object{AttributeTypes: map[string]tftypes.Type{}}
	}
	return SchemaBlockToType(upstream.Block)
}
