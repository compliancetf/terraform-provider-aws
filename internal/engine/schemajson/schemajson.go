// Package schemajson converts `terraform providers schema -json` into the
// tfprotov5 schemas the engine binds values with. The bundle generator and
// the public pkg/engine facade share it, so both read a schema the same way.
package schemajson

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// schemaJSON is one type in `terraform providers schema -json`. Protocol 5
// has no nested attribute types, so an attribute without type is an error.
type schemaJSON struct {
	Version *int64     `json:"version"`
	Block   *blockJSON `json:"block"`
}

type blockJSON struct {
	Attributes map[string]struct {
		Type                                                json.RawMessage `json:"type"`
		Optional, Required, Computed, Sensitive, Deprecated bool
	} `json:"attributes"`
	BlockTypes map[string]struct {
		NestingMode string     `json:"nesting_mode"`
		MinItems    int64      `json:"min_items"`
		MaxItems    int64      `json:"max_items"`
		Block       *blockJSON `json:"block"`
	} `json:"block_types"`
	Deprecated bool `json:"deprecated"`
}

// Provider is one provider in the provider_schemas map of the output.
type Provider struct {
	Resources   map[string]schemaJSON `json:"resource_schemas"`
	DataSources map[string]schemaJSON `json:"data_source_schemas"`
	Ephemeral   map[string]schemaJSON `json:"ephemeral_resource_schemas"`
}

var nestingModes = map[string]tfprotov5.SchemaNestedBlockNestingMode{
	"single": tfprotov5.SchemaNestedBlockNestingModeSingle,
	"list":   tfprotov5.SchemaNestedBlockNestingModeList,
	"set":    tfprotov5.SchemaNestedBlockNestingModeSet,
	"map":    tfprotov5.SchemaNestedBlockNestingModeMap,
	"group":  tfprotov5.SchemaNestedBlockNestingModeGroup,
}

// Convert converts every resource, data source and ephemeral resource
// schema of p.
func Convert(p Provider) (*tfprotov5.GetProviderSchemaResponse, error) {
	resp := &tfprotov5.GetProviderSchemaResponse{}
	var err error
	for _, x := range []struct {
		in  map[string]schemaJSON
		out *map[string]*tfprotov5.Schema
	}{
		{p.Resources, &resp.ResourceSchemas},
		{p.DataSources, &resp.DataSourceSchemas},
		{p.Ephemeral, &resp.EphemeralResourceSchemas},
	} {
		if *x.out, err = convertSchemas(x.in); err != nil {
			return nil, err
		}
	}
	return resp, nil
}

func convertSchemas(in map[string]schemaJSON) (map[string]*tfprotov5.Schema, error) {
	out := make(map[string]*tfprotov5.Schema, len(in))
	for _, typ := range slices.Sorted(maps.Keys(in)) {
		sj := in[typ]
		if sj.Block == nil {
			return nil, fmt.Errorf("schema %s has no block", typ)
		}
		b, err := convertBlock(typ, sj.Block)
		if err != nil {
			return nil, err
		}
		s := &tfprotov5.Schema{Block: b}
		if sj.Version != nil {
			s.Version = *sj.Version
		}
		out[typ] = s
	}
	return out, nil
}

// convertBlock emits attributes and nested blocks sorted by name, so the
// result does not depend on map order.
func convertBlock(path string, bj *blockJSON) (*tfprotov5.SchemaBlock, error) {
	b := &tfprotov5.SchemaBlock{Deprecated: bj.Deprecated}
	for _, n := range slices.Sorted(maps.Keys(bj.Attributes)) {
		a := bj.Attributes[n]
		if len(a.Type) == 0 {
			return nil, fmt.Errorf("schema %s.%s has no type (nested attribute types are protocol 6)", path, n)
		}
		typ, err := tftypes.ParseJSONType(a.Type) //nolint:staticcheck // reads `terraform providers schema -json` type signatures
		if err != nil {
			return nil, fmt.Errorf("schema %s.%s: %v", path, n, err)
		}
		b.Attributes = append(b.Attributes, &tfprotov5.SchemaAttribute{
			Name: n, Type: typ, Optional: a.Optional, Required: a.Required, Computed: a.Computed, Sensitive: a.Sensitive,
			Deprecated: a.Deprecated,
		})
	}
	for _, n := range slices.Sorted(maps.Keys(bj.BlockTypes)) {
		nb := bj.BlockTypes[n]
		mode, ok := nestingModes[nb.NestingMode]
		if !ok || nb.Block == nil {
			return nil, fmt.Errorf("schema %s.%s: nesting_mode %q or block invalid", path, n, nb.NestingMode)
		}
		inner, err := convertBlock(path+"."+n, nb.Block)
		if err != nil {
			return nil, err
		}
		b.BlockTypes = append(b.BlockTypes, &tfprotov5.SchemaNestedBlock{
			TypeName: n, Nesting: mode, MinItems: nb.MinItems, MaxItems: nb.MaxItems, Block: inner,
		})
	}
	return b, nil
}

// Schema converts one type's schema object of `terraform providers schema
// -json` (the value under resource_schemas.<type>).
func Schema(raw []byte) (*tfprotov5.Schema, error) {
	var sj schemaJSON
	if err := json.Unmarshal(raw, &sj); err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}
	out, err := convertSchemas(map[string]schemaJSON{"schema": sj})
	if err != nil {
		return nil, err
	}
	return out["schema"], nil
}
