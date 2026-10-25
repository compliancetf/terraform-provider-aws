package bundlegen

import (
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
)

// Schemas holds the pruned `terraform providers schema -json` of the
// upstream provider converted to tfprotov5 schemas, the response
// celeng.Load receives at runtime. It implements hook.SchemaSource.
type Schemas struct {
	resp *tfprotov5.GetProviderSchemaResponse
}

// ProviderSchema is the converted schema response for celeng.Load.
func (s Schemas) ProviderSchema() *tfprotov5.GetProviderSchemaResponse {
	if s.resp == nil {
		return &tfprotov5.GetProviderSchemaResponse{}
	}
	return s.resp
}

func (s Schemas) Resource(typ string) (*tfprotov5.Schema, bool) {
	x, ok := s.ProviderSchema().ResourceSchemas[typ]
	return x, ok
}

func (s Schemas) DataSource(typ string) (*tfprotov5.Schema, bool) {
	x, ok := s.ProviderSchema().DataSourceSchemas[typ]
	return x, ok
}

func (s Schemas) EphemeralResource(typ string) (*tfprotov5.Schema, bool) {
	x, ok := s.ProviderSchema().EphemeralResourceSchemas[typ]
	return x, ok
}

// Lookup is the schema of type typ for control kind k.
func (s Schemas) Lookup(k bundle.Kind, typ string) (*tfprotov5.Schema, bool) {
	if get := s.kind(k); get != nil {
		return get(typ)
	}
	return nil, false
}

func (s Schemas) kind(k bundle.Kind) func(string) (*tfprotov5.Schema, bool) {
	switch k {
	case bundle.KindResource, bundle.KindDeletionGuard:
		return s.Resource
	case bundle.KindDataSource:
		return s.DataSource
	case bundle.KindEphemeral:
		return s.EphemeralResource
	}
	return nil
}

// SchemaCompatDigest is the P0B schema_compat_digest of cs: sha256 of
// SchemaCompatLines joined by "\n".
func SchemaCompatDigest(cs []bundle.Control, s Schemas) (string, error) {
	lines, err := SchemaCompatLines(cs, s)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// SchemaCompatLines are the sorted, unique lines "<type>\t<read>\t<cty type
// JSON>" of cs, where the cty type is that of the value at the read path
// (list and set steps implicit, a map step is a key, a step into a dynamic
// value stays dynamic, as in celeng). A read the schema lacks fails with
// E_SCHEMA_TYPE.
func SchemaCompatLines(cs []bundle.Control, s Schemas) ([]string, error) {
	seen := map[string]bool{}
	for _, c := range cs {
		get := s.kind(c.Kind)
		if get == nil {
			return nil, errf("E_SCHEMA_TYPE", "%s: unknown kind %q", c.ID, c.Kind)
		}
		sc, ok := get(c.ResourceType)
		if !ok {
			return nil, errf("E_SCHEMA_TYPE", "%s: %s type %s is not in the upstream schema", c.ID, c.Kind, c.ResourceType)
		}
		for _, r := range c.Reads {
			t := typeAt(sc.ValueType(), r)
			if t == nil {
				return nil, errf("E_SCHEMA_TYPE", "%s: read %s.%s is not in the upstream schema", c.ID, c.ResourceType, r)
			}
			tj, err := t.MarshalJSON() //nolint:staticcheck // the P0B digest hashes the schema -json type signature
			if err != nil {
				return nil, errf("E_SCHEMA_TYPE", "%s: read %s.%s: %v", c.ID, c.ResourceType, r, err)
			}
			seen[c.ResourceType+"\t"+r+"\t"+string(tj)] = true
		}
	}
	return slices.Sorted(maps.Keys(seen)), nil
}

// typeAt is the type of the value at a name-only read path in t, nil when
// the path is not in the schema.
func typeAt(t tftypes.Type, path string) tftypes.Type {
	for _, seg := range strings.Split(path, ".") {
		for {
			if l, ok := t.(tftypes.List); ok {
				t = l.ElementType
			} else if st, ok := t.(tftypes.Set); ok {
				t = st.ElementType
			} else {
				break
			}
		}
		switch c := t.(type) {
		case tftypes.Map:
			t = c.ElementType
		case tftypes.Object:
			t = c.AttributeTypes[seg]
		default:
			if t != nil && t.Is(tftypes.DynamicPseudoType) {
				return t // as celeng: the rest of the path is inside a dynamic value
			}
			return nil
		}
		if t == nil {
			return nil
		}
	}
	return t
}
