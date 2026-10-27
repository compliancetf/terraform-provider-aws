package bundlegen

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/celeng"
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

// SchemaCompatDigest is the manifest schema_compat_digest of cs: sha256 of
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
// JSON>" of every read of cs (ControlReads), where the cty type is that of
// the value at the read path (list and set steps implicit, a map step is a
// key, a step into a dynamic value stays dynamic, as in celeng). A read the
// schema lacks fails with E_SCHEMA_TYPE.
func SchemaCompatLines(cs []bundle.Control, s Schemas) ([]string, error) {
	seen := map[string]bool{}
	for i := range cs {
		c := &cs[i]
		reads, err := ControlReads(c, s)
		if err != nil {
			return nil, err
		}
		for _, r := range reads {
			sc, _ := s.Lookup(r.Kind, r.Type) // ControlReads found it
			t := typeAt(sc.ValueType(), r.Path)
			if t == nil {
				return nil, errf("E_SCHEMA_TYPE", "%s: read %s.%s is not in the upstream schema", c.ID, r.Type, r.Path)
			}
			tj, err := t.MarshalJSON() //nolint:staticcheck // the digest hashes the schema -json type signature
			if err != nil {
				return nil, errf("E_SCHEMA_TYPE", "%s: read %s.%s: %v", c.ID, r.Type, r.Path, err)
			}
			seen[r.Type+"\t"+r.Path+"\t"+string(tj)] = true
		}
	}
	return slices.Sorted(maps.Keys(seen)), nil
}

// SchemaRead is one attribute path a control's decision reads, on type Type
// of kind Kind.
type SchemaRead struct {
	Kind       bundle.Kind
	Type, Path string
}

// ControlReads are the reads of c that s must hold: c.Reads on its type, or
// GraphReads for a graph control. A type s lacks fails with E_SCHEMA_TYPE;
// the read paths are left to the caller.
func ControlReads(c *bundle.Control, s Schemas) ([]SchemaRead, error) {
	if c.Kind == bundle.KindGraph {
		return GraphReads(c, s)
	}
	if s.kind(c.Kind) == nil {
		return nil, errf("E_SCHEMA_TYPE", "%s: unknown kind %q", c.ID, c.Kind)
	}
	if _, ok := s.Lookup(c.Kind, c.ResourceType); !ok {
		return nil, errf("E_SCHEMA_TYPE", "%s: %s type %s is not in the upstream schema", c.ID, c.Kind, c.ResourceType)
	}
	out := make([]SchemaRead, len(c.Reads))
	for i, r := range c.Reads {
		out[i] = SchemaRead{c.Kind, c.ResourceType, r}
	}
	return out, nil
}

// GraphReads are the sorted, unique reads that decide graph control c, as
// ctfkit's graph analyzer reads them: each target_attrs entry on the target
// (resource_type) and link_attr on the companion (companion_type), for
// either rule; and every read of companion_expr on the companion, from the
// reads analysis resource controls get (celeng.CompanionReads against the
// companion schema in s). A target or companion type s lacks, a graph
// control without graph, or a companion_expr whose reads cannot be bounded
// fails with E_SCHEMA_TYPE.
func GraphReads(c *bundle.Control, s Schemas) ([]SchemaRead, error) {
	g := c.Graph
	if g == nil {
		return nil, errf("E_SCHEMA_TYPE", "%s: graph control without graph", c.ID)
	}
	var out []SchemaRead
	for _, side := range []struct {
		typ   string
		paths []string
	}{{c.ResourceType, g.TargetAttrs}, {g.CompanionType, []string{g.LinkAttr}}} {
		if _, ok := s.Resource(side.typ); !ok {
			return nil, errf("E_SCHEMA_TYPE", "%s: resource type %s is not in the upstream schema", c.ID, side.typ)
		}
		for _, p := range side.paths {
			out = append(out, SchemaRead{bundle.KindResource, side.typ, p})
		}
	}
	if g.CompanionExpr != nil {
		sc, _ := s.Resource(g.CompanionType)
		paths, err := celeng.CompanionReads(*g.CompanionExpr, sc)
		if err != nil {
			return nil, errf("E_SCHEMA_TYPE", "%s: companion_expr: %v", c.ID, err)
		}
		for _, p := range paths {
			out = append(out, SchemaRead{bundle.KindResource, g.CompanionType, p})
		}
	}
	slices.SortFunc(out, func(a, b SchemaRead) int {
		return cmp.Or(cmp.Compare(a.Type, b.Type), cmp.Compare(a.Path, b.Path))
	})
	return slices.Compact(out), nil
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
