package bundlegen

import (
	"cmp"
	"maps"
	"reflect"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
)

// typeAliases maps, per schema key (schemaKeys), each hashicorp/aws type
// that is another name for a canonical type to that type: aws_alb* are the
// older names of aws_lb*, with the same schema. Every hashicorp/aws 6.x
// release has them. Content targets the canonical names only, so
// mirrorAliases adds every control on a canonical type to its alias too.
var typeAliases = map[string]map[string]string{
	"resource_schemas": {
		"aws_alb":                         "aws_lb",
		"aws_alb_listener":                "aws_lb_listener",
		"aws_alb_listener_certificate":    "aws_lb_listener_certificate",
		"aws_alb_listener_rule":           "aws_lb_listener_rule",
		"aws_alb_target_group":            "aws_lb_target_group",
		"aws_alb_target_group_attachment": "aws_lb_target_group_attachment",
	},
	"data_source_schemas": {
		"aws_alb":              "aws_lb",
		"aws_alb_listener":     "aws_lb_listener",
		"aws_alb_target_group": "aws_lb_target_group",
	},
}

// aliasesOf are the alias types of type typ for control kind k, sorted;
// none for a graph control (schemaKeys has no graph kind).
func aliasesOf(k bundle.Kind, typ string) []string {
	var out []string
	for alias, canon := range typeAliases[schemaKeys[k]] {
		if canon == typ {
			out = append(out, alias)
		}
	}
	slices.Sort(out)
	return out
}

// aliasCovered reports whether target t is an alias type that mirrorAliases
// fills from a control of cs on its canonical type.
func aliasCovered(cs []bundle.Control, t Target) bool {
	return slices.ContainsFunc(cs, func(c bundle.Control) bool {
		return string(c.Kind) == t.Kind && slices.Contains(aliasesOf(c.Kind, c.ResourceType), t.Type)
	})
}

// mirrorAliases returns cs plus, for each control on a canonical type of
// typeAliases, the same control on the alias type, and adds its cases to
// cases (the canonical cases with the type renamed), so verify and
// diffcheck replay the mirror like any control. The mirror keeps the
// canonical version: the lock holds canonical keys only. It is skipped
// when cs already has that id and kind on the alias (an explicit target
// stays as written), and graph controls have no alias (ctfkit gate decides
// them; their dispositions name both types).
//
// An alias type s lacks fails E_ALIAS_MISSING: every supported upstream
// release has it, so its absence means a schema pruned without it, and
// skipping would drop the alias enforcement with normal-looking output.
// An alias whose schema differs from the canonical one fails
// E_ALIAS_SCHEMA, naming the first difference: the copy would judge
// another resource shape.
func mirrorAliases(cs []bundle.Control, cases map[ControlKey][]Case, s Schemas) ([]bundle.Control, error) {
	have := map[ControlKey]bool{}
	for i := range cs {
		have[keyOf(&cs[i])] = true
	}
	out := slices.Clone(cs)
	for _, c := range cs {
		for _, alias := range aliasesOf(c.Kind, c.ResourceType) {
			m := cloneControl(c)
			m.ResourceType = alias
			if have[keyOf(&m)] {
				continue
			}
			as, ok := s.Lookup(c.Kind, alias)
			if !ok {
				return nil, errf("E_ALIAS_MISSING", "%s: %s type %s has a control and the schema lacks its alias %s (prune the schema again)",
					c.ID, c.Kind, c.ResourceType, alias)
			}
			if cc, _ := s.Lookup(c.Kind, c.ResourceType); !reflect.DeepEqual(cc, as) {
				return nil, errf("E_ALIAS_SCHEMA", "%s: %s type %s is an alias of %s but its schema differs at %s",
					c.ID, c.Kind, alias, c.ResourceType, schemaDiff(cc, as))
			}
			prefix := caseID(c, "")
			var mc []Case
			for _, k := range cases[keyOf(&c)] {
				k.ID = caseID(m, strings.TrimPrefix(k.ID, prefix))
				k.ResourceType, k.Control = alias, m
				k.Bindings = cloneBindings(k.Bindings)
				k.Expect.UnknownPaths = slices.Clone(k.Expect.UnknownPaths)
				mc = append(mc, k)
			}
			cases[keyOf(&m)] = mc
			out = append(out, m)
		}
	}
	return out, nil
}

// cloneControl copies c with no slice, map or pointer shared with it.
func cloneControl(c bundle.Control) bundle.Control {
	m := c
	m.Reads, m.On, m.FrameworkRefs = slices.Clone(c.Reads), slices.Clone(c.On), slices.Clone(c.FrameworkRefs)
	m.ExemptionCoverable, m.ToolRefs = slices.Clone(c.ExemptionCoverable), cloneToolRefs(c.ToolRefs)
	if c.Expr != nil {
		e := *c.Expr
		m.Expr = &e
	}
	if c.Graph != nil {
		g := *c.Graph
		g.TargetAttrs = slices.Clone(g.TargetAttrs)
		if g.CompanionExpr != nil {
			e := *g.CompanionExpr
			g.CompanionExpr = &e
		}
		m.Graph = &g
	}
	return m
}

func cloneBindings(b CaseBindings) CaseBindings {
	b.Provider = maps.Clone(b.Provider)
	b.Env, b.Resource, b.Config, b.Prior = slices.Clone(b.Env), slices.Clone(b.Resource), slices.Clone(b.Config), slices.Clone(b.Prior)
	return b
}

// schemaDiff names the first difference of a and b: "version", or the
// attribute or nested block path (dot-separated) whose definition
// differs; "block <path>" for a block's own fields.
func schemaDiff(a, b *tfprotov5.Schema) string {
	if a == nil || b == nil {
		return "schema"
	}
	if a.Version != b.Version {
		return "version"
	}
	return blockDiff(a.Block, b.Block, "")
}

func blockDiff(a, b *tfprotov5.SchemaBlock, at string) string {
	if a == nil || b == nil {
		return "block " + cmp.Or(strings.TrimSuffix(at, "."), "(root)")
	}
	attrs := map[string][2]*tfprotov5.SchemaAttribute{}
	for i, blk := range []*tfprotov5.SchemaBlock{a, b} {
		for _, x := range blk.Attributes {
			if x != nil {
				e := attrs[x.Name]
				e[i] = x
				attrs[x.Name] = e
			}
		}
	}
	for _, n := range slices.Sorted(maps.Keys(attrs)) {
		if e := attrs[n]; !reflect.DeepEqual(e[0], e[1]) {
			return "attribute " + at + n
		}
	}
	blocks := map[string][2]*tfprotov5.SchemaNestedBlock{}
	for i, blk := range []*tfprotov5.SchemaBlock{a, b} {
		for _, x := range blk.BlockTypes {
			if x != nil {
				e := blocks[x.TypeName]
				e[i] = x
				blocks[x.TypeName] = e
			}
		}
	}
	for _, n := range slices.Sorted(maps.Keys(blocks)) {
		x, y := blocks[n][0], blocks[n][1]
		if x == nil || y == nil || x.Nesting != y.Nesting || x.MinItems != y.MinItems || x.MaxItems != y.MaxItems {
			return "block " + at + n
		}
		if d := blockDiff(x.Block, y.Block, at+n+"."); d != "" {
			return d
		}
	}
	if !reflect.DeepEqual(a, b) {
		return "block " + cmp.Or(strings.TrimSuffix(at, "."), "(root)")
	}
	return ""
}
