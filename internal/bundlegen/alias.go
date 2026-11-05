package bundlegen

import (
	"maps"
	"reflect"
	"slices"
	"strings"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
)

// typeAliases maps each hashicorp/aws type that is another name for a
// canonical type to that type: aws_alb* are the older names of aws_lb*,
// with the same schema. Content targets the canonical names only, so
// mirrorAliases adds every control on a canonical type to its alias too.
var typeAliases = map[string]string{
	"aws_alb":                         "aws_lb",
	"aws_alb_listener":                "aws_lb_listener",
	"aws_alb_listener_certificate":    "aws_lb_listener_certificate",
	"aws_alb_listener_rule":           "aws_lb_listener_rule",
	"aws_alb_target_group":            "aws_lb_target_group",
	"aws_alb_target_group_attachment": "aws_lb_target_group_attachment",
}

// aliasCovered reports whether target t is an alias type that mirrorAliases
// fills from a control of cs on its canonical type.
func aliasCovered(cs []bundle.Control, t Target) bool {
	canon, ok := typeAliases[t.Type]
	return ok && t.Kind != string(bundle.KindGraph) &&
		slices.ContainsFunc(cs, func(c bundle.Control) bool { return string(c.Kind) == t.Kind && c.ResourceType == canon })
}

// mirrorAliases returns cs plus, for each control on a canonical type of
// typeAliases, the same control on the alias type, and adds its cases to
// cases (the canonical cases with the type renamed), so verify and
// diffcheck replay the mirror like any control. The mirror keeps the
// canonical version: the lock holds canonical keys only. It is skipped
// when cs already has that id and kind on the alias (an explicit target
// stays as written), when s has no alias type of that kind, and for graph
// controls (ctfkit gate decides them; their dispositions name both types).
// An alias whose schema differs from the canonical one fails
// E_ALIAS_SCHEMA: the copy would judge another resource shape.
func mirrorAliases(cs []bundle.Control, cases map[ControlKey][]Case, s Schemas) ([]bundle.Control, error) {
	have := map[ControlKey]bool{}
	for i := range cs {
		have[keyOf(&cs[i])] = true
	}
	out := slices.Clone(cs)
	for _, c := range cs {
		if c.Kind == bundle.KindGraph {
			continue
		}
		for _, alias := range slices.Sorted(maps.Keys(typeAliases)) {
			if typeAliases[alias] != c.ResourceType {
				continue
			}
			m := c
			m.ResourceType = alias
			as, ok := s.Lookup(c.Kind, alias)
			if !ok || have[keyOf(&m)] {
				continue
			}
			if cc, _ := s.Lookup(c.Kind, c.ResourceType); !reflect.DeepEqual(cc, as) {
				return nil, errf("E_ALIAS_SCHEMA", "%s: %s type %s is an alias of %s but its schema differs", c.ID, c.Kind, alias, c.ResourceType)
			}
			prefix := caseID(c, "")
			var mc []Case
			for _, k := range cases[keyOf(&c)] {
				k.ID = caseID(m, strings.TrimPrefix(k.ID, prefix))
				k.ResourceType, k.Control = alias, m
				mc = append(mc, k)
			}
			cases[keyOf(&m)] = mc
			out = append(out, m)
		}
	}
	return out, nil
}
