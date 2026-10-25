package bundlegen

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"unicode"
)

// toolSlugs maps catalog export keys to the tool slugs the bundle loader accepts
// (the catalog tools config export_key -> slug). tools.yaml is catalog source config,
// not part of the export, so the table lives here; a key outside it fails
// generation (E_TOOL_KEY) instead of dropping refs.
var toolSlugs = map[string]string{
	"AWS_CONFIG":    "aws_config",
	"CKV":           "checkov",
	"CONTROL_TOWER": "control_tower",
	"KICS":          "kics",
	"POWERPIPE":     "powerpipe",
	"PROWLER":       "prowler",
	"SECURITY_HUB":  "security_hub",
	"TRIVY":         "trivy",
}

// UnmarshalJSON reads metadata and keeps every other key as a tool export
// key with its list of tool ids.
func (c *CatalogControl) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	c.Tools = map[string][]string{}
	for k, v := range raw {
		if k == "metadata" {
			if err := json.Unmarshal(v, &c.Metadata); err != nil {
				return err
			}
			continue
		}
		var ids []string
		if err := json.Unmarshal(v, &ids); err != nil {
			return fmt.Errorf("tool export key %q: %w", k, err)
		}
		c.Tools[k] = ids
	}
	return nil
}

// FrameworkRefs returns sorted, unique `<framework_id>:<clause_ref>` refs from
// the control's clause titles. clause_ref is the title's first token (up to
// the first ':' or whitespace) when that token has a digit, so it reads as a
// clause id ("3.2", "CC6.1"); any other title is kept whole and trimmed
// ("Data protection"). Supporting clause titles are not read, and a framework
// with no clause title gets no ref.
func FrameworkRefs(c CatalogControl) []string {
	var refs []string
	for fw, titles := range c.Metadata.ClauseTitles {
		for _, t := range titles {
			if ref := clauseRef(t); ref != "" {
				refs = append(refs, fw+":"+ref)
			}
		}
	}
	slices.Sort(refs)
	return slices.Compact(refs)
}

func clauseRef(title string) string {
	title = strings.TrimSpace(title)
	tok, _, _ := strings.Cut(title, ":")
	if i := strings.IndexFunc(tok, unicode.IsSpace); i >= 0 {
		tok = tok[:i]
	}
	if strings.ContainsAny(tok, "0123456789") {
		return tok
	}
	return title
}

// ToolRefs maps the control's tool export keys to slugs with sorted, unique
// ids; empty lists are omitted and a control with none returns nil.
func ToolRefs(c CatalogControl) (map[string][]string, error) {
	var refs map[string][]string
	for _, k := range slices.Sorted(maps.Keys(c.Tools)) {
		slug, ok := toolSlugs[k]
		if !ok {
			return nil, errf("E_TOOL_KEY", "unknown catalog tool export key %q", k)
		}
		ids := slices.Sorted(slices.Values(c.Tools[k]))
		if slices.Contains(ids, "") {
			return nil, errf("E_TOOL_KEY", "%s has an empty tool id", k)
		}
		if len(ids) == 0 {
			continue
		}
		if refs == nil {
			refs = map[string][]string{}
		}
		refs[slug] = slices.Compact(ids)
	}
	return refs, nil
}

// cloneToolRefs deep-copies tool refs so controls of one id share no slice.
func cloneToolRefs(m map[string][]string) map[string][]string {
	if m == nil {
		return nil
	}
	out := make(map[string][]string, len(m))
	for k, v := range m {
		out[k] = slices.Clone(v)
	}
	return out
}
