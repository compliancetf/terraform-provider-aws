package lifecycle

import (
	"slices"
	"strings"
)

// Field is one optional detail line of a control diagnostic.
type Field uint8

// The fields in the order they print.
const (
	FieldFix Field = 1 << iota
	FieldDocs
	FieldWaive
	FieldSeverity
	FieldMode
	FieldStage
	FieldFrameworks
)

// fieldNames are the COMPLIANCETF_DIAGNOSTICS field names, in print order.
var fieldNames = []string{"fix", "docs", "waive", "severity", "mode", "stage", "frameworks"}

// presets are the COMPLIANCETF_DIAGNOSTICS preset names.
var presets = map[string]Field{
	"minimal": FieldFix,
	"default": FieldFix | FieldDocs | FieldWaive,
	"full":    FieldFix | FieldDocs | FieldWaive | FieldSeverity | FieldMode | FieldStage | FieldFrameworks,
}

// docsBase is the control documentation URL prefix; the control id follows.
const docsBase = "https://compliance.tf/docs/controls/aws/"

// parseFields reads COMPLIANCETF_DIAGNOSTICS: empty is default, one preset
// name is that preset, anything else is a comma list of field names.
// Unknown tokens, and presets inside a list, are dropped and named in the
// warning; with nothing valid left it is default. It never fails: the
// setting only changes what diagnostics show.
func parseFields(v string) (Field, string) {
	var toks []string
	for t := range strings.SplitSeq(strings.ToLower(v), ",") {
		if t = strings.TrimSpace(t); t != "" && !slices.Contains(toks, t) {
			toks = append(toks, t)
		}
	}
	if len(toks) == 0 {
		return presets["default"], ""
	}
	if p, ok := presets[toks[0]]; ok && len(toks) == 1 {
		return p, ""
	}
	var f Field
	var bad []string
	for _, t := range toks {
		if i := slices.Index(fieldNames, t); i >= 0 {
			f |= 1 << i
		} else {
			bad = append(bad, t)
		}
	}
	if f == 0 {
		f = presets["default"]
	}
	if bad == nil {
		return f, ""
	}
	return f, "COMPLIANCETF_DIAGNOSTICS: ignored " + strings.Join(bad, ", ") +
		"; use minimal, default, full or a comma list of " + strings.Join(fieldNames, ", ")
}
