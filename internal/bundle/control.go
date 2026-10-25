// Package bundle holds the bundle 2.0 control format (this file), the archive
// reader, the manifest and ControlSet.
//
// Control rules follow the normative Control 2.0 schema for every kind.
// A control carries a CEL `expr` (a graph control carries `graph`
// instead); the
// legacy v0.1 `predicate` is rejected (control_predicate). Rules that
// need the CEL compiler or provider schemas (expr compiles, reads analysis,
// variables by mode, Computed-only reads) belong to celeng.Load.
// schema/bundle-control-2.schema.json mirrors DecodeControls for generators
// and ctfkit; this decoder stays the authority for rules JSON Schema cannot express.
package bundle

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
)

type (
	Kind          string
	PresenceMode  string
	On            string
	Action        string
	Severity      string
	ExemptionKind string
)

const (
	KindResource      Kind = "resource"
	KindDataSource    Kind = "data_source"
	KindEphemeral     Kind = "ephemeral"
	KindDeletionGuard Kind = "deletion_guard"
	// KindGraph is decided by ctfkit gate from the whole plan; the
	// provider loads it but never evaluates it.
	KindGraph Kind = "graph"

	PresenceEffective  PresenceMode = "effective"
	PresenceConfigured PresenceMode = "configured"

	OnCreate On = "create"
	OnUpdate On = "update"
	OnDelete On = "delete"

	// Action is a control's action (parent 6.1); warn controls never error.
	ActionDeny Action = "deny"
	ActionWarn Action = "warn"

	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"

	CoverBaseline    ExemptionKind = "baseline"
	CoverBreakGlass  ExemptionKind = "break_glass"
	CoverGrant       ExemptionKind = "grant"
	CoverSelfService ExemptionKind = "self_service"

	GraphCompanionPresent         GraphRule = "companion_present"
	GraphCompanionAbsentForbidden GraphRule = "companion_absent_forbidden"
)

type GraphRule string

// Graph is the linkage rule of a graph control: resource_type is the
// target, companion_type the companion whose link_attr must equal one of
// the target's target_attrs (an ordered identity list).
type Graph struct {
	Rule          GraphRule `json:"rule"`
	CompanionType string    `json:"companion_type"`
	LinkAttr      string    `json:"link_attr"`
	TargetAttrs   []string  `json:"target_attrs"`
	CompanionExpr *string   `json:"companion_expr,omitempty"` // CEL over the companion; absent for none
}

// Control is one bundle 2.0 control.
type Control struct {
	ID                 string              `json:"id"`
	Version            string              `json:"version"`
	Kind               Kind                `json:"kind"`
	ResourceType       string              `json:"resource_type"`
	Reads              []string            `json:"reads,omitempty"`         // nil only for graph
	PresenceMode       PresenceMode        `json:"presence_mode,omitempty"` // empty for deletion_guard, ephemeral and graph
	On                 []On                `json:"on,omitempty"`            // nil for data_source, ephemeral and graph
	Expr               *string             `json:"expr,omitempty"`          // CEL; required, except graph which must not set it
	Graph              *Graph              `json:"graph,omitempty"`         // graph only
	Action             Action              `json:"action"`
	Severity           Severity            `json:"severity"`
	Message            string              `json:"message"`
	Fix                string              `json:"fix,omitempty"`
	FrameworkRefs      []string            `json:"framework_refs,omitempty"`
	ToolRefs           map[string][]string `json:"tool_refs,omitempty"`
	ExemptionCoverable []ExemptionKind     `json:"exemption_coverable"` // never nil after ParseControls
}

// Error is a control load error with a stable code.
type Error struct {
	Index int    // control index in controls.json; -1 for document errors
	ID    string // control id as written, may be invalid
	Code  string
	Msg   string
}

func (e *Error) Error() string {
	where := "controls"
	switch {
	case e.Index >= 0 && idRe.MatchString(e.ID):
		where = "control " + e.ID
	case e.Index >= 0:
		where = fmt.Sprintf("control[%d]", e.Index)
	}
	return fmt.Sprintf("%s: %s (%s)", where, e.Msg, e.Code)
}

var (
	idRe        = regexp.MustCompile(`^[a-z0-9][a-z0-9_]{2,127}$`)
	versionRe   = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	typeRe      = regexp.MustCompile(`^[a-z0-9_]+$`)
	readRe      = regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_]+)*$`)
	frameworkRe = regexp.MustCompile(`^[A-Za-z0-9_.\-]+:.+$`)

	toolSlugs = []string{"aws_config", "checkov", "control_tower", "kics", "powerpipe", "prowler", "security_hub", "trivy"}
)

// ParseControls is the provider load path. data_source and ephemeral
// controls load like any kind, so it is
// DecodeControls; the per-kind schema rules are celeng.Load's and the
// cross-bundle ones NewControlSet's.
func ParseControls(data []byte) ([]Control, error) {
	return DecodeControls(data)
}

// DecodeControls strictly decodes controls.json for every kind: a non-empty
// JSON array of controls whose key (id, kind, resource_type) is unique.
// Unknown fields are errors. The generator validates with it.
func DecodeControls(data []byte) ([]Control, error) {
	var raws []json.RawMessage
	if err := json.Unmarshal(data, &raws); err != nil {
		return nil, &Error{Index: -1, Code: "controls_decode", Msg: err.Error()}
	}
	if len(raws) == 0 {
		return nil, &Error{Index: -1, Code: "controls_empty", Msg: "no controls"}
	}
	out := make([]Control, len(raws))
	seen := map[[3]string]bool{}
	for i, raw := range raws {
		var head struct{ ID string }
		if err := json.Unmarshal(raw, &head); err != nil {
			head.ID = "" // only names the control in errors; the strict decode reports the problem
		}
		fail := func(code, format string, a ...any) error {
			return &Error{Index: i, ID: head.ID, Code: code, Msg: fmt.Sprintf(format, a...)}
		}
		// encoding/json matches keys case-insensitively and keeps the last
		// duplicate, and maps null to "absent"; the schema allows none of that.
		scan := json.NewDecoder(bytes.NewReader(raw))
		scan.UseNumber() // keep numbers such as 1e309 that overflow float64
		top, msg := scanStrict(scan)
		if msg != "" {
			return nil, fail("control_decode", "%s", msg)
		}
		if top["predicate"] {
			return nil, fail("control_predicate", "predicate is the legacy v0.1 form; write the check as a CEL expr")
		}
		c := &out[i]
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(c); err != nil {
			var te *json.UnmarshalTypeError
			if errors.As(err, &te) && te.Field == "exemption_coverable" {
				return nil, fail("control_coverable", "exemption_coverable must be a list of exemption kinds")
			}
			return nil, fail("control_decode", "%s", err.Error())
		}
		if code, msg := c.validate(top); code != "" {
			return nil, fail(code, "%s", msg)
		}
		key := [3]string{c.ID, string(c.Kind), c.ResourceType}
		if seen[key] {
			return nil, fail("control_duplicate", "duplicate control key (%s, %s, %s)", key[0], key[1], key[2])
		}
		seen[key] = true
	}
	return out, nil
}

// validate returns the first rule the control breaks as (code, message).
// top holds the keys present in the control object.
func (c *Control) validate(top map[string]bool) (string, string) {
	switch {
	case !idRe.MatchString(c.ID):
		return "control_id", fmt.Sprintf("id %q does not match %s", c.ID, idRe)
	case !versionRe.MatchString(c.Version):
		return "control_version", fmt.Sprintf("version %q: want MAJOR.MINOR.PATCH", c.Version)
	case !slices.Contains([]Kind{KindResource, KindDataSource, KindEphemeral, KindDeletionGuard, KindGraph}, c.Kind):
		return "control_kind", fmt.Sprintf("kind %q: want resource, data_source, ephemeral, deletion_guard or graph", c.Kind)
	case !typeRe.MatchString(c.ResourceType):
		return "control_resource_type", fmt.Sprintf("resource_type %q does not match %s", c.ResourceType, typeRe)
	case c.Kind == KindGraph:
		if code, msg := c.validateGraph(top); code != "" {
			return code, msg
		}
		return c.validateText()
	case top["graph"]:
		return "control_graph", fmt.Sprintf("%s must not set graph", c.Kind)
	case c.Expr == nil:
		return "control_expr", "expr is required"
	case *c.Expr == "" || len(*c.Expr) > 4096:
		return "control_expr", "expr must be 1-4096 bytes"
	}
	if len(c.Reads) == 0 {
		return "control_reads", "reads must not be empty"
	}
	for _, r := range c.Reads {
		if !readRe.MatchString(r) {
			return "control_reads", fmt.Sprintf("read %q does not match %s", r, readRe)
		}
	}
	if !strictlySorted(c.Reads) {
		return "control_reads", "reads must be sorted and unique"
	}
	if code, msg := c.validateTriggers(top); code != "" {
		return code, msg
	}
	return c.validateText()
}

// validateGraph enforces the graph control shape: graph set, and none of
// the expr control fields (expr, reads, presence_mode, on).
func (c *Control) validateGraph(top map[string]bool) (string, string) {
	for _, f := range []string{"expr", "reads", "presence_mode", "on"} {
		if top[f] {
			return "control_graph", "graph control must not set " + f
		}
	}
	g := c.Graph
	if g == nil {
		return "control_graph", "graph is required"
	}
	switch {
	case g.Rule != GraphCompanionPresent && g.Rule != GraphCompanionAbsentForbidden:
		return "control_graph", fmt.Sprintf("graph.rule %q: want companion_present or companion_absent_forbidden", g.Rule)
	case !typeRe.MatchString(g.CompanionType):
		return "control_graph", fmt.Sprintf("graph.companion_type %q does not match %s", g.CompanionType, typeRe)
	case !readRe.MatchString(g.LinkAttr):
		return "control_graph", fmt.Sprintf("graph.link_attr %q does not match %s", g.LinkAttr, readRe)
	case len(g.TargetAttrs) == 0:
		return "control_graph", "graph.target_attrs must not be empty"
	case g.CompanionExpr != nil && (*g.CompanionExpr == "" || len(*g.CompanionExpr) > 4096):
		return "control_graph", "graph.companion_expr must be 1-4096 bytes"
	}
	for i, a := range g.TargetAttrs {
		if !readRe.MatchString(a) {
			return "control_graph", fmt.Sprintf("graph.target_attrs %q does not match %s", a, readRe)
		}
		if slices.Contains(g.TargetAttrs[:i], a) {
			return "control_graph", "graph.target_attrs must be unique"
		}
	}
	return "", ""
}

// validateTriggers enforces presence_mode and on per kind. top catches an
// explicit "" or [] that decodes like an absent field.
func (c *Control) validateTriggers(top map[string]bool) (string, string) {
	hasPresence := c.Kind == KindResource || c.Kind == KindDataSource
	switch {
	case !hasPresence && top["presence_mode"]:
		return "control_presence", fmt.Sprintf("%s must not set presence_mode", c.Kind)
	case hasPresence && c.PresenceMode != PresenceEffective && c.PresenceMode != PresenceConfigured:
		return "control_presence", fmt.Sprintf("presence_mode %q: want effective or configured", c.PresenceMode)
	}
	switch c.Kind {
	case KindDeletionGuard:
		if !slices.Equal(c.On, []On{OnDelete}) {
			return "control_on", `deletion guard must set on = ["delete"]`
		}
	case KindResource:
		ok := len(c.On) > 0
		for i, o := range c.On {
			ok = ok && (o == OnCreate || o == OnUpdate) && !slices.Contains(c.On[:i], o)
		}
		if !ok {
			return "control_on", "on must be a non-empty subset of create, update"
		}
	default:
		if top["on"] {
			return "control_on", fmt.Sprintf("%s must not set on", c.Kind)
		}
	}
	return "", ""
}

func (c *Control) validateText() (string, string) {
	switch c.Action {
	case ActionDeny, ActionWarn:
	default:
		return "control_action", fmt.Sprintf("action %q: want deny or warn", c.Action)
	}
	switch c.Severity {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
	default:
		return "control_severity", fmt.Sprintf("severity %q: want critical, high, medium, low or info", c.Severity)
	}
	if c.Message == "" || len(c.Message) > 256 || strings.ContainsAny(c.Message, "\r\n") {
		return "control_message", "message must be 1-256 bytes without a newline"
	}
	if len(c.Fix) > 512 {
		return "control_fix", "fix must be at most 512 bytes"
	}
	for _, f := range c.FrameworkRefs {
		if !frameworkRe.MatchString(f) {
			return "control_framework_refs", fmt.Sprintf("framework_ref %q does not match %s", f, frameworkRe)
		}
	}
	for _, k := range slices.Sorted(maps.Keys(c.ToolRefs)) {
		if !slices.Contains(toolSlugs, k) {
			return "control_tool_refs", fmt.Sprintf("tool_refs key %q is not a known tool", k)
		}
		if slices.Contains(c.ToolRefs[k], "") {
			return "control_tool_refs", fmt.Sprintf("tool_refs %q has an empty ref", k)
		}
	}
	for _, k := range c.ExemptionCoverable {
		switch k {
		case CoverBaseline, CoverBreakGlass, CoverGrant, CoverSelfService:
		default:
			return "control_coverable", fmt.Sprintf("exemption kind %q: want grant, baseline, break_glass or self_service", k)
		}
	}
	if !strictlySorted(c.ExemptionCoverable) {
		return "control_coverable", "exemption_coverable must be sorted and unique"
	}
	if c.ExemptionCoverable == nil {
		c.ExemptionCoverable = []ExemptionKind{}
	}
	return "", ""
}

// scanStrict walks one JSON value and rejects null, duplicate object keys and
// keys outside [a-z0-9_]+ at any depth. It returns the keys of a top-level object.
func scanStrict(dec *json.Decoder) (map[string]bool, string) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err.Error()
	}
	switch tok {
	case nil:
		return nil, "null is not allowed"
	case json.Delim('['):
		for dec.More() {
			if _, msg := scanStrict(dec); msg != "" {
				return nil, msg
			}
		}
	case json.Delim('{'):
		keys := map[string]bool{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return nil, err.Error()
			}
			k, ok := kt.(string)
			switch {
			case !ok || !typeRe.MatchString(k):
				return nil, fmt.Sprintf("key %q must match %s", k, typeRe)
			case keys[k]:
				return nil, fmt.Sprintf("duplicate key %q", k)
			}
			keys[k] = true
			if _, msg := scanStrict(dec); msg != "" {
				return nil, fmt.Sprintf("%s: %s", k, msg)
			}
		}
		if _, err := dec.Token(); err != nil {
			return nil, err.Error()
		}
		return keys, ""
	default:
		return nil, ""
	}
	if _, err := dec.Token(); err != nil { // closing ']'
		return nil, err.Error()
	}
	return nil, ""
}

func strictlySorted[T ~string](s []T) bool {
	for i := 1; i < len(s); i++ {
		if s[i-1] >= s[i] {
			return false
		}
	}
	return true
}
