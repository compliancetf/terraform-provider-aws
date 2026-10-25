package bundlegen

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/celeng"
)

// ReviewReason says why Translate refused an intent. Every reason emits no
// control: the id waits for an authored override (E_REVIEW_PENDING).
type ReviewReason string

const (
	// ReviewCondition: contains, not_equals and any condition outside the
	// translation table (port_range_*).
	ReviewCondition ReviewReason = "condition"
	// ReviewUnboundedBlock: the path steps through a list or set block
	// without max_items = 1; an intent [0] checks the first element only.
	ReviewUnboundedBlock ReviewReason = "unbounded_block"
	// ReviewBlockExists: exists on a block. The content uses it for prohibitions
	// too (ec2_instance_not_use_multiple_enis), so the polarity is unknown.
	ReviewBlockExists ReviewReason = "block_exists"
	// ReviewValuesRef: values resolved from a valid_values key may age.
	ReviewValuesRef ReviewReason = "values_ref"
	// ReviewStrategy: a strategy condition {} needs another resource
	// (disposition graph).
	ReviewStrategy ReviewReason = "strategy_condition"
	// ReviewPath: the path is not in the schema or has a shape the table
	// does not cover (an index other than [0], a step below an attribute,
	// a single, group or map block).
	ReviewPath ReviewReason = "path"
	// ReviewType: the condition does not fit the attribute type or the
	// values (no values, null, a fraction, a type mismatch).
	ReviewType ReviewReason = "type"
	// ReviewLoad: the generated control does not load warning-free through
	// celeng (compile, reads coverage, Computed-only rule).
	ReviewLoad ReviewReason = "load"
)

// ReviewItem is a typed refusal. Detail names paths, conditions and diag
// codes only, never values. Proposal and Alternative are CEL for the owner,
// empty when the translator has none; they are never emitted as controls.
type ReviewItem struct {
	ID           string       `json:"id"`
	ResourceType string       `json:"resource_type"`
	Reason       ReviewReason `json:"reason"`
	Detail       string       `json:"detail"`
	Proposal     string       `json:"proposal,omitempty"`
	Alternative  string       `json:"alternative,omitempty"`
}

// Translate turns a content intent into a resource control per the
// translation table, or refuses it. When err
// is nil exactly one of the control and the review item is set; an intent
// that cannot be translated safely is always a ReviewItem, never a
// permissive expression. err is for malformed input (E_INTENT). Message,
// severity and refs are filled by Generate; Version is a placeholder the
// content lock replaces.
func Translate(it Intent, s *tfprotov5.Schema) (bundle.Control, *ReviewItem, error) {
	if it.ID == "" || it.ResourceType == "" || len(it.Attributes) == 0 {
		return bundle.Control{}, nil, errf("E_INTENT", "intent %q: id, resource_type and attributes are required", it.ID)
	}
	if s == nil || s.Block == nil {
		return bundle.Control{}, nil, errf("E_INTENT", "%s: no schema for %s", it.ID, it.ResourceType)
	}
	review := func(r ReviewReason, format string, a ...any) *ReviewItem {
		return &ReviewItem{ID: it.ID, ResourceType: it.ResourceType, Reason: r, Detail: fmt.Sprintf(format, a...)}
	}
	if hasNil(s.Block) {
		return bundle.Control{}, review(ReviewType, "schema has a nil attribute or block"), nil
	}
	if it.HasStrategyCondition {
		return bundle.Control{}, review(ReviewStrategy, "strategy condition"), nil
	}

	root := &node{}
	var reads []string
	var refusal *ReviewItem
	mode := bundle.PresenceEffective
	for _, a := range it.Attributes {
		segs, err := parsePath(a.SchemaPath)
		if err != nil {
			return bundle.Control{}, nil, errf("E_INTENT", "%s: %v", it.ID, err)
		}
		m, r := translateAttr(root, s.Block, segs, a, &reads)
		if r != nil && refusal == nil {
			refusal = review(r.Reason, "%s %s: %s", a.SchemaPath, safeName(a.Condition), r.Detail)
		}
		if m == bundle.PresenceConfigured {
			mode = m // strictest member wins
		}
	}
	if root.hasUnbounded && refusal == nil {
		// never reached through translateAttr; a guard so an unbounded
		// step can never become an auto control
		refusal = review(ReviewUnboundedBlock, "unbounded block on the path")
	}
	rootVar := "resource"
	if mode == bundle.PresenceConfigured {
		rootVar = "config"
	}
	expr := root.render(rootVar, false, 0)
	if refusal != nil {
		if !root.unrenderable {
			refusal.Proposal = expr
			if root.hasUnbounded {
				refusal.Alternative = root.render(rootVar, true, 0)
			} else if root.alternative {
				refusal.Alternative = root.renderAlt(rootVar)
			}
		}
		return bundle.Control{}, refusal, nil
	}

	slices.Sort(reads)
	c := bundle.Control{
		ID: it.ID, Version: "1.0.0", Kind: bundle.KindResource, ResourceType: it.ResourceType,
		Reads: slices.Compact(reads), PresenceMode: mode, On: []bundle.On{bundle.OnCreate, bundle.OnUpdate},
		Expr: &expr, Action: bundle.ActionDeny, Fix: it.Explanation, ExemptionCoverable: []bundle.ExemptionKind{},
	}
	resp := &tfprotov5.GetProviderSchemaResponse{ResourceSchemas: map[string]*tfprotov5.Schema{it.ResourceType: s}}
	_, diags, err := celeng.Load([]bundle.Control{c}, resp)
	var d *celeng.LoadDiag
	switch {
	case errors.As(err, &d):
		r := review(ReviewLoad, "%s", d.Code)
		r.Proposal = expr
		return bundle.Control{}, r, nil
	case err != nil:
		return bundle.Control{}, nil, errf("E_INTENT", "%s: %v", it.ID, err)
	case len(diags) > 0:
		r := review(ReviewLoad, "%s", diags[0].Code)
		r.Proposal = expr
		return bundle.Control{}, r, nil
	}
	return c, nil, nil
}

// node is one level of the rendered expression: the root object or a
// list/set block every member under it shares, so several attributes of one
// block are checked on the same element. Terms keep intent order.
type node struct {
	terms []term
	// set on the root only
	unrenderable, hasUnbounded, alternative bool
}

type term struct {
	pred      func(acc string) string // leaf predicate on <acc>
	altPred   func(acc string) string // block exists: the prohibition reading
	block     string                  // child block name when child is set
	child     *node
	unbounded bool
}

func (n *node) child(name string, unbounded bool) *node {
	for _, t := range n.terms {
		if t.child != nil && t.block == name {
			return t.child
		}
	}
	c := &node{}
	n.terms = append(n.terms, term{block: name, child: c, unbounded: unbounded})
	return c
}

// render joins the terms with &&. A bounded block is exists() (an empty
// block fails); an unbounded one, proposals only, is a guarded all() or,
// with exists, exists(). acc is the CEL path of this node's value.
func (n *node) render(acc string, existsUnbounded bool, depth int) string {
	var parts []string
	for _, t := range n.terms {
		if t.child == nil {
			parts = append(parts, t.pred(acc))
			continue
		}
		v := "e" + strconv.Itoa(depth)
		b := acc + "." + t.block
		inner := t.child.render(v, existsUnbounded, depth+1)
		if t.unbounded && !existsUnbounded {
			parts = append(parts, fmt.Sprintf("size(%s) > 0 && %s.all(%s, %s)", b, b, v, inner))
		} else {
			parts = append(parts, fmt.Sprintf("%s.exists(%s, %s)", b, v, inner))
		}
	}
	return strings.Join(parts, " && ")
}

// renderAlt renders the root terms with the alternative predicate of a
// block exists (one level only: alternatives come from root-level terms).
func (n *node) renderAlt(acc string) string {
	parts := make([]string, len(n.terms))
	for i, t := range n.terms {
		switch {
		case t.altPred != nil:
			parts[i] = t.altPred(acc)
		case t.child == nil:
			parts[i] = t.pred(acc)
		default:
			parts[i] = (&node{terms: []term{t}}).render(acc, false, 0)
		}
	}
	return strings.Join(parts, " && ")
}

type pathSeg struct {
	name    string
	indexed bool
	index   int
}

var segRe = regexp.MustCompile(`^([a-z0-9_]+)(?:\[([0-9]+)\])?$`)

func parsePath(p string) ([]pathSeg, error) {
	var segs []pathSeg
	for i, s := range strings.Split(p, ".") {
		m := segRe.FindStringSubmatch(s)
		if m == nil {
			return nil, fmt.Errorf("schema_path segment %d is malformed", i)
		}
		seg := pathSeg{name: m[1], indexed: m[2] != ""}
		if seg.indexed {
			n, err := strconv.Atoi(m[2])
			if err != nil {
				return nil, fmt.Errorf("schema_path segment %d: index out of range", i)
			}
			seg.index = n
		}
		segs = append(segs, seg)
	}
	return segs, nil
}

// translateAttr resolves one intent attribute against the schema, adds its
// term below the shared block nodes of root and its reads, and returns its
// presence mode and a refusal, if any. A refusal still adds a proposal term
// when it has one; otherwise it marks root unrenderable.
func translateAttr(root *node, b *tfprotov5.SchemaBlock, segs []pathSeg, a IntentAttribute, reads *[]string) (bundle.PresenceMode, *ReviewItem) {
	refuse := func(r ReviewReason, format string, x ...any) (bundle.PresenceMode, *ReviewItem) {
		root.unrenderable = true
		return "", &ReviewItem{Reason: r, Detail: fmt.Sprintf(format, x...)}
	}
	n := root
	var refusal *ReviewItem
	var path []string
	for i, seg := range segs {
		path = append(path, seg.name)
		last := i == len(segs)-1
		if seg.indexed && seg.index != 0 {
			return refuse(ReviewPath, "index [%d] on %s", seg.index, seg.name)
		}
		at, nb := attrNamed(b, seg.name), blockNamed(b, seg.name)
		if at != nil && nb != nil {
			return refuse(ReviewPath, "%s is both an attribute and a block", strings.Join(path, "."))
		}
		if at != nil {
			if !last || seg.indexed {
				return refuse(ReviewPath, "%s is an attribute, not a block", strings.Join(path, "."))
			}
			*reads = append(*reads, strings.Join(path, "."))
			m, pred, r := attrPred(at, a)
			if r != nil && pred == nil {
				return refuse(r.Reason, "%s", r.Detail)
			}
			n.terms = append(n.terms, term{pred: pred})
			return m, firstRefusal(refusal, r)
		}
		if nb == nil {
			return refuse(ReviewPath, "%s is not in the schema", strings.Join(path, "."))
		}
		if nb.Block == nil {
			return refuse(ReviewType, "%s has no block schema", strings.Join(path, "."))
		}
		if nb.Nesting != tfprotov5.SchemaNestedBlockNestingModeList && nb.Nesting != tfprotov5.SchemaNestedBlockNestingModeSet {
			return refuse(ReviewPath, "%s is a %s block", strings.Join(path, "."), nb.Nesting)
		}
		*reads = append(*reads, strings.Join(path, "."))
		if last {
			if seg.indexed {
				return refuse(ReviewPath, "index on the checked block %s", seg.name)
			}
			m, r := blockTerm(root, n, seg.name, a)
			return m, firstRefusal(refusal, r)
		}
		unbounded := nb.MaxItems != 1
		if unbounded {
			root.hasUnbounded = true
			refusal = firstRefusal(refusal, &ReviewItem{Reason: ReviewUnboundedBlock, Detail: strings.Join(path, ".") + " has no max_items = 1"})
		}
		n = n.child(seg.name, unbounded)
		b = nb.Block
	}
	return refuse(ReviewPath, "empty path") // unreachable: parsePath yields one segment at least
}

// firstRefusal keeps the first refusal.
func firstRefusal(a, b *ReviewItem) *ReviewItem {
	if a != nil {
		return a
	}
	return b
}

// blockTerm handles not_empty and exists on a block: size(b) >= 1, mode
// configured. exists goes to review with the prohibition as alternative.
func blockTerm(root, n *node, name string, a IntentAttribute) (bundle.PresenceMode, *ReviewItem) {
	size := func(acc string) string { return "size(" + acc + "." + name + ") >= 1" }
	var ref *ReviewItem
	if a.ValuesFromRef != nil {
		ref = &ReviewItem{Reason: ReviewValuesRef, Detail: "values from " + safeName(*a.ValuesFromRef)}
	}
	switch a.Condition {
	case "not_empty":
		n.terms = append(n.terms, term{pred: size})
		return bundle.PresenceConfigured, ref
	case "exists":
		if n == root {
			root.alternative = true
		}
		n.terms = append(n.terms, term{pred: size, altPred: func(acc string) string { return "size(" + acc + "." + name + ") == 0" }})
		return bundle.PresenceConfigured, firstRefusal(ref, &ReviewItem{Reason: ReviewBlockExists, Detail: "exists on a block: presence or prohibition"})
	}
	root.unrenderable = true
	return "", &ReviewItem{Reason: ReviewType, Detail: "condition on a block"}
}

// attrPred returns the presence mode and predicate of one attribute, and a
// refusal. A refusal with a predicate is a proposal (contains, not_equals,
// values_ref); without one nothing renders.
func attrPred(at *tfprotov5.SchemaAttribute, a IntentAttribute) (bundle.PresenceMode, func(string) string, *ReviewItem) {
	refuse := func(r ReviewReason, format string, x ...any) (bundle.PresenceMode, func(string) string, *ReviewItem) {
		return "", nil, &ReviewItem{Reason: r, Detail: fmt.Sprintf(format, x...)}
	}
	if at.Type == nil {
		return refuse(ReviewType, "attribute without a type")
	}
	sel := func(acc string) string { return acc + "." + at.Name }
	optMode := bundle.PresenceEffective
	if at.Optional {
		optMode = bundle.PresenceConfigured // Optional, incl. Optional+Computed
	}
	var ref *ReviewItem
	if a.ValuesFromRef != nil {
		ref = &ReviewItem{Reason: ReviewValuesRef, Detail: "values from " + safeName(*a.ValuesFromRef)}
	}
	switch a.Condition {
	case "equals_any", "contains", "not_equals":
		lits, r := literals(at.Type, a.Values, a.Condition == "contains")
		if r != nil {
			return refuse(r.Reason, "%s", r.Detail)
		}
		var pred func(string) string
		switch a.Condition {
		case "equals_any":
			if len(lits) == 1 {
				pred = func(acc string) string { return sel(acc) + " == " + lits[0] }
			} else {
				pred = func(acc string) string { return sel(acc) + " in [" + strings.Join(lits, ", ") + "]" }
			}
			return bundle.PresenceEffective, pred, ref
		case "contains":
			pred = func(acc string) string {
				p := sel(acc) + " != null"
				for _, l := range lits {
					p += " && " + sel(acc) + ".contains(" + l + ")"
				}
				return p
			}
		default:
			pred = func(acc string) string {
				return sel(acc) + " != null && !(" + sel(acc) + " in [" + strings.Join(lits, ", ") + "])"
			}
		}
		return bundle.PresenceEffective, pred, firstRefusal(ref, &ReviewItem{Reason: ReviewCondition, Detail: a.Condition + " needs review"})
	case "not_empty":
		if !at.Type.Is(tftypes.String) && !isCollection(at.Type) {
			return refuse(ReviewType, "not_empty on a %s attribute", at.Type)
		}
		return optMode, func(acc string) string { return sel(acc) + " != null && size(" + sel(acc) + ") > 0" }, ref
	case "exists":
		return optMode, func(acc string) string { return sel(acc) + " != null" }, ref
	}
	return refuse(ReviewCondition, "condition %s is not in the translation table", safeName(a.Condition))
}

func isCollection(t tftypes.Type) bool {
	return t.Is(tftypes.List{}) || t.Is(tftypes.Set{}) || t.Is(tftypes.Map{})
}

// literals renders values as CEL literals of attribute type t: strings for
// a string attribute, bools for a bool, integers for a number. Anything else
// (no values, null, a fraction, a mismatch, a collection or dynamic
// attribute) is a refusal. strOnly also requires a string attribute.
func literals(t tftypes.Type, vals []json.RawMessage, strOnly bool) ([]string, *ReviewItem) {
	bad := func(format string, x ...any) ([]string, *ReviewItem) {
		return nil, &ReviewItem{Reason: ReviewType, Detail: fmt.Sprintf(format, x...)}
	}
	if len(vals) == 0 {
		return bad("no values")
	}
	if strOnly && !t.Is(tftypes.String) {
		return bad("contains on a %s attribute", t)
	}
	var out []string
	for i, raw := range vals {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var v any
		if err := dec.Decode(&v); err != nil {
			return bad("value %d is not JSON", i)
		}
		switch x := v.(type) {
		case string:
			if !t.Is(tftypes.String) {
				return bad("value %d: string for a %s attribute", i, t)
			}
			var buf bytes.Buffer
			enc := json.NewEncoder(&buf)
			enc.SetEscapeHTML(false)
			if err := enc.Encode(x); err != nil {
				return bad("value %d: %v", i, err)
			}
			out = append(out, strings.TrimSuffix(buf.String(), "\n")) // JSON escapes are CEL escapes
		case bool:
			if !t.Is(tftypes.Bool) {
				return bad("value %d: bool for a %s attribute", i, t)
			}
			out = append(out, strconv.FormatBool(x))
		case json.Number:
			n, err := strconv.ParseInt(x.String(), 10, 64)
			if err != nil || !t.Is(tftypes.Number) {
				return bad("value %d: integer for a number attribute only", i)
			}
			out = append(out, strconv.FormatInt(n, 10))
		default:
			return bad("value %d: unsupported value kind", i)
		}
	}
	return out, nil
}

var safeNameRe = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

// safeName keeps Detail value-free: input text that is not name-shaped is
// replaced.
func safeName(s string) string {
	if safeNameRe.MatchString(s) {
		return s
	}
	return "<non-name>"
}

// hasNil reports a nil attribute, nested block or block body anywhere in b;
// the schema walk and celeng would dereference it.
func hasNil(b *tfprotov5.SchemaBlock) bool {
	if b == nil || slices.Contains(b.Attributes, nil) {
		return true
	}
	for _, nb := range b.BlockTypes {
		if nb == nil || hasNil(nb.Block) {
			return true
		}
	}
	return false
}

func attrNamed(b *tfprotov5.SchemaBlock, name string) *tfprotov5.SchemaAttribute {
	for _, a := range b.Attributes {
		if a.Name == name {
			return a
		}
	}
	return nil
}

func blockNamed(b *tfprotov5.SchemaBlock, name string) *tfprotov5.SchemaNestedBlock {
	for _, nb := range b.BlockTypes {
		if nb.TypeName == name {
			return nb
		}
	}
	return nil
}
