package bundlegen

import (
	"bytes"
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
)

// Review reasons Generate adds to the translator's (translate.go).
const (
	// ReviewNoIntent: content intents but the intents export has no policy
	// for the id (deprecated, or the export is out of date).
	ReviewNoIntent ReviewReason = "no_intent"
	// ReviewTarget: the intent's resource type is not a resource target of
	// the disposition.
	ReviewTarget ReviewReason = "target"
	// ReviewPartialTargets: a disposition target the one-type intent does
	// not cover, or an authored file that leaves a target out; the id is
	// not generated until every target has a control.
	ReviewPartialTargets ReviewReason = "partial_targets"
	// ReviewDiffcheck: the generated control disagrees with the content
	// postcondition on a case (E_DIFFCHECK_MISMATCH) and no allow entry
	// accepts it; the id is not generated.
	ReviewDiffcheck ReviewReason = "diffcheck"
)

// intentsByID indexes the intents export; a duplicate id is E_INTENT.
func intentsByID(ps []Intent) (map[string]Intent, error) {
	m := map[string]Intent{}
	for _, it := range ps {
		if _, dup := m[it.ID]; dup {
			return nil, errf("E_INTENT", "duplicate intent %s", safeName(it.ID))
		}
		m[it.ID] = it
	}
	return m, nil
}

// translateID translates the intent of a content intents id without an
// authored override. A review item emits nothing for the id until an
// authored override exists (E_REVIEW_PENDING, review-queue.md).
func translateID(id string, d Disposition, it Intent, ok bool, s Schemas) (bundle.Control, *ReviewItem, error) {
	if !ok {
		return bundle.Control{}, &ReviewItem{ID: id, Reason: ReviewNoIntent, Detail: "no intent for a disposition with content intents"}, nil
	}
	if !slices.Contains(d.Targets, Target{Kind: string(bundle.KindResource), Type: it.ResourceType}) {
		return bundle.Control{}, &ReviewItem{ID: id, ResourceType: safeName(it.ResourceType), Reason: ReviewTarget,
			Detail: "intent resource type is not a resource target of the disposition"}, nil
	}
	schema, _ := s.Resource(it.ResourceType) // a disposition target, so in the schema (validate)
	return Translate(it, schema)
}

// partialTargets queues every disposition target the controls cs (one
// id, translated or authored) do not cover, as partial_targets
// (E_REVIEW_PENDING); by names the source in the detail. Coverage counts
// the id as generated only when every target has a control (generatedIDs).
func partialTargets(id string, cs []bundle.Control, d Disposition, by string) []ReviewItem {
	var out []ReviewItem
	for _, t := range d.Targets {
		if !slices.ContainsFunc(cs, func(c bundle.Control) bool { return string(c.Kind) == t.Kind && c.ResourceType == t.Type }) {
			out = append(out, ReviewItem{ID: id, ResourceType: t.Type, Reason: ReviewPartialTargets,
				Detail: fmt.Sprintf("%s target not covered by %s", t.Kind, by)})
		}
	}
	slices.SortFunc(out, func(a, b ReviewItem) int {
		return cmp.Or(cmp.Compare(a.ResourceType, b.ResourceType), cmp.Compare(a.Detail, b.Detail))
	})
	return out
}

// PendingLine is the E_REVIEW_PENDING report line of a queue item.
func (r ReviewItem) PendingLine() string {
	return fmt.Sprintf("E_REVIEW_PENDING %s %s: %s: %s", r.ID, cmp.Or(r.ResourceType, "-"), r.Reason, r.Detail)
}

// ReviewQueue renders review-queue.md: the intents ids waiting for an authored
// override, numbered in id order.
func ReviewQueue(items []ReviewItem) []byte {
	var w bytes.Buffer
	fmt.Fprintf(&w, "# Review queue\n\n%d content intents emit no control until an authored override exists in provider/controls/<id>.yaml.\n", len(items))
	for i, r := range items {
		fmt.Fprintf(&w, "\n## %d. `%s`\n\n- `%s`\n", i+1, r.ID, r.PendingLine())
		for _, p := range [][2]string{{"Proposal", r.Proposal}, {"Alternative", r.Alternative}} {
			if p[1] != "" {
				fmt.Fprintf(&w, "\n%s:\n\n```cel\n%s\n```\n", p[0], p[1])
			}
		}
	}
	return w.Bytes()
}

// ReviewSheet renders review-sheet.md: one line per translated (auto)
// control, for the owner's skim of what each intent became.
func ReviewSheet(autos []bundle.Control) ([]byte, error) {
	var w bytes.Buffer
	fmt.Fprintf(&w, "# Review sheet\n\n%d controls translated from content intents.\n\n| Id | Type | catalog name | Expr |\n|---|---|---|---|\n", len(autos))
	cell := func(s string) string { return strings.NewReplacer("|", `\|`, "\n", " ").Replace(s) }
	for _, c := range autos {
		if c.Expr == nil {
			return nil, errf("E_EMIT", "review sheet: control %s %s has no expr", c.ID, c.ResourceType)
		}
		fmt.Fprintf(&w, "| `%s` | `%s` | %s | `%s` |\n", c.ID, c.ResourceType, cell(c.Message), cell(*c.Expr))
	}
	return w.Bytes(), nil
}
