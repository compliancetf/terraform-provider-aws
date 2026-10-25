package verdict

// The apply situation table:
// what one ApplyResourceChange's own half decides from its matched entries.

import (
	"fmt"
	"slices"
	"strings"
)

// Severities of a situation row: none, warning or error (blocks).
const (
	SevNone    = "none"
	SevWarning = "warning"
	SevError   = "error"
)

// Situation results (evidence result column).
const (
	SitPass         = "pass"
	SitFail         = "fail"
	SitNotEvaluable = "not_evaluable"
	SitPending      = "pending"
	SitExcepted     = "excepted" // provisional with its final proof
	SitUnproven     = "exemption_unproven"
	SitMissing      = "missing_decision"
	SitNoMatch      = "no_match"
	SitCollision    = "collision"
	SitNoVerdict    = "no_verdict"
)

// Spec texts of the gate rows.
const (
	TextNoVerdict    = "This change needs a verdict (profile sets verdict_required). Apply through ctfkit apply or the configured runner."
	TextNotEnforced  = "graph controls not enforced for this run"
	textNoMatchReq   = "No verdict entry matches this %s instance; the profile requires a verdict for every change. Re-run plan and ctfkit gate."
	textNoMatchGraph = "No verdict entry matches this %s instance; graph controls %s cannot be decided. Re-run plan and ctfkit gate."
	textCollision    = "Verdict entries %s share this instance key; graph controls %s cannot be decided. Waive with an exception or make the instances distinguishable."
)

// Graph is one loaded graph control the RPC's half checks, re-derived from
// the verified bundles. FailSeverity is the mode table's fail row for it at
// apply_pre (error when it blocks).
type Graph struct {
	ID, Version, Message string
	FailSeverity         string
}

// Apply is one ApplyResourceChange's situation input.
type Apply struct {
	Verdict  *Verdict // nil: verdict none
	Required bool     // profile verdict_required
	Type     string
	Delete   bool        // destroy RPC: delete_decisions; else decisions
	Matches  []*Instance // Verdict.Match of the RPC's own half
	Graph    []Graph
	// Excepted reports whether an exception applies to the control on this
	// change (under verdict_required only one the verdict lists for every
	// match). It is a provisional decision's final proof, and it waives a
	// no_match or collision row of that control (an exception selector sees
	// the type and the planned value); it never waives a gate row.
	Excepted func(control string) bool
	// BreakGlass reports the override_id of an honored break-glass receipt
	// covering the control's decision result on every match; nil
	// honors none. A covered fail or not_evaluable row blocks no more (its
	// warning stays), a covered provisional one is proven; pending never.
	BreakGlass func(control, result string) (id string, ok bool)
}

// Row is one situation outcome; Control is "" for a gate row.
type Row struct {
	Control, Version string
	Result, Severity string
	Text             string
	Address          string // the matched entry, "" without one
	BreakGlassID     string // override_id of the receipt that downgraded it
}

// Situation evaluates a. Every row other than pass and pending takes the
// fail row of its control (never better than fail).
func Situation(a Apply) []Row {
	ids := make([]string, len(a.Graph))
	for i, g := range a.Graph {
		ids[i] = g.ID
	}
	idList := strings.Join(ids, ", ")
	perControl := func(result, text, address string) []Row {
		rows := make([]Row, len(a.Graph))
		for i, g := range a.Graph {
			rows[i] = Row{Control: g.ID, Version: g.Version, Result: result, Severity: g.FailSeverity, Text: text, Address: address}
			if a.excepted(g.ID) {
				rows[i].Result, rows[i].Severity, rows[i].Text = SitExcepted, SevNone, ""
			}
		}
		return rows
	}
	switch {
	case a.Verdict == nil && a.Required:
		return []Row{{Result: SitNoVerdict, Severity: SevError, Text: TextNoVerdict}}
	case a.Verdict == nil && len(a.Graph) > 0:
		return []Row{{Result: SitNoVerdict, Severity: SevWarning, Text: TextNotEnforced}}
	case a.Verdict == nil:
		return nil
	case len(a.Matches) == 0 && a.Required:
		return []Row{{Result: SitNoMatch, Severity: SevError, Text: fmt.Sprintf(textNoMatchReq, a.Type)}}
	case len(a.Matches) == 0:
		return perControl(SitNoMatch, fmt.Sprintf(textNoMatchGraph, a.Type, idList), "")
	}
	first := a.Matches[0]
	for _, m := range a.Matches[1:] {
		if !sameHalf(first, m, a.Delete) {
			addrs := make([]string, len(a.Matches))
			for i, x := range a.Matches {
				addrs[i] = x.Address
			}
			text := fmt.Sprintf(textCollision, strings.Join(addrs, ", "), idList)
			if len(a.Graph) == 0 && a.Required {
				return []Row{{Result: SitCollision, Severity: SevError, Text: text}}
			}
			return perControl(SitCollision, text, "")
		}
	}
	rows := make([]Row, 0, len(a.Graph))
	for _, g := range a.Graph {
		rows = append(rows, decide(a, first, g))
	}
	return rows
}

func decide(a Apply, in *Instance, g Graph) Row {
	r := Row{Control: g.ID, Version: g.Version, Severity: g.FailSeverity, Address: in.Address}
	i := slices.IndexFunc(half(in, a.Delete), func(d Decision) bool { return d.Control == g.ID && d.Version == g.Version })
	if i < 0 {
		r.Result = SitMissing
		r.Text = fmt.Sprintf("Verdict entry for %s has no decision for %s@%s; re-run plan and ctfkit gate.", in.Address, g.ID, g.Version)
		return r
	}
	switch half(in, a.Delete)[i].Result {
	case ResultPass:
		r.Result, r.Severity = SitPass, SevNone
	case ResultPending:
		r.Result = SitPending
		if r.Severity == SevError {
			r.Severity = SevWarning
		}
		r.Text = fmt.Sprintf("%s: link for %s verified after apply by ctfkit apply", g.ID, in.Address)
	case ResultProvisional:
		if a.excepted(g.ID) {
			r.Result, r.Severity = SitExcepted, SevNone
			return r
		}
		if id, ok := a.breakGlass(g.ID, ResultProvisional); ok {
			r.Result, r.Severity, r.BreakGlassID = SitExcepted, SevNone, id
			return r
		}
		// A provisional decision exists only for a blocking control: without
		// its proof it blocks whatever the mode maps.
		r.Result, r.Severity = SitUnproven, SevError
		r.Text = UnprovenText(g.ID, in.Address)
	case ResultFail:
		r.Result = SitFail
		r.Text = fmt.Sprintf("%s: %s (graph control, decided by ctfkit gate for %s)", g.ID, g.Message, in.Address)
		r.overridden(a)
	default: // not_evaluable, and any other state, takes the fail row
		reason := "reason not recorded"
		if j := slices.IndexFunc(in.NotEvaluable, func(n NotEvaluable) bool { return n.Control == g.ID }); j >= 0 {
			reason = in.NotEvaluable[j].Reason
		}
		r.Result = SitNotEvaluable
		r.Text = fmt.Sprintf("%s: not decidable at plan (%s) for %s; blocking control fails closed", g.ID, reason, in.Address)
		if half(in, a.Delete)[i].Result == ResultNotEvaluable { // any other state is never overridden
			r.overridden(a)
		}
	}
	return r
}

// overridden downgrades a fail or not_evaluable row from block to warning
// when an honored break-glass receipt covers it.
func (r *Row) overridden(a Apply) {
	result := ResultFail
	if r.Result == SitNotEvaluable {
		result = ResultNotEvaluable
	}
	id, ok := a.breakGlass(r.Control, result)
	if !ok {
		return
	}
	r.BreakGlassID = id
	if r.Severity == SevError {
		r.Severity = SevWarning
	}
	r.Text += "; overridden by approved break-glass " + id
}

// UnprovenText is the block of a provisional decision without final proof.
func UnprovenText(control, address string) string {
	return fmt.Sprintf("%s: provisional exemption for %s has no final proof; re-run ctfkit gate with the grant, baseline or approved break-glass", control, address)
}

func (a Apply) excepted(id string) bool { return a.Excepted != nil && a.Excepted(id) }

func (a Apply) breakGlass(control, result string) (string, bool) {
	if a.BreakGlass == nil {
		return "", false
	}
	return a.BreakGlass(control, result)
}

func half(in *Instance, del bool) []Decision {
	if del {
		return in.DeleteDecisions
	}
	return in.Decisions
}

// sameHalf reports whether two matched entries decide this half alike:
// equal decision sets (every member) and equal not_evaluable sets. Their
// exemption lists may differ: only the digests every match lists count
// (Listed).
func sameHalf(a, b *Instance, del bool) bool {
	return sameSet(half(a, del), half(b, del)) && sameSet(a.NotEvaluable, b.NotEvaluable)
}

func sameSet[T comparable](a, b []T) bool {
	in := func(x, y []T) bool {
		return !slices.ContainsFunc(x, func(e T) bool { return !slices.Contains(y, e) })
	}
	return in(a, b) && in(b, a)
}

// Listed is the set of exception digests every match lists (the
// intersection, so no match borrows another's exemption).
func Listed(matches []*Instance) map[string]bool {
	if len(matches) == 0 {
		return map[string]bool{}
	}
	out := map[string]bool{}
	for _, d := range matches[0].Exceptions {
		if !slices.ContainsFunc(matches[1:], func(m *Instance) bool { return !slices.Contains(m.Exceptions, d) }) {
			out[d] = true
		}
	}
	return out
}

// ExceptionRef is the top-level exceptions[] member with digest d.
func (v *Verdict) ExceptionRef(d string) (ExceptionRef, bool) {
	i := slices.IndexFunc(v.Doc.Exceptions, func(e ExceptionRef) bool { return e.Digest == d })
	if i < 0 {
		return ExceptionRef{}, false
	}
	return v.Doc.Exceptions[i], true
}
