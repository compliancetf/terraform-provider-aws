package iampolicy

import (
	"slices"
	"strings"
	"time"
)

const (
	// MaxExpandedActions bounds actions_expanded + not_actions_expanded
	// summed over one document; past it Normalize returns limit.
	MaxExpandedActions = 10_000
	// decodeCost is the admission estimate per document byte, the same rate
	// as json.path. matchCost is the estimate per catalog action a pattern
	// is matched against. shortcut: fixed rates, calibrate with the p99
	// benchmark.
	decodeCost = 20 * time.Nanosecond
	matchCost  = 20 * time.Nanosecond
)

// admitDecode is the pre-decode admission check: the decode estimate from
// the document size against the remaining budget.
func admitDecode(doc string, budget time.Duration) error {
	if budget > 0 && time.Duration(len(doc)+1)*decodeCost > budget {
		return limit(rAdmission)
	}
	return nil
}

// expand fills the catalog fields of p.
// Before any matching it charges every non-* pattern scanCost on top of the
// decode estimate; over budget is limit.
// "*" is a flag and never expanded. A pattern matching no catalog
// action is unresolved (unknown service, unknown action, empty wildcard).
func expand(p *Policy, c *Catalog, docLen int, budget time.Duration) error {
	cost := time.Duration(docLen+1) * decodeCost
	for _, st := range p.Statements {
		for _, pat := range slices.Concat(st.Actions, st.NotActions) {
			cost += scanCost(c, pat)
		}
	}
	if budget > 0 && cost > budget {
		return limit(rAdmission)
	}
	left := MaxExpandedActions
	for i := range p.Statements {
		st := &p.Statements[i]
		var unres, unresNot []string
		var err error
		// Under action_all, actions_expanded stays empty and uncounted;
		// the other patterns are only checked for unresolved.
		bound := &left
		if st.ActionAll {
			bound = nil
		}
		if st.ActionsExpanded, unres, err = expandList(c, st.Actions, bound); err != nil {
			return err
		}
		if st.NotActionsExpanded, unresNot, err = expandList(c, st.NotActions, &left); err != nil {
			return err
		}
		st.UnresolvedActions = dedupeSort(append(unres, unresNot...))
		st.catalog = c.digest
	}
	p.Catalog = c.digest
	return nil
}

// expandList matches patterns against the catalog; *left is the remaining
// expansion bound, charged with this list's deduped size. A nil left only
// finds the unresolved patterns: each stops at its first match and nothing
// is collected.
func expandList(c *Catalog, patterns []string, left *int) (expanded, unresolved []string, err error) {
	set := map[string]bool{}
	unresolved = []string{}
	for _, pat := range patterns {
		if pat == "*" {
			continue
		}
		matched := false
		scan(c, pat, func(a string) bool {
			if !glob(pat, a) {
				return true
			}
			matched = true
			if left == nil {
				return false
			}
			if !set[a] {
				if set[a] = true; len(set) > *left {
					err = limit(rExpanded)
					return false
				}
			}
			return true
		})
		if err != nil {
			return nil, nil, err
		}
		if !matched {
			unresolved = append(unresolved, pat)
		}
	}
	if left != nil {
		*left -= len(set)
	}
	expanded = make([]string, 0, len(set))
	for a := range set {
		expanded = append(expanded, a)
	}
	return dedupeSort(expanded), unresolved, nil
}

// scan calls fn with every "service:name" pat can match until fn returns
// false: its own service's actions when the service part has no wildcard
// (the literal colon then anchors it), every action otherwise. "*" scans
// nothing.
func scan(c *Catalog, pat string, fn func(string) bool) {
	svc, _, _ := strings.Cut(pat, ":")
	switch {
	case pat == "*":
	case !strings.ContainsAny(svc, "*?"):
		for _, name := range c.services[svc] {
			if !fn(svc + ":" + name) {
				return
			}
		}
	default:
		for s, names := range c.services {
			for _, name := range names {
				if !fn(s + ":" + name) {
					return
				}
			}
		}
	}
}

// scanCost is the admission estimate of matching pat: every action scan
// visits, each at matchCost scaled by pattern length (glob keeps only the
// last star, so a restart costs at most the trailing segment against one
// catalog name). shortcut: fixed rates, calibrate with the bench gate.
func scanCost(c *Catalog, pat string) time.Duration {
	svc, _, _ := strings.Cut(pat, ":")
	n := c.total
	switch {
	case pat == "*":
		n = 0
	case !strings.ContainsAny(svc, "*?"):
		n = len(c.services[svc])
	}
	return time.Duration(n) * matchCost * time.Duration(1+len(pat)/8)
}

// Grants is iam.grants(stmt, a): with Action, action_all or any pattern
// globs a; with NotAction, no pattern globs a. The statement must come from
// Normalize with this catalog; a statement with unresolved patterns, a
// different or absent catalog, or an action outside the catalog is
// ErrUnresolved (not_evaluable / unresolved), never a non-match.
func Grants(st Statement, c *Catalog, action string) (bool, error) {
	if err := usable(st, c); err != nil {
		return false, err
	}
	a := asciiLower(action)
	if !c.has(a) {
		return false, unresolved(rCatalogMiss)
	}
	return grants(st, a), nil
}

// GrantsAll is iam.grants_all(stmt, svc): every catalog action of svc
// satisfies Grants. A service outside the catalog is ErrUnresolved.
func GrantsAll(st Statement, c *Catalog, svc string) (bool, error) {
	if err := usable(st, c); err != nil {
		return false, err
	}
	s := asciiLower(svc)
	names, ok := c.services[s]
	if !ok {
		return false, unresolved(rCatalogMiss)
	}
	for _, n := range names {
		if !grants(st, s+":"+n) {
			return false, nil
		}
	}
	return true, nil
}

func usable(st Statement, c *Catalog) error {
	switch {
	case c == nil || st.catalog != c.digest:
		return unresolved(rCatalogMismatch)
	case len(st.UnresolvedActions) > 0:
		return unresolved(rUnresolvedActions)
	}
	return nil
}

// grants answers from the expanded sets: a is a catalog action (callers
// check), usable() pinned the statement to this catalog with no unresolved
// pattern, so a pattern globs a exactly when a is in its expanded set. "*"
// is a flag and never expanded: Action * is action_all, NotAction * excludes
// everything.
func grants(st Statement, a string) bool {
	if len(st.NotActions) > 0 {
		_, out := slices.BinarySearch(st.NotActionsExpanded, a)
		return !out && !slices.Contains(st.NotActions, "*")
	}
	_, in := slices.BinarySearch(st.ActionsExpanded, a)
	return st.ActionAll || in
}

// glob matches s against p: * any run (including empty), ? one byte.
// Iterative with single-star backtracking, O(len(p)*len(s)) worst case.
func glob(p, s string) bool {
	px, sx, star, mark := 0, 0, -1, 0
	for sx < len(s) {
		switch {
		case px < len(p) && (p[px] == '?' || p[px] == s[sx]):
			px, sx = px+1, sx+1
		case px < len(p) && p[px] == '*':
			star, mark, px = px, sx, px+1
		case star >= 0:
			mark++
			px, sx = star+1, mark
		default:
			return false
		}
	}
	for px < len(p) && p[px] == '*' {
		px++
	}
	return px == len(p)
}
