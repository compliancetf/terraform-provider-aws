package iampolicy

import (
	"cmp"
	"encoding/json"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Policy is a normalized IAM policy document. Field order is the golden
// JSON order (testdata/iam/cases), the contract shared with ctfkit.
type Policy struct {
	// Format pins the golden shape shared with ctfkit; a shape change bumps it.
	Format     string      `json:"format"`
	Version    string      `json:"version"`
	Statements []Statement `json:"statements"`
	// Catalog is the digest of the action catalog the statements were
	// expanded against; "" when Normalize ran without one.
	Catalog string `json:"catalog"`
}

// Statement is one normalized statement. Flags are effect-agnostic and
// computed after canonicalization:
//   - *_any over-approximates ("may apply to all"): prohibition controls.
//     A Not* element always sets it.
//   - *_all under-approximates ("certainly applies to all" on that
//     dimension): requirement controls. A Not* element never sets it.
//   - Unconditional is true only when the statement has no Condition
//     element. It under-approximates, for requirement controls: a
//     dimension certainly applies to all only with its *_all flag and
//     Unconditional; the whole statement only with all three *_all.
//
// Unconditional == false (and the ambiguous code "conditional") means only
// that a Condition element is present. The normalizer does not judge
// whether it narrows anything, and often it does not: unrelated keys
// (aws:SecureTransport), wildcard or ${...} values, match-all CIDRs,
// ...IfExists on an absent key, ForAllValues on an empty set, negated
// operators. A prohibition control never treats !Unconditional or any
// Ambiguous code as narrowing: it
// uses *_any regardless of conditions, or excuses a statement only through
// an explicit check on Conditions that proves narrowing for that control.
// Non-negated operator, no IfExists, no set prefix, no wildcard or variable
// value and a key that scopes the principal or resource are necessary for
// such a check, not sufficient. The polarity lint enforces it at bundle load.
//
// Ambiguous lists value-free diagnostic reason codes, never a control
// input; the fail-closed property comes from the flags.
type Statement struct {
	Sid           string              `json:"sid"`
	Effect        string              `json:"effect"`
	Actions       []string            `json:"actions"`
	NotActions    []string            `json:"not_actions"`
	Resources     []string            `json:"resources"`
	NotResources  []string            `json:"not_resources"`
	Principals    map[string][]string `json:"principals"`
	NotPrincipals map[string][]string `json:"not_principals"`
	Conditions    []Condition         `json:"conditions"`
	ActionAll     bool                `json:"action_all"`
	PrincipalAny  bool                `json:"principal_any"`
	ResourceAny   bool                `json:"resource_any"`
	ActionAny     bool                `json:"action_any"`
	PrincipalAll  bool                `json:"principal_all"`
	ResourceAll   bool                `json:"resource_all"`
	Unconditional bool                `json:"unconditional"`
	Ambiguous     []string            `json:"ambiguous"`
	// Catalog expansion (expand.go); empty without Options.Catalog.
	ActionsExpanded    []string `json:"actions_expanded"`
	NotActionsExpanded []string `json:"not_actions_expanded"`
	UnresolvedActions  []string `json:"unresolved_actions"`
	// Non-canonical identities (identity.go); never in Principals / Resources.
	UnresolvedPrincipals map[string][]string `json:"unresolved_principals"`
	UnresolvedResources  []string            `json:"unresolved_resources"`

	// catalog is the digest the expanded fields were computed against;
	// Grants refuses a statement whose digest is not its catalog's.
	catalog string
}

// Condition is one (operator, key) pair of a Condition block.
type Condition struct {
	Op       string   `json:"op"`
	SetOp    string   `json:"set_op"`
	IfExists bool     `json:"if_exists"`
	Key      string   `json:"key"`
	Values   []string `json:"values"`
}

// Options carries evaluation context the document cannot.
type Options struct {
	// Partition rewrites a bare 12-digit account id principal to
	// arn:<Partition>:iam::<id>:root. Empty keeps the id verbatim and marks
	// the statement account_id_bare (the id alone does not name its partition).
	Partition string
	// Catalog expands actions (expand.go); nil leaves the expanded fields
	// empty and Catalog "", and Grants then refuses the statements.
	Catalog *Catalog
	// Budget is the remaining per-resource budget the admission checks
	// estimate against: before decode (document size) and before expansion
	// (patterns times the catalog actions they scan); over it is limit.
	// 0 disables admission (tests and tools); the engine always passes the
	// live remainder. Fixed limits apply regardless.
	Budget time.Duration
}

// partitions is the closed list of AWS partition ids; a new partition fails
// closed (partition_invalid) until it is added here.
var partitions = []string{"", "aws", "aws-cn", "aws-us-gov", "aws-iso", "aws-iso-b", "aws-iso-e", "aws-iso-f", "aws-eusc"}

// statementKeys are the statement elements of the IAM JSON policy grammar
// (docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html);
// element names are case-sensitive. Anything else is rejected: AWS rejects it
// too, and ignoring it would let two readers see different statements.
var statementKeys = []string{"Action", "Condition", "Effect", "NotAction", "NotPrincipal", "NotResource", "Principal", "Resource", "Sid"}

// principalTypes are the Principal element keys
// (reference_policies_elements_principal.html), lower-cased.
var principalTypes = []string{"aws", "canonicaluser", "federated", "service"}

// operators maps lower-cased condition operator names to their documented
// spelling (reference_policies_elements_condition_operators.html). Matching
// is ASCII case-insensitive so an odd-cased operator is never a false block;
// an unknown operator is rejected, never dropped.
var operators = func() map[string]string {
	m := map[string]string{}
	for _, op := range []string{
		"StringEquals", "StringNotEquals", "StringEqualsIgnoreCase", "StringNotEqualsIgnoreCase", "StringLike", "StringNotLike",
		"NumericEquals", "NumericNotEquals", "NumericLessThan", "NumericLessThanEquals", "NumericGreaterThan", "NumericGreaterThanEquals",
		"DateEquals", "DateNotEquals", "DateLessThan", "DateLessThanEquals", "DateGreaterThan", "DateGreaterThanEquals",
		"Bool", "BinaryEquals", "IpAddress", "NotIpAddress", "ArnEquals", "ArnLike", "ArnNotEquals", "ArnNotLike", "Null",
	} {
		m[asciiLower(op)] = op
	}
	return m
}()

// Normalize parses an IAM policy document (IAM normalization steps 1-11
// and the later additions). On error
// the policy is nil and the error is an *Error wrapping ErrInvalid or
// ErrLimit.
func Normalize(doc string, o Options) (*Policy, error) {
	if !slices.Contains(partitions, o.Partition) {
		return nil, invalid(rPartition)
	}
	if len(doc) > MaxDocBytes {
		return nil, limit(rDocSize)
	}
	if err := admitDecode(doc, o.Budget); err != nil {
		return nil, err
	}
	raw, err := decode(doc)
	if err != nil {
		return nil, err
	}
	top, ok := raw.(map[string]any)
	if !ok {
		return nil, invalid(rTopLevel)
	}
	// Other top-level keys are ignored (spec step 3), but a case variant of
	// a known one ("version") would silently change the document.
	for k := range top {
		if l := asciiLower(k); k != "Version" && k != "Statement" && k != "Id" && (l == "version" || l == "statement" || l == "id") {
			return nil, invalid(rTopLevel)
		}
	}
	// Absent Version means 2008-10-17, in which ${...} is literal text
	// (reference_policies_elements_version.html).
	version := "2008-10-17"
	if v, ok := top["Version"]; ok {
		s, isStr := v.(string)
		if !isStr || (s != "2012-10-17" && s != "2008-10-17") {
			return nil, invalid(rVersion)
		}
		version = s
	}
	var stmts []any
	switch s := top["Statement"].(type) {
	case map[string]any:
		stmts = []any{s}
	case []any:
		stmts = s
	default:
		return nil, invalid(rStatement)
	}
	if len(stmts) > MaxStatements {
		return nil, limit(rStatementCount)
	}
	p := &Policy{Format: Format, Version: version, Statements: make([]Statement, 0, len(stmts))}
	for _, s := range stmts {
		m, ok := s.(map[string]any)
		if !ok {
			return nil, invalid(rStatement)
		}
		st, err := statement(m, version, o)
		if err != nil {
			return nil, err
		}
		p.Statements = append(p.Statements, st)
	}
	if o.Catalog != nil {
		if err := expand(p, o.Catalog, len(doc), o.Budget); err != nil {
			return nil, err
		}
	}
	return p, nil
}

func statement(m map[string]any, version string, o Options) (Statement, error) {
	st := Statement{
		Actions: []string{}, NotActions: []string{}, Resources: []string{}, NotResources: []string{},
		Principals: map[string][]string{}, NotPrincipals: map[string][]string{}, Conditions: []Condition{},
		Ambiguous: []string{}, ActionsExpanded: []string{}, NotActionsExpanded: []string{},
		UnresolvedActions: []string{}, UnresolvedPrincipals: map[string][]string{}, UnresolvedResources: []string{},
	}
	for _, k := range sortedKeys(m) {
		if !slices.Contains(statementKeys, k) {
			return st, invalid(rStatementKey)
		}
	}
	if v, ok := m["Sid"]; ok {
		var isStr bool
		if st.Sid, isStr = v.(string); !isStr {
			return st, invalid(rSid)
		}
	}
	// Effect values are exactly Allow or Deny (reference_policies_elements_effect.html).
	effect, isStr := m["Effect"].(string)
	if !isStr || (effect != "Allow" && effect != "Deny") {
		return st, invalid(rEffect)
	}
	st.Effect = effect
	var err error
	act, hasA := m["Action"]
	nact, hasNA := m["NotAction"]
	switch {
	case hasA == hasNA:
		return st, invalid(rActionElement)
	case hasA:
		st.Actions, err = actions(act)
	default:
		st.NotActions, err = actions(nact)
	}
	if err != nil {
		return st, err
	}
	pr, hasP := m["Principal"]
	npr, hasNP := m["NotPrincipal"]
	var bare bool
	switch {
	case hasP && hasNP:
		return st, invalid(rPrincipalElement)
	case hasP:
		// "Principal": "*" is the only string form (reference_policies_elements_principal.html).
		if s, isStr := pr.(string); isStr {
			if s != "*" {
				return st, invalid(rPrincipalValue)
			}
			st.Principals["aws"] = []string{"*"}
		} else if st.Principals, bare, err = principals(pr, false, o); err != nil {
			return st, err
		}
	case hasNP:
		if st.NotPrincipals, bare, err = principals(npr, true, o); err != nil {
			return st, err
		}
	}
	res, hasR := m["Resource"]
	nres, hasNR := m["NotResource"]
	switch {
	case hasR && hasNR:
		return st, invalid(rResourceElement)
	case hasR:
		st.Resources, err = strList(res, rResourceValue)
	case hasNR:
		st.NotResources, err = strList(nres, rResourceValue)
	}
	if err != nil {
		return st, err
	}
	// Resources stay verbatim (ARNs are case-sensitive), deduped and sorted.
	st.Resources, st.NotResources = dedupeSort(st.Resources), dedupeSort(st.NotResources)
	cond, hasC := m["Condition"]
	if hasC {
		if st.Conditions, err = conditions(cond); err != nil {
			return st, err
		}
	}

	st.ActionAll = slices.Contains(st.Actions, "*")
	st.ActionAny = st.ActionAll || len(st.NotActions) > 0
	for _, a := range st.Actions { // e.g. ?*:*? matches every action
		svc, name, _ := strings.Cut(a, ":")
		st.ActionAny = st.ActionAny || (onlyWild(svc) && onlyWild(name))
	}
	st.PrincipalAll = slices.Contains(st.Principals["aws"], "*")
	st.PrincipalAny = len(st.NotPrincipals) > 0
	for _, v := range st.Principals {
		st.PrincipalAny = st.PrincipalAny || slices.Contains(v, "*")
	}
	st.ResourceAny = len(st.NotResources) > 0
	for _, r := range st.Resources {
		st.ResourceAll = st.ResourceAll || strings.Trim(r, "*") == ""
		st.ResourceAny = st.ResourceAny || broadResource(r, version)
	}
	st.Unconditional = !hasC

	amb := func(code string, on bool) {
		if on {
			st.Ambiguous = append(st.Ambiguous, code)
		}
	}
	amb("not_action", hasNA)
	amb("not_principal", hasNP)
	amb("not_resource", hasNR)
	amb("principal_absent", !hasP && !hasNP)
	amb("resource_absent", !hasR && !hasNR)
	amb("conditional", hasC)
	amb("account_id_bare", bare)
	var variable, wildcard bool
	for _, r := range slices.Concat(st.Resources, st.NotResources) {
		variable = variable || strings.Contains(r, "${")
		wildcard = wildcard || (strings.Trim(r, "*") != "" && strings.ContainsAny(r, "*?"))
	}
	for _, c := range st.Conditions {
		for _, v := range c.Values {
			variable = variable || strings.Contains(v, "${")
		}
	}
	// Policy variables are substituted only under 2012-10-17 and only in
	// Resource and Condition values (reference_policies_variables.html).
	amb("variable", variable && version == "2012-10-17")
	amb("variable_literal", variable && version == "2008-10-17")
	amb("resource_wildcard", wildcard)
	slices.Sort(st.Ambiguous)
	resolveIdentities(&st)
	return st, nil
}

// actions lower-cases (IAM action names are case-insensitive), maps *:* to
// *, dedupes and sorts. Grammar: * or <service>:<name>, exactly one colon,
// both parts non-empty printable ASCII; wildcards allowed in both parts.
// Policy variables are not allowed in actions.
func actions(v any) ([]string, error) {
	l, err := strList(v, rActionValue)
	if err != nil {
		return nil, err
	}
	for i, a := range l {
		svc, name, ok := strings.Cut(a, ":")
		if a == "*" {
			continue
		}
		if !ok || svc == "" || name == "" || strings.Contains(name, ":") || strings.Contains(a, "${") || !printable(a) {
			return nil, invalid(rAction)
		}
		// A run of * matches what one * matches, so **:* is *:* is *.
		if l[i] = squeezeStars(asciiLower(a)); l[i] == "*:*" {
			l[i] = "*"
		}
	}
	return dedupeSort(l), nil
}

// principals normalizes a Principal or NotPrincipal object: type keys
// lower-cased (ASCII case-insensitive, collisions rejected), values deduped
// and sorted. AWS allows no partial wildcards in principals; "*" is allowed
// in Principal only (NotPrincipal "*" excludes everyone, rejected as
// intentional hardening). Policy variables are not allowed. A bare 12-digit
// AWS account id behaves like its root ARN (reference_policies_elements_principal.html,
// "AWS account principals") and becomes arn:<partition>:iam::<id>:root.
func principals(v any, not bool, o Options) (map[string][]string, bool, error) {
	m, ok := v.(map[string]any)
	if !ok || len(m) == 0 {
		return nil, false, invalid(rPrincipalValue)
	}
	out := map[string][]string{}
	var bare bool
	for _, k := range sortedKeys(m) {
		t := asciiLower(k)
		if _, dup := out[t]; dup || !slices.Contains(principalTypes, t) {
			return nil, false, invalid(rPrincipalType)
		}
		vals, err := strList(m[k], rPrincipalValue)
		if err != nil {
			return nil, false, err
		}
		for i, s := range vals {
			switch {
			case strings.Contains(s, "${"):
				return nil, false, invalid(rPrincipalVariable)
			case s == "*" && not:
				return nil, false, invalid(rNotPrincipalStar)
			case s != "*" && strings.ContainsAny(s, "*?"):
				return nil, false, invalid(rPrincipalWildcard)
			case t == "aws" && accountID(s):
				if o.Partition == "" {
					bare = true
				} else {
					vals[i] = "arn:" + o.Partition + ":iam::" + s + ":root"
				}
			}
		}
		out[t] = dedupeSort(vals)
	}
	return out, bare, nil
}

// conditions flattens a Condition block into (operator, key) entries sorted
// by key, op, set_op, if_exists. Context key names are not case-sensitive,
// including the tag-key part of aws:ResourceTag/<key>
// (reference_policies_elements_condition.html), so keys are lower-cased and
// two keys equal after lower-casing under one operator are rejected.
func conditions(v any) ([]Condition, error) {
	m, ok := v.(map[string]any)
	if !ok || len(m) == 0 {
		return nil, invalid(rCondition)
	}
	out := []Condition{}
	type opKey struct {
		set, op string
		ifx     bool
	}
	seen := map[opKey]bool{}
	for _, raw := range sortedKeys(m) {
		set, op, ifx, ok := operator(raw)
		if !ok {
			return nil, invalid(rConditionOperator)
		}
		if k := (opKey{set, op, ifx}); seen[k] {
			return nil, invalid(rConditionOpDup)
		} else {
			seen[k] = true
		}
		body, ok := m[raw].(map[string]any)
		if !ok || len(body) == 0 {
			return nil, invalid(rCondition)
		}
		keys := map[string]bool{}
		for _, rk := range sortedKeys(body) {
			key := asciiLower(rk)
			if key == "" || strings.Contains(key, "${") {
				return nil, invalid(rConditionKey)
			}
			if keys[key] {
				return nil, invalid(rConditionKeyDup)
			}
			keys[key] = true
			vals, err := conditionValues(body[rk], op)
			if err != nil {
				return nil, err
			}
			out = append(out, Condition{Op: op, SetOp: set, IfExists: ifx, Key: key, Values: vals})
		}
	}
	slices.SortFunc(out, func(a, b Condition) int {
		return cmp.Or(cmp.Compare(a.Key, b.Key), cmp.Compare(a.Op, b.Op), cmp.Compare(a.SetOp, b.SetOp),
			cmp.Compare(strconv.FormatBool(a.IfExists), strconv.FormatBool(b.IfExists)))
	})
	return out, nil
}

// operator splits [ForAllValues:|ForAnyValue:]<Operator>[IfExists]
// (reference_policies_condition-single-vs-multi-valued-context-keys.html,
// reference_policies_elements_condition_operators.html). Null takes neither
// a set prefix nor IfExists. A second prefix is an unknown operator.
func operator(s string) (set, op string, ifx, ok bool) {
	l := asciiLower(s)
	for _, p := range []string{"ForAllValues", "ForAnyValue"} {
		if rest, found := strings.CutPrefix(l, asciiLower(p)+":"); found {
			set, l = p, rest
			break
		}
	}
	l, ifx = strings.CutSuffix(l, "ifexists")
	if op, ok = operators[l]; !ok || (op == "Null" && (set != "" || ifx)) {
		return "", "", false, false
	}
	return set, op, ifx, true
}

// conditionValues: a scalar or a non-empty list of scalars; bool and number
// become their JSON text. Bool and Null take only true/false (JSON booleans
// or the strings "true"/"false"; accepting JSON booleans is intentional
// normalization, both read the same).
func conditionValues(v any, op string) ([]string, error) {
	raw, isList := v.([]any)
	if !isList {
		raw = []any{v}
	}
	if len(raw) == 0 {
		return nil, invalid(rConditionValue)
	}
	out := make([]string, 0, len(raw))
	for _, x := range raw {
		var s string
		switch x := x.(type) {
		case string:
			s = x
		case bool:
			s = strconv.FormatBool(x)
		case json.Number:
			s = string(x)
		default:
			return nil, invalid(rConditionValue)
		}
		if (op == "Bool" || op == "Null") && s != "true" && s != "false" {
			return nil, invalid(rConditionValue)
		}
		out = append(out, s)
	}
	return dedupeSort(out), nil
}

// strList reads a string or a non-empty list of non-empty strings.
func strList(v any, reason string) ([]string, error) {
	raw, isList := v.([]any)
	if !isList {
		raw = []any{v}
	}
	if len(raw) == 0 {
		return nil, invalid(reason)
	}
	out := make([]string, 0, len(raw))
	for _, x := range raw {
		s, ok := x.(string)
		if !ok || s == "" {
			return nil, invalid(reason)
		}
		out = append(out, s)
	}
	return out, nil
}

func dedupeSort(l []string) []string {
	slices.Sort(l)
	return slices.Compact(l)
}

// sortedKeys makes error selection independent of map order.
func sortedKeys(m map[string]any) []string { return slices.Sorted(maps.Keys(m)) }

// broadResource over-approximates "this pattern can match every resource":
// a wildcard (or, under 2012-10-17, a policy variable) in the ARN prefix up
// to and including the service segment, or before the pattern reaches it.
// arn:aws:s3:::* stays scoped to S3.
func broadResource(r, version string) bool {
	parts := strings.SplitN(r, ":", 4)
	for i := 0; i < len(parts) && i < 3; i++ {
		if strings.ContainsAny(parts[i], "*?") || (version == "2012-10-17" && strings.Contains(parts[i], "${")) {
			return true
		}
	}
	return false
}

func onlyWild(s string) bool { return strings.Trim(s, "*?") == "" }

func squeezeStars(s string) string {
	for strings.Contains(s, "**") {
		s = strings.ReplaceAll(s, "**", "*")
	}
	return s
}

func accountID(s string) bool {
	return len(s) == 12 && strings.Trim(s, "0123456789") == ""
}

func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] > '~' {
			return false
		}
	}
	return true
}

// asciiLower lower-cases A-Z only, so non-ASCII bytes never fold together.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}
