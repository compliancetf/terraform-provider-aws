package iampolicy

import (
	"slices"
	"strings"
)

// IAM identity resolution:
// no identity answer is ever "no match" by default. A canonical identity is
// "*" (carried by *_any), a full ARN without wildcards or policy variables,
// or a known AWS service / federation host. Everything else (a role or user
// name, a unique id such as AROA..., a bare account id without a partition, a
// CanonicalUser id, an ARN with a path or name wildcard or a ${...} variable,
// an unknown host) moves from Principals / Resources into
// UnresolvedPrincipals / UnresolvedResources, and PrincipalIs / ResourceIs
// refuse the statement with ErrUnresolved.

// Format is the normalized policy format id (Policy.Format).
const Format = "compliancetf.iampolicy/v1"

// resolveIdentities moves the non-canonical principal and resource values
// out of the canonical lists. Flags are computed before, over all values.
func resolveIdentities(st *Statement) {
	for t, vals := range st.Principals {
		var canon, unres []string
		for _, v := range vals {
			if canonicalPrincipal(t, v) {
				canon = append(canon, v)
			} else {
				unres = append(unres, v)
			}
		}
		if len(canon) == 0 {
			delete(st.Principals, t)
		} else {
			st.Principals[t] = canon
		}
		if len(unres) > 0 {
			st.UnresolvedPrincipals[t] = unres
		}
	}
	canon := []string{}
	for _, r := range st.Resources {
		if r == "*" || canonicalARN(r) {
			canon = append(canon, r)
		} else {
			st.UnresolvedResources = append(st.UnresolvedResources, r)
		}
	}
	st.Resources = canon
}

func canonicalPrincipal(typ, v string) bool {
	switch typ {
	case "aws":
		return v == "*" || canonicalARN(v)
	case "service":
		return v == "*" || awsHost(v)
	case "federated": // an identity provider ARN or host (cognito-identity.amazonaws.com)
		return canonicalARN(v) || awsHost(v)
	}
	// canonicaluser: an S3 canonical user id is an account alias the account
	// context cannot place.
	return false
}

// canonicalARN: arn:<partition>:<service>:<region>:<account>:<resource> with
// a known partition, a lower-case service, a non-empty resource and no
// wildcard or policy variable anywhere. Case variants are not canonical, so
// an exact compare never turns a case difference into a non-match.
func canonicalARN(s string) bool {
	p := strings.SplitN(s, ":", 6)
	return len(p) == 6 && p[0] == "arn" && p[1] != "" && slices.Contains(partitions, p[1]) &&
		lowerName(p[2]) && p[5] != "" && plainIdentity(s)
}

// federationHosts are the non-AWS hosts of web identity federation
// (reference_policies_elements_principal.html, "Federated web identity").
var federationHosts = []string{"accounts.google.com", "graph.facebook.com", "www.amazon.com"}

// awsHostSuffixes end service principal and AWS federation host names.
var awsHostSuffixes = []string{".amazonaws.com", ".amazonaws.com.cn", ".c2s.ic.gov", ".sc2s.sgov.gov"}

// awsHost: a lower-case host under an AWS service domain or a federation
// host; any other dotted name (an IAM name may contain dots) is not canonical.
func awsHost(s string) bool {
	if slices.Contains(federationHosts, s) {
		return true
	}
	for _, suf := range awsHostSuffixes {
		if label, ok := strings.CutSuffix(s, suf); ok && label != "" && !strings.HasPrefix(label, ".") &&
			!strings.HasSuffix(label, ".") && lowerName(strings.ReplaceAll(label, ".", "")) {
			return true
		}
	}
	return false
}

// lowerName: non-empty [a-z0-9-].
func lowerName(s string) bool {
	return s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyz0123456789-") == ""
}

func plainIdentity(s string) bool {
	return printable(s) && !strings.ContainsAny(s, "*?") && !strings.Contains(s, "${")
}

// usableIdentity refuses a statement with any unresolved_* entry (actions
// and both identity dimensions: "any unresolved_* entry in the statement"), any Not* element
// or an absent element on the queried dimension.
func usableIdentity(st Statement, absent bool) error {
	if len(st.UnresolvedPrincipals) > 0 || len(st.UnresolvedResources) > 0 || len(st.UnresolvedActions) > 0 || absent {
		return unresolved(rUnresolvedIdentity)
	}
	return nil
}

// PrincipalIs is iam.principal_is(stmt, arn): whether the statement's
// Principal grants arn. An ARN query matches the AWS and Federated lists, a
// host query the Service and Federated lists; "*" in the AWS list (everyone)
// matches any query, "*" elsewhere only queries of that type. In the AWS list
// an account root also matches every IAM and STS principal of its account and
// partition, and a role its sessions (see covers). An unresolved identity, a
// NotPrincipal (whether it excludes arn depends on the control polarity), an
// absent Principal (an identity policy applies to the identity it is attached
// to) or a non-canonical query is ErrUnresolved; so is a match that AWS
// documentation does not decide, unless another principal matches.
func PrincipalIs(st Statement, arn string) (bool, error) {
	if err := usableIdentity(st, len(st.NotPrincipals) > 0 || len(st.Principals) == 0); err != nil {
		return false, err
	}
	types := []string{"aws", "federated"}
	switch {
	case arn == "*":
		types = principalTypes
	case awsHost(arn):
		types = []string{"service", "federated"}
	case !canonicalARN(arn):
		return false, unresolved(rUnresolvedIdentity)
	}
	if slices.Contains(st.Principals["aws"], "*") {
		return true, nil
	}
	for _, t := range types {
		if slices.Contains(st.Principals[t], "*") || slices.Contains(st.Principals[t], arn) {
			return true, nil
		}
	}
	undecided := false
	for _, v := range st.Principals["aws"] {
		m, err := covers(v, arn)
		if m {
			return true, nil
		}
		undecided = undecided || err != nil
	}
	if undecided {
		return false, unresolved(rUnresolvedIdentity)
	}
	return false, nil
}

// covers: the canonical AWS principal v (not "*", not arn) grants principal
// q of its account and partition. An account root delegates to every
// principal of the account (reference_policies_elements_principal.html, "AWS
// account principals"); a role grants its sessions, which name the role
// without its path (access_policies.html, "Session policies"). A session
// queried as its role, and role names that differ only in case (unique
// regardless of case, matched by an undocumented rule), are ErrUnresolved.
// So is a user against a federated user of its account either way: a grant
// to a user applies to the sessions it federates
// (reference_policies_evaluation-logic_policy-eval-denyallow.html), and the
// session name does not name that user. Other names compare exactly: a
// Principal user name is case sensitive.
func covers(v, q string) (bool, error) {
	p := strings.SplitN(v, ":", 6)
	if len(p) != 6 {
		return false, nil
	}
	prefix, account := p[0]+":"+p[1], p[4]
	if !accountPrincipal(q, prefix, account) || !accountPrincipal(v, prefix, account) {
		return false, nil
	}
	if v == prefix+":iam::"+account+":root" {
		return true, nil
	}
	iamUser, fedUser := prefix+":iam::"+account+":user/", prefix+":sts::"+account+":federated-user/"
	if strings.HasPrefix(v, iamUser) && strings.HasPrefix(q, fedUser) || strings.HasPrefix(v, fedUser) && strings.HasPrefix(q, iamUser) {
		return false, unresolved(rUnresolvedIdentity)
	}
	vn, vs, ok := roleName(v, prefix, account)
	qn, qs, qok := roleName(q, prefix, account)
	if !ok || !qok || !strings.EqualFold(vn, qn) {
		return false, nil
	}
	switch {
	case vn == qn && !vs && qs: // the role grants its session
		return true, nil
	case vn == qn && vs == qs: // two roles on different paths, or two sessions
		return false, nil
	case vs && qs && !strings.EqualFold(v, q): // sessions of one role, other names
		return false, nil
	}
	return false, unresolved(rUnresolvedIdentity)
}

// roleName: the role name of a role ARN (last path segment) or of an
// assumed-role session ARN of account under prefix, and whether it is a
// session.
func roleName(s, prefix, account string) (name string, session, ok bool) {
	if res, found := strings.CutPrefix(s, prefix+":iam::"+account+":role/"); found {
		return res[strings.LastIndex(res, "/")+1:], false, res != "" && !strings.HasSuffix(res, "/")
	}
	if rs, found := strings.CutPrefix(s, prefix+":sts::"+account+":assumed-role/"); found {
		role, _, cut := strings.Cut(rs, "/")
		return role, true, cut && role != ""
	}
	return "", false, false
}

// PrincipalsInAccount is iam.principals_in_account(stmt, account, partition):
// true only when every principal of the statement is a principal ARN of the
// 12-digit account in the provider partition: arn:<partition>:iam::<account>:
// root, :user/.., :role/.., or arn:<partition>:sts::<account>:assumed-role/..,
// :federated-user/.. (subset, not membership: [own root, other root] is
// false). "*", a service, a federated principal, another account, another
// partition or any other ARN form makes it false. Not*, absent, empty or
// unresolved principals (a bare account id included), any other unresolved_*
// entry, a malformed account and an empty partition or one outside the closed
// partition list are ErrUnresolved, as for PrincipalIs.
func PrincipalsInAccount(st Statement, account, partition string) (bool, error) {
	n := 0
	for _, vals := range st.Principals {
		n += len(vals)
	}
	if err := usableIdentity(st, len(st.NotPrincipals) > 0 || n == 0); err != nil {
		return false, err
	}
	if len(account) != 12 || strings.Trim(account, "0123456789") != "" || !KnownPartition(partition) {
		return false, unresolved(rUnresolvedIdentity)
	}
	for t, vals := range st.Principals {
		for _, v := range vals {
			if t != "aws" || !accountPrincipal(v, "arn:"+partition, account) {
				return false, nil
			}
		}
	}
	return true, nil
}

// KnownPartition: p names a partition of the closed list. The list's ""
// (Normalize without a partition) is not a partition.
func KnownPartition(p string) bool {
	return p != "" && slices.Contains(partitions, p)
}

// accountPrincipal: v is an IAM or STS principal ARN under prefix
// (arn:<partition>) of account with a non-empty name (assumed-role: role and
// session).
func accountPrincipal(v, prefix, account string) bool {
	if res, ok := strings.CutPrefix(v, prefix+":iam::"+account+":"); ok {
		return res == "root" || named(res, "user/") || named(res, "role/")
	}
	res, ok := strings.CutPrefix(v, prefix+":sts::"+account+":")
	if !ok {
		return false
	}
	// STS ARNs carry no path: assumed-role/<role>/<session>,
	// federated-user/<name>; session and user names contain no "/".
	if rs, ok := strings.CutPrefix(res, "assumed-role/"); ok {
		role, session, ok := strings.Cut(rs, "/")
		return ok && role != "" && session != "" && !strings.Contains(session, "/")
	}
	return named(res, "federated-user/") && strings.Count(res, "/") == 1
}

// named: s is prefix followed by a name that neither is empty nor ends in "/".
func named(s, prefix string) bool {
	name, ok := strings.CutPrefix(s, prefix)
	return ok && name != "" && !strings.HasSuffix(name, "/")
}

// ResourceIs is iam.resource_is(stmt, arn): exact match of a canonical arn
// (or "*") over the canonical resources, true on "*". An unresolved identity,
// a NotResource, an absent Resource (a resource policy applies to the
// resource it is attached to) or a non-canonical query is ErrUnresolved.
func ResourceIs(st Statement, arn string) (bool, error) {
	if err := usableIdentity(st, len(st.NotResources) > 0 || len(st.Resources) == 0); err != nil {
		return false, err
	}
	if arn != "*" && !canonicalARN(arn) {
		return false, unresolved(rUnresolvedIdentity)
	}
	return slices.Contains(st.Resources, "*") || slices.Contains(st.Resources, arn), nil
}
