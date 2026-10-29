package iampolicy

import (
	"errors"
	"fmt"
	"testing"
)

// TestIdentity pins PrincipalIs / ResourceIs: canonical matches decide,
// everything else is ErrUnresolved, never a non-match.
func TestIdentity(t *testing.T) {
	const role = "arn:aws:iam::222222222222:role/bobthecorp-app"
	const bucket = "arn:aws:s3:::bobthecorp-logs"
	const root = "arn:aws:iam::222222222222:root"
	const session = "arn:aws:sts::222222222222:assumed-role/bobthecorp-app/s"
	stmt := func(rest string) Statement {
		t.Helper()
		p, err := Normalize(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:getobject",`+rest+`}}`, Options{})
		if err != nil {
			t.Fatal(err)
		}
		return p.Statements[0]
	}
	const unres = "unresolved"
	for _, tc := range []struct {
		name, rest, query string
		resource          bool
		want              string // "true", "false" or unresolved
	}{
		{"principal match", `"Principal":{"AWS":"` + role + `"},"Resource":"*"`, role, false, "true"},
		{"principal other", `"Principal":{"AWS":"arn:aws:iam::222222222222:role/x"},"Resource":"*"`, role, false, "false"},
		{"principal star", `"Principal":"*","Resource":"*"`, role, false, "true"},
		{"service match", `"Principal":{"Service":"ec2.amazonaws.com"},"Resource":"*"`, "ec2.amazonaws.com", false, "true"},
		{"federated provider arn", `"Principal":{"Federated":"arn:aws:iam::222222222222:saml-provider/bobthecorp"},"Resource":"*"`, role, false, "false"},
		{"role name", `"Principal":{"AWS":"bobthecorp-app"},"Resource":"*"`, role, false, unres},
		{"unique id beside canonical", `"Principal":{"AWS":["` + role + `","AIDAEXAMPLEBOBTHECORP"]},"Resource":"*"`, role, false, unres},
		{"bare account without partition", `"Principal":{"AWS":"222222222222"},"Resource":"*"`, "arn:aws:iam::222222222222:root", false, unres},
		{"principal absent", `"Resource":"*"`, role, false, unres},
		{"not principal", `"NotPrincipal":{"AWS":"` + role + `"},"Resource":"*"`, role, false, unres},
		{"query name", `"Principal":"*","Resource":"*"`, "bobthecorp-app", false, unres},
		{"query wildcard", `"Principal":"*","Resource":"*"`, "arn:aws:iam::222222222222:role/*", false, unres},
		{"query dotted role name", `"Principal":{"AWS":"arn:aws:iam::222222222222:role/bob.app"},"Resource":"*"`, "bob.app", false, unres},
		{"principal non-aws host", `"Principal":{"Service":"bobthecorp.example"},"Resource":"*"`, role, false, unres},
		{"query upper-case service", `"Principal":{"AWS":"` + role + `"},"Resource":"*"`, "arn:aws:IAM::222222222222:role/bobthecorp-app", false, unres},
		{"query star", `"Principal":"*","Resource":"*"`, "*", false, "true"},
		{"service star is not a role", `"Principal":{"Service":"*"},"Resource":"*"`, role, false, "false"},
		{"aws star is every service", `"Principal":"*","Resource":"*"`, "ec2.amazonaws.com", false, "true"},
		{"unresolved resource refuses principal_is", `"Principal":{"AWS":"` + role + `"},"Resource":"arn:aws:s3:::b/*"`, role, false, unres},
		{"unresolved principal refuses resource_is", `"Principal":{"AWS":"app"},"Resource":"` + bucket + `"`, bucket, true, unres},
		{"query unknown partition", `"Principal":"*","Resource":"*"`, "arn:bobthecorp:iam::222222222222:root", false, unres},
		{"resource match", `"Principal":"*","Resource":"` + bucket + `"`, bucket, true, "true"},
		{"resource other", `"Principal":"*","Resource":"arn:aws:s3:::bobthecorp-other"`, bucket, true, "false"},
		{"resource star", `"Principal":"*","Resource":"*"`, bucket, true, "true"},
		{"resource path wildcard", `"Principal":"*","Resource":"arn:aws:s3:::bobthecorp-logs/*"`, bucket, true, unres},
		{"resource question mark", `"Principal":"*","Resource":"arn:aws:s3:::bobthecorp-log?"`, bucket, true, unres},
		{"resource variable", `"Principal":"*","Resource":"arn:aws:s3:::${aws:username}"`, bucket, true, unres},
		{"resource name only", `"Principal":"*","Resource":"bobthecorp-logs"`, bucket, true, unres},
		{"resource absent", `"Principal":"*"`, bucket, true, unres},
		{"not resource", `"Principal":"*","NotResource":"arn:aws:s3:::bobthecorp-other"`, bucket, true, unres},
		{"query resource wildcard", `"Principal":"*","Resource":"*"`, "arn:aws:s3:::bobthecorp-*", true, unres},
		// Unresolved principals refuse the statement even beside a match.
		{"role unique id", `"Principal":{"AWS":"AROAEXAMPLEBOBTHECORP"},"Resource":"*"`, role, false, unres},
		{"canonical user", `"Principal":{"CanonicalUser":"79a59df900b949e55d96a1e698fbace"},"Resource":"*"`, role, false, unres},
		{"federated star", `"Principal":{"Federated":"*"},"Resource":"*"`, role, false, unres},
		{"aws star beside role name", `"Principal":{"AWS":["*","bobthecorp-app"]},"Resource":"*"`, role, false, unres},
		{"not principal with query star", `"NotPrincipal":{"AWS":"` + role + `"},"Resource":"*"`, "*", false, unres},
		{"query bare account", `"Principal":"*","Resource":"*"`, "222222222222", false, unres},
		{"query variable", `"Principal":"*","Resource":"*"`, "arn:aws:iam::222222222222:role/${aws:username}", false, unres},
		// principal_is reads the Resource dimension only through unresolved_resources.
		{"not resource keeps principal_is", `"Principal":{"AWS":"` + role + `"},"NotResource":"arn:aws:s3:::b/*"`, role, false, "true"},
		{"resource absent keeps principal_is", `"Principal":{"AWS":"` + role + `"}`, role, false, "true"},
		{"unresolved resource refuses principal_is star", `"Principal":"*","Resource":"bobthecorp-logs"`, role, false, unres},
		// resource_is reads the Principal dimension only through unresolved_principals.
		{"not principal keeps resource_is", `"NotPrincipal":{"AWS":"bobthecorp-app"},"Resource":"` + bucket + `"`, bucket, true, "true"},
		{"principal absent keeps resource_is", `"Resource":"` + bucket + `"`, bucket, true, "true"},
		{"resource glob beside match", `"Principal":"*","Resource":["` + bucket + `","arn:aws:s3:::bobthecorp-logs/*"]`, bucket, true, unres},
		{"not resource with query star", `"Principal":"*","NotResource":"` + bucket + `"`, "*", true, unres},
		{"query resource name", `"Principal":"*","Resource":"*"`, "bobthecorp-logs", true, unres},
		// An account root delegates to every principal of its account.
		{"own root covers role", `"Principal":{"AWS":"` + root + `"},"Resource":"*"`, role, false, "true"},
		{"own root covers user", `"Principal":{"AWS":"` + root + `"},"Resource":"*"`, "arn:aws:iam::222222222222:user/bob", false, "true"},
		{"own root covers role session", `"Principal":{"AWS":"` + root + `"},"Resource":"*"`, session, false, "true"},
		{"own root covers federated user", `"Principal":{"AWS":"` + root + `"},"Resource":"*"`, "arn:aws:sts::222222222222:federated-user/bob", false, "true"},
		{"own root covers itself", `"Principal":{"AWS":"` + root + `"},"Resource":"*"`, root, false, "true"},
		{"other account root", `"Principal":{"AWS":"arn:aws:iam::333333333333:root"},"Resource":"*"`, role, false, "false"},
		{"other partition root", `"Principal":{"AWS":"arn:aws-cn:iam::222222222222:root"},"Resource":"*"`, role, false, "false"},
		{"root is not its provider", `"Principal":{"AWS":"` + root + `"},"Resource":"*"`, "arn:aws:iam::222222222222:saml-provider/bobthecorp", false, "false"},
		{"root is not a resource arn", `"Principal":{"AWS":"` + root + `"},"Resource":"*"`, "arn:aws:lambda:eu-west-1:222222222222:function:bobthecorp", false, "false"},
		{"root is not a service", `"Principal":{"AWS":"` + root + `"},"Resource":"*"`, "ec2.amazonaws.com", false, "false"},
		{"role is not the account", `"Principal":{"AWS":"` + role + `"},"Resource":"*"`, root, false, "false"},
		{"root beside aws star", `"Principal":{"AWS":["*","` + root + `"]},"Resource":"*"`, role, false, "true"},
		{"not principal root", `"NotPrincipal":{"AWS":"` + root + `"},"Resource":"*"`, role, false, unres},
		// A role covers its sessions; a session ARN carries no role path.
		{"role covers its session", `"Principal":{"AWS":"` + role + `"},"Resource":"*"`, session, false, "true"},
		{"role with path covers its session", `"Principal":{"AWS":"arn:aws:iam::222222222222:role/ops/bobthecorp-app"},"Resource":"*"`, session, false, "true"},
		{"role is not another role's session", `"Principal":{"AWS":"` + role + `"},"Resource":"*"`, "arn:aws:sts::222222222222:assumed-role/bobthecorp-ops/s", false, "false"},
		{"role is not a session in another account", `"Principal":{"AWS":"` + role + `"},"Resource":"*"`, "arn:aws:sts::333333333333:assumed-role/bobthecorp-app/s", false, "false"},
		{"session exact", `"Principal":{"AWS":"` + session + `"},"Resource":"*"`, session, false, "true"},
		{"other session of the role", `"Principal":{"AWS":"` + session + `"},"Resource":"*"`, "arn:aws:sts::222222222222:assumed-role/bobthecorp-app/t", false, "false"},
		{"session queried as its role", `"Principal":{"AWS":"` + session + `"},"Resource":"*"`, role, false, unres},
		{"session queried as its role with path", `"Principal":{"AWS":"` + session + `"},"Resource":"*"`, "arn:aws:iam::222222222222:role/ops/bobthecorp-app", false, unres},
		{"session of another role", `"Principal":{"AWS":"arn:aws:sts::222222222222:assumed-role/bobthecorp-ops/s"},"Resource":"*"`, role, false, "false"},
		{"role path differs", `"Principal":{"AWS":"arn:aws:iam::222222222222:role/ops/bobthecorp-app"},"Resource":"*"`, role, false, "false"},
		// Role names are unique regardless of case; matching ignoring case is undocumented.
		{"role name case variant", `"Principal":{"AWS":"arn:aws:iam::222222222222:role/BobTheCorp-App"},"Resource":"*"`, role, false, unres},
		{"role case variant session", `"Principal":{"AWS":"arn:aws:iam::222222222222:role/BobTheCorp-App"},"Resource":"*"`, session, false, unres},
		{"case variant beside match", `"Principal":{"AWS":["arn:aws:iam::222222222222:role/BobTheCorp-App","` + role + `"]},"Resource":"*"`, role, false, "true"},
		{"case variant beside other root", `"Principal":{"AWS":["arn:aws:iam::222222222222:role/BobTheCorp-App","arn:aws:iam::333333333333:root"]},"Resource":"*"`, role, false, unres},
		{"case variant in other account", `"Principal":{"AWS":"arn:aws:iam::333333333333:role/BobTheCorp-App"},"Resource":"*"`, role, false, "false"},
		// A user's grant applies to the federated user sessions it creates;
		// the session name does not name that user.
		{"user queried as same-name federated user", `"Principal":{"AWS":"arn:aws:iam::222222222222:user/bob"},"Resource":"*"`, "arn:aws:sts::222222222222:federated-user/bob", false, unres},
		{"user queried as other-name federated user", `"Principal":{"AWS":"arn:aws:iam::222222222222:user/bob"},"Resource":"*"`, "arn:aws:sts::222222222222:federated-user/alice", false, unres},
		{"user with path queried as federated user", `"Principal":{"AWS":"arn:aws:iam::222222222222:user/ops/bob"},"Resource":"*"`, "arn:aws:sts::222222222222:federated-user/bob", false, unres},
		{"user queried as federated user in other account", `"Principal":{"AWS":"arn:aws:iam::333333333333:user/bob"},"Resource":"*"`, "arn:aws:sts::222222222222:federated-user/bob", false, "false"},
		{"user queried as federated user in other partition", `"Principal":{"AWS":"arn:aws-cn:iam::222222222222:user/bob"},"Resource":"*"`, "arn:aws:sts::222222222222:federated-user/bob", false, "false"},
		{"user beside matching federated user", `"Principal":{"AWS":["arn:aws:iam::222222222222:user/bob","arn:aws:sts::222222222222:federated-user/alice"]},"Resource":"*"`, "arn:aws:sts::222222222222:federated-user/alice", false, "true"},
		{"user beside own root", `"Principal":{"AWS":["arn:aws:iam::222222222222:user/bob","` + root + `"]},"Resource":"*"`, "arn:aws:sts::222222222222:federated-user/alice", false, "true"},
		// As a session queried as its role: the session may be the queried user's.
		{"federated user queried as a user", `"Principal":{"AWS":"arn:aws:sts::222222222222:federated-user/bob"},"Resource":"*"`, "arn:aws:iam::222222222222:user/alice", false, unres},
		{"federated user queried as a user in other account", `"Principal":{"AWS":"arn:aws:sts::333333333333:federated-user/bob"},"Resource":"*"`, "arn:aws:iam::222222222222:user/bob", false, "false"},
		{"other federated user", `"Principal":{"AWS":"arn:aws:sts::222222222222:federated-user/bob"},"Resource":"*"`, "arn:aws:sts::222222222222:federated-user/alice", false, "false"},
		{"user is not a role session", `"Principal":{"AWS":"arn:aws:iam::222222222222:user/bob"},"Resource":"*"`, session, false, "false"},
		{"user name case is significant", `"Principal":{"AWS":"arn:aws:iam::222222222222:user/Bob"},"Resource":"*"`, "arn:aws:iam::222222222222:user/bob", false, "false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := PrincipalIs
			if tc.resource {
				f = ResourceIs
			}
			got, err := f(stmt(tc.rest), tc.query)
			switch {
			case tc.want == unres:
				if !errors.Is(err, ErrUnresolved) {
					t.Fatalf("got %v, %v; want ErrUnresolved", got, err)
				}
			case err != nil || (got != (tc.want == "true")):
				t.Fatalf("got %v, %v; want %s", got, err, tc.want)
			}
		})
	}
}

// TestPrincipalIsBareAccount pins a bare account id normalized with a
// partition: it is the account root and covers that account's principals.
func TestPrincipalIsBareAccount(t *testing.T) {
	p, err := Normalize(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:getobject","Resource":"*","Principal":{"AWS":"222222222222"}}}`, Options{Partition: "aws"})
	if err != nil {
		t.Fatal(err)
	}
	for q, want := range map[string]bool{
		"arn:aws:iam::222222222222:role/bobthecorp-app":    true,
		"arn:aws:iam::333333333333:role/bobthecorp-app":    false,
		"arn:aws-cn:iam::222222222222:role/bobthecorp-app": false,
	} {
		if got, err := PrincipalIs(p.Statements[0], q); err != nil || got != want {
			t.Errorf("%s: got %v, %v; want %v", q, got, err, want)
		}
	}
}

// TestPrincipalsInAccount pins the subset helper: true only when every
// principal is an IAM or STS ARN of the account; another account, "*", a
// service or federated principal is false; Not*, absent or unresolved
// principals and a malformed account are ErrUnresolved.
func TestPrincipalsInAccount(t *testing.T) {
	const own, other = "111111111111", "222222222222"
	stmt := func(principal string) Statement {
		t.Helper()
		p, err := Normalize(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:getobject","Resource":"*"`+principal+`}}`, Options{})
		if err != nil {
			t.Fatal(err)
		}
		return p.Statements[0]
	}
	const unres = "unresolved"
	for _, tc := range []struct{ name, principal, account, want string }{
		{"own root", `,"Principal":{"AWS":"arn:aws:iam::111111111111:root"}`, own, "true"},
		{"own role and assumed role", `,"Principal":{"AWS":["arn:aws:iam::111111111111:role/bobthecorp-app","arn:aws:sts::111111111111:assumed-role/bobthecorp-app/s"]}`, own, "true"},
		{"own and other account", `,"Principal":{"AWS":["arn:aws:iam::111111111111:root","arn:aws:iam::222222222222:root"]}`, own, "false"},
		{"other account only", `,"Principal":{"AWS":"arn:aws:iam::222222222222:root"}`, own, "false"},
		{"other account query", `,"Principal":{"AWS":"arn:aws:iam::222222222222:root"}`, other, "true"},
		{"everyone", `,"Principal":"*"`, own, "false"},
		{"aws star", `,"Principal":{"AWS":"*"}`, own, "false"},
		{"own root and service", `,"Principal":{"AWS":"arn:aws:iam::111111111111:root","Service":"logging.s3.amazonaws.com"}`, own, "false"},
		{"own federated provider", `,"Principal":{"Federated":"arn:aws:iam::111111111111:saml-provider/bobthecorp"}`, own, "false"},
		{"non-iam arn with account", `,"Principal":{"AWS":"arn:aws:lambda:eu-west-1:111111111111:function:bobthecorp"}`, own, "false"},
		{"own federated user", `,"Principal":{"AWS":"arn:aws:sts::111111111111:federated-user/bob"}`, own, "true"},
		{"other partition same account", `,"Principal":{"AWS":"arn:aws-cn:iam::111111111111:root"}`, own, "false"},
		{"gov partition beside own", `,"Principal":{"AWS":["arn:aws:iam::111111111111:root","arn:aws-us-gov:sts::111111111111:assumed-role/r/s"]}`, own, "false"},
		{"iam arn with region", `,"Principal":{"AWS":"arn:aws:iam:eu-west-1:111111111111:root"}`, own, "false"},
		{"own non-principal iam form", `,"Principal":{"AWS":"arn:aws:iam::111111111111:instance-profile/bobthecorp"}`, own, "false"},
		{"own policy arn", `,"Principal":{"AWS":"arn:aws:iam::111111111111:policy/bobthecorp"}`, own, "false"},
		{"own role with path", `,"Principal":{"AWS":"arn:aws:iam::111111111111:role/ops/bobthecorp"}`, own, "true"},
		{"empty user name", `,"Principal":{"AWS":"arn:aws:iam::111111111111:user/"}`, own, "false"},
		{"empty role name", `,"Principal":{"AWS":"arn:aws:iam::111111111111:role/"}`, own, "false"},
		{"assumed role without session", `,"Principal":{"AWS":"arn:aws:sts::111111111111:assumed-role/r"}`, own, "false"},
		{"assumed role empty session", `,"Principal":{"AWS":"arn:aws:sts::111111111111:assumed-role/r/"}`, own, "false"},
		{"assumed role extra component", `,"Principal":{"AWS":"arn:aws:sts::111111111111:assumed-role/r/s/x"}`, own, "false"},
		{"federated user extra component", `,"Principal":{"AWS":"arn:aws:sts::111111111111:federated-user/bob/x"}`, own, "false"},
		{"empty federated user", `,"Principal":{"AWS":"arn:aws:sts::111111111111:federated-user/"}`, own, "false"},
		{"lower-case principal key", `,"Principal":{"aws":"arn:aws:iam::111111111111:root"}`, own, "true"},
		{"root prefix is not root", `,"Principal":{"AWS":"arn:aws:iam::111111111111:rootx"}`, own, "false"},
		{"bare account id", `,"Principal":{"AWS":"111111111111"}`, own, unres},
		{"account with letter", `,"Principal":{"AWS":"arn:aws:iam::111111111111:root"}`, "11111111111a", unres},
		{"own root and role name", `,"Principal":{"AWS":["arn:aws:iam::111111111111:root","bobthecorp-app"]}`, own, unres},
		{"not principal", `,"NotPrincipal":{"AWS":"arn:aws:iam::111111111111:root"}`, own, unres},
		{"principal absent", ``, own, unres},
		{"account not 12 digits", `,"Principal":{"AWS":"arn:aws:iam::111111111111:root"}`, "11111111111", unres},
		{"account arn", `,"Principal":{"AWS":"arn:aws:iam::111111111111:root"}`, "arn:aws:iam::111111111111:root", unres},
		{"empty account", `,"Principal":{"AWS":"arn:aws:iam::111111111111:root"}`, "", unres},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := PrincipalsInAccount(stmt(tc.principal), tc.account, "aws")
			switch {
			case tc.want == unres:
				if !errors.Is(err, ErrUnresolved) {
					t.Fatalf("got %v, %v; want ErrUnresolved", got, err)
				}
			case err != nil || (got != (tc.want == "true")):
				t.Fatalf("got %v, %v; want %s", got, err, tc.want)
			}
		})
	}
}

// TestPrincipalsInAccountPartition pins the partition binding:
// own-account principals match only in the bound partition; an empty or
// unknown partition is ErrUnresolved.
func TestPrincipalsInAccountPartition(t *testing.T) {
	const own = "111111111111"
	stmt := func(principal string) Statement {
		t.Helper()
		p, err := Normalize(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:getobject","Resource":"*","Principal":{"AWS":`+principal+`}}}`, Options{})
		if err != nil {
			t.Fatal(err)
		}
		return p.Statements[0]
	}
	const unres = "unresolved"
	for _, tc := range []struct{ name, principal, partition, want string }{
		{"china root", `"arn:aws-cn:iam::111111111111:root"`, "aws-cn", "true"},
		{"gov assumed role and user", `["arn:aws-us-gov:sts::111111111111:assumed-role/r/s","arn:aws-us-gov:iam::111111111111:user/bob"]`, "aws-us-gov", "true"},
		{"iso role", `"arn:aws-iso:iam::111111111111:role/r"`, "aws-iso", "true"},
		{"aws root in china", `"arn:aws:iam::111111111111:root"`, "aws-cn", "false"},
		{"china and aws", `["arn:aws-cn:iam::111111111111:root","arn:aws:iam::111111111111:root"]`, "aws-cn", "false"},
		{"china other account", `"arn:aws-cn:iam::222222222222:root"`, "aws-cn", "false"},
		{"empty partition", `"arn:aws:iam::111111111111:root"`, "", unres},
		{"unknown partition", `"arn:aws:iam::111111111111:root"`, "aws-mars", unres},
		{"upper-case partition", `"arn:aws:iam::111111111111:root"`, "AWS", unres},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := PrincipalsInAccount(stmt(tc.principal), own, tc.partition)
			switch {
			case tc.want == unres:
				if !errors.Is(err, ErrUnresolved) {
					t.Fatalf("got %v, %v; want ErrUnresolved", got, err)
				}
			case err != nil || (got != (tc.want == "true")):
				t.Fatalf("got %v, %v; want %s", got, err, tc.want)
			}
		})
	}
}

// TestPrincipalWildcardParse pins the parse rules for Principal and
// NotPrincipal: a ${...} variable or any "*" / "?" other than a lone "*" is
// rejected (type_error), a lone "*" is rejected in NotPrincipal and accepted
// in Principal, and NotPrincipal values are kept as written.
func TestPrincipalWildcardParse(t *testing.T) {
	const role = "arn:aws:iam::222222222222:role/bobthecorp-app"
	for _, tc := range []struct {
		name, elem string
		reason     string // "" when accepted
		principals string // fmt of Principals, UnresolvedPrincipals, NotPrincipals
	}{
		{"variable", `"Principal":{"AWS":"${aws:username}"}`, rPrincipalVariable, ""},
		{"variable in array", `"Principal":{"AWS":["` + role + `","arn:aws:iam::222222222222:role/${aws:username}"]}`, rPrincipalVariable, ""},
		{"variable before wildcard", `"Principal":{"AWS":"${aws:username}*"}`, rPrincipalVariable, ""},
		{"account glob", `"Principal":{"AWS":"arn:aws:iam::12345*:root"}`, rPrincipalWildcard, ""},
		{"account glob in array", `"Principal":{"AWS":["` + role + `","arn:aws:iam::12345*:root"]}`, rPrincipalWildcard, ""},
		{"lone question mark", `"Principal":{"AWS":"?"}`, rPrincipalWildcard, ""},
		{"lone question mark in array", `"Principal":{"AWS":["?"]}`, rPrincipalWildcard, ""},
		{"double star", `"Principal":{"AWS":"**"}`, rPrincipalWildcard, ""},
		{"star beside glob", `"Principal":{"AWS":["*","arn:aws:iam::222222222222:role/bob*"]}`, rPrincipalWildcard, ""},
		{"service glob", `"Principal":{"Service":"*.amazonaws.com"}`, rPrincipalWildcard, ""},
		{"string question mark", `"Principal":"?"`, rPrincipalValue, ""},
		{"string glob", `"Principal":"arn:aws:iam::12345*:root"`, rPrincipalValue, ""},
		{"string variable", `"Principal":"${aws:username}"`, rPrincipalValue, ""},
		{"top-level array", `"Principal":["*"]`, rPrincipalValue, ""},
		{"not variable", `"NotPrincipal":{"AWS":"${aws:username}"}`, rPrincipalVariable, ""},
		{"not star", `"NotPrincipal":{"AWS":"*"}`, rNotPrincipalStar, ""},
		{"not star in array", `"NotPrincipal":{"AWS":["` + role + `","*"]}`, rNotPrincipalStar, ""},
		{"not service star", `"NotPrincipal":{"Service":"*"}`, rNotPrincipalStar, ""},
		{"not account glob", `"NotPrincipal":{"AWS":["arn:aws:iam::12345*:root"]}`, rPrincipalWildcard, ""},
		{"not question mark", `"NotPrincipal":{"AWS":"?"}`, rPrincipalWildcard, ""},
		{"not string star", `"NotPrincipal":"*"`, rPrincipalValue, ""},
		{"star", `"Principal":"*"`, "", "map[aws:[*]] map[] map[]"},
		{"aws star", `"Principal":{"AWS":"*"}`, "", "map[aws:[*]] map[] map[]"},
		{"aws star in array", `"Principal":{"AWS":["*"]}`, "", "map[aws:[*]] map[] map[]"},
		{"service star", `"Principal":{"Service":"*"}`, "", "map[service:[*]] map[] map[]"},
		{"federated star is unresolved", `"Principal":{"Federated":"*"}`, "", "map[] map[federated:[*]] map[]"},
		{"not principal as written", `"NotPrincipal":{"AWS":["bobthecorp-app","222222222222"]}`, "", "map[] map[] map[aws:[222222222222 bobthecorp-app]]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Normalize(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:getobject","Resource":"*",`+tc.elem+`}}`, Options{})
			if tc.reason != "" {
				var e *Error
				if !isReason(err, ErrInvalid, tc.reason) || !errors.As(err, &e) || e.Class() != "type_error" {
					t.Fatalf("got %v; want type_error %s", err, tc.reason)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			st := p.Statements[0]
			if got := fmt.Sprint(st.Principals, " ", st.UnresolvedPrincipals, " ", st.NotPrincipals); got != tc.principals {
				t.Fatalf("got %s; want %s", got, tc.principals)
			}
		})
	}
}

// TestResourceResolution pins identity resolution of Resource: "*" and full
// ARNs stay canonical, globs, variables and names move to
// unresolved_resources, NotResource stays as written.
func TestResourceResolution(t *testing.T) {
	const bucket = "arn:aws:s3:::bobthecorp-logs"
	for _, tc := range []struct {
		name, elem string
		want       string // fmt of Resources, UnresolvedResources, NotResources
	}{
		{"star", `"Resource":"*"`, "[*] [] []"},
		{"full arn", `"Resource":"` + bucket + `"`, "[" + bucket + "] [] []"},
		{"object glob", `"Resource":"arn:aws:s3:::bobthecorp-logs/*"`, "[] [arn:aws:s3:::bobthecorp-logs/*] []"},
		{"question mark", `"Resource":"arn:aws:s3:::bobthecorp-log?"`, "[] [arn:aws:s3:::bobthecorp-log?] []"},
		{"double star", `"Resource":"**"`, "[] [**] []"},
		{"variable", `"Resource":"arn:aws:s3:::${aws:username}"`, "[] [arn:aws:s3:::${aws:username}] []"},
		{"name", `"Resource":"bobthecorp-logs"`, "[] [bobthecorp-logs] []"},
		{"unknown partition", `"Resource":"arn:bobthecorp:s3:::bobthecorp-logs"`, "[] [arn:bobthecorp:s3:::bobthecorp-logs] []"},
		{"mixed", `"Resource":["*","` + bucket + `","arn:aws:s3:::bobthecorp-logs/*"]`, "[* " + bucket + "] [arn:aws:s3:::bobthecorp-logs/*] []"},
		{"not resource as written", `"NotResource":["arn:aws:s3:::bobthecorp-logs/*","bobthecorp-logs"]`, "[] [] [arn:aws:s3:::bobthecorp-logs/* bobthecorp-logs]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Normalize(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:getobject","Principal":"*",`+tc.elem+`}}`, Options{})
			if err != nil {
				t.Fatal(err)
			}
			st := p.Statements[0]
			if got := fmt.Sprint(st.Resources, " ", st.UnresolvedResources, " ", st.NotResources); got != tc.want {
				t.Fatalf("got %s; want %s", got, tc.want)
			}
		})
	}
}
