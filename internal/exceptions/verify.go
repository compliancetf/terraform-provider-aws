package exceptions

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/profile"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

// Error codes (GrantError.Code and Rejection.Code).
const (
	CodeNoKeys               = "grant_no_keys"
	CodeKeysInvalid          = "grant_keys_invalid"
	CodeSignature            = "grant_signature"
	CodeKeyNotValid          = "grant_key_not_valid" // signature verifies, but its key is outside its window at the run clock
	CodeInvalid              = "grant_invalid"
	CodeApprovers            = "grant_approvers"
	CodeWrongOrg             = "grant_wrong_org"
	CodeExpired              = "grant_expired"
	CodeScopeUntrusted       = "exception_scope_untrusted"
	CodeWrongWorkspace       = "grant_wrong_workspace"
	CodeWrongEnvironment     = "grant_wrong_environment"
	CodeEnvironmentForbidden = "grant_environment_forbidden"
	CodeDuplicateID          = "grant_duplicate_id"
	CodeFileUnreadable       = "file_unreadable"
	CodeFileTooLarge         = "file_too_large"
	CodeFileNotRegular       = "file_not_regular"
)

// Grant.Source values: a compiled keyring key or a profile grant_keys entry.
const (
	SourceKeyring = "keyring"
	SourceProfile = "profile_grant_key"
)

// maxIssueSkew is how far issued_at may lie ahead of the run clock. Expiry
// has no skew: a grant is expired from expires_at on.
const maxIssueSkew = 5 * time.Minute

// GrantError is a rejected grant. Detail is fixed text or verified payload
// values, never unsigned input.
type GrantError struct {
	Code, Detail string
	Err          error
}

func (e *GrantError) Error() string { return e.Code + ": " + e.Detail }
func (e *GrantError) Unwrap() error { return e.Err }

func fail(code, format string, a ...any) error {
	return &GrantError{Code: code, Detail: fmt.Sprintf(format, a...)}
}

// VerifierInput: Compiled is the compiled keyring (trust.Embedded()), Table
// the run's mode table (trusted scope and profile exception policy), OrgID
// the run's org ("" on the free tier: no grant applies), Now the local run
// clock and Clock the exceptions clock (NewClock; zero: Now). Under airgap
// every time check uses the air-gap time, never Now.
type VerifierInput struct {
	Compiled    *trust.Keyring
	Revocations trust.Revocations
	Table       profile.ModeTable
	OrgID       string
	Now         time.Time
	Clock       Clock
}

// Verifier checks grants for one run.
type Verifier struct {
	in       VerifierInput
	unknown  string // non-empty: the exceptions clock is unknown, no grant applies
	kr       *trust.Keyring
	keys     map[string]trust.Key
	compiled map[string]bool
	hasKey   bool
}

// NewVerifier builds the grant keyring once: the compiled keys plus the
// profile grant_keys as exception-only keys.
func NewVerifier(in VerifierInput) (*Verifier, error) {
	now, unknown := in.Clock.resolve(in.Now) // under airgap Now is not read
	switch {
	case in.Compiled == nil:
		return nil, errors.New("exceptions: no compiled keyring")
	case unknown == "" && now.IsZero():
		return nil, errors.New("exceptions: no run clock")
	case !in.Revocations.Valid():
		return nil, errors.New("exceptions: invalid revocation set")
	}
	var ext []trust.ExtKey
	if e := in.Table.Exceptions; e != nil {
		for _, k := range e.GrantKeys {
			der, err := base64.StdEncoding.Strict().DecodeString(k.SPKIB64)
			if err != nil {
				return nil, fail(CodeKeysInvalid, "grant key %s: spki_b64", k.KID)
			}
			ext = append(ext, trust.ExtKey{KID: k.KID, Alg: k.Alg, SPKI: der, NotBefore: k.NotBefore, NotAfter: k.NotAfter})
		}
	}
	kr, err := trust.ExceptionKeyring(in.Compiled, ext)
	if err != nil {
		return nil, &GrantError{Code: CodeKeysInvalid, Detail: err.Error(), Err: err}
	}
	v := &Verifier{in: in, kr: kr, keys: map[string]trust.Key{}, compiled: map[string]bool{}}
	v.in.Now, v.unknown = now, unknown
	for _, k := range in.Compiled.Keys() {
		v.compiled[k.KID] = true
	}
	for _, k := range kr.Keys() {
		v.keys[k.KID] = k
		v.hasKey = v.hasKey || k.Purpose == trust.PurposeException
	}
	return v, nil
}

// VerifyGrant verifies one DSSE grant envelope. Checks run in this order:
// signature and accepted key window at Now, payload shape, approvers, org,
// expiry, scope (untrusted dimension, then membership, then
// forbid_environment_scoped). A zero Grant comes with every error.
func (v *Verifier) VerifyGrant(env []byte) (Grant, error) {
	if v.unknown != "" {
		return Grant{}, fail(CodeAirgapTimeUnknown, "%s", v.unknown)
	}
	if !v.hasKey {
		return Grant{}, fail(CodeNoKeys, "no exception grant key is trusted")
	}
	if len(env) > trust.MaxEnvelopeBytes {
		return Grant{}, fail(CodeInvalid, "envelope larger than %d bytes", trust.MaxEnvelopeBytes)
	}
	vd, err := v.kr.Verify(env, trust.PayloadExceptionGrant, v.in.Revocations)
	if err != nil {
		return Grant{}, &GrantError{Code: CodeSignature, Detail: err.Error(), Err: err} // trust errors never echo unsigned input
	}
	key := v.keys[vd.KeyID]
	if v.in.Now.Before(key.NotBefore) || !v.in.Now.Before(key.NotAfter) {
		return Grant{}, fail(CodeKeyNotValid, "signing key %s is not valid now%s", vd.KeyID, v.in.Clock.ref())
	}
	g, err := parse(vd.Payload)
	if err != nil {
		return Grant{}, &GrantError{Code: CodeInvalid, Detail: err.Error(), Err: err}
	}
	if err := checkApprovers(g.Approvers); err != nil {
		return Grant{}, &GrantError{Code: CodeApprovers, Detail: err.Error(), Err: err}
	}
	if v.in.OrgID == "" || g.OrgID != v.in.OrgID {
		return Grant{}, fail(CodeWrongOrg, "grant %s is for org %s", g.GrantID, g.OrgID)
	}
	switch {
	case !v.in.Now.Before(g.ExpiresAt):
		return Grant{}, fail(CodeExpired, "grant %s expired at %s%s", g.GrantID, g.ExpiresAt.Format(time.RFC3339), v.in.Clock.ref())
	case g.IssuedAt.After(v.in.Now.Add(maxIssueSkew)):
		return Grant{}, fail(CodeInvalid, "grant %s is issued in the future%s", g.GrantID, v.in.Clock.ref())
	case g.ExpiresAt.After(key.NotAfter):
		return Grant{}, fail(CodeInvalid, "grant %s outlives its signing key", g.GrantID)
	}
	if err := v.checkScope(g); err != nil {
		return Grant{}, err
	}
	g.KeyID, g.Source = vd.KeyID, SourceProfile
	if v.compiled[vd.KeyID] {
		g.Source = SourceKeyring
	}
	g.Digest, g.PayloadDigest = digest(env), digest(vd.Payload)
	return g, nil
}

// checkScope matches only the trusted workspace and environment. A grant
// without environments is not environment-scoped, so
// forbid_environment_scoped (environment as a narrowing scope, owner
// 2026-10-05) does not apply to it; barring every grant for a control is
// forbid_controls / coverability.
func (v *Verifier) checkScope(g Grant) error {
	t := v.in.Table
	if err := t.CheckScope(g.Workspaces, g.Environments, false); err != nil { // false: a grant is not a sidecar entry
		return &GrantError{Code: CodeScopeUntrusted, Detail: fmt.Sprintf("grant %s: %v", g.GrantID, err), Err: err}
	}
	if len(g.Workspaces) > 0 && !slices.Contains(g.Workspaces, t.Workspace.Value) {
		return fail(CodeWrongWorkspace, "grant %s does not list workspace %s", g.GrantID, t.Workspace.Value)
	}
	if len(g.Environments) == 0 {
		return nil
	}
	if !slices.Contains(g.Environments, t.Environment.Value) {
		return fail(CodeWrongEnvironment, "grant %s does not list environment %s", g.GrantID, t.Environment.Value)
	}
	if t.Exceptions != nil {
		for _, c := range g.Controls {
			if slices.ContainsFunc(t.Exceptions.ForbidEnvironmentScoped, func(f string) bool { return strings.EqualFold(f, c) }) {
				return fail(CodeEnvironmentForbidden, "grant %s: control %s may not be excepted per environment", g.GrantID, c)
			}
		}
	}
	return nil
}

func digest(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}
