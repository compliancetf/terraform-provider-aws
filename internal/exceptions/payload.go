// Package exceptions verifies signed exception grants.
package exceptions

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/engine/celeng"
)

// Format is the grant payload format.
const Format = "compliancetf.exception-grant/v1"

// Grant is a verified grant: signature, key window, payload shape,
// approvers, org, expiry and trusted scope checked. Honoring it also needs
// Coverability.GrantCoverable, the content_digest / floor_epoch binding
// and an honor-time clock check. Callers never
// re-parse the payload.
type Grant struct {
	Format        string     `json:"format"`
	GrantID       string     `json:"grant_id"`
	OrgID         string     `json:"org_id"`
	Workspaces    []string   `json:"workspaces"`
	Controls      []string   `json:"controls"`
	Selector      string     `json:"selector"` // CEL
	Environments  []string   `json:"environments"`
	Reason        string     `json:"reason"`
	Ticket        string     `json:"ticket"`
	Approvers     []Approver `json:"approvers"`
	ContentDigest string     `json:"content_digest"`
	FloorEpoch    int64      `json:"floor_epoch"` // validated here, bound by the grant check
	IssuedAt      time.Time  `json:"issued_at"`
	ExpiresAt     time.Time  `json:"expires_at"`

	KeyID         string `json:"-"` // first accepted signature (trust contract)
	Source        string `json:"-"` // SourceKeyring or SourceProfile
	Digest        string `json:"-"` // sha256 of the envelope bytes: audit id only
	PayloadDigest string `json:"-"` // sha256 of the verified payload bytes

	sel *celeng.Selector // Selector compiled at verification
}

// Approver is an authenticated identity recorded by the signer.
type Approver struct {
	Subject string `json:"subject"`
	Issuer  string `json:"issuer"`
}

var (
	grantIDRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	controlRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	digestRE   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	visibleRE  = regexp.MustCompile(`^[\x21-\x7e]+$`)
	hostRE     = regexp.MustCompile(`^[a-z0-9-]+(\.[a-z0-9-]+)*$`)
	segmentRE  = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)
	required   = []string{"format", "grant_id", "org_id", "controls", "selector", "reason", "approvers", "content_digest", "floor_epoch", "issued_at", "expires_at"}
	errNull    = errors.New("null value")
	errMissing = errors.New("missing member")
)

// parse decodes a verified payload: trust already rejected duplicate
// (case-folded) members, depth > 32 and trailing values. Here: no null
// anywhere, required members present, unknown members rejected, then the
// field grammars.
func parse(payload []byte) (Grant, error) {
	var raw any
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return Grant{}, errors.New("payload is not JSON")
	}
	if hasNull(raw) {
		return Grant{}, errNull
	}
	top := obj(raw)
	if err := present(top, required...); err != nil {
		return Grant{}, err
	}
	for _, a := range asList(top["approvers"]) {
		if err := present(a, "subject", "issuer"); err != nil {
			return Grant{}, fmt.Errorf("approvers: %w", err)
		}
	}
	var g Grant
	sd := json.NewDecoder(bytes.NewReader(payload))
	sd.DisallowUnknownFields()
	if err := sd.Decode(&g); err != nil {
		return Grant{}, errors.New("payload does not match the grant schema")
	}
	return g, g.validate()
}

func hasNull(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case map[string]any:
		for _, e := range x {
			if hasNull(e) {
				return true
			}
		}
	case []any:
		return slices.ContainsFunc(x, hasNull)
	}
	return false
}

func asList(v any) []map[string]any {
	l, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(l))
	for _, e := range l {
		out = append(out, obj(e))
	}
	return out
}

// obj is v as a JSON object, nil when it is not one.
func obj(v any) map[string]any {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	return m
}

func present(m map[string]any, keys ...string) error {
	if m == nil {
		return errors.New("not an object")
	}
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			return fmt.Errorf("%w %s", errMissing, k)
		}
	}
	return nil
}

func (g *Grant) validate() error {
	switch {
	case g.Format != Format:
		return errors.New("format")
	case !grantIDRE.MatchString(g.GrantID):
		return errors.New("grant_id")
	case g.OrgID == "":
		return errors.New("org_id")
	case len(g.Controls) == 0 || len(g.Controls) > 64:
		return errors.New("controls: want 1 to 64")
	case len(g.Reason) == 0 || len(g.Reason) > 1024 || len(g.Ticket) > 256:
		return errors.New("reason or ticket length")
	case !digestRE.MatchString(g.ContentDigest):
		return errors.New("content_digest")
	case g.FloorEpoch < 0:
		return errors.New("floor_epoch is negative")
	case !g.IssuedAt.Before(g.ExpiresAt):
		return errors.New("issued_at is not before expires_at")
	}
	seen := map[string]bool{}
	for _, c := range g.Controls {
		if !controlRE.MatchString(c) || seen[strings.ToLower(c)] {
			return errors.New("controls: bad or duplicate id")
		}
		seen[strings.ToLower(c)] = true
	}
	for name, l := range map[string][]string{"workspaces": g.Workspaces, "environments": g.Environments} {
		if len(l) > 64 {
			return fmt.Errorf("%s: more than 64", name)
		}
		for i, s := range l {
			if len(s) > 128 || !visibleRE.MatchString(s) || slices.Contains(l[:i], s) {
				return fmt.Errorf("%s: bad or duplicate entry", name)
			}
		}
	}
	sel, err := compileSelector(g.Selector)
	if err != nil {
		return fmt.Errorf("exception %s: %w", g.GrantID, err)
	}
	g.sel = sel
	return nil
}

// compileSelector compiles a grant selector or sidecar match; the error is
// "match: " and a position or fixed reason, never the expression text.
func compileSelector(expr string) (*celeng.Selector, error) {
	sel, err := celeng.CompileSelector(expr)
	if err != nil {
		return nil, fmt.Errorf("match: %w", err)
	}
	return sel, nil
}

// checkApprovers: 2 to 16 authenticated identities with distinct subjects
// (case-folded) and canonical https issuers; the same rule for compiled and
// customer keys.
func checkApprovers(as []Approver) error {
	if len(as) < 2 || len(as) > 16 {
		return errors.New("want 2 to 16 approvers")
	}
	seen := map[string]bool{}
	for _, a := range as {
		s := strings.ToLower(a.Subject)
		if len(a.Subject) > 256 || !visibleRE.MatchString(a.Subject) || seen[s] {
			return errors.New("approver subject is malformed or repeated")
		}
		seen[s] = true
		if !canonicalIssuer(a.Issuer) {
			return errors.New("approver issuer is not a canonical https URL")
		}
	}
	return nil
}

// canonicalIssuer: https://host[/seg...] with a lower-case DNS host and no
// port, userinfo, query, fragment, percent escape, dot segment or trailing
// slash. Non-canonical issuers are rejected, never normalized.
func canonicalIssuer(s string) bool {
	rest, ok := strings.CutPrefix(s, "https://")
	if !ok || len(s) > 256 {
		return false
	}
	host, path, _ := strings.Cut(rest, "/")
	if !hostRE.MatchString(host) {
		return false
	}
	if path == "" {
		return !strings.HasSuffix(rest, "/")
	}
	for _, seg := range strings.Split(path, "/") {
		if !segmentRE.MatchString(seg) || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}
