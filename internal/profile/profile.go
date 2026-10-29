package profile

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

// Format is the only accepted profile format.
const Format = "compliancetf.profile/v1"

const (
	maxLifetime = 30 * 24 * time.Hour
	FloorOnline = "online"
	FloorAirgap = "airgap"
)

var (
	orgRE       = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	semverRE    = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$`)
	exemptKinds = []string{"grant", "baseline", "break_glass", "self_service"}
)

// verifyEnvelope is trust.Verify for profiles. Only in-package tests replace
// it; no exported seam can add keys.
var verifyEnvelope = func(env []byte, revs trust.Revocations) (trust.Verified, error) {
	return trust.Verify(env, trust.PayloadProfile, revs)
}

// Profile is a verified, validated org profile. It is always applied whole:
// no caller merges fields from two profiles.
type Profile struct {
	Format            string          `json:"format"`
	OrgID             string          `json:"org_id"`
	ProfileVersion    int64           `json:"profile_version"`
	IssuedAt          time.Time       `json:"issued_at"`
	ExpiresAt         time.Time       `json:"expires_at"`
	Governed          bool            `json:"governed"`
	MinWrapperVersion string          `json:"min_wrapper_version,omitempty"`
	ModeFloor         ModeFloor       `json:"mode_floor"`
	Scope             *Scope          `json:"scope,omitempty"`
	FloorMode         string          `json:"floor_mode,omitempty"`
	FloorAirgapPath   string          `json:"floor_airgap_path,omitempty"`
	ControlFloors     map[string]Mode `json:"control_floors,omitempty"`
	VerdictRequired   bool            `json:"verdict_required"`
	DataSources       string          `json:"data_sources,omitempty"` // advisory (default) or deny
	Bundles           []BundleMin     `json:"bundles,omitempty"`
	Exceptions        Exceptions      `json:"exceptions"`
	Evidence          Evidence        `json:"evidence"`
	Budgets           Budgets         `json:"budgets"`
	// Verdict, Baseline, BreakGlass and RevokedKIDs are the verdict gate fields;
	// nil when absent.
	Verdict     *Verdict    `json:"verdict,omitempty"`
	Baseline    *Baseline   `json:"baseline,omitempty"`
	BreakGlass  *BreakGlass `json:"break_glass,omitempty"`
	RevokedKIDs []string    `json:"revoked_kids,omitempty"` // verdict, baseline and receipt key ids no longer trusted

	Digest string `json:"-"` // "sha256:" hex of the signed payload bytes
}

type ModeFloor struct {
	Default      Mode            `json:"default"`
	Environments map[string]Mode `json:"environments,omitempty"`
}

// Scope is the gate-asserted context of a profile issued to one workspace;
// the mode table treats it as trusted context, it never filters selection.
type Scope struct {
	Environment string `json:"environment,omitempty"`
	Workspace   string `json:"workspace,omitempty"`
}

type BundleMin struct {
	BundleID   string `json:"bundle_id"`
	MinVersion int64  `json:"min_version"`
}

type Exceptions struct {
	// Coverable is parsed and validated (a null list or an unknown kind
	// still rejects the profile) but never read: only the bundle's
	// exemption_coverable declares coverability. Profiles signed with it
	// keep loading.
	Coverable               map[string][]string `json:"coverable,omitempty"`
	SelfService             []string            `json:"self_service,omitempty"`
	MaxLifetimeDays         int64               `json:"max_lifetime_days,omitempty"`
	ForbidControls          []string            `json:"forbid_controls,omitempty"`
	ForbidEnvironmentScoped []string            `json:"forbid_environment_scoped,omitempty"`
	GrantKeys               []GrantKey          `json:"grant_keys,omitempty"`
}

// GrantKey is a customer KMS key allowed to sign exception grants.
type GrantKey struct {
	KID       string    `json:"kid"`
	Alg       string    `json:"alg"`
	SPKIB64   string    `json:"spki_b64"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
}

// Verdict configures the customer-signed verdict.
type Verdict struct {
	PublicKeys []SignerKey `json:"public_keys,omitempty"` // use "verdict"
	// MaxTTL bounds a verdict's expires_at - issued_at: a Go duration,
	// at most 72h; DefaultVerdictTTL when absent (VerdictTTL).
	MaxTTL string `json:"max_ttl,omitempty"`
	// GraphUnknown is "pending" (the default when absent) or "block".
	GraphUnknown string `json:"graph_unknown,omitempty"`
}

// Baseline configures customer-signed grandfather baselines.
type Baseline struct {
	PublicKeys []SignerKey `json:"public_keys,omitempty"` // use "baseline"
	MaxDays    int64       `json:"max_days,omitempty"`    // entry lifetime limit; required with public_keys
}

// BreakGlass configures break-glass; receipts verify only against
// ReceiptKeys (compliance.tf keys, use "receipt").
type BreakGlass struct {
	Enabled     bool        `json:"enabled"`
	ReceiptKeys []SignerKey `json:"receipt_keys,omitempty"`
}

// SignerKey is a verdict, baseline or break_glass signing key listed in the profile:
// {kid, alg, use, spki_b64, not_before, not_after}.
type SignerKey struct {
	KID       string    `json:"kid"`
	Alg       string    `json:"alg"`
	Use       string    `json:"use"`
	SPKIB64   string    `json:"spki_b64"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
}

const (
	DefaultVerdictTTL = 24 * time.Hour
	maxVerdictTTL     = 72 * time.Hour

	GraphUnknownPending = "pending"
	GraphUnknownBlock   = "block"
)

// VerdictTTL is verdict.max_ttl, DefaultVerdictTTL when unset or p is nil.
func (p *Profile) VerdictTTL() time.Duration {
	if p != nil && p.Verdict != nil && p.Verdict.MaxTTL != "" {
		if d, err := time.ParseDuration(p.Verdict.MaxTTL); err == nil { // Parse validated it
			return d
		}
	}
	return DefaultVerdictTTL
}

// GraphUnknown is verdict.graph_unknown, GraphUnknownPending when unset or
// p is nil.
func (p *Profile) GraphUnknown() string {
	if p != nil && p.Verdict != nil && p.Verdict.GraphUnknown != "" {
		return p.Verdict.GraphUnknown
	}
	return GraphUnknownPending
}

type Evidence struct {
	Required bool            `json:"required"`
	Sinks    json.RawMessage `json:"sinks,omitempty"`
}

type Budgets struct {
	PerResourceMs int64 `json:"per_resource_ms,omitempty"`
	PerRunS       int64 `json:"per_run_s,omitempty"`
}

// Parse decodes and validates a payload returned by trust.Verify for
// trust.PayloadProfile (which already rejected duplicate member names). It
// returns warnings for clamped budgets.
func Parse(payload []byte) (*Profile, []string, error) {
	var p Profile
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		// The decoder text quotes member names and values; errors name the
		// field only, never a value of the signed payload.
		return nil, nil, errors.New("profile: unknown member or invalid value (types, RFC 3339 times, enforcement modes)")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, nil, errors.New("profile: trailing data")
	}
	if err := p.validate(); err != nil {
		return nil, nil, fmt.Errorf("profile: %w", err)
	}
	sum := sha256.Sum256(payload)
	p.Digest = "sha256:" + hex.EncodeToString(sum[:])
	return &p, p.clampBudgets(), nil
}

func (p *Profile) validate() error {
	switch {
	case p.Format != Format:
		return fmt.Errorf("format is not %q", Format)
	case !orgRE.MatchString(p.OrgID):
		return fmt.Errorf("org_id: want %s", orgRE)
	case p.ProfileVersion < 1:
		return errors.New("profile_version must be >= 1")
	case !p.IssuedAt.Before(p.ExpiresAt):
		return errors.New("expires_at must be after issued_at")
	case p.ExpiresAt.Sub(p.IssuedAt) > maxLifetime:
		return errors.New("lifetime exceeds 30 days")
	}
	if p.MinWrapperVersion != "" && !semverRE.MatchString(p.MinWrapperVersion) {
		return errors.New("min_wrapper_version: want a semantic version")
	}
	switch p.FloorMode {
	case FloorOnline, FloorAirgap:
	case "":
		if p.Governed || len(p.Bundles) > 0 {
			return errors.New("floor_mode is required when governed or bundles are set")
		}
	default:
		return errors.New("floor_mode: want online or airgap")
	}
	if p.FloorAirgapPath != "" && p.FloorMode != FloorAirgap {
		return errors.New("floor_airgap_path needs floor_mode airgap")
	}
	if _, err := ParseDataSources(p.DataSources); err != nil {
		return errors.New("data_sources: want advisory or deny")
	}
	if p.Scope != nil && p.Scope.Environment == "" && p.Scope.Workspace == "" {
		return errors.New("scope is empty")
	}
	seen := map[string]bool{}
	for i, b := range p.Bundles {
		if b.BundleID == "" || b.MinVersion < 1 || seen[b.BundleID] {
			return fmt.Errorf("bundles: bad or duplicate entry %d", i)
		}
		seen[b.BundleID] = true
	}
	if err := p.Exceptions.validate(p.ExpiresAt); err != nil {
		return fmt.Errorf("exceptions: %w", err)
	}
	return p.validatePhase3()
}

var kidRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// validatePhase3 checks the verdict, baseline, break_glass and revoked_kids
// fields. Errors name the field, never a value.
func (p *Profile) validatePhase3() error {
	if v := p.Verdict; v != nil {
		if err := validateKeys("verdict.public_keys", "verdict", v.PublicKeys, p.ExpiresAt); err != nil {
			return err
		}
		if v.MaxTTL != "" {
			d, err := time.ParseDuration(v.MaxTTL)
			if err != nil || d <= 0 || d > maxVerdictTTL {
				return errors.New("verdict.max_ttl: want a duration above 0 and at most 72h")
			}
		}
		switch v.GraphUnknown {
		case "":
			v.GraphUnknown = GraphUnknownPending
		case GraphUnknownPending, GraphUnknownBlock:
		default:
			return errors.New("verdict.graph_unknown: want pending or block")
		}
	}
	if b := p.Baseline; b != nil {
		if err := validateKeys("baseline.public_keys", "baseline", b.PublicKeys, p.ExpiresAt); err != nil {
			return err
		}
		if b.MaxDays < 0 || len(b.PublicKeys) > 0 && b.MaxDays == 0 {
			return errors.New("baseline.max_days: want a positive number of days with public_keys")
		}
	}
	if bg := p.BreakGlass; bg != nil {
		if err := validateKeys("break_glass.receipt_keys", "receipt", bg.ReceiptKeys, p.ExpiresAt); err != nil {
			return err
		}
		// Without floor_mode online or receipt_keys no receipt is ever
		// honored: stricter, so not rejected.
		if bg.Enabled && p.FloorMode == FloorAirgap {
			return errors.New("break_glass is unavailable with floor_mode airgap")
		}
	}
	for i, k := range p.RevokedKIDs {
		if !kidRE.MatchString(k) || slices.Contains(p.RevokedKIDs[:i], k) {
			return fmt.Errorf("revoked_kids: bad or duplicate entry %d", i)
		}
	}
	return nil
}

// validateKeys checks a verdict, baseline or break_glass key list as grant keys are checked (alg
// allowlist, kid = B5 of spki_b64, key type) plus use and unique kids, and
// limits each window to the profile's expires_at.
func validateKeys(field, use string, keys []SignerKey, expires time.Time) error {
	for i := range keys {
		k := &keys[i]
		switch {
		case k.Use != use:
			return fmt.Errorf("%s %d: use must be %s", field, i, use)
		case k.Alg != trust.AlgES256 && (k.Alg != trust.AlgEd25519 || !allowEd25519):
			return fmt.Errorf("%s %d: alg not allowed", field, i)
		}
		der, err := base64.StdEncoding.Strict().DecodeString(k.SPKIB64)
		if err != nil || trust.KIDFromSPKI(der) != k.KID {
			return fmt.Errorf("%s %d: kid does not match spki_b64", field, i)
		}
		if slices.ContainsFunc(keys[:i], func(o SignerKey) bool { return o.KID == k.KID }) {
			return fmt.Errorf("%s %d: duplicate kid", field, i)
		}
		if err := checkKeyAlg(der, k.Alg); err != nil {
			return fmt.Errorf("%s %d: %w", field, i, err)
		}
		if k.NotAfter.After(expires) {
			k.NotAfter = expires
		}
		if !k.NotBefore.Before(k.NotAfter) {
			return fmt.Errorf("%s %d: empty validity window", field, i)
		}
	}
	return nil
}

// Forbidden reports whether forbid_controls lists id. It matches
// case-insensitively, deliberately wider than the exact coverable keys
// (fail-closed, as forbid_environment_scoped).
func (e *Exceptions) Forbidden(id string) bool {
	return e != nil && slices.ContainsFunc(e.ForbidControls, func(f string) bool { return strings.EqualFold(f, id) })
}

// CheckSelfService rejects the profile when a self_service id is not
// coverable for self_service on the effective coverable map (bundle
// lists, forbid_controls applied): selfService reports
// that for one id. Configure calls it on every run, so a bundle that drops
// self_service from a control fails Configure for a profile still listing
// it. A nil receiver (no signed profile) has no self_service ids.
func (e *Exceptions) CheckSelfService(selfService func(id string) bool) error {
	if e == nil {
		return nil
	}
	for _, id := range e.SelfService {
		if !selfService(id) {
			return fmt.Errorf("self_service_not_coverable: self_service control %s is not exemption-coverable for self_service", id)
		}
	}
	return nil
}

// validate also limits each grant key window to the profile's expires_at:
// the profile is the only statement that vouches for the key.
func (e *Exceptions) validate(expires time.Time) error {
	for _, kinds := range e.Coverable {
		if kinds == nil { // JSON null: not a list
			return errors.New("coverable: want a list of exemption kinds")
		}
		for _, k := range kinds {
			if !slices.Contains(exemptKinds, k) {
				return errors.New("coverable: unknown exemption kind")
			}
		}
	}
	for _, id := range e.SelfService {
		if e.Forbidden(id) {
			return errors.New("self_service_not_coverable: a self_service control is in forbid_controls")
		}
	}
	if e.MaxLifetimeDays < 0 {
		return errors.New("max_lifetime_days is negative")
	}
	for i := range e.GrantKeys {
		k := &e.GrantKeys[i]
		if k.Alg != trust.AlgES256 && (k.Alg != trust.AlgEd25519 || !allowEd25519) {
			return fmt.Errorf("grant key %d: alg not allowed", i)
		}
		der, err := base64.StdEncoding.Strict().DecodeString(k.SPKIB64)
		if err != nil || trust.KIDFromSPKI(der) != k.KID {
			return fmt.Errorf("grant key %d: kid does not match spki_b64", i)
		}
		if err := checkKeyAlg(der, k.Alg); err != nil {
			return fmt.Errorf("grant key %d: %w", i, err)
		}
		if k.NotAfter.After(expires) {
			k.NotAfter = expires
		}
		if !k.NotBefore.Before(k.NotAfter) {
			return fmt.Errorf("grant key %d: empty validity window", i)
		}
	}
	return nil
}

// checkKeyAlg: the SPKI must be the key type its alg names, as for keyring
// entries (trust.parseKeyEntry).
func checkKeyAlg(der []byte, alg string) error {
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return errors.New("spki_b64 is not a PKIX public key")
	}
	ec, isEC := pub.(*ecdsa.PublicKey)
	_, isEd := pub.(ed25519.PublicKey)
	switch {
	case alg == trust.AlgES256 && (!isEC || ec.Curve != elliptic.P256()):
		return errors.New("spki_b64 is not an ES256 (P-256) key")
	case alg == trust.AlgEd25519 && !isEd:
		return errors.New("spki_b64 is not an Ed25519 key")
	case alg != trust.AlgES256 && alg != trust.AlgEd25519:
		return errors.New("alg not allowed")
	}
	return nil
}

func clamp(name string, v *int64, lo, hi int64) []string {
	if *v == 0 || (*v >= lo && *v <= hi) {
		return nil
	}
	c := min(max(*v, lo), hi)
	w := fmt.Sprintf("profile budget %s %d clamped to %d", name, *v, c)
	*v = c
	return []string{w}
}

func (p *Profile) clampBudgets() []string {
	return append(clamp("per_resource_ms", &p.Budgets.PerResourceMs, 10, 5000),
		clamp("per_run_s", &p.Budgets.PerRunS, 10, 600)...)
}

// CheckWrapper fails when provider version v is below minimum m (trust.CheckWrapper).
func CheckWrapper(v, m string) error { return trust.CheckWrapper(v, m) }
