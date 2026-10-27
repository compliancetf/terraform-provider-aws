// Package baseline loads the customer-signed grandfather baseline
// `compliancetf.baseline/v1` and matches its entries. It replaces the stub that
// grandfathered nothing.
//
// Load runs at ConfigureProvider and fails closed: a baseline file that does
// not verify fails Configure, it is never ignored. Grandfathered matches per
// instance and control at apply; every check fails closed, so an entry
// grandfathers only an exact match. Errors and reasons are value-free: they
// name control ids, digests, majors, epochs and entry indexes, never
// attribute values, identities, file paths or OS errors.
//
// The baseline document, the approver statement and the read digest are
// defined here; ctfkit implements the same formats.
package baseline

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
	"github.com/compliancetf/terraform-provider-aws/internal/verdict"
)

const (
	Format          = "compliancetf.baseline/v1"
	StatementFormat = "compliancetf.baseline-approval/v1"
	RoleApprover    = "baseline_approver"

	EnvFile    = "COMPLIANCETF_BASELINE_FILE"
	EnvKeyFile = "COMPLIANCETF_BASELINE_KEY_FILE"

	MaxBytes = 8 << 20 // baseline file limit

	// ErrNoKey is the normative text for a baseline without its key file.
	ErrNoKey = "Baseline file present but COMPLIANCETF_BASELINE_KEY_FILE is not set: grandfather cannot be evaluated"
)

// Document is the signed baseline. Every member is a string, array or
// object (no numbers), so B1 has no JCS number caveat.
type Document struct {
	Format        string            `json:"format"`
	OrgID         string            `json:"org_id"`
	IssuedAt      string            `json:"issued_at"`
	ContentDigest string            `json:"content_digest"`
	Entries       []Entry           `json:"entries"`
	Signature     verdict.Signature `json:"signature"`
}

// Entry is one grandfathered (instance, control). Identity is the plaintext
// identity object (identity_kind identity) or {"id": <id>} (kind id).
type Entry struct {
	Workspace             string            `json:"workspace"`
	Scope                 Scope             `json:"scope"`
	Type                  string            `json:"type"`
	IdentityKind          string            `json:"identity_kind"`
	Identity              map[string]string `json:"identity"`
	Address               string            `json:"address"`
	Control               string            `json:"control"`
	ControlMajor          string            `json:"control_major"`
	ControlManifestDigest string            `json:"control_manifest_digest"`
	ReadDigest            string            `json:"read_digest"`
	ApproverStatement     Statement         `json:"approver_statement"`
	Approver              string            `json:"approver"`
	Expires               string            `json:"expires"`
	Ticket                string            `json:"ticket"`
}

type Scope struct {
	AccountID string `json:"account_id"`
	Region    string `json:"region"`
}

// Statement is the app-signed approver-role statement (F6): signed
// with a compliance.tf key of the profile's break_glass.receipt_keys.
type Statement struct {
	Format        string            `json:"format"`
	OrgID         string            `json:"org_id"`
	Role          string            `json:"role"`
	Subject       string            `json:"subject"`
	Workspace     string            `json:"workspace"`
	Scope         Scope             `json:"scope"`
	RunID         string            `json:"run_id"`
	PlanDigest    string            `json:"plan_digest"`
	ContentDigest string            `json:"content_digest"`
	IssuedAt      string            `json:"issued_at"`
	Signature     verdict.Signature `json:"signature"`
}

// Set is a verified baseline. A nil *Set grandfathers nothing.
type Set struct {
	org       string
	kid       string // the baseline signing key
	key       []byte // the org baseline key (B4)
	entries   []Entry
	digests   []string // digests[i]: sha256 over JCS of entries[i]
	revs      trust.Revocations
	coverable func(control string) bool
}

// LoadInput is the Configure context of a baseline. Path is the baseline
// file ("" none); Key and KeyErr are what ReadKey returned for the baseline
// key file, read once per Configure so matching and evidence read digests
// use the same bytes. Profile is the floor-validated signed profile, the
// only source of trusted keys; Coverable reports whether the signed
// coverable map lists baseline for a control.
type LoadInput struct {
	Path        string
	Key         []byte
	KeyErr      error
	Profile     *profile.Profile
	Revocations trust.Revocations
	Coverable   func(control string) bool
	Now         time.Time
}

// ErrKeyUnusable is ReadKey's error for a key file that is not a usable key.
var ErrKeyUnusable = errors.New("COMPLIANCETF_BASELINE_KEY_FILE must name a regular file owned by this user that group and others cannot read, holding 64 lowercase hex characters")

// ReadKey reads the baseline key file at path: nil, nil when path is ""
// (COMPLIANCETF_BASELINE_KEY_FILE unset), ErrKeyUnusable when the file is
// not a usable key.
func ReadKey(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	key, ok := verdict.ReadSecretFile(path)
	if !ok {
		return nil, ErrKeyUnusable
	}
	return key, nil
}

var (
	reDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	reMajor  = regexp.MustCompile(`^(0|[1-9][0-9]{0,17})$`)
)

// Load returns nil, nil without a baseline file; otherwise the verified set
// or an error that fails Configure.
func Load(in LoadInput) (*Set, error) {
	if in.Path == "" {
		return nil, nil
	}
	if in.Key == nil && in.KeyErr == nil {
		return nil, errors.New(ErrNoKey) //nolint:staticcheck // normative text
	}
	if in.Profile == nil || in.Profile.Baseline == nil {
		return nil, errors.New("a baseline file is set, but the signed profile lists no baseline keys")
	}
	if in.KeyErr != nil {
		return nil, fmt.Errorf("%w: grandfather cannot be evaluated", in.KeyErr)
	}
	key := in.Key
	raw, err := readFile(in.Path)
	if err != nil {
		return nil, err
	}
	doc, signed, err := parse[Document](raw, Format)
	if err != nil {
		return nil, fmt.Errorf("baseline file: %w", err)
	}
	issued, err := parseUTC(doc.IssuedAt)
	switch {
	case err != nil:
		return nil, errors.New("baseline issued_at must be an RFC 3339 UTC time")
	case issued.After(in.Now.Add(verdict.Skew)):
		return nil, errors.New("baseline issued_at lies in the future")
	}
	if reason := verify(doc.Signature, signed, in, verdict.UseBaseline, issued); reason != "" {
		return nil, fmt.Errorf("baseline signature invalid: %s", reason)
	}
	switch {
	case doc.OrgID != in.Profile.OrgID:
		return nil, errors.New("baseline issued for another org than the profile")
	case !reDigest.MatchString(doc.ContentDigest):
		return nil, errors.New("baseline content_digest is not a sha256 digest")
	}
	s := &Set{org: doc.OrgID, kid: doc.Signature.KID, key: key, entries: doc.Entries, revs: in.Revocations, coverable: in.Coverable}
	maxLife := time.Duration(in.Profile.Baseline.MaxDays) * 24 * time.Hour
	for i := range doc.Entries {
		if err := checkEntry(&doc.Entries[i], doc, issued, maxLife, in); err != nil {
			return nil, fmt.Errorf("baseline entry %d: %w", i, err)
		}
		d, err := digestJSON(doc.Entries[i])
		if err != nil {
			return nil, fmt.Errorf("baseline entry %d: %w", i, err)
		}
		s.digests = append(s.digests, d)
	}
	return s, nil
}

// checkEntry validates an entry and verifies its approver statement.
func checkEntry(e *Entry, doc *Document, issued time.Time, maxLife time.Duration, in LoadInput) error {
	expires, err := parseUTC(e.Expires)
	switch {
	case err != nil:
		return errors.New("expires must be an RFC 3339 UTC time")
	case expires.Sub(issued) > maxLife:
		return errors.New("expires lies beyond the profile baseline.max_days")
	case e.Workspace == "" || e.Scope.AccountID == "" || e.Scope.Region == "" || e.Type == "" || e.Address == "" || e.Control == "":
		return errors.New("workspace, scope, type, address and control must be set")
	case !validIdentity(e.IdentityKind, e.Identity):
		return errors.New("identity_kind must be identity or id with a non-empty identity")
	case !reMajor.MatchString(e.ControlMajor):
		return errors.New("control_major must be a decimal integer")
	case !reDigest.MatchString(e.ControlManifestDigest) || !reDigest.MatchString(e.ReadDigest):
		return errors.New("control_manifest_digest and read_digest must be sha256 digests")
	case e.Approver == "":
		return errors.New("approver must be set")
	}
	st := e.ApproverStatement
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	_, signed, ok := verdict.SignedBytes(raw)
	if !ok {
		return errors.New("approver_statement is not a signed document")
	}
	stIssued, err := parseUTC(st.IssuedAt)
	if err != nil || stIssued.After(in.Now.Add(verdict.Skew)) {
		return errors.New("approver_statement issued_at must be a past RFC 3339 UTC time")
	}
	if verify(st.Signature, signed, in, verdict.UseReceipt, stIssued) != "" {
		return errors.New("approver_statement signature invalid")
	}
	switch {
	case st.Format != StatementFormat || st.Role != RoleApprover:
		return errors.New("approver_statement is not a baseline_approver statement")
	case st.Subject != e.Approver:
		return errors.New("approver does not equal the approver_statement subject")
	case st.OrgID != doc.OrgID || st.Workspace != e.Workspace || st.Scope != e.Scope || st.ContentDigest != doc.ContentDigest:
		return errors.New("approver_statement is bound to another org, scope or content digest")
	case st.RunID == "" || !reDigest.MatchString(st.PlanDigest):
		return errors.New("approver_statement must bind the observation run_id and plan_digest")
	}
	return nil
}

// verify returns "" when sig verifies over signed with a use key of the
// profile that is valid both now and at issued, and whose kid neither the
// profile nor a merged revocation lists (VerifySignature); else a fixed
// reason.
func verify(sig verdict.Signature, signed []byte, in LoadInput, use string, issued time.Time) string {
	for _, at := range []time.Time{in.Now, issued} {
		if reason := verdict.VerifySignature(sig, signed, in.Profile, in.Revocations, use, at); reason != "" {
			return reason
		}
	}
	return ""
}

func validIdentity(kind string, id map[string]string) bool {
	if kind == "id" && (len(id) != 1 || id["id"] == "") || kind != "id" && kind != "identity" || len(id) == 0 {
		return false
	}
	for _, v := range id {
		if v == "" {
			return false
		}
	}
	return true
}

// parse decodes raw strictly: I-JSON, strings, arrays and objects only, and
// the typed document must re-encode to the same JCS bytes (no unknown,
// missing or case-variant member). It returns the document and its signed
// bytes.
func parse[T any](raw []byte, format string) (*T, []byte, error) {
	errDoc := fmt.Errorf("not a %s document", format)
	canon, signed, ok := verdict.SignedBytes(raw)
	if !ok {
		return nil, nil, errDoc
	}
	var doc T
	if json.Unmarshal(canon, &doc) != nil {
		return nil, nil, errDoc
	}
	re, err := json.Marshal(&doc)
	if err == nil {
		re, err = bundle.CanonicalJSON(re)
	}
	var head struct{ Format string }
	if err != nil || string(re) != string(canon) || json.Unmarshal(canon, &head) != nil || head.Format != format {
		return nil, nil, errDoc
	}
	return &doc, signed, nil
}

func readFile(path string) ([]byte, error) {
	f, fi, err := verdict.OpenNoFollow(path)
	if err != nil {
		return nil, errors.New("the baseline file cannot be opened as a regular file without following a symlink")
	}
	defer f.Close() //nolint:errcheck // read-only
	if !fi.Mode().IsRegular() || fi.Size() > MaxBytes {
		return nil, errors.New("the baseline file is not a regular file of at most 8 MiB")
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxBytes+1))
	if err != nil || len(b) > MaxBytes {
		return nil, errors.New("the baseline file cannot be read")
	}
	return b, nil
}

// digestJSON is sha256 over JCS of v.
func digestJSON(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return bundle.DigestJSON(b)
}

func parseUTC(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil || len(s) == 0 || s[len(s)-1] != 'Z' {
		return time.Time{}, errors.New("not an RFC 3339 UTC time")
	}
	return t, nil
}

// major is the semver major of a control version, -1 when it has none.
func major(version string) int64 {
	for i, r := range version {
		if r == '.' {
			version = version[:i]
			break
		}
	}
	m, err := strconv.ParseInt(version, 10, 64)
	if err != nil {
		return -1
	}
	return m
}
