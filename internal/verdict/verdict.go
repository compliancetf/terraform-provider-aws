// Package verdict loads and verifies the customer-signed verdict.
// It is read only at the
// first ApplyResourceChange of the process (Lazy), never at Configure, plan,
// read or import. Every check fails closed; diagnostics carry fixed text or
// values of the signature-verified document and the loaded configuration,
// never file contents, paths or OS errors.
//
// Check order: verdict file, document, signature, key file, lifetime, org,
// profile, bundle, content, scope, provider versions. The key file runs right after
// the signature (design panel) so a caller without the run key never
// learns which loaded digest differs.
//
// This package holds the provider side of B1 (JCS signed bytes), B5 (kid)
// and the key check.
package verdict

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

const (
	Format = "compliancetf.verdict/v1"

	EnvVerdict = "COMPLIANCETF_VERDICT"
	EnvKeyFile = "COMPLIANCETF_VERDICT_KEY_FILE"

	MaxBytes = 32 << 20 // verdict file limit

	// Skew is the clock skew allowed on issued_at, expires_at, not_before
	// and not_after.
	Skew = 5 * time.Minute

	infoLeaf  = "compliancetf.verdict/v1 leaf"
	infoCheck = "compliancetf.verdict/v1 key-check"

	testSecret = "INSECURE-TEST-SECRET-instancekey" // instance_key FORMAT.md v1
)

// Diagnostic summaries.
const (
	SummaryInvalid   = "Invalid verdict file"
	SummaryKey       = "Verdict key missing or does not belong to this verdict: run apply through ctfkit apply"
	prefixSignature  = "Verdict signature invalid: "
	detailReRun      = "Re-run terraform plan and ctfkit gate, then apply through ctfkit apply."
	detailKey        = "COMPLIANCETF_VERDICT_KEY_FILE must name the ctfkit-run.key of this verdict's plan artifact set: a regular file owned by this user that group and others cannot read."
	detailInvalidDoc = "The file is not a compliancetf.verdict/v1 document."
)

// Error is a load failure: Summary is the normative diagnostic summary.
type Error struct{ Summary, Detail string }

func (e *Error) Error() string { return e.Summary + ": " + e.Detail }

func invalid(detail string) *Error { return &Error{Summary: SummaryInvalid, Detail: detail} }

// Document is the verdict. Top-level members and instances are strict
// (the JCS round trip rejects any unknown, missing or case-variant member);
// baselines and receipts stay raw for the baseline and break-glass packages.
type Document struct {
	Format             string            `json:"format"`
	OrgID              string            `json:"org_id"`
	Workspace          string            `json:"workspace"`
	Environment        string            `json:"environment"`
	RunID              string            `json:"run_id"`
	Caller             json.RawMessage   `json:"caller"`
	PlanDigest         string            `json:"plan_digest"`
	Provenance         json.RawMessage   `json:"provenance"`
	PlanFormatVersion  string            `json:"plan_format_version"`
	ProfileDigest      string            `json:"profile_digest"`
	BundleDigest       string            `json:"bundle_digest"`
	ContentDigest      string            `json:"content_digest"`
	FloorEpoch         string            `json:"floor_epoch"`
	ProviderVersions   map[string]string `json:"provider_versions"`
	TerraformVersion   string            `json:"terraform_version"`
	Nonce              string            `json:"nonce"`
	IssuedAt           string            `json:"issued_at"`
	ExpiresAt          string            `json:"expires_at"`
	InstanceKeyCheck   string            `json:"instance_key_check"`
	Instances          []Instance        `json:"instances"`
	Exceptions         []ExceptionRef    `json:"exceptions"`
	Baselines          []BaselineRef     `json:"baselines"`
	BreakGlassReceipts []json.RawMessage `json:"break_glass_receipts"`
	Signature          Signature         `json:"signature"`
}

// BaselineRef is a top-level baselines[] member: the digest of a baseline
// entry the gate matched (A57), sha256 over JCS of the entry.
type BaselineRef struct {
	Digest string `json:"digest"`
}

// Signature is {kid, alg, value}: value is base64url (no padding) ASN.1 DER.
type Signature struct {
	KID   string `json:"kid"`
	Alg   string `json:"alg"`
	Value string `json:"value"`
}

// Verdict is a verified verdict.
type Verdict struct {
	Doc    Document
	Digest string // "sha256:" hex over JCS of the whole document
	leaf   [32]byte
	idx    index // built once at load
}

// LeafKey is the B3 leaf-hash key derived from the verified run key.
func (v *Verdict) LeafKey() [32]byte { return v.leaf }

// Input is the loaded context a verdict must bind.
type Input struct {
	Profile         *profile.Profile  // nil: no verdict key is trusted
	Revocations     trust.Revocations // merged revocations; the zero value revokes every kid
	BundleDigest    string            // bundle.ControlSet.Digest
	ContentDigest   string            // the loaded content digest (B11)
	WrapperName     string            // provider_versions name of this provider, compliancetf/<type>
	WrapperVersion  string            // this provider's version
	UpstreamName    string            // provider_versions name of the upstream, hashicorp/<type>
	UpstreamVersion string            // the running upstream version
	Now             time.Time
}

// Lazy loads once per process: the first Load reads the environment and
// files, every later Load returns the same verdict or error.
type Lazy struct {
	once   sync.Once
	v      *Verdict
	err    error
	loaded atomic.Pointer[Verdict] // set once a verdict verified
}

// Peek is the verified verdict once Load returned one, else nil; it never
// loads.
func (z *Lazy) Peek() *Verdict { return z.loaded.Load() }

// Load calls in and Load once; in is evaluated only on that first call. A
// panic there is recorded as a load failure, never as verdict none: once
// marks itself done even when its function panics.
func (z *Lazy) Load(in func() Input) (*Verdict, error) {
	z.once.Do(func() {
		defer func() {
			if recover() != nil {
				z.v, z.err = nil, invalid("The verdict could not be loaded.")
			}
		}()
		z.v, z.err = Load(in())
		if z.v != nil {
			z.loaded.Store(z.v)
		}
	})
	return z.v, z.err
}

// Load returns nil, nil when COMPLIANCETF_VERDICT is unset (verdict =
// none); otherwise the verified verdict or an *Error.
func Load(in Input) (*Verdict, error) {
	path, set := os.LookupEnv(EnvVerdict)
	if !set {
		return nil, nil
	}
	raw, err := readVerdict(path)
	if err != nil {
		return nil, err
	}
	doc, canon, signed, err := parse(raw)
	if err != nil {
		return nil, err
	}
	if reason := VerifySignature(doc.Signature, signed, in.Profile, in.Revocations, UseVerdict, in.Now); reason != "" {
		return nil, &Error{Summary: prefixSignature + reason, Detail: detailReRun}
	}
	leaf, ok := checkKey(doc.InstanceKeyCheck)
	if !ok {
		return nil, &Error{Summary: SummaryKey, Detail: detailKey}
	}
	if err := checkContext(doc, in); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(canon)
	return &Verdict{Doc: *doc, Digest: "sha256:" + hex.EncodeToString(sum[:]), leaf: leaf, idx: buildIndex(doc.Instances)}, nil
}

func readVerdict(path string) ([]byte, error) {
	if t := strings.TrimSpace(path); t == "" || strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[") || strings.ContainsAny(path, "\n\r") {
		// The payload is never accepted in the environment, and never echoed.
		return nil, invalid("COMPLIANCETF_VERDICT must hold the path of the verdict file, never the verdict itself.")
	}
	f, fi, err := openNoFollow(path)
	if err != nil {
		return nil, invalid("The file named by COMPLIANCETF_VERDICT cannot be opened as a regular file without following a symlink.")
	}
	defer f.Close() //nolint:errcheck // read-only
	switch {
	case !fi.Mode().IsRegular():
		return nil, invalid("The file named by COMPLIANCETF_VERDICT is not a regular file.")
	case !ownedByUser(fi):
		return nil, invalid("The verdict file is not owned by the user running terraform.")
	case fi.Mode() != 0o600:
		return nil, invalid("The verdict file mode must be exactly 0600.")
	case fi.Size() > MaxBytes:
		return nil, invalid("The verdict file is larger than 32 MiB.")
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxBytes+1))
	switch {
	case err != nil:
		return nil, invalid("The verdict file cannot be read.")
	case len(b) > MaxBytes:
		return nil, invalid("The verdict file is larger than 32 MiB.")
	}
	return b, nil
}

// parse decodes raw strictly: I-JSON (no duplicate members), no number, bool
// or null anywhere, and the typed top level must re-encode to the same JCS
// bytes (no unknown, missing or case-variant member). It returns the
// document, its JCS bytes and the signed bytes (JCS of the document minus
// the top-level signature, B1).
func parse(raw []byte) (*Document, []byte, []byte, error) {
	canon, signed, ok := SignedBytes(raw)
	if !ok {
		return nil, nil, nil, invalid(detailInvalidDoc)
	}
	var doc Document
	if json.Unmarshal(canon, &doc) != nil {
		return nil, nil, nil, invalid(detailInvalidDoc)
	}
	re, err := json.Marshal(&doc)
	if err != nil {
		return nil, nil, nil, invalid(detailInvalidDoc)
	}
	if re, err = bundle.CanonicalJSON(re); err != nil || !bytes.Equal(re, canon) {
		return nil, nil, nil, invalid(detailInvalidDoc)
	}
	if doc.Format != Format {
		return nil, nil, nil, invalid(detailInvalidDoc)
	}
	for _, b := range doc.Baselines {
		if !reDigest.MatchString(b.Digest) {
			return nil, nil, nil, invalid(detailInvalidDoc)
		}
	}
	if err := doc.validate(); err != nil {
		return nil, nil, nil, invalid("The verdict is malformed: " + err.Error() + ".")
	}
	return &doc, canon, signed, nil
}

var reDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// SignedBytes returns the JCS bytes of a signed document and its signed
// bytes (B1: JCS of the document minus the top-level signature). ok is false
// when raw is not I-JSON (duplicate members included), is not an object, or
// holds a number, bool or null token. The verdict and the baseline
// (internal/baseline) share it.
func SignedBytes(raw []byte) (canon, signed []byte, ok bool) {
	canon, err := bundle.CanonicalJSON(raw)
	if err != nil || !onlyStringsArraysObjects(canon) {
		return nil, nil, false
	}
	var top map[string]json.RawMessage
	if json.Unmarshal(canon, &top) != nil {
		return nil, nil, false
	}
	delete(top, "signature")
	signed, err = json.Marshal(top)
	if err == nil {
		signed, err = bundle.CanonicalJSON(signed)
	}
	return canon, signed, err == nil
}

// onlyStringsArraysObjects reports whether the JSON in b holds no number,
// bool or null token (the verdict format has none, so JCS has no number
// caveat).
func onlyStringsArraysObjects(b []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return true
		}
		if err != nil {
			return false
		}
		switch tok.(type) {
		case json.Delim, string:
		default:
			return false
		}
	}
}

// checkKey reads COMPLIANCETF_VERDICT_KEY_FILE and checks it against the
// verdict's instance_key_check (B3); it returns the leaf key.
func checkKey(want string) ([32]byte, bool) {
	var leaf [32]byte
	path, _ := os.LookupEnv(EnvKeyFile)
	secret, ok := ReadSecretFile(path)
	if !ok {
		return leaf, false
	}
	if !allowTestSecret && subtle.ConstantTimeCompare(secret, []byte(testSecret)) == 1 {
		return leaf, false // the public golden secret (FORMAT.md Test secret): ctftest builds only
	}
	check, err1 := hkdf.Key(sha256.New, secret, nil, infoCheck, 32)
	l, err2 := hkdf.Key(sha256.New, secret, nil, infoLeaf, 32)
	if err1 != nil || err2 != nil {
		return leaf, false
	}
	m := hmac.New(sha256.New, check)
	m.Write([]byte(infoCheck))
	if !hmac.Equal([]byte(hex.EncodeToString(m.Sum(nil))), []byte(want)) {
		return leaf, false
	}
	copy(leaf[:], l)
	return leaf, true
}

// ReadSecretFile reads a 32-byte secret file: 64 lowercase hex characters,
// an optional final newline, a regular file owned by this user that group
// and others cannot read, opened without following a symlink. The run key
// and the baseline key (internal/baseline) share it; ok is false on any
// other path, encoding or length.
func ReadSecretFile(path string) ([]byte, bool) {
	if path == "" {
		return nil, false
	}
	f, fi, err := openNoFollow(path)
	if err != nil {
		return nil, false
	}
	defer f.Close() //nolint:errcheck // read-only
	if !fi.Mode().IsRegular() || fi.Mode()&(fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky|0o077) != 0 || !ownedByUser(fi) {
		return nil, false
	}
	b, err := io.ReadAll(io.LimitReader(f, 66))
	if err != nil {
		return nil, false
	}
	text := strings.TrimSuffix(string(b), "\n")
	secret, err := hex.DecodeString(text)
	if err != nil || len(secret) != 32 || hex.EncodeToString(secret) != text {
		return nil, false
	}
	return secret, true
}

// OpenNoFollow opens path read-only without following a final symlink and
// returns the fstat of the opened file (internal/baseline reads the
// baseline file through it).
func OpenNoFollow(path string) (*os.File, fs.FileInfo, error) { return openNoFollow(path) }

// checkContext checks the lifetime, then the bindings to the loaded org,
// profile, bundle, content and provider versions.
func checkContext(doc *Document, in Input) error {
	issued, err1 := parseUTC(doc.IssuedAt)
	expires, err2 := parseUTC(doc.ExpiresAt)
	switch {
	case err1 != nil || err2 != nil:
		return invalid("issued_at and expires_at must be RFC 3339 UTC times.")
	case in.Now.After(expires.Add(Skew)):
		return &Error{Summary: fmt.Sprintf("Verdict expired at %s: re-run plan and gate", doc.ExpiresAt), Detail: detailReRun}
	case issued.After(in.Now.Add(Skew)):
		return invalid("The verdict issued_at lies in the future.")
	case !expires.After(issued):
		return invalid("The verdict expires_at must be after issued_at.")
	case expires.Sub(issued) > in.Profile.VerdictTTL():
		return invalid("The verdict lifetime exceeds the profile verdict.max_ttl.")
	}
	org, digest := "", ""
	if in.Profile != nil {
		org, digest = in.Profile.OrgID, in.Profile.Digest
	}
	switch {
	case doc.OrgID != org:
		return &Error{Summary: fmt.Sprintf("Verdict issued for org %s, profile is for org %s", doc.OrgID, none(org)), Detail: detailReRun}
	case doc.ProfileDigest != digest:
		return mismatch("profile", doc.ProfileDigest, digest)
	case doc.BundleDigest != in.BundleDigest:
		return mismatch("bundle", doc.BundleDigest, in.BundleDigest)
	case doc.ContentDigest != in.ContentDigest:
		return mismatch("control content", doc.ContentDigest, in.ContentDigest)
	}
	if err := checkScope(doc, in.Profile); err != nil {
		return err
	}
	// The provider_versions names checked, in this order. An empty name
	// fails closed even when the signed document has an empty member.
	for _, nv := range [][2]string{{in.WrapperName, in.WrapperVersion}, {in.UpstreamName, in.UpstreamVersion}} {
		running := strings.TrimPrefix(nv[1], "v")
		if got, ok := doc.ProviderVersions[nv[0]]; nv[0] == "" || !ok || running == "" || got != running {
			return &Error{Summary: fmt.Sprintf("Verdict issued for %s %s, running %s: re-run plan and gate", none(nv[0]), none(got), none(running)), Detail: detailReRun}
		}
	}
	return nil
}

// checkScope (Scope binding): a workspace or environment the signed
// profile scope fixes must be the verdict's, an empty verdict member
// included. The summary names the dimension only, never a value.
func checkScope(doc *Document, p *profile.Profile) error {
	if p == nil || p.Scope == nil {
		return nil
	}
	for _, d := range [][3]string{{"workspace", p.Scope.Workspace, doc.Workspace}, {"environment", p.Scope.Environment, doc.Environment}} {
		if d[1] != "" && d[2] != d[1] {
			return &Error{Summary: "Verdict " + d[0] + " does not match the signed profile scope: re-run plan and gate", Detail: detailReRun}
		}
	}
	return nil
}

// Scope is the gate-asserted scope, checked by Load against a
// scope the signed profile fixes. The mode table trusts only the members
// the profile fixes.
func (v *Verdict) Scope() *profile.Scope {
	return &profile.Scope{Environment: v.Doc.Environment, Workspace: v.Doc.Workspace}
}

func mismatch(what, got, loaded string) error {
	return &Error{Summary: fmt.Sprintf("verdict issued for %s %s, provider loaded %s: re-run plan and gate", what, none(got), none(loaded)), Detail: detailReRun}
}

func none(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

var errNotUTC = errors.New("not an RFC 3339 UTC time")

func parseUTC(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil || !strings.HasSuffix(s, "Z") {
		return time.Time{}, errNotUTC
	}
	return t, nil
}
