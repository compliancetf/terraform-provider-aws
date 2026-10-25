package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/iampolicy"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

// Archive limits (spec, Bundle archive and manifest). The decompressed limit
// counts every byte gzip yields: tar headers, padding and trailing zeros.
const (
	maxCompressed   = 8 << 20
	maxDecompressed = 32 << 20
	maxFile         = 16 << 20
	maxEntries      = 64 // manifest.dsse.json included

	ManifestEntry  = "manifest.dsse.json"
	ManifestFormat = "compliancetf.bundle-manifest/v2"
	ControlsFile   = "controls.json"
	RevokesFile    = "revocations.json"
	GraphFile      = "graph.json"
	IAMActionsFile = "iam-actions.json"

	// ExpiryGrace is how long past expires_at a bundle still loads, with a warning.
	ExpiryGrace = 7 * 24 * time.Hour
	// maxSkew bounds a manifest issued_at in the future.
	maxSkew = 5 * time.Minute
)

// ErrExpired wraps only the past-grace expiry error of Check, so the embedded
// CIS loader can downgrade exactly that error to a warning.
var ErrExpired = errors.New("bundle expired")

var (
	bundleIDRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	digestRE   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	hexRE      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// knownFiles is the archive allowlist; names match byte for byte.
	knownFiles = map[string]bool{ControlsFile: true, RevokesFile: true, GraphFile: true, IAMActionsFile: true}
)

// Manifest is the bundle manifest 2.0 payload.
type Manifest struct {
	Format        string `json:"format"`
	BundleID      string `json:"bundle_id"`
	BundleVersion int64  `json:"bundle_version"`
	Label         string `json:"label,omitempty"`
	OrgID         string `json:"org_id"`
	Profile       string `json:"profile"`
	Catalog       struct {
		SnapshotID    string `json:"snapshot_id"`
		SchemaVersion string `json:"schema_version"`
	} `json:"catalog"`
	Provider struct {
		Address      string `json:"address"`
		VersionRange string `json:"version_range"`
	} `json:"provider"`
	Upstream struct {
		Source       string `json:"source"`
		VersionRange string `json:"version_range"`
	} `json:"upstream"`
	SchemaCompatDigest string      `json:"schema_compat_digest"`
	Files              []FileEntry `json:"files"`
	IssuedAt           string      `json:"issued_at"`
	ExpiresAt          string      `json:"expires_at"`
	MinBundleVersion   int64       `json:"min_bundle_version"`
	MinProfileVersion  int64       `json:"min_profile_version"`

	issued, expires time.Time
}

// FileEntry is one manifest files[] entry.
type FileEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// DecodeManifest decodes manifest JSON strictly (unknown, duplicate, non
// [a-z0-9_] or null members and trailing data are errors) and checks every
// field rule except files, which a build source omits.
func DecodeManifest(data []byte) (*Manifest, error) {
	scan := json.NewDecoder(bytes.NewReader(data))
	scan.UseNumber()
	// Errors name the field, never a value: the scanner and decoder texts
	// quote member names and values.
	if _, msg := scanStrict(scan); msg != "" {
		return nil, errors.New("manifest: not strict JSON (null, duplicate or non-[a-z0-9_] member name)")
	}
	if _, err := scan.Token(); err != io.EOF {
		return nil, errors.New("manifest: trailing data")
	}
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, errors.New("manifest: unknown member or wrong value type")
	}
	switch {
	case m.Format != ManifestFormat:
		return nil, fmt.Errorf("manifest format is not %s", ManifestFormat)
	case !bundleIDRE.MatchString(m.BundleID) || m.BundleVersion < 1:
		return nil, errors.New("manifest bundle_id or bundle_version invalid")
	case m.MinBundleVersion < 0 || m.MinBundleVersion > m.BundleVersion || m.MinProfileVersion < 0:
		return nil, fmt.Errorf("manifest min_bundle_version %d / min_profile_version %d invalid", m.MinBundleVersion, m.MinProfileVersion)
	case m.Profile == "" || m.Catalog.SnapshotID == "" || m.Catalog.SchemaVersion == "" || m.Provider.Address == "" ||
		m.Provider.VersionRange == "" || m.Upstream.Source == "" || m.Upstream.VersionRange == "":
		// org_id stays optional: it is empty for public bundles.
		return nil, errors.New("manifest needs profile, catalog.{snapshot_id,schema_version}, provider.{address,version_range} and upstream.{source,version_range}")
	case !digestRE.MatchString(m.SchemaCompatDigest):
		return nil, errors.New("manifest schema_compat_digest is not sha256:<hex>")
	}
	var err1, err2 error
	m.issued, err1 = time.Parse(time.RFC3339, m.IssuedAt)
	m.expires, err2 = time.Parse(time.RFC3339, m.ExpiresAt)
	if err1 != nil || err2 != nil || !m.expires.After(m.issued) {
		return nil, errors.New("manifest issued_at or expires_at invalid")
	}
	return &m, nil
}

// ParseManifest is DecodeManifest plus the files rules: only allowlisted
// names, each once, controls.json required, lowercase hex digests, sizes
// within the per-file limit.
func ParseManifest(data []byte) (*Manifest, error) {
	m, err := DecodeManifest(data)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for i, f := range m.Files {
		if !knownFiles[f.Path] || seen[f.Path] {
			return nil, fmt.Errorf("manifest file %d is unknown or listed twice", i)
		}
		if !hexRE.MatchString(f.SHA256) || f.Size < 0 || f.Size > maxFile {
			return nil, fmt.Errorf("manifest file %s: bad sha256 or size", f.Path) // f.Path is allowlisted
		}
		seen[f.Path] = true
	}
	if !seen[ControlsFile] {
		return nil, errors.New("manifest files must list controls.json")
	}
	return m, nil
}

// VerifyFunc checks a DSSE envelope of the given payload type; production
// passes trust.Verify with the current revocations.
type VerifyFunc func(env []byte, payloadType string) (trust.Verified, error)

// Bundle is a verified, parsed archive. It is not yet checked against org,
// revocations or expiry: enforcement uses only a ControlSet, which
// NewControlSet builds after Check.
type Bundle struct {
	Manifest    *Manifest
	Digest      string // "sha256:<hex>" of the raw manifest.dsse.json bytes
	KeyID       string // signing key of the manifest (trust.Verified.KeyID)
	Controls    []Control
	Revocations trust.Revocations // NoRevocations() when the bundle has none
	// IAMCatalog is the parsed iam-actions.json (celeng.Content.IAMCatalog);
	// nil when the bundle has none.
	IAMCatalog *iampolicy.Catalog
	// content is the DigestJSON of each content-digest file present
	// (controls.json, graph.json, iam-actions.json), from verified bytes.
	content map[string]string
	// Embedded is set only by internal/embedded: past its expiry grace the
	// compiled CIS bundle stays loaded with a warning.
	Embedded bool `json:"-"`
	// Source is where the loader got the bundle (Source* below), for the
	// configure evidence record; ReadArchive leaves it empty.
	Source string `json:"-"`
}

// Bundle sources, the evidence bundle_sources enum.
const (
	SourceEmbedded = "embedded" // compiled into the provider
	SourceLocal    = "local"    // the air-gap control_bundle_path archive
	SourceFetched  = "fetched"  // the bundle service
	SourceCache    = "cache"    // a cached archive
)

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// ReadArchive verifies and parses a bundle archive: the manifest signature
// before the manifest is parsed, each file's size and digest before the file
// is parsed. Only plain USTAR regular entries with allowlisted names, the
// archive limits, and a single gzip member followed by nothing are accepted.
func ReadArchive(archive []byte, verify VerifyFunc) (*Bundle, error) {
	if len(archive) > maxCompressed {
		return nil, fmt.Errorf("archive exceeds %d bytes", maxCompressed)
	}
	br := bytes.NewReader(archive) // an io.ByteReader: gzip reads nothing past its member
	zr, err := gzip.NewReader(br)
	if err != nil {
		return nil, errCorrupt
	}
	zr.Multistream(false)
	lr := &io.LimitedReader{R: zr, N: maxDecompressed + 1}
	ts := &tarStream{r: lr}
	tr := tar.NewReader(ts)
	var b *Bundle
	want := map[string]FileEntry{}
	var off int64 // where the next header block starts
	for n := 0; ; n++ {
		h, err := tr.Next()
		if err == io.EOF {
			// Only an absent, half or full end marker may follow the last
			// entry: at most two blocks, all zero. Anything else is a
			// header tar.Reader consumed without returning it.
			if ts.pos-off > 1024 || ts.tailDirty {
				return nil, errors.New("trailing data after the tar entries")
			}
			break
		}
		if err != nil {
			return nil, overLimit(lr, errCorrupt)
		}
		if n >= maxEntries {
			return nil, fmt.Errorf("more than %d entries", maxEntries)
		}
		if h.Typeflag != tar.TypeReg || h.Format != tar.FormatUSTAR || len(h.PAXRecords) != 0 {
			return nil, fmt.Errorf("entry %d: not a plain USTAR regular file", n) // header values are unsigned, never echoed
		}
		if ts.pos != off+512 {
			return nil, fmt.Errorf("entry %d: extra tar header blocks", n)
		}
		if n == 0 {
			b, err = readManifest(tr, h, verify, want)
		} else {
			err = b.readFile(tr, h, want)
		}
		if err != nil {
			return nil, overLimit(lr, err)
		}
		// The body was read in full; its block padding must be zero.
		ts.zeroFrom, off = off+512+h.Size, off+512+(h.Size+511)/512*512
		ts.zeroTo, ts.tailFrom, ts.tailDirty = off, off, false
	}
	if ts.dirty {
		return nil, errors.New("non-zero tar block padding")
	}
	if b == nil {
		return nil, errors.New("empty archive")
	}
	// Drain the member: gzip checks CRC32 and ISIZE at its end, and only zero
	// padding may follow the tar end marker.
	rest, err := io.ReadAll(lr)
	if err != nil {
		return nil, errCorrupt
	}
	if lr.N <= 0 {
		return nil, fmt.Errorf("decompressed size exceeds %d", maxDecompressed)
	}
	if len(bytes.Trim(rest, "\x00")) != 0 {
		return nil, errors.New("trailing data after the tar entries")
	}
	if br.Len() != 0 {
		return nil, errors.New("trailing data after the gzip member")
	}
	for name := range want {
		return nil, fmt.Errorf("%s: missing file listed in the manifest", name)
	}
	// Graph controls without a signed graph.json never load (never a
	// silent pass). Its format is defined elsewhere; the
	// file is digest-bound here and not parsed.
	if _, ok := b.content[GraphFile]; !ok {
		for i := range b.Controls {
			if b.Controls[i].Kind == KindGraph {
				return nil, fmt.Errorf("%s: control[%d]: control_graph_file_missing", ControlsFile, i)
			}
		}
	}
	return b, nil
}

// tarStream counts the bytes tar.Reader consumes. It flags a non-zero byte
// in [zeroFrom, zeroTo), the padding after the body read last (tar.Reader
// skips padding unchecked), and any non-zero byte from tailFrom on, which
// matters only when tar.Reader then reports the end of the archive.
type tarStream struct {
	r                               io.Reader
	pos, zeroFrom, zeroTo, tailFrom int64
	dirty, tailDirty                bool
}

func (s *tarStream) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	for at := max(s.zeroFrom, s.pos); at < min(s.zeroTo, s.pos+int64(n)); at++ {
		s.dirty = s.dirty || p[at-s.pos] != 0
	}
	for at := max(s.tailFrom, s.pos); at < s.pos+int64(n) && !s.tailDirty; at++ {
		s.tailDirty = p[at-s.pos] != 0
	}
	s.pos += int64(n)
	return n, err
}

// errCorrupt replaces gzip, flate and tar read errors: their text can quote
// an offset or header value of the unsigned archive.
var errCorrupt = errors.New("corrupt archive stream")

// overLimit reports a read error caused by the decompressed limit as such.
func overLimit(lr *io.LimitedReader, err error) error {
	if lr.N <= 0 {
		return fmt.Errorf("decompressed size exceeds %d", maxDecompressed)
	}
	return err
}

func readManifest(tr *tar.Reader, h *tar.Header, verify VerifyFunc, want map[string]FileEntry) (*Bundle, error) {
	if h.Name != ManifestEntry {
		return nil, fmt.Errorf("%s must be the first entry", ManifestEntry)
	}
	if h.Size > trust.MaxEnvelopeBytes {
		return nil, fmt.Errorf("%s: size exceeds %d", ManifestEntry, trust.MaxEnvelopeBytes)
	}
	env, err := io.ReadAll(tr)
	if err != nil {
		return nil, errCorrupt
	}
	v, err := verify(env, trust.PayloadBundleManifest)
	if err != nil {
		return nil, err
	}
	m, err := ParseManifest(v.Payload)
	if err != nil {
		return nil, err
	}
	for _, f := range m.Files {
		want[f.Path] = f
	}
	return &Bundle{Manifest: m, Digest: DigestRaw(env), KeyID: v.KeyID, Revocations: trust.NoRevocations()}, nil
}

func (b *Bundle) readFile(tr *tar.Reader, h *tar.Header, want map[string]FileEntry) error {
	f, ok := want[h.Name]
	if !ok {
		return errors.New("an entry is unlisted or duplicate")
	}
	delete(want, h.Name)
	if h.Size != f.Size {
		return fmt.Errorf("%s: size does not match the manifest", f.Path)
	}
	body, err := io.ReadAll(tr)
	if err != nil {
		return errCorrupt
	}
	if int64(len(body)) != f.Size || DigestRaw(body) != "sha256:"+f.SHA256 {
		return fmt.Errorf("%s: digest mismatch", f.Path)
	}
	// Only bytes bound to the verified manifest reach the parsers.
	return b.parseFile(f.Path, body)
}

// parseFile parses a file bound to the verified manifest into b.
func (b *Bundle) parseFile(path string, body []byte) error {
	var err error
	switch path {
	case ControlsFile, GraphFile, IAMActionsFile:
		if b.content == nil {
			b.content = map[string]string{}
		}
		if b.content[path], err = DigestJSON(body); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
	}
	switch path {
	case ControlsFile:
		b.Controls, err = ParseControls(body)
	case RevokesFile:
		b.Revocations, err = trust.ParseRevocations(body)
	case IAMActionsFile:
		if b.IAMCatalog, err = iampolicy.LoadCatalog(body); err != nil {
			return fmt.Errorf("%s: not a valid action catalog", path) // the parser error may quote content
		}
	}
	var ce *Error
	switch {
	case errors.As(err, &ce): // its text quotes control ids and values
		return fmt.Errorf("%s: control[%d]: %s", path, ce.Index, ce.Code)
	case err != nil:
		return fmt.Errorf("%s: %w", path, err) // ParseRevocations errors are value-free
	}
	return nil
}

// Check applies the load rules that depend on the caller: org, revocations
// (before expiry, so a revoked bundle gets no grace), a future issued_at,
// then expiry with ExpiryGrace. It returns a warning inside the grace window.
func (b *Bundle) Check(org string, now time.Time, revs trust.Revocations) (string, error) {
	m := b.Manifest
	if m.OrgID != "" && m.OrgID != org {
		return "", fmt.Errorf("bundle %s is for another org, not %q", m.BundleID, org) // org_id is not echoed
	}
	if revs.KeyRevoked(b.KeyID) || revs.BundleRevoked(m.BundleID, m.BundleVersion) {
		return "", fmt.Errorf("bundle %s v%d (%s) is revoked", m.BundleID, m.BundleVersion, b.Digest)
	}
	if m.issued.After(now.Add(maxSkew)) {
		return "", fmt.Errorf("bundle %s v%d issued_at %s is in the future", m.BundleID, m.BundleVersion, m.issued.UTC().Format(time.RFC3339))
	}
	switch end := m.expires.Add(ExpiryGrace); {
	case !now.After(m.expires):
		return "", nil
	case !now.After(end):
		return fmt.Sprintf("Bundle %s v%d expired %s; it stops loading after %s.",
			m.BundleID, m.BundleVersion, m.expires.UTC().Format(time.RFC3339), end.UTC().Format(time.RFC3339)), nil
	default:
		return "", fmt.Errorf("%w: %s v%d expired %s, grace ended %s", ErrExpired,
			m.BundleID, m.BundleVersion, m.expires.UTC().Format(time.RFC3339), end.UTC().Format(time.RFC3339))
	}
}
