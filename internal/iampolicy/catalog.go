package iampolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"time"
)

const (
	// CatalogFile is the bundle file name of the action catalog; a bundle
	// with iam.* controls carries it in its signed manifest.
	CatalogFile = "iam-actions.json"
	// CatalogFormat is the format id of iam-actions.json v1.
	CatalogFormat = "compliancetf.iam-actions/v1"
	// CatalogSource names the data the catalog is built from.
	CatalogSource = "aws-service-reference"
)

// catalogFile is the iam-actions.json shape. Fields are declared in JCS key
// order, map keys marshal sorted, and every string is restricted to
// nameChars (or a fixed form), so json.Marshal of this struct is the RFC
// 8785 form of the document.
type catalogFile struct {
	Format    string              `json:"format"`
	Retrieved string              `json:"retrieved"`
	Services  map[string][]string `json:"services"`
	Snapshot  string              `json:"snapshot"`
	Source    string              `json:"source"`
}

// Catalog is a loaded action catalog: service prefix -> sorted action names,
// both lower-cased.
type Catalog struct {
	digest   string
	services map[string][]string
	total    int
}

// Digest is "sha256:<hex>" of the file bytes. LoadCatalog accepts only
// canonical bytes, so this is also the JCS digest of the document.
func (c *Catalog) Digest() string { return c.digest }

// LoadCatalog parses iam-actions.json. The bytes must be exactly the
// canonical encoding (compact, sorted keys and names, no duplicates, no
// trailing newline); anything else is ErrInvalid catalog_invalid, so two
// readers can never see different catalogs under one digest.
func LoadCatalog(b []byte) (*Catalog, error) {
	var f catalogFile
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil || !validCatalog(f) {
		return nil, invalid(rCatalog)
	}
	if canon, err := json.Marshal(f); err != nil || !bytes.Equal(canon, b) {
		return nil, invalid(rCatalog)
	}
	sum := sha256.Sum256(b)
	c := &Catalog{digest: "sha256:" + hex.EncodeToString(sum[:]), services: f.Services}
	for _, names := range f.Services {
		c.total += len(names)
	}
	return c, nil
}

// EncodeCatalog builds canonical iam-actions.json bytes (cmd/iamcatalog).
// Names are lower-cased, deduped and sorted; retrieved is YYYY-MM-DD and
// snapshot "sha256:<hex>" of the source snapshot.
func EncodeCatalog(retrieved, snapshot string, services map[string][]string) ([]byte, error) {
	f := catalogFile{Format: CatalogFormat, Retrieved: retrieved, Services: map[string][]string{}, Snapshot: snapshot, Source: CatalogSource}
	for svc, names := range services {
		l := make([]string, len(names))
		for i, n := range names {
			l[i] = asciiLower(n)
		}
		f.Services[asciiLower(svc)] = append(f.Services[asciiLower(svc)], l...)
	}
	for svc, l := range f.Services {
		f.Services[svc] = dedupeSort(l)
	}
	b, err := json.Marshal(f)
	if err != nil {
		return nil, invalid(rCatalog)
	}
	if _, err := LoadCatalog(b); err != nil {
		return nil, err
	}
	return b, nil
}

func validCatalog(f catalogFile) bool {
	d, err := time.Parse(time.DateOnly, f.Retrieved)
	if err != nil || d.Format(time.DateOnly) != f.Retrieved || f.Format != CatalogFormat || f.Source != CatalogSource {
		return false
	}
	hexPart, ok := strings.CutPrefix(f.Snapshot, "sha256:")
	if _, err := hex.DecodeString(hexPart); !ok || err != nil || len(hexPart) != 64 || hexPart != strings.ToLower(hexPart) {
		return false
	}
	if len(f.Services) == 0 {
		return false
	}
	for svc, names := range f.Services {
		if !nameChars(svc) || len(names) == 0 || !slices.IsSorted(names) || len(slices.Compact(slices.Clone(names))) != len(names) {
			return false
		}
		for _, n := range names {
			if !nameChars(n) {
				return false
			}
		}
	}
	return true
}

// nameChars: non-empty [a-z0-9_-]. AWS service prefixes and action names fit
// [verify against each new snapshot: cmd/iamcatalog fails, never escapes];
// the restriction keeps json.Marshal output equal to JCS.
func nameChars(s string) bool {
	return s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyz0123456789_-") == ""
}

// HasAction reports whether service:name (any case) is a catalog action,
// the lookup iam.grants makes.
func (c *Catalog) HasAction(action string) bool { return c.has(asciiLower(action)) }

// HasService reports whether svc (any case) is a catalog service, the
// lookup iam.grants_all makes.
func (c *Catalog) HasService(svc string) bool {
	_, ok := c.services[asciiLower(svc)]
	return ok
}

// has reports whether the lower-cased service:name is a catalog action.
func (c *Catalog) has(action string) bool {
	svc, name, _ := strings.Cut(action, ":")
	_, found := slices.BinarySearch(c.services[svc], name)
	return found
}
