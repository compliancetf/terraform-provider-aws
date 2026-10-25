// Package bundlegen generates bundle 2.0 controls.json files from a catalog
// export, content provider intents and hand-authored controls
// This repo holds the code and a synthetic
// test catalog only; real content stays in the private content pipeline.
//
// Skeleton: input loaders, canonical emitter. Refs and bundle
// selectors: refs.go, select.go. Coverage report and ledger
// generation_status writer: coverage.go.
// Translation: translate.go. Review queue, review sheet and the
// authored YAML loader: review.go, authored.go. The version lock:
// lock.go. Disposition exemption_coverable kinds:
// coverable.go. Fixtures and verify: fixtures.go, verify.go.
// Digests: contentdigest.go, the catalog digests in LoadCatalog.
package bundlegen

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/schemajson"
	"github.com/compliancetf/terraform-provider-aws/internal/iampolicy"
)

// Error is a generation error with a stable code from the spec (E_*).
type Error struct {
	Code string
	Msg  string
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func errf(code, format string, args ...any) error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, args...)}
}

// Inputs are the loaded generator inputs.
type Inputs struct {
	Catalog Catalog
	Intents Intents
	Schemas Schemas
	// SupportedSchemas are the schemas of the supported releases below the
	// pin, by version (LoadSupportedSchemas); Generate needs one per release.
	SupportedSchemas map[string]Schemas
	// Authored holds hand-authored controls by catalog id; they win over
	// translated intents. LoadAuthored reads them from the authored YAML files.
	Authored map[string][]bundle.Control
	// IAMActions is the canonical iam-actions.json (cmd/iamcatalog), copied
	// into every bundle with an iam.* control; nil when none was given.
	IAMActions []byte
	// AuthoredFixtures are the authored controls' own cases and
	// AuthoredBumps their version_bump, by catalog id (SetAuthored).
	AuthoredFixtures map[string][]Fixture
	AuthoredBumps    map[string]Bump
	// Lock is the previous content-lock.json and Bumps the version_bump
	// declarations from --bumps (bumps.yaml); Generate merges
	// AuthoredBumps into them (MergeBumps). A nil Lock is a fresh lock.
	Lock  Lock
	Bumps Bumps
	// PolicyFixtures is the content policy fixture export and DiffAllow the
	// diffcheck-allow.yaml entries; Generate runs Diffcheck only when
	// PolicyFixtures is set.
	PolicyFixtures *PolicyFixtures
	DiffAllow      []DiffAllow
}

// Catalog is a catalog provider export: controls.json, provider_dispositions.json,
// frameworks_metadata.json and manifest.json. ControlsSHA256 and
// DispositionsSHA256 are bundle.DigestJSON of controls.json and
// provider_dispositions.json as LoadCatalog read them (build.json catalog).
type Catalog struct {
	Manifest           Manifest
	Controls           map[string]CatalogControl
	Dispositions       Dispositions
	Frameworks         map[string]Framework
	ControlsSHA256     string
	DispositionsSHA256 string
}

// Framework is one frameworks_metadata.json entry; its clause titles are the
// denominator of clause coverage. The clause list lives here, not in
// frameworks.json, which maps a framework to control ids only.
type Framework struct {
	ClauseTitles map[string][]string `json:"clause_titles"`
}

type Manifest struct {
	SnapshotID    string `json:"snapshot_id"`
	SchemaVersion string `json:"schema_version"`
}

// CatalogControl is one controls.json entry: metadata plus tool export keys
// (CKV, AWS_CONFIG, ...) with their tool ids, kept in Tools by UnmarshalJSON.
type CatalogControl struct {
	Metadata struct {
		Name         string              `json:"name"`
		Frameworks   []string            `json:"frameworks"`
		ClauseTitles map[string][]string `json:"clause_titles"`
	} `json:"metadata"`
	Tools map[string][]string `json:"-"`
}

type Dispositions struct {
	SchemaVersion  int                    `json:"schema_version"`
	CompanionTypes map[string]Companion   `json:"companion_types"`
	Controls       map[string]Disposition `json:"controls"`
}

type Companion struct {
	Parent string `json:"parent"`
	Ref    string `json:"ref"`
}

type Disposition struct {
	Disposition        string          `json:"disposition"`
	Targets            []Target        `json:"targets"`
	Content            string          `json:"content"`
	Severity           bundle.Severity `json:"severity"`
	ExemptionCoverable coverableKinds  `json:"exemption_coverable"`
	Reason             string          `json:"reason"`
}

type Target struct {
	Kind string `json:"kind"`
	Type string `json:"type"`
}

// Intents is a content provider-intents export (format content.provider-intents/1).
type Intents struct {
	Format            string   `json:"format"`
	ContentVersion    string   `json:"content_version"`
	ContentCommit     string   `json:"content_commit"`
	CatalogSnapshotID string   `json:"catalog_snapshot_id"`
	Policies          []Intent `json:"policies"`
}

type Intent struct {
	ID                   string            `json:"id"`
	ResourceType         string            `json:"resource_type"`
	Attributes           []IntentAttribute `json:"attributes"`
	Explanation          string            `json:"explanation"`
	Postcondition        string            `json:"postcondition"`
	HasStrategyCondition bool              `json:"has_strategy_condition"`
}

type IntentAttribute struct {
	SchemaPath    string            `json:"schema_path"`
	Condition     string            `json:"condition"`
	Values        []json.RawMessage `json:"values"`
	ValuesFromRef *string           `json:"values_from_ref"`
}

const (
	intentsFormat    = "content.provider-intents/1"
	upstreamProvider = "registry.terraform.io/hashicorp/aws"
)

// LoadInputs loads a catalog export directory, a content intents file and a
// provider schema file.
func LoadInputs(catalogDir, intentsPath, schemaPath string) (Inputs, error) {
	var in Inputs
	var err error
	if in.Catalog, err = LoadCatalog(catalogDir); err != nil {
		return in, err
	}
	if in.Intents, err = LoadIntents(intentsPath); err != nil {
		return in, err
	}
	in.Schemas, err = LoadSchemas(schemaPath)
	return in, err
}

func LoadCatalog(dir string) (Catalog, error) {
	var c Catalog
	root, err := openDirRoot(dir, "E_INPUT")
	if err != nil {
		return c, err
	}
	defer root.Close() //nolint:errcheck // read-only
	digests := map[string]*string{"controls.json": &c.ControlsSHA256, "provider_dispositions.json": &c.DispositionsSHA256}
	for name, v := range map[string]any{
		"manifest.json":              &c.Manifest,
		"controls.json":              &c.Controls,
		"provider_dispositions.json": &c.Dispositions,
		"frameworks_metadata.json":   &c.Frameworks,
	} {
		path := filepath.Join(dir, name)
		data, err := readRootFile(root, name)
		if err != nil {
			return c, err
		}
		if err := decodeJSON(path, data, v); err != nil {
			return c, err
		}
		if d := digests[name]; d != nil {
			if *d, err = bundle.DigestJSON(data); err != nil {
				return c, errf("E_INPUT", "%s: %v", path, err)
			}
		}
	}
	if c.Manifest.SnapshotID == "" {
		return c, errf("E_INPUT", "%s: manifest.json has no snapshot_id", dir)
	}
	return c, nil
}

// LoadIntents reads a content intents export. A field the format does not
// define (a source-only where, quantifier, ...) fails with E_INTENT naming its path:
// dropping it could change what the intent means.
func LoadIntents(path string) (Intents, error) {
	var it Intents
	data, err := readRegular(path)
	if err != nil {
		return it, err
	}
	var raw any
	if err := json.Unmarshal(data, &raw); err != nil {
		return it, errf("E_INPUT", "%s: %v", path, err)
	}
	if p := unknownField(raw, reflect.TypeOf(it), ""); p != "" {
		return it, errf("E_INTENT", "%s: unknown field %s", path, p)
	}
	if err := decodeJSON(path, data, &it); err != nil {
		return it, err
	}
	if it.Format != intentsFormat {
		return it, errf("E_INPUT", "%s: format %q, want %q", path, it.Format, intentsFormat)
	}
	return it, nil
}

func LoadSchemas(path string) (Schemas, error) {
	var doc struct {
		ProviderSchemas map[string]*schemajson.Provider `json:"provider_schemas"`
	}
	if err := readJSON(path, &doc); err != nil {
		return Schemas{}, err
	}
	s := doc.ProviderSchemas[upstreamProvider]
	if s == nil {
		return Schemas{}, errf("E_INPUT", "%s: no %s provider schema", path, upstreamProvider)
	}
	resp, err := schemajson.Convert(*s)
	if err != nil {
		return Schemas{}, errf("E_INPUT", "%s: %v", path, err)
	}
	return Schemas{resp}, nil
}

// LoadIAMActions reads iam-actions.json. It must load through
// iampolicy.LoadCatalog, the check ctfbundle build and the provider apply.
func LoadIAMActions(path string) ([]byte, error) {
	data, err := readRegular(path)
	if err != nil {
		return nil, err
	}
	if _, err := iampolicy.LoadCatalog(data); err != nil {
		return nil, errf("E_INPUT", "%s: %v", path, err)
	}
	return data, nil
}

// readRegular reads a regular file through one descriptor opened without
// following a final symlink or blocking on a FIFO; symlinks and special
// files fail with E_SPECIAL_FILE.
func readRegular(path string) ([]byte, error) {
	f, err := openNoFollow(path)
	if err != nil {
		if fi, lerr := os.Lstat(path); lerr == nil && !fi.Mode().IsRegular() {
			return nil, errf("E_SPECIAL_FILE", "%s is not a regular file", path)
		}
		return nil, errf("E_INPUT", "%v", err)
	}
	defer f.Close() //nolint:errcheck // read-only
	fi, err := f.Stat()
	if err != nil {
		return nil, errf("E_INPUT", "%v", err)
	}
	// Off Unix the open follows a symlink swapped in after a check, so the
	// descriptor must also be the file Lstat sees at path.
	if li, err := os.Lstat(path); err != nil || !fi.Mode().IsRegular() || !li.Mode().IsRegular() || !os.SameFile(fi, li) {
		return nil, errf("E_SPECIAL_FILE", "%s is not a regular file", path)
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, errf("E_INPUT", "%v", err)
	}
	return data, nil
}

// openDirRoot opens dir as an os.Root pinned to the real directory Lstat
// sees at dir: a symlink or special file there, or a swap between the check
// and the open, fails E_SPECIAL_FILE; other errors take code.
func openDirRoot(dir, code string) (*os.Root, error) {
	li, err := os.Lstat(dir)
	if err != nil {
		return nil, errf(code, "%v", err)
	}
	if !li.IsDir() {
		return nil, errf("E_SPECIAL_FILE", "%s is not a directory", dir)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, errf(code, "%v", err)
	}
	if ri, err := root.Stat("."); err != nil || !os.SameFile(li, ri) {
		root.Close() //nolint:errcheck,gosec // the swap error wins
		return nil, errf("E_SPECIAL_FILE", "%s changed while opening it", dir)
	}
	return root, nil
}

// readRootFile reads the regular file name under root. os.Root follows a
// symlink inside the root, so the descriptor must be the regular file Lstat
// sees at name before and after the open; anything else is E_SPECIAL_FILE.
func readRootFile(root *os.Root, name string) ([]byte, error) {
	path := filepath.Join(root.Name(), name)
	before, err := root.Lstat(name)
	if err != nil {
		return nil, errf("E_INPUT", "%v", err)
	}
	if !before.Mode().IsRegular() {
		return nil, errf("E_SPECIAL_FILE", "%s is not a regular file", path)
	}
	f, err := root.OpenFile(name, os.O_RDONLY|openNonBlock, 0)
	if err != nil {
		return nil, errf("E_INPUT", "%v", err)
	}
	defer f.Close() //nolint:errcheck // read-only
	fi, err := f.Stat()
	if err != nil {
		return nil, errf("E_INPUT", "%v", err)
	}
	if after, err := root.Lstat(name); err != nil || !fi.Mode().IsRegular() || !after.Mode().IsRegular() || !os.SameFile(fi, before) || !os.SameFile(fi, after) {
		return nil, errf("E_SPECIAL_FILE", "%s is not a regular file", path)
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, errf("E_INPUT", "%v", err)
	}
	return data, nil
}

// readJSON reads a regular file with readRegular and decodes it, rejecting
// trailing data.
func readJSON(path string, v any) error {
	data, err := readRegular(path)
	if err != nil {
		return err
	}
	return decodeJSON(path, data, v)
}

// unknownField returns the path of the first JSON object key, in sorted key
// order, that t has no json field for, or "". Only struct, slice and pointer
// types are walked; other values are left to the decoder.
func unknownField(v any, t reflect.Type, path string) string {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Struct:
		m, ok := v.(map[string]any)
		if !ok {
			return ""
		}
		fields := map[string]reflect.Type{}
		for i := range t.NumField() {
			if name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ","); name != "" && name != "-" {
				fields[name] = t.Field(i).Type
			}
		}
		for _, k := range slices.Sorted(maps.Keys(m)) {
			ft, ok := fields[k]
			if !ok {
				return path + safeName(k)
			}
			if p := unknownField(m[k], ft, path+k+"."); p != "" {
				return p
			}
		}
	case reflect.Slice:
		l, ok := v.([]any)
		if !ok {
			return ""
		}
		for i, e := range l {
			if p := unknownField(e, t.Elem(), strings.TrimSuffix(path, ".")+"["+strconv.Itoa(i)+"]."); p != "" {
				return p
			}
		}
	}
	return ""
}

// decodeJSON decodes data, rejecting trailing data; name labels errors.
func decodeJSON(name string, data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(v); err != nil {
		// A field decoder's coded error (E_COVERABLE_KIND) keeps its code.
		if e := (*Error)(nil); errors.As(err, &e) {
			return errf(e.Code, "%s: %s", name, e.Msg)
		}
		return errf("E_INPUT", "%s: %v", name, err)
	}
	if err := dec.Decode(new(json.RawMessage)); err != io.EOF {
		return errf("E_INPUT", "%s: trailing data", name)
	}
	return nil
}
