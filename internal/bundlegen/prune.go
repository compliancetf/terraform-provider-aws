package bundlegen

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
)

// schemaKeys maps a control kind to its `terraform providers schema -json`
// key, as Schemas.kind does for the converted schema.
var schemaKeys = map[bundle.Kind]string{
	bundle.KindResource:      "resource_schemas",
	bundle.KindDeletionGuard: "resource_schemas",
	bundle.KindDataSource:    "data_source_schemas",
	bundle.KindEphemeral:     "ephemeral_resource_schemas",
}

// prunedProvider is the aws entry of a pruned schema. TypeNames lists every
// type of the full schema per key, so a later diff still sees which types
// the upstream version has.
type prunedProvider struct {
	Resources   map[string]any      `json:"resource_schemas"`
	DataSources map[string]any      `json:"data_source_schemas"`
	Ephemeral   map[string]any      `json:"ephemeral_resource_schemas"`
	TypeNames   map[string][]string `json:"type_names"`
}

// PruneSchema reduces `terraform providers schema -json` output to the aws
// types the controls cs reference plus the full list of type names
// A referenced type the schema lacks is left
// out, for schemadiff to report as removed. The output is canonical JSON
// that LoadSchemas reads, independent of input key order.
func PruneSchema(raw []byte, cs []bundle.Control) ([]byte, error) {
	var doc struct {
		FormatVersion   string                                `json:"format_version"`
		ProviderSchemas map[string]map[string]json.RawMessage `json:"provider_schemas"`
	}
	if err := decodeStrict(raw, &doc); err != nil {
		return nil, err
	}
	p, ok := doc.ProviderSchemas[upstreamProvider]
	if !ok {
		return nil, errf("E_INPUT", "schema: no %s provider schema", upstreamProvider)
	}
	keep := map[string]map[string]bool{}
	for _, c := range cs {
		key, ok := schemaKeys[c.Kind]
		types := []string{c.ResourceType}
		if c.Kind == bundle.KindGraph && c.Graph != nil {
			// A graph control links two resource types; schemadiff checks both.
			key, ok = "resource_schemas", true
			types = append(types, c.Graph.CompanionType)
		}
		if !ok {
			return nil, errf("E_SCHEMA_TYPE", "%s: unknown kind %q", c.ID, c.Kind)
		}
		if keep[key] == nil {
			keep[key] = map[string]bool{}
		}
		for _, t := range types {
			keep[key][t] = true
		}
	}
	// A pruned input keeps its type names: pruning is idempotent.
	var names map[string][]string
	if len(p["type_names"]) > 0 {
		if err := decodeStrict(p["type_names"], &names); err != nil {
			return nil, err
		}
	}
	out := prunedProvider{TypeNames: map[string][]string{}}
	for key, dst := range map[string]*map[string]any{
		"resource_schemas":           &out.Resources,
		"data_source_schemas":        &out.DataSources,
		"ephemeral_resource_schemas": &out.Ephemeral,
	} {
		var all map[string]json.RawMessage
		if len(p[key]) > 0 {
			if err := decodeStrict(p[key], &all); err != nil {
				return nil, err
			}
		}
		*dst = map[string]any{}
		tn := append(slices.Collect(maps.Keys(all)), names[key]...)
		slices.Sort(tn)
		out.TypeNames[key] = append([]string{}, slices.Compact(tn)...) // never null
		for typ := range keep[key] {
			sj, ok := all[typ]
			if !ok {
				continue
			}
			var v any
			if err := decodeStrict(sj, &v); err != nil {
				return nil, err
			}
			(*dst)[typ] = v
		}
	}
	return canonicalJSON(struct {
		FormatVersion   string                    `json:"format_version"`
		ProviderSchemas map[string]prunedProvider `json:"provider_schemas"`
	}{doc.FormatVersion, map[string]prunedProvider{upstreamProvider: out}})
}

// decodeStrict decodes data keeping numbers exact and rejects trailing data.
func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		return errf("E_INPUT", "schema: %v", err)
	}
	if err := dec.Decode(new(json.RawMessage)); err != io.EOF {
		return errf("E_INPUT", "schema: trailing data")
	}
	return nil
}

// ReadRegular reads a regular file; symlinks and special files fail with
// E_SPECIAL_FILE.
func ReadRegular(path string) ([]byte, error) { return readRegular(path) }

// LoadControls reads a controls.json (a regular file) through
// bundle.ParseControls, the provider's decoder.
func LoadControls(path string) ([]bundle.Control, error) {
	data, err := readRegular(path)
	if err != nil {
		return nil, err
	}
	cs, err := bundle.ParseControls(data)
	if err != nil {
		return nil, errf("E_INPUT", "%s: %v", path, err)
	}
	return cs, nil
}

// WriteFileAtomic writes data to a temp file in path's directory and renames
// it over path (mode 0644): an interrupted write leaves the old file, and a
// symlink at path is replaced, never followed.
func WriteFileAtomic(path string, data []byte) (err error) {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, os.Remove(f.Name()))
		}
	}()
	if _, err = f.Write(data); err != nil {
		return errors.Join(err, f.Close())
	}
	if err = f.Chmod(0o644); err != nil {
		return errors.Join(err, f.Close())
	}
	if err = f.Sync(); err != nil {
		return errors.Join(err, f.Close())
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
