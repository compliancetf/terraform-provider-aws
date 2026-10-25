package bundlegen

import (
	"bytes"
	"cmp"
	"encoding/json"
	"io"
	"slices"
	"strings"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
)

// EmitControls renders controls.json canonically: controls sorted by
// (id, kind, resource_type), struct field order, map keys sorted, 2-space
// indent, LF, trailing newline. The result must load through
// bundle.ParseControls, so the generator never emits what the provider rejects.
func EmitControls(cs []bundle.Control) ([]byte, error) {
	cs = slices.Clone(cs)
	slices.SortFunc(cs, func(a, b bundle.Control) int {
		return cmp.Or(cmp.Compare(a.ID, b.ID), cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.ResourceType, b.ResourceType))
	})
	data, err := canonicalJSON(cs)
	if err != nil {
		return nil, err
	}
	if _, err := bundle.ParseControls(data); err != nil {
		return nil, errf("E_EMIT", "generated controls.json does not load: %v", err)
	}
	return data, nil
}

// canonicalJSON encodes v with 2-space indent, no HTML escaping, integers
// only and a trailing newline. Struct fields keep declaration order; map keys are sorted
// by encoding/json.
func canonicalJSON(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, errf("E_EMIT", "%v", err)
	}
	if err := integersOnly(b.Bytes()); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// integersOnly fails on a number with a fraction or exponent anywhere in
// data: generated files carry integers only (no floats in values).
func integersOnly(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return errf("E_EMIT", "%v", err)
		}
		if n, ok := tok.(json.Number); ok && strings.ContainsAny(string(n), ".eE") {
			return errf("E_EMIT", "float %s in emitted JSON; values must be integers", n)
		}
	}
}
