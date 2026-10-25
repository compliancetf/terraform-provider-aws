package verdict

// Instance key, provider side (instance_key FORMAT.md v1, B2, B3): the
// tftypes adapter builds the value tree from the apply PlannedState with
// its declared schema type, masks the verdict entry's unknown_paths and
// hashes every leaf. testdata/instancekey holds the frozen goldens, shared
// with ctfkit, that this code must reproduce byte for byte.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
)

// Form is the key form; the provider picks it from the RPC shape (H2).
type Form string

const (
	FormCreate Form = "create"
	FormUpdate Form = "update"
	FormDelete Form = "delete"
)

// Prior identity kinds.
const (
	KindIdentity = "identity"
	KindID       = "id"
	KindNone     = "none"
)

const keyDomain = "compliancetf.instance_key/v1"

// unknownMark stands for an unknown value until masking removes it.
type unknownMark struct{}

var reIndex = regexp.MustCompile(`^(0|[1-9][0-9]{0,8})$`)

// Key is the instance key of typ under form: planned is the apply
// PlannedState (create and update; ignored for delete), unknown the entry's
// unknown_paths, prior the prior identity tree source: nil for create,
// else a JSON object (the envelope identity for kind identity, {"id": id}
// for kind id).
func Key(leaf [32]byte, typ string, form Form, planned tftypes.Value, unknown [][]string, prior json.RawMessage) (string, error) {
	after, err := afterJCS(leaf, form, planned, unknown)
	if err != nil {
		return "", err
	}
	priorJCS := []byte("null")
	if form != FormCreate {
		if priorJCS, err = priorTree(leaf, prior); err != nil {
			return "", err
		}
	}
	h := sha256.New()
	for _, part := range [][]byte{[]byte(keyDomain), []byte(typ), []byte(form), after} {
		h.Write(part)
		h.Write([]byte{0})
	}
	h.Write(priorJCS)
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func afterJCS(leaf [32]byte, form Form, planned tftypes.Value, unknown [][]string) ([]byte, error) {
	if form == FormDelete {
		if len(unknown) != 0 {
			return nil, errors.New("a delete key has no unknown paths")
		}
		return []byte("null"), nil
	}
	if !planned.IsKnown() {
		return nil, errors.New("whole planned value unknown")
	}
	if _, ok := planned.Type().(tftypes.Object); !ok || planned.IsNull() {
		return nil, errors.New("planned value is not an object")
	}
	tree, err := valueTree(leaf, planned, planned.Type())
	if err != nil {
		return nil, err
	}
	for _, p := range unknown {
		if err := checkPath(planned.Type(), p); err != nil {
			return nil, err
		}
		tree = mask(tree, p)
	}
	if hasUnknown(tree) {
		return nil, errors.New("an unknown value lies outside the entry's unknown_paths")
	}
	return jcs(tree)
}

// dynamicBearing reports whether t is dynamic, or a list, set, map or tuple
// holding a dynamic-bearing type; an object never is.
func dynamicBearing(t tftypes.Type) bool {
	switch t := t.(type) {
	case tftypes.List:
		return dynamicBearing(t.ElementType)
	case tftypes.Set:
		return dynamicBearing(t.ElementType)
	case tftypes.Map:
		return dynamicBearing(t.ElementType)
	case tftypes.Tuple:
		return slices.ContainsFunc(t.ElementTypes, dynamicBearing)
	}
	return t.Is(tftypes.DynamicPseudoType)
}

// valueTree is v as a hashed tree: string leaves are leaf hashes, objects
// are map[string]any, lists, tuples and sets []any, null nil, unknown
// unknownMark. t is the declared type (dynamic positions keep
// DynamicPseudoType there while the value carries its concrete type).
func valueTree(leaf [32]byte, v tftypes.Value, t tftypes.Type) (any, error) {
	if !v.IsKnown() {
		return unknownMark{}, nil
	}
	if v.IsNull() {
		return nil, nil
	}
	switch t := t.(type) {
	case tftypes.Object:
		var attrs map[string]tftypes.Value
		if err := v.As(&attrs); err != nil {
			return nil, err
		}
		out := map[string]any{}
		for name, at := range t.AttributeTypes {
			a, ok := attrs[name]
			if !ok || dynamicBearing(at) {
				continue
			}
			n, err := valueTree(leaf, a, at)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			if n != nil {
				out[name] = n
			}
		}
		return out, nil
	case tftypes.Map:
		var elems map[string]tftypes.Value
		if err := v.As(&elems); err != nil {
			return nil, err
		}
		out := map[string]any{}
		for k, e := range elems {
			if !utf8.ValidString(k) {
				return nil, errors.New("map key is not valid UTF-8")
			}
			n, err := valueTree(leaf, e, t.ElementType)
			if err != nil {
				return nil, err
			}
			if n != nil {
				out[k] = n
			}
		}
		return out, nil
	case tftypes.List, tftypes.Set, tftypes.Tuple:
		return seqTree(leaf, v, t)
	}
	return leafOf(leaf, v)
}

func seqTree(leaf [32]byte, v tftypes.Value, t tftypes.Type) (any, error) {
	var elems []tftypes.Value
	if err := v.As(&elems); err != nil {
		return nil, err
	}
	out := make([]any, 0, len(elems))
	for i, e := range elems {
		et := tftypes.Type(tftypes.DynamicPseudoType)
		switch t := t.(type) {
		case tftypes.List:
			et = t.ElementType
		case tftypes.Set:
			et = t.ElementType
		case tftypes.Tuple:
			if len(t.ElementTypes) != len(elems) {
				return nil, errors.New("tuple arity differs from its type")
			}
			et = t.ElementTypes[i]
		}
		n, err := valueTree(leaf, e, et)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	if _, isSet := t.(tftypes.Set); !isSet {
		return out, nil
	}
	if hasUnknown(out) {
		return unknownMark{}, nil // an unknown inside a set masks the whole set
	}
	type elem struct {
		v   any
		key []byte
	}
	sorted := make([]elem, len(out))
	for i, e := range out {
		b, err := jcs(e)
		if err != nil {
			return nil, err
		}
		sorted[i] = elem{e, b}
	}
	slices.SortStableFunc(sorted, func(a, b elem) int { return bytes.Compare(a.key, b.key) })
	for i := range sorted {
		out[i] = sorted[i].v
	}
	return out, nil
}

func leafOf(leaf [32]byte, v tftypes.Value) (any, error) {
	switch {
	case v.Type().Is(tftypes.String):
		var s string
		if err := v.As(&s); err != nil {
			return nil, err
		}
		if !utf8.ValidString(s) {
			return nil, errors.New("string is not valid UTF-8")
		}
		return leafHash(leaf, 's', s), nil
	case v.Type().Is(tftypes.Bool):
		var b bool
		if err := v.As(&b); err != nil {
			return nil, err
		}
		return leafHash(leaf, 'b', strconv.FormatBool(b)), nil
	case v.Type().Is(tftypes.Number):
		f := new(big.Float)
		if err := v.As(&f); err != nil {
			return nil, err
		}
		if f.IsInf() {
			return nil, errors.New("number is infinite")
		}
		text, err := NumberText(new(big.Float).SetPrec(512).SetMode(big.ToNearestEven).Set(f).Text('e', -1))
		if err != nil {
			return nil, err
		}
		return leafHash(leaf, 'n', text), nil
	}
	return nil, fmt.Errorf("unsupported value type %s", v.Type())
}

func leafHash(leaf [32]byte, tag byte, text string) string {
	m := hmac.New(sha256.New, leaf[:])
	m.Write([]byte{tag, 0})
	m.Write([]byte(text))
	return hex.EncodeToString(m.Sum(nil))
}

// NumberText is the canonical text of a decimal literal (FORMAT.md
// Numbers): length and exponent bounds, zero as "0", then the 512-bit
// rounding as an exact integer or the shortest round-trip 'g' text.
func NumberText(s string) (string, error) {
	if len(s) > 1200 {
		return "", errors.New("number text longer than 1200 bytes")
	}
	e, zero, err := literalExp(s)
	switch {
	case err != nil:
		return "", err
	case zero:
		return "0", nil
	case e > 1000 || e < -1000:
		return "", fmt.Errorf("number exponent out of range")
	}
	f, _, err := big.ParseFloat(s, 10, 512, big.ToNearestEven)
	if err != nil {
		return "", err
	}
	if f.IsInt() {
		return f.Text('f', 0), nil
	}
	return f.Text('g', -1), nil
}

// literalExp is floor(log10(|x|)) of the decimal literal s, from its
// coefficient digits and exponent without expanding the value.
func literalExp(s string) (int64, bool, error) {
	t := strings.TrimPrefix(strings.TrimPrefix(s, "-"), "+")
	coef, expText := t, "0"
	if i := strings.IndexAny(t, "eE"); i >= 0 {
		coef, expText = t[:i], t[i+1:]
	}
	intPart, frac, _ := strings.Cut(coef, ".")
	digits := intPart + frac
	if digits == "" || strings.Trim(digits, "0123456789") != "" {
		return 0, false, errors.New("malformed number")
	}
	first := strings.IndexFunc(digits, func(r rune) bool { return r != '0' })
	if first < 0 {
		return 0, true, nil // zero, whatever its exponent
	}
	exp, err := strconv.ParseInt(expText, 10, 64)
	switch {
	case errors.Is(err, strconv.ErrRange):
		return 1 << 62, false, nil // beyond any bound
	case err != nil:
		return 0, false, errors.New("malformed number exponent")
	}
	return int64(len(intPart)-1-first) + exp, false, nil
}

// checkPath validates one unknown path against the schema type alone
// (FORMAT.md Unknown values): attribute and map-key steps, list and tuple
// indices; a step into a set or a dynamic value is an error.
func checkPath(t tftypes.Type, path []string) error {
	if len(path) == 0 {
		return errors.New("empty unknown path")
	}
	for _, step := range path {
		switch tt := t.(type) {
		case tftypes.Object:
			at, ok := tt.AttributeTypes[step]
			if !ok {
				return fmt.Errorf("unknown path step %q is not a declared attribute", step)
			}
			t = at
		case tftypes.Map:
			t = tt.ElementType
		case tftypes.List:
			if !reIndex.MatchString(step) {
				return fmt.Errorf("unknown path step %q is not a list index", step)
			}
			t = tt.ElementType
		case tftypes.Tuple:
			i, err := strconv.Atoi(step)
			if !reIndex.MatchString(step) || err != nil || i >= len(tt.ElementTypes) {
				return fmt.Errorf("unknown path step %q is not a tuple index", step)
			}
			t = tt.ElementTypes[i]
		default:
			return fmt.Errorf("unknown path step %q cannot be read", step)
		}
		if dynamicBearing(t) {
			return errors.New("unknown path into a dynamic value")
		}
	}
	return nil
}

// mask applies one validated path: the last step removes an attribute or
// map key, or nulls a list element; a path that does not resolve is a no-op.
func mask(tree any, path []string) any {
	switch n := tree.(type) {
	case map[string]any:
		c, ok := n[path[0]]
		switch {
		case !ok:
		case len(path) == 1:
			delete(n, path[0])
		default:
			n[path[0]] = mask(c, path[1:])
		}
	case []any:
		i, err := strconv.Atoi(path[0])
		switch {
		case err != nil || i >= len(n):
		case len(path) == 1:
			n[i] = nil
		default:
			n[i] = mask(n[i], path[1:])
		}
	}
	return tree
}

func hasUnknown(tree any) bool {
	switch n := tree.(type) {
	case unknownMark:
		return true
	case map[string]any:
		for _, c := range n {
			if hasUnknown(c) {
				return true
			}
		}
	case []any:
		return slices.ContainsFunc(n, hasUnknown)
	}
	return false
}

// priorTree is JCS(H(prior)) of a JSON object: kind identity's identity
// object or kind id's {"id": id}. Null members are omitted; the object
// must keep at least one leaf.
func priorTree(leaf [32]byte, prior json.RawMessage) ([]byte, error) {
	if _, err := bundle.CanonicalJSON(prior); err != nil {
		return nil, errors.New("prior identity is not JSON") // also duplicate members, invalid UTF-8
	}
	dec := json.NewDecoder(bytes.NewReader(prior))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, errors.New("prior identity is not JSON")
	}
	if _, ok := v.(map[string]any); !ok {
		return nil, errors.New("prior identity is not an object")
	}
	tree, err := jsonTree(leaf, v)
	if err != nil {
		return nil, err
	}
	if !hasLeaf(tree) {
		return nil, errors.New("prior identity has no leaf")
	}
	return jcs(tree)
}

// jsonTree is the hashed tree of a decoded JSON value; arrays are lists
// (an identity schema has no sets).
func jsonTree(leaf [32]byte, v any) (any, error) {
	switch v := v.(type) {
	case nil:
		return nil, nil
	case string:
		return leafHash(leaf, 's', v), nil
	case bool:
		return leafHash(leaf, 'b', strconv.FormatBool(v)), nil
	case json.Number:
		text, err := NumberText(v.String())
		if err != nil {
			return nil, err
		}
		return leafHash(leaf, 'n', text), nil
	case []any:
		out := make([]any, len(v))
		for i, e := range v {
			n, err := jsonTree(leaf, e)
			if err != nil {
				return nil, err
			}
			out[i] = n
		}
		return out, nil
	case map[string]any:
		out := map[string]any{}
		for k, e := range v {
			n, err := jsonTree(leaf, e)
			if err != nil {
				return nil, err
			}
			if n != nil {
				out[k] = n
			}
		}
		return out, nil
	}
	return nil, errors.New("unsupported JSON value")
}

func hasLeaf(tree any) bool {
	switch n := tree.(type) {
	case string:
		return true
	case map[string]any:
		for _, c := range n {
			if hasLeaf(c) {
				return true
			}
		}
	case []any:
		return slices.ContainsFunc(n, hasLeaf)
	}
	return false
}

// jcs is the RFC 8785 form of a hashed tree (strings, null, arrays and
// objects only): encoding/json escapes are undone by the JCS writer.
func jcs(tree any) ([]byte, error) {
	b, err := json.Marshal(tree)
	if err != nil {
		return nil, err
	}
	return bundle.CanonicalJSON(b)
}
