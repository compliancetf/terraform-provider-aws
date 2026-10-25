package baseline

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
)

const infoReadDigest = "compliancetf.read-digest/v1"

// ReadDigest is B4 (read_digest): "sha256:" + hex(sha256(JCS(o))) where o
// maps each read path, as written in the control, to H_b of the value at
// that path. H_b is the keyed value tree of the instance_key format v1
// (internal/verdict/testdata/instancekey/FORMAT.md): leaf(v) = hex(HMAC-SHA256(k, tag
// || 0x00 || text(v))) with tags s, n and b; null is never hashed but kept
// as JSON null wherever it occurs, so a map key holding null differs from
// an absent key (unlike the instance_key tree, which omits null members);
// sets sort by the JCS bytes of their hashed elements. k =
// HKDF-SHA256(baseline key, salt "", info "compliancetf.read-digest/v1").
// A path ending in null, or crossing a null object, maps to null. ok is
// false when any read value is unknown, wholly or partly, or a path steps
// into a value that is not an object: such an instance is never
// grandfathered.
func ReadDigest(baselineKey []byte, reads []string, v tftypes.Value) (string, bool) {
	k, err := hkdf.Key(sha256.New, baselineKey, nil, infoReadDigest, 32)
	if err != nil {
		return "", false
	}
	o := map[string]any{}
	for _, r := range reads {
		at, ok := walk(v, strings.Split(r, "."))
		if !ok {
			return "", false
		}
		if o[r], ok = hashTree(k, at); !ok {
			return "", false
		}
	}
	b, err := json.Marshal(o)
	if err == nil {
		b, err = bundle.CanonicalJSON(b)
	}
	if err != nil {
		return "", false
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), true
}

// walk follows object attribute steps; a null object on the way ends at null.
func walk(v tftypes.Value, steps []string) (tftypes.Value, bool) {
	for _, s := range steps {
		if !v.IsKnown() {
			return v, false
		}
		if v.IsNull() {
			return v, true
		}
		var attrs map[string]tftypes.Value
		if !v.Type().Is(tftypes.Object{}) || v.As(&attrs) != nil {
			return v, false
		}
		a, ok := attrs[s]
		if !ok {
			return v, false
		}
		v = a
	}
	return v, true
}

// hashTree is H_b(v); ok is false on any unknown.
func hashTree(k []byte, v tftypes.Value) (any, bool) {
	if !v.IsKnown() {
		return nil, false
	}
	if v.IsNull() {
		return nil, true
	}
	t := v.Type()
	switch {
	case t.Is(tftypes.String):
		var s string
		if v.As(&s) != nil {
			return nil, false
		}
		return leaf(k, "s", s), true
	case t.Is(tftypes.Bool):
		var b bool
		if v.As(&b) != nil {
			return nil, false
		}
		return leaf(k, "b", map[bool]string{true: "true", false: "false"}[b]), true
	case t.Is(tftypes.Number):
		var n big.Float
		if v.As(&n) != nil {
			return nil, false
		}
		text, ok := numberText(&n)
		return leaf(k, "n", text), ok
	case t.Is(tftypes.Object{}), t.Is(tftypes.Map{}):
		var m map[string]tftypes.Value
		if v.As(&m) != nil {
			return nil, false
		}
		out := map[string]any{}
		for name, e := range m {
			h, ok := hashTree(k, e)
			if !ok {
				return nil, false
			}
			out[name] = h
		}
		return out, true
	case t.Is(tftypes.List{}), t.Is(tftypes.Set{}), t.Is(tftypes.Tuple{}):
		var l []tftypes.Value
		if v.As(&l) != nil {
			return nil, false
		}
		out := make([]any, 0, len(l))
		for _, e := range l {
			h, ok := hashTree(k, e)
			if !ok {
				return nil, false
			}
			out = append(out, h)
		}
		if t.Is(tftypes.Set{}) {
			return sortByJCS(out)
		}
		return out, true
	}
	return nil, false // a dynamic or unrecognized type is never grandfathered
}

func leaf(k []byte, tag, text string) string {
	m := hmac.New(sha256.New, k)
	m.Write([]byte(tag))
	m.Write([]byte{0})
	m.Write([]byte(text))
	return hex.EncodeToString(m.Sum(nil))
}

func sortByJCS(elems []any) (any, bool) {
	keys := make([][]byte, len(elems))
	for i, e := range elems {
		b, err := json.Marshal(e)
		if err == nil {
			b, err = bundle.CanonicalJSON(b)
		}
		if err != nil {
			return nil, false
		}
		keys[i] = b
	}
	idx := make([]int, len(elems))
	for i := range idx {
		idx[i] = i
	}
	slices.SortStableFunc(idx, func(a, b int) int { return bytes.Compare(keys[a], keys[b]) })
	out := make([]any, len(elems))
	for i, j := range idx {
		out[i] = elems[j]
	}
	return out, true
}

// numberText is the canonical number text of the instance_key format v1
// ("Numbers"): 0 for zero; |floor(log10|x|)| above 1000 is refused; else the
// value rounded to a 512-bit mantissa, ties to even, written as an exact
// integer when integral, otherwise as the shortest 'g' text.
func numberText(n *big.Float) (string, bool) {
	if n.Sign() == 0 {
		return "0", true
	}
	if n.IsInf() {
		return "", false
	}
	// |floor(log10|x|)| <= 1000 exactly: 10^-1000 <= |x| < 10^1001, compared
	// as exact rationals before any rounding. The provider holds a binary
	// value, so a literal at exactly 10^-1000 may land just below and be
	// refused: fail closed.
	abs, _ := new(big.Float).Abs(n).Rat(nil)
	ten := func(e int64) *big.Int { return new(big.Int).Exp(big.NewInt(10), big.NewInt(e), nil) }
	if abs.Cmp(new(big.Rat).SetFrac(big.NewInt(1), ten(1000))) < 0 || abs.Cmp(new(big.Rat).SetInt(ten(1001))) >= 0 {
		return "", false
	}
	r := new(big.Float).SetPrec(512).SetMode(big.ToNearestEven).Set(n)
	if r.IsInt() {
		return r.Text('f', 0), true
	}
	return r.Text('g', -1), true
}

// sensitiveRead reports whether a read path touches a schema-sensitive
// attribute, or cannot be resolved through attributes and single or group
// nested blocks: either way the control is not grandfatherable.
func sensitiveRead(s *tfprotov5.Schema, read string) bool {
	if s == nil || s.Block == nil {
		return true
	}
	b := s.Block
	steps := strings.Split(read, ".")
	for i, step := range steps {
		if j := slices.IndexFunc(b.Attributes, func(a *tfprotov5.SchemaAttribute) bool { return a.Name == step }); j >= 0 {
			return b.Attributes[j].Sensitive // deeper steps stay inside its type: sensitivity is per attribute
		}
		j := slices.IndexFunc(b.BlockTypes, func(bt *tfprotov5.SchemaNestedBlock) bool { return bt.TypeName == step })
		if j < 0 || b.BlockTypes[j].Block == nil {
			return true
		}
		bt := b.BlockTypes[j]
		if i == len(steps)-1 {
			return blockSensitive(bt.Block)
		}
		if bt.Nesting != tfprotov5.SchemaNestedBlockNestingModeSingle && bt.Nesting != tfprotov5.SchemaNestedBlockNestingModeGroup {
			return true
		}
		b = bt.Block
	}
	return true
}

func blockSensitive(b *tfprotov5.SchemaBlock) bool {
	if b == nil {
		return true
	}
	for _, a := range b.Attributes {
		if a.Sensitive {
			return true
		}
	}
	for _, bt := range b.BlockTypes {
		if blockSensitive(bt.Block) {
			return true
		}
	}
	return false
}
