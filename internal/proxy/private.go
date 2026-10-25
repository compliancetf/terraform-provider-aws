package proxy

// private.go frames the PlannedPrivate envelope (format v1, frozen):
// magic, version byte, uint32 big-endian header length, header
// JSON, then upstream planned_private verbatim. Only
// PlanResourceChange.Response.planned_private is wrapped and only
// ApplyResourceChange.Request.planned_private is unwrapped, so state never
// holds envelope bytes. The envelope carries no MAC: every field can only
// raise enforcement, and parsing rejects anything outside the v1 accept-set.

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"slices"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/vmihailenco/msgpack/v5"
	"github.com/vmihailenco/msgpack/v5/msgpcode"

	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/internal/tfplugin/tfplugin5"
)

// envelopeMagic starts with NUL, which never starts the JSON that SDKv2 and
// framework providers keep in planned_private.
var envelopeMagic = []byte("\x00CTFPRV")

const (
	envelopeVersion = 1
	maxHeader       = 4096 // header JSON bytes
	maxDepth        = 32   // JSON or msgpack nesting
	maxIntLen       = 64   // digits of an integer identity leaf
)

var (
	envelopeOps   = map[hook.Op]bool{hook.OpCreate: true, hook.OpUpdate: true, hook.OpReplace: true, hook.OpDelete: true, hook.OpImport: true}
	identityKinds = map[string]bool{"": true, "identity": true, "id": true, "none": true}
)

// Wrap frames h around upstream. It fails rather than produce bytes Unwrap
// would reject (oversized header, upstream already starting with the magic).
func Wrap(h hook.EnvelopeHeader, upstream []byte) ([]byte, error) {
	hj, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}
	if len(hj) > maxHeader {
		return nil, fmt.Errorf("header is %d bytes, over %d", len(hj), maxHeader)
	}
	b := make([]byte, 0, len(envelopeMagic)+5+len(hj)+len(upstream))
	b = append(append(b, envelopeMagic...), envelopeVersion)
	b = binary.BigEndian.AppendUint32(b, uint32(len(hj))) //nolint:gosec // bounded by maxHeader above
	b = append(append(b, hj...), upstream...)
	if _, _, err := Unwrap(b); err != nil {
		return nil, err
	}
	return b, nil
}

// Unwrap splits an envelope into header and upstream bytes. Bytes without
// the magic are not an envelope: (nil, b, nil).
func Unwrap(b []byte) (*hook.EnvelopeHeader, []byte, error) {
	if !bytes.HasPrefix(b, envelopeMagic) {
		if len(b) > 0 && bytes.HasPrefix(envelopeMagic, b) {
			return nil, nil, errors.New("truncated magic")
		}
		return nil, b, nil
	}
	rest := b[len(envelopeMagic):]
	if len(rest) < 5 {
		return nil, nil, errors.New("truncated header length")
	}
	if rest[0] != envelopeVersion {
		return nil, nil, fmt.Errorf("unsupported version %d", rest[0])
	}
	n := binary.BigEndian.Uint32(rest[1:5])
	rest = rest[5:]
	if n > maxHeader {
		return nil, nil, fmt.Errorf("header length %d over %d", n, maxHeader)
	}
	if int(n) > len(rest) {
		return nil, nil, errors.New("header runs past the end")
	}
	h, err := parseHeader(rest[:n])
	if err != nil {
		return nil, nil, err
	}
	if bytes.HasPrefix(rest[n:], envelopeMagic) {
		return nil, nil, errors.New("nested envelope")
	}
	return h, rest[n:], nil
}

// parseHeader accepts exactly the v1 key set: keys match case-sensitively
// after unescaping, duplicates and unknown keys are rejected at every level.
func parseHeader(b []byte) (*hook.EnvelopeHeader, error) {
	if err := checkJSON(b); err != nil {
		return nil, err
	}
	top, err := objectFields(b, "v", "ctf")
	if err != nil {
		return nil, err
	}
	if string(top["v"]) != "1" {
		return nil, errors.New("v is not 1")
	}
	ctf, err := objectFields(top["ctf"], "op", "control_versions_digest", "prior_identity", "prior_identity_kind", "imported")
	if err != nil {
		return nil, fmt.Errorf("ctf: %w", err)
	}
	h := &hook.EnvelopeHeader{V: 1}
	var op string
	for _, f := range []struct {
		key string
		dst any
	}{{"op", &op}, {"control_versions_digest", &h.CTF.ControlVersionsDigest}, {"prior_identity_kind", &h.CTF.PriorIdentityKind}, {"imported", &h.CTF.Imported}} {
		raw, ok := ctf[f.key]
		if !ok {
			continue
		}
		if string(raw) == "null" || json.Unmarshal(raw, f.dst) != nil {
			return nil, fmt.Errorf("ctf.%s has the wrong type", f.key)
		}
	}
	h.CTF.Op = hook.Op(op)
	if pi, ok := ctf["prior_identity"]; ok {
		if pi[0] != '{' {
			return nil, errors.New("ctf.prior_identity is not an object")
		}
		if h.CTF.PriorIdentity, err = json.Marshal(pi); err != nil { // the form Wrap writes
			return nil, errors.New("ctf.prior_identity is bad JSON")
		}
	}
	kind := h.CTF.PriorIdentityKind
	switch {
	case !envelopeOps[h.CTF.Op]:
		return nil, errors.New("ctf.op is missing or unknown")
	case !identityKinds[kind]:
		return nil, errors.New("ctf.prior_identity_kind is unknown")
	case (kind == "identity") != (h.CTF.PriorIdentity != nil):
		return nil, errors.New("ctf.prior_identity and prior_identity_kind disagree")
	case h.CTF.Op == hook.OpCreate && (kind == "identity" || kind == "id"):
		return nil, errors.New("ctf.op create carries a prior identity")
	}
	return h, nil
}

// objectFields decodes a JSON object whose keys must all be in allowed. The
// error is a fixed reason: header keys come from a tamperable plan, so no
// key text reaches a diagnostic.
func objectFields(b []byte, allowed ...string) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if t := bytes.TrimSpace(b); len(t) == 0 || t[0] != '{' || json.Unmarshal(t, &m) != nil {
		return nil, errors.New("not an object")
	}
	for k := range m {
		if !slices.Contains(allowed, k) {
			return nil, errors.New("unknown header key")
		}
	}
	return m, nil
}

// checkJSON requires one JSON value, nested at most maxDepth, with no
// duplicate object key at any level.
func checkJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := walkJSON(dec, 0); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after the header")
	}
	return nil
}

func walkJSON(dec *json.Decoder, depth int) error {
	if depth > maxDepth {
		return errors.New("nested too deep")
	}
	tok, err := dec.Token()
	if err != nil {
		return errors.New("bad JSON")
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	for dec.More() {
		if d == '{' {
			k, err := dec.Token()
			ks, ok := k.(string)
			if err != nil || !ok || seen[ks] {
				return errors.New("duplicate or bad key")
			}
			seen[ks] = true
		}
		if err := walkJSON(dec, depth+1); err != nil {
			return err
		}
	}
	if _, err := dec.Token(); err != nil {
		return errors.New("bad JSON")
	}
	return nil
}

// IdentityEqual reports whether env (envelope prior_identity JSON) and id
// (an apply request identity) hold the same identity object. It fails
// closed: both codecs set, a decode error, bin/ext values, non-string or
// duplicate keys, integer against float, or non-finite numbers are unequal.
// prior_identity is written with these rules.
func IdentityEqual(env json.RawMessage, id *tfplugin5.ResourceIdentityData) bool {
	a, err := identityJSON(env)
	if err != nil {
		return false
	}
	dv := id.GetIdentityData()
	var b any
	switch {
	case dv == nil || (len(dv.Msgpack) > 0 && len(dv.Json) > 0):
		return false
	case len(dv.Msgpack) > 0:
		b, err = decodeIdentityMsgpack(dv.Msgpack)
	default:
		b, err = identityJSON(dv.Json)
	}
	return err == nil && sameValue(a, b)
}

// identityObject decodes a request or response identity for the hook
// (evidence only) with the IdentityEqual rules: nil when absent,
// both codecs set, unreadable (an unknown value included) or not an object.
func identityObject(id *tfplugin5.ResourceIdentityData) map[string]any {
	dv := id.GetIdentityData()
	var v any
	var err error
	switch {
	case dv == nil || (len(dv.Msgpack) > 0) == (len(dv.Json) > 0):
		return nil
	case len(dv.Msgpack) > 0:
		v, err = decodeIdentityMsgpack(dv.Msgpack)
	default:
		v, err = identityJSON(dv.Json)
	}
	if m, ok := v.(map[string]any); ok && err == nil {
		return m
	}
	return nil
}

func identityJSON(b []byte) (any, error) {
	if err := checkJSON(b); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	v, err := normJSON(v)
	if _, ok := v.(map[string]any); !ok || err != nil {
		return nil, errors.New("identity is not an object")
	}
	return v, nil
}

// normJSON turns json.Number leaves into the shared number forms.
func normJSON(v any) (any, error) {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			n, err := normJSON(e)
			if err != nil {
				return nil, err
			}
			x[k] = n
		}
	case []any:
		for i, e := range x {
			n, err := normJSON(e)
			if err != nil {
				return nil, err
			}
			x[i] = n
		}
	case json.Number:
		s := string(x)
		if !strings.ContainsAny(s, ".eE") {
			n, ok := new(big.Int).SetString(s, 10)
			if len(s) > maxIntLen || !ok {
				return nil, errors.New("bad integer")
			}
			return n, nil
		}
		return finite(strconv.ParseFloat(s, 64))
	}
	return v, nil
}

func finite(f float64, err error) (any, error) {
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return nil, errors.New("non-finite number")
	}
	return f, nil
}

func decodeIdentityMsgpack(b []byte) (any, error) {
	r := bytes.NewReader(b)
	v, err := decodeMsgpack(msgpack.NewDecoder(r), 0)
	if err != nil {
		return nil, err
	}
	if _, ok := v.(map[string]any); !ok || r.Len() != 0 {
		return nil, errors.New("identity is not one object")
	}
	return v, nil
}

func decodeMsgpack(d *msgpack.Decoder, depth int) (any, error) {
	if depth > maxDepth {
		return nil, errors.New("nested too deep")
	}
	c, err := d.PeekCode()
	if err != nil {
		return nil, err
	}
	switch {
	case msgpcode.IsFixedMap(c) || c == msgpcode.Map16 || c == msgpcode.Map32:
		n, err := d.DecodeMapLen()
		m := map[string]any{}
		for i := 0; err == nil && i < n; i++ {
			var k string
			if kc, perr := d.PeekCode(); perr != nil || !msgpcode.IsString(kc) {
				return nil, errors.New("non-string key")
			}
			if k, err = d.DecodeString(); err != nil {
				break
			}
			if _, dup := m[k]; dup {
				return nil, errors.New("duplicate key")
			}
			m[k], err = decodeMsgpack(d, depth+1)
		}
		return m, err
	case msgpcode.IsFixedArray(c) || c == msgpcode.Array16 || c == msgpcode.Array32:
		n, err := d.DecodeArrayLen()
		var a []any
		for i := 0; err == nil && i < n; i++ {
			var e any
			e, err = decodeMsgpack(d, depth+1)
			a = append(a, e)
		}
		return a, err
	case msgpcode.IsString(c):
		return d.DecodeString()
	case c == msgpcode.Nil:
		return nil, d.DecodeNil()
	case c == msgpcode.True || c == msgpcode.False:
		return d.DecodeBool()
	case c == msgpcode.Float || c == msgpcode.Double:
		return finite(d.DecodeFloat64())
	case c == msgpcode.Uint64:
		u, err := d.DecodeUint64()
		return new(big.Int).SetUint64(u), err
	case msgpcode.IsFixedNum(c) || (c >= msgpcode.Uint8 && c <= msgpcode.Int64):
		i, err := d.DecodeInt64()
		return big.NewInt(i), err
	}
	return nil, fmt.Errorf("unsupported msgpack code %#x", c)
}

// sameValue compares decoded identity values; types must match exactly.
func sameValue(a, b any) bool {
	switch x := a.(type) {
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, v := range x {
			if w, ok := y[k]; !ok || !sameValue(v, w) {
				return false
			}
		}
		return true
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !sameValue(x[i], y[i]) {
				return false
			}
		}
		return true
	case *big.Int:
		y, ok := b.(*big.Int)
		return ok && x.Cmp(y) == 0
	case nil, string, bool, float64:
		return a == b
	}
	return false
}

// identityNotSent is the envelopeDisagrees reason of a destroy RPC whose
// request carries no identity for a kind identity envelope: Terraform
// before 1.16.6 and OpenTofu (checked with 1.13) send none on the destroy
// half of a replace.
const identityNotSent = "identity not sent"

// envelopeDisagrees cross-checks the envelope against the apply request and
// returns a reason (no values) when they disagree, else "". A missing kind
// fails closed: every plan stamps one. A create RPC (null prior) may carry a
// prior identity only as the create half of a replace. The destroy RPC of a
// tainted replace (or of a replace planned by an older provider) carries the
// create half's envelope (op create, kind none), which makes no claim about
// the prior; its verdict delete key takes kind id from the prior state id
// (lifecycle instanceKey). Kind identity needs an identity the
// request carries, on every RPC with a prior: planned_identity, which Core
// fills with the prior identity on a destroy, so a type without an identity
// schema never passes it. Conversely a destroy whose request
// carries an identity with a non-null leaf needs kind identity (the plan
// stamped it from that identity), except on the tainted op create path
// above: kind id keys {"id": id} only, which a same-type object with the
// same id elsewhere in the verdict may share.
// Passing is consistency, not authentication.
func (s *server5) envelopeDisagrees(ctx context.Context, h *hook.EnvelopeHeader, req *tfplugin5.ApplyResourceChange_Request) string {
	kind := h.CTF.PriorIdentityKind
	switch {
	case kind == "":
		return "kind missing"
	case isNull(req.PriorState):
		if (kind == "identity" || kind == "id") && h.CTF.Op != hook.OpReplace {
			return "prior identity on create"
		}
		return ""
	case h.CTF.Op == hook.OpCreate && isNull(req.PlannedState):
		if kind != "none" { // Unwrap rejects it too; the delete key's kind id rewrite needs none
			return "prior identity on create"
		}
		return ""
	}
	switch {
	case kind != "identity" && isNull(req.PlannedState) && keyIdentity(req.PlannedIdentity) != nil:
		return "identity" // the plan stamps kind identity from this identity
	case kind != "identity":
	case noIdentityData(req.PlannedIdentity) && isNull(req.PlannedState):
		return identityNotSent
	case keyIdentity(req.PlannedIdentity) == nil || !IdentityEqual(h.CTF.PriorIdentity, req.PlannedIdentity):
		return "identity"
	}
	id, err := s.stateID(ctx, req.TypeName, req.PriorState)
	switch {
	case err != nil:
		return "prior state unreadable"
	case kind == "id" && id == "", kind == "none" && id != "":
		return "id"
	}
	return ""
}

// priorIdentity is the envelope prior_identity and prior_identity_kind of a
// plan (instance_key FORMAT.md v1): kind identity with the identity as JSON
// when the request carries a prior identity with at least one non-null leaf
// (an all-null SDKv2 identity is not usable), else id when the prior state
// has a non-empty id, else none. The JSON keeps integer and float forms apart, so
// it passes IdentityEqual against the same identity at apply. An unreadable
// identity or prior state is an error (no value in the text).
func (s *server5) priorIdentity(ctx context.Context, req *tfplugin5.PlanResourceChange_Request) (json.RawMessage, string, error) {
	if isNull(req.PriorState) {
		return nil, "none", nil
	}
	if dv := req.PriorIdentity.GetIdentityData(); dv != nil && !isNull(dv) {
		m := identityObject(req.PriorIdentity)
		if m == nil {
			return nil, "", errors.New("prior identity unreadable")
		}
		if hasLeaf(m) {
			b, err := json.Marshal(jsonNumbers(m))
			if err != nil {
				return nil, "", errors.New("prior identity unreadable")
			}
			return b, "identity", nil
		}
	}
	id, err := s.stateID(ctx, req.TypeName, req.PriorState)
	switch {
	case err != nil:
		return nil, "", errors.New("prior state unreadable")
	case id != "":
		return nil, "id", nil
	}
	return nil, "none", nil
}

// noIdentityData reports whether id carries no identity bytes at all, as
// a destroy RPC of Terraform before 1.16.6 or OpenTofu does; an all-null identity
// Terraform did send is not this case.
func noIdentityData(id *tfplugin5.ResourceIdentityData) bool {
	dv := id.GetIdentityData()
	return dv == nil || (len(dv.Msgpack) == 0 && len(dv.Json) == 0)
}

// keyIdentity is the request identity id as JSON in the form priorIdentity
// stamps, nil when absent, unreadable or without a non-null leaf. After
// envelopeDisagrees passes, kind identity keys from these bytes, never the
// envelope's.
func keyIdentity(id *tfplugin5.ResourceIdentityData) json.RawMessage {
	m := identityObject(id)
	if m == nil || !hasLeaf(m) {
		return nil
	}
	b, err := json.Marshal(jsonNumbers(m))
	if err != nil {
		return nil
	}
	return b
}

// carriedPrior is the prior identity and kind a create re-plan carries for
// the object it replaces. Core re-plans the create half of a
// destroy-before-create replace (and of -replace) with a null prior and
// PriorPrivate = the first plan's planned_private, keeps the re-plan's
// private for the change and sends it to the destroy RPC, whose request has
// no prior identity. So when that PriorPrivate is an envelope with kind
// identity or id, the re-plan envelope takes its identity and kind under op
// replace (create RPC: kind none; destroy RPC: the delete key's). Upstream
// gets that PriorPrivate without the envelope (upstreamPrivate).
func carriedPrior(req *tfplugin5.PlanResourceChange_Request) (json.RawMessage, string, bool) {
	if !isNull(req.PriorState) {
		return nil, "", false
	}
	h, _, err := Unwrap(req.PriorPrivate)
	if err != nil || h == nil || (h.CTF.PriorIdentityKind != "identity" && h.CTF.PriorIdentityKind != "id") {
		return nil, "", false
	}
	return h.CTF.PriorIdentity, h.CTF.PriorIdentityKind, true
}

// upstreamPrivate is the private upstream produced itself: a readable
// envelope's tail, else b untouched (state private is never wrapped; an
// unreadable envelope reaches upstream as before). Core sends the first
// plan's envelope as the create re-plan's PriorPrivate, and hashicorp/aws
// (SDKv2) json-decodes PriorPrivate, so it fails on our header.
func upstreamPrivate(b []byte) []byte {
	if h, tail, err := Unwrap(b); err == nil && h != nil {
		return tail
	}
	return b
}

// hasLeaf reports whether a decoded identity holds a non-null scalar.
func hasLeaf(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case map[string]any:
		for _, e := range x {
			if hasLeaf(e) {
				return true
			}
		}
		return false
	case []any:
		for _, e := range x {
			if hasLeaf(e) {
				return true
			}
		}
		return false
	}
	return true
}

// jsonNumbers copies a decoded identity with numbers as json.Number: an
// integer as its digits, a float always with a fraction or exponent, so the
// JSON reads back as the same number form.
func jsonNumbers(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = jsonNumbers(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = jsonNumbers(e)
		}
		return out
	case *big.Int:
		return json.Number(x.String())
	case float64:
		f := strconv.FormatFloat(x, 'g', -1, 64)
		if !strings.ContainsAny(f, ".eE") {
			f += ".0"
		}
		return json.Number(f)
	}
	return v
}

// stateID is the top-level string id of state, an object of type typ; ""
// when absent, null, unknown or not a string.
func (s *server5) stateID(ctx context.Context, typ string, state *tfplugin5.DynamicValue) (string, error) {
	if isNull(state) {
		return "", nil
	}
	v, err := s.value(ctx, typ, state).Get()
	if err != nil {
		return "", err
	}
	var m map[string]tftypes.Value
	if err := v.As(&m); err != nil {
		return "", err
	}
	id, ok := m["id"]
	if !ok || !id.IsKnown() || id.IsNull() || !id.Type().Is(tftypes.String) {
		return "", nil
	}
	var sid string
	return sid, id.As(&sid)
}
