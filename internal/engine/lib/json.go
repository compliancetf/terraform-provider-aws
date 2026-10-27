package lib

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/interpreter"
)

const (
	// MaxDocBytes is the document size limit of json.path and iam.parse,
	// checked before decode.
	MaxDocBytes = 256 << 10
	// decodeCost is the admission estimate of token-level decode work per
	// document byte. shortcut: one fixed rate, calibrate against the p99
	// benchmark in test/bench.
	decodeCost = 20 * time.Nanosecond
	// DefaultDocCacheBytes is the process document cache cap until
	// SetDocCacheBytes changes it (celeng Options.DocCacheBytes default).
	DefaultDocCacheBytes = 64 << 20
	// nodeBytes is the cache charge per decoded JSON value on top of the
	// document bytes: interface, map entry or slice slot and headers.
	// shortcut: conservative guess, measure with the p99 benchmark.
	nodeBytes = 96
	// entryBytes is the cache charge of every entry: key, map slot and
	// buckets the map keeps after a clear. shortcut: measured ~550 B per
	// entry with growth slack; the p99 benchmark can refine it.
	entryBytes = 512
)

// JSON is the CEL library of json.path(doc, pointer): RFC 6901 JSON Pointer
// into a JSON string. A missing location is null. A document over
// MaxDocBytes or over the admission estimate is ErrLimit, checked before
// decode. Malformed JSON, duplicate object keys at any depth, trailing data,
// invalid UTF-8 and malformed pointers are ErrInvalid. Strict like Helpers:
// an unknown argument makes the call unknown; a null document is a type error.
// Every program of the env admits against the evaluation's remaining budget
// (DeadlineVar, like iam.parse); without that entry, or with a deadline that
// is spent, zero or not a time.Time, the call is ErrLimit before the cache
// lookup, so the result never depends on cache state (fail closed).
func JSON() cel.EnvOption { return cel.Lib(jsonLib{}) }

type jsonLib struct{}

func (jsonLib) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{cel.Function("json.path",
		cel.Overload("json_path_string_string", []*cel.Type{cel.StringType, cel.StringType}, cel.DynType,
			cel.BinaryBinding(func(d, p ref.Val) ref.Val { return jsonPath(d, p, 0) })))} // no deadline: admits nothing
}

func (jsonLib) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{cel.CustomDecoratorV2(func(i interpreter.InterpretableV2) (interpreter.InterpretableV2, error) {
		if c, ok := i.(interpreter.InterpretableCall); ok && c.OverloadID() == "json_path_string_string" && len(c.Args()) == 2 {
			return &pathCall{c}, nil
		}
		return i, nil
	})}
}

func jsonPath(d, p ref.Val, remaining time.Duration) ref.Val {
	s, ok := strs(d, p)
	if !ok {
		return invalid()
	}
	v, err := docs.path(s[0], s[1], remaining)
	if err != nil {
		return types.WrapErr(err)
	}
	return types.DefaultTypeAdapter.NativeToValue(v)
}

// pathCall replaces the json.path call node so admission sees the live
// deadline. Strict like the binary call it replaces: an error
// argument returns first, then unknowns merge.
type pathCall struct{ interpreter.InterpretableCall }

func (c *pathCall) Eval(a interpreter.Activation) ref.Val { return c.Exec(interpreter.AsFrame(a)) }

func (c *pathCall) Exec(f *interpreter.ExecutionFrame) ref.Val {
	args := c.Args()
	d := args[0].Exec(f)
	if types.IsError(d) {
		return d
	}
	p := args[1].Exec(f)
	if types.IsError(p) {
		return p
	}
	var unk *types.Unknown
	unk, _ = types.MaybeMergeUnknowns(d, unk)
	if unk, _ = types.MaybeMergeUnknowns(p, unk); unk != nil {
		return unk
	}
	for _, a := range []ref.Val{d, p} { // the overload's runtime signature
		if _, ok := a.(types.String); !ok {
			return types.MaybeNoSuchOverloadErr(a)
		}
	}
	var remaining time.Duration // no deadline, or not a time.Time: admits nothing
	if v, ok := f.ResolveName(DeadlineVar); ok {
		if t, ok := v.(time.Time); ok {
			remaining = time.Until(t)
		}
	}
	return types.LabelErrNode(c.ID(), jsonPath(d, p, remaining))
}

// docs is the process document cache.
var docs = newDocCache(DefaultDocCacheBytes)

// SetDocCacheBytes sets the process document cache cap shared by json.path
// and iam.parse; a cache already over the new cap is cleared. n <= 0
// caches nothing.
func SetDocCacheBytes(n int) {
	docs.mu.Lock()
	defer docs.mu.Unlock()
	docs.max = n
	if docs.bytes > n {
		clear(docs.m)
		docs.bytes = 0
	}
}

// docCache maps jsonKey to the decoded document or its error class. Entries
// are charged their document length plus nodeBytes per decoded value (error
// entries keep no tree: document length only); when the next entry
// would pass max the cache is cleared and refilled. shortcut: no LRU, add
// one when a profile shows churn.
type docCache struct {
	mu      sync.Mutex
	m       map[[sha256.Size]byte]docEntry
	bytes   int
	max     int
	decodes int // decode calls, for tests
}

type docEntry struct {
	v   any
	err error
}

func newDocCache(max int) *docCache {
	return &docCache{m: map[[sha256.Size]byte]docEntry{}, max: max}
}

// jsonKey is sha256(kind || 0x00 || keyDigest || 0x00 || doc), kind iam or
// json; keyDigest is the content digest for iam, empty for json.
func jsonKey(kind string, keyDigest []byte, doc string) [sha256.Size]byte {
	h := sha256.New()
	h.Write([]byte(kind))
	h.Write([]byte{0})
	h.Write(keyDigest)
	h.Write([]byte{0})
	h.Write([]byte(doc))
	var k [sha256.Size]byte
	h.Sum(k[:0])
	return k
}

// path resolves ptr in doc. Order: size limit, spent budget, cache,
// admission against remaining, decode; nothing past a limit is decoded or
// cached.
func (c *docCache) path(doc, ptr string, remaining time.Duration) (any, error) {
	if len(doc) > MaxDocBytes || remaining <= 0 {
		return nil, ErrLimit
	}
	k := jsonKey("json", nil, doc)
	c.mu.Lock()
	e, hit := c.m[k]
	c.mu.Unlock()
	if !hit {
		if time.Duration(len(doc)+1)*decodeCost > remaining {
			return nil, ErrLimit
		}
		var nodes int
		e.v, nodes, e.err = decode(doc)
		if e.err != nil {
			nodes = 0
		}
		c.store(k, e, len(doc)+nodes*nodeBytes)
	}
	if e.err != nil {
		return nil, e.err
	}
	return pointer(e.v, ptr)
}

func (c *docCache) store(k [sha256.Size]byte, e docEntry, n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.decodes++
	n += entryBytes
	if n > c.max {
		return
	}
	if c.bytes+n > c.max {
		clear(c.m)
		c.bytes = 0
	}
	if _, ok := c.m[k]; !ok {
		c.m[k] = e
		c.bytes += n
	}
}

// decode reads one JSON value token by token, rejecting duplicate object
// keys at any depth and anything after the value. Numbers are int64 when
// integral, else float64; an integer beyond int64 is invalid.
// It also returns the number of decoded values.
func decode(doc string) (any, int, error) {
	if !utf8.ValidString(doc) { // encoding/json would replace bad bytes silently
		return nil, 0, ErrInvalid
	}
	dec := json.NewDecoder(strings.NewReader(doc))
	dec.UseNumber()
	var nodes int
	v, err := value(dec, &nodes)
	if err != nil {
		return nil, 0, ErrInvalid
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, 0, ErrInvalid
	}
	return v, nodes, nil
}

func value(dec *json.Decoder, nodes *int) (any, error) {
	*nodes++
	t, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := t.(type) {
	case json.Delim:
		if t == '[' {
			l := []any{}
			for dec.More() {
				v, err := value(dec, nodes)
				if err != nil {
					return nil, err
				}
				l = append(l, v)
			}
			_, err := dec.Token()
			return l, err
		}
		m := map[string]any{}
		for dec.More() {
			k, err := dec.Token()
			if err != nil {
				return nil, err
			}
			key, ok := k.(string) // the decoder only yields string keys
			if !ok {
				return nil, ErrInvalid
			}
			if _, dup := m[key]; dup {
				return nil, ErrInvalid
			}
			if m[key], err = value(dec, nodes); err != nil {
				return nil, err
			}
		}
		_, err := dec.Token()
		return m, err
	case json.Number:
		if !strings.ContainsAny(string(t), ".eE") {
			return t.Int64()
		}
		return t.Float64()
	}
	return t, nil // string, bool or nil
}

// pointer resolves an RFC 6901 pointer. A missing key, an index past the
// end, "-" or a step below a scalar is null; a pointer without a leading
// "/", a bad "~" escape or a non-canonical array index is ErrInvalid.
func pointer(v any, ptr string) (any, error) {
	if ptr == "" {
		return v, nil
	}
	if ptr[0] != '/' {
		return nil, ErrInvalid
	}
	toks := strings.Split(ptr[1:], "/")
	for i, tok := range toks { // validate the whole pointer before walking
		var ok bool
		if toks[i], ok = unescape(tok); !ok {
			return nil, ErrInvalid
		}
	}
	for _, tok := range toks {
		var ok bool
		switch c := v.(type) {
		case map[string]any:
			if v, ok = c[tok]; !ok {
				return nil, nil
			}
		case []any:
			if tok == "-" {
				return nil, nil
			}
			i, err := strconv.Atoi(tok)
			if errors.Is(err, strconv.ErrRange) && strings.Trim(tok, "0123456789") == "" && tok[0] != '0' {
				return nil, nil // a canonical index past any possible end
			}
			if err != nil || strconv.Itoa(i) != tok || i < 0 {
				return nil, ErrInvalid
			}
			if i >= len(c) {
				return nil, nil
			}
			v = c[i]
		default:
			return nil, nil
		}
	}
	return v, nil
}

// unescape decodes ~1 to "/" and ~0 to "~"; any other "~" is malformed.
func unescape(tok string) (string, bool) {
	if !strings.Contains(tok, "~") {
		return tok, true
	}
	var b strings.Builder
	for i := 0; i < len(tok); i++ {
		if tok[i] != '~' {
			b.WriteByte(tok[i])
			continue
		}
		if i+1 == len(tok) || (tok[i+1] != '0' && tok[i+1] != '1') {
			return "", false
		}
		b.WriteByte("~/"[tok[i+1]-'0'])
		i++
	}
	return b.String(), true
}

// DocDecodes counts process document cache fills (misses), for tests in
// other packages that check a cache key change.
func DocDecodes() int {
	docs.mu.Lock()
	defer docs.mu.Unlock()
	return docs.decodes
}
