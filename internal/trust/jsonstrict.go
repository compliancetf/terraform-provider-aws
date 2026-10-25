package trust

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

// foldName maps every rune to the smallest rune of its Unicode simple-fold
// orbit, so two names collide exactly when encoding/json would match them to
// the same field (it folds like bytes.EqualFold, e.g. U+017F to "s").
func foldName(s string) string {
	var b strings.Builder
	for _, r := range s {
		m := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			m = min(m, f)
		}
		b.WriteRune(m)
	}
	return b.String()
}

const maxJSONDepth = 32

type jsonFrame struct {
	obj     bool
	wantKey bool
	seen    map[string]bool
}

// checkJSON walks data token by token (no recursion) and rejects: invalid
// UTF-8, more than one top-level value, nesting deeper than maxJSONDepth,
// member names duplicated under case folding (encoding/json matches field
// names case-insensitively and keeps the last duplicate), and, when allowed is
// non-nil, member names not in allowed (exact match) and null values.
func checkJSON(data []byte, allowed map[string]bool) error {
	if !utf8.Valid(data) {
		return errors.New("invalid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var stack []*jsonFrame
	values := 0
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errInvalidJSON // a syntax error quotes input; never echo it
		}
		top := (*jsonFrame)(nil)
		if n := len(stack); n > 0 {
			top = stack[n-1]
		}
		if d, ok := tok.(json.Delim); ok && (d == '}' || d == ']') {
			stack = stack[:len(stack)-1]
			continue
		}
		if top != nil && top.obj && top.wantKey {
			name, ok := tok.(string)
			if !ok {
				return errors.New("non-string member name")
			}
			folded := foldName(name)
			if top.seen[folded] {
				return errors.New("duplicate member name") // value-free: names are unsigned input
			}
			top.seen[folded] = true
			if allowed != nil && !allowed[name] {
				return errors.New("unknown member name") // value-free: names are unsigned input
			}
			top.wantKey = false
			continue
		}
		// A value starts here.
		if top == nil {
			if values++; values > 1 {
				return errors.New("trailing data after JSON value")
			}
		} else if top.obj {
			top.wantKey = true
		}
		switch tok {
		case json.Delim('{'), json.Delim('['):
			if len(stack) >= maxJSONDepth {
				return errors.New("JSON nested too deep")
			}
			obj := tok == json.Delim('{')
			stack = append(stack, &jsonFrame{obj: obj, wantKey: obj, seen: map[string]bool{}})
		case nil:
			if allowed != nil {
				return errors.New("null value")
			}
		}
	}
	if values != 1 {
		return errors.New("empty JSON")
	}
	return nil
}

var (
	errInvalidJSON = errors.New("invalid JSON")
	errWrongShape  = errors.New("JSON value has the wrong shape")
)

// strictUnmarshal runs checkJSON with the allowed member names, then decodes
// with unknown fields rejected. A decode error is errWrongShape alone: the
// decoder's text quotes member names and values, signed or not.
func strictUnmarshal(data []byte, allowed map[string]bool, v any) error {
	if err := checkJSON(data, allowed); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errWrongShape
	}
	return nil
}

func names(n ...string) map[string]bool {
	m := make(map[string]bool, len(n))
	for _, s := range n {
		m[s] = true
	}
	return m
}
