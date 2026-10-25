package iampolicy

import (
	"encoding/json"
	"io"
	"strings"
	"unicode/utf8"
)

const (
	// MaxDocBytes is the document size limit, checked before decode.
	MaxDocBytes = 256 << 10
	// MaxStatements is the statement count limit, checked after decode.
	MaxStatements = 500
	// maxDepth bounds container nesting; a valid policy needs 6 (document,
	// Statement list, statement, Condition, operator, value list).
	maxDepth = 16
)

// decode reads one JSON value token by token with the rules of the
// json.path decoder in internal/engine/lib (duplicate object keys at any
// depth, trailing data and invalid UTF-8 rejected), plus a nesting bound and
// rejection of U+FFFD, which encoding/json substitutes for lone surrogate
// escapes. Numbers stay json.Number so condition values keep their exact
// JSON text. Objects are map[string]any, arrays []any.
func decode(doc string) (any, error) {
	if !utf8.ValidString(doc) {
		return nil, invalid(rUTF8)
	}
	dec := json.NewDecoder(strings.NewReader(doc))
	dec.UseNumber()
	v, err := value(dec, 1)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, invalid(rJSON)
	}
	return v, nil
}

func value(dec *json.Decoder, depth int) (any, error) {
	t, err := dec.Token()
	if err != nil {
		return nil, invalid(rJSON)
	}
	switch t := t.(type) {
	case json.Delim:
		if depth > maxDepth {
			return nil, limit(rDepth)
		}
		if t == '[' {
			l := []any{}
			for dec.More() {
				v, err := value(dec, depth+1)
				if err != nil {
					return nil, err
				}
				l = append(l, v)
			}
			return l, closing(dec)
		}
		if t != '{' {
			return nil, invalid(rJSON)
		}
		m := map[string]any{}
		for dec.More() {
			k, err := dec.Token()
			if err != nil {
				return nil, invalid(rJSON)
			}
			key, ok := k.(string)
			if !ok {
				return nil, invalid(rJSON)
			}
			if strings.ContainsRune(key, utf8.RuneError) {
				return nil, invalid(rUTF8)
			}
			if _, dup := m[key]; dup {
				return nil, invalid(rDuplicateKey)
			}
			if m[key], err = value(dec, depth+1); err != nil {
				return nil, err
			}
		}
		return m, closing(dec)
	case string:
		if strings.ContainsRune(t, utf8.RuneError) {
			return nil, invalid(rUTF8)
		}
	}
	return t, nil // string, json.Number, bool or nil
}

func closing(dec *json.Decoder) error {
	if _, err := dec.Token(); err != nil {
		return invalid(rJSON)
	}
	return nil
}
