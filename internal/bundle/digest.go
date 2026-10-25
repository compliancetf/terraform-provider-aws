package bundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// ErrNotJSON is the digest_not_json class: input that is not one I-JSON
// (RFC 7493) value.
var ErrNotJSON = errors.New("digest_not_json")

// ErrSpecialFile is the digest_special_file class: a symlink, device, FIFO,
// socket or other non-regular file in a digested directory.
var ErrSpecialFile = errors.New("digest_special_file")

// ErrChanged is the digest_changed class: the tree changed while DigestDir
// walked it (a file removed, replaced by another file or resized).
var ErrChanged = errors.New("digest_changed")

// maxJSONDepth bounds nesting so a deep document cannot exhaust the stack.
const maxJSONDepth = 10000

// DigestJSON is "sha256:" + hex of sha256 over the RFC 8785 (JCS) form of
// data. Input that is not I-JSON is
// digest_not_json: invalid UTF-8, an unpaired surrogate escape, a
// noncharacter in a string (RFC 7493 section 2.1), a duplicate member name,
// a number outside float64, trailing data or nesting past maxJSONDepth.
func DigestJSON(data []byte) (string, error) {
	b, err := canonicalJSON(data)
	if err != nil {
		return "", err
	}
	return "sha256:" + sha256Hex(b), nil
}

// CanonicalJSON is the RFC 8785 (JCS) form of data, with the I-JSON checks
// of DigestJSON (ErrNotJSON). The verdict signature covers these bytes.
func CanonicalJSON(data []byte) ([]byte, error) { return canonicalJSON(data) }

func canonicalJSON(data []byte) ([]byte, error) {
	if !utf8.Valid(data) || !surrogatesPaired(data) {
		return nil, ErrNotJSON
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := decodeJSON(dec, 0)
	if err != nil {
		return nil, ErrNotJSON
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, ErrNotJSON
	}
	var buf bytes.Buffer
	if err := writeJCS(&buf, v); err != nil {
		return nil, ErrNotJSON
	}
	return buf.Bytes(), nil
}

// decodeJSON reads one value as string, json.Number, bool, nil, []any or
// map[string]any, rejecting duplicate member names.
func decodeJSON(dec *json.Decoder, depth int) (any, error) {
	if depth > maxJSONDepth {
		return nil, ErrNotJSON
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch tok {
	case json.Delim('['):
		list := []any{}
		for dec.More() {
			v, err := decodeJSON(dec, depth+1)
			if err != nil {
				return nil, err
			}
			list = append(list, v)
		}
		_, err = dec.Token()
		return list, err
	case json.Delim('{'):
		obj := map[string]any{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return nil, err
			}
			k, ok := kt.(string)
			if !ok || hasNoncharacter(k) {
				return nil, ErrNotJSON
			}
			if _, dup := obj[k]; dup {
				return nil, ErrNotJSON
			}
			if obj[k], err = decodeJSON(dec, depth+1); err != nil {
				return nil, err
			}
		}
		_, err = dec.Token()
		return obj, err
	}
	if str, ok := tok.(string); ok && hasNoncharacter(str) {
		return nil, ErrNotJSON
	}
	return tok, nil
}

// surrogatesPaired reports whether every \uD800-\uDBFF escape in a string of
// data is immediately followed by a \uDC00-\uDFFF escape and no low
// surrogate escape stands alone; a truncated or non-hex \u escape fails.
// encoding/json would decode an unpaired one as U+FFFD. data is valid UTF-8,
// so a '"' or '\\' byte is never inside a multi-byte sequence.
func surrogatesPaired(data []byte) bool {
	in := false
	for i := 0; i < len(data); i++ {
		switch c := data[i]; {
		case !in:
			in = c == '"'
		case c == '"':
			in = false
		case c != '\\':
		case i+1 < len(data) && data[i+1] != 'u':
			i++ // a one-character escape
		default:
			hi, ok := hex4(data, i)
			switch {
			case !ok || 0xDC00 <= hi && hi <= 0xDFFF:
				return false
			case 0xD800 <= hi && hi <= 0xDBFF:
				lo, ok := hex4(data, i+6)
				if !ok || lo < 0xDC00 || lo > 0xDFFF {
					return false
				}
				i += 11
			default:
				i += 5
			}
		}
	}
	return true
}

// hex4 decodes the \uXXXX escape at data[i:i+6].
func hex4(data []byte, i int) (int, bool) {
	if i+6 > len(data) || data[i] != '\\' || data[i+1] != 'u' {
		return 0, false
	}
	v, err := strconv.ParseUint(string(data[i+2:i+6]), 16, 16)
	return int(v), err == nil
}

// hasNoncharacter reports a Unicode noncharacter: U+FDD0..U+FDEF or a code
// point ending in FFFE or FFFF (RFC 7493 section 2.1).
func hasNoncharacter(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool {
		return 0xFDD0 <= r && r <= 0xFDEF || r&0xFFFE == 0xFFFE
	}) >= 0
}

// DigestRaw is "sha256:" + hex of sha256 over the raw bytes of b
// (binary file).
func DigestRaw(b []byte) string {
	return "sha256:" + sha256Hex(b)
}

// DigestDir is "sha256:" + hex of sha256 over the JCS form of the manifest
// of the directory tree at root:
//
//	[{"path": "a/b.txt", "type": "file", "mode": "0644", "digest": "sha256:<hex>"}]
//
// One entry per regular file at any depth; directories are walked and get no
// entry, so an empty tree is []. path is relative to root with "/"
// separators, valid UTF-8 without noncharacters (else digest_not_json); entries are sorted by
// path in byte order. mode is the 4-digit octal Unix mode of the opened file:
// permission bits plus setuid 04000, setgid 02000 and sticky 01000. digest is
// DigestRaw of the file bytes. A symlink (root included), device, FIFO,
// socket or other non-regular file anywhere is digest_special_file; it is
// never followed or skipped. A file removed, replaced, resized or rewritten
// (mtime or mode changed) while it is digested, or a directory removed
// during the walk, is digest_changed; a same-size rewrite within one mtime
// tick is not seen, nor is a replacement that reuses the freed inode number
// (os.SameFile compares device and inode only; an open descriptor pins the
// inode on local file systems, not on every network or FUSE mount). Any
// other I/O error (permission) is returned as is, even when the entry is
// also removed. Each file is opened without following a
// final symlink and checked regular on the open descriptor; the tree is
// assumed owned by the caller (a swapped intermediate directory is not
// detected).
func DigestDir(root string) (string, error) {
	root = filepath.Clean(root) // "link/" or "link/." would resolve the symlink
	fi, err := os.Lstat(root)
	if err != nil {
		return "", err
	}
	if !fi.IsDir() {
		if fi.Mode().IsRegular() {
			return "", fmt.Errorf("%s is not a directory", root)
		}
		return "", fmt.Errorf(".: %w", ErrSpecialFile)
	}
	type entry struct {
		path string
		e    map[string]any
	}
	var entries []entry
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return changed(err)
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		switch {
		case d.IsDir():
			return nil
		case !d.Type().IsRegular():
			return fmt.Errorf("%s: %w", rel, ErrSpecialFile)
		case !utf8.ValidString(rel) || hasNoncharacter(rel):
			return fmt.Errorf("file name is not I-JSON: %w", ErrNotJSON)
		}
		e, err := dirEntry(p, rel)
		if err == nil {
			entries = append(entries, entry{rel, e})
		}
		return err
	})
	if err != nil {
		return "", err
	}
	slices.SortFunc(entries, func(a, b entry) int { return strings.Compare(a.path, b.path) })
	manifest := []any{} // an empty tree is [], not null
	for _, e := range entries {
		manifest = append(manifest, e.e)
	}
	var buf bytes.Buffer
	if err := writeJCS(&buf, manifest); err != nil {
		return "", err
	}
	return DigestRaw(buf.Bytes()), nil
}

// dirEntry opens p without following a final symlink (non-blocking, so a
// FIFO swapped in after the walk cannot hang) and digests it if the open
// descriptor is a regular file.
func dirEntry(p, rel string) (map[string]any, error) {
	f, err := openNoFollow(p)
	if err != nil {
		if fi, lerr := os.Lstat(p); lerr == nil && !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("%s: %w", rel, ErrSpecialFile)
		}
		return nil, changed(err)
	}
	defer f.Close() //nolint:errcheck // read-only
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	// The descriptor must be a regular file and still the one at p: os.Open
	// off Unix follows a symlink swapped in after the walk.
	li, err := os.Lstat(p)
	switch {
	case err != nil:
		return nil, changed(err)
	case !fi.Mode().IsRegular() || !li.Mode().IsRegular():
		return nil, fmt.Errorf("%s: %w", rel, ErrSpecialFile)
	case !os.SameFile(fi, li):
		return nil, fmt.Errorf("%s: %w", rel, ErrChanged)
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	if testHookAfterCopy != nil {
		testHookAfterCopy(p)
	}
	// The hashed bytes are the file's only if nothing changed meanwhile: the
	// descriptor keeps its size, mtime and mode (an in-place rewrite) and p
	// still names it (not replaced or unlinked after the Lstat).
	fi2, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if fi2.Size() != fi.Size() || !fi2.ModTime().Equal(fi.ModTime()) || fi2.Mode() != fi.Mode() {
		return nil, fmt.Errorf("%s: %w", rel, ErrChanged)
	}
	if li, err := os.Lstat(p); err != nil {
		return nil, changed(err)
	} else if !os.SameFile(fi, li) {
		return nil, fmt.Errorf("%s: %w", rel, ErrChanged)
	}
	m := fi.Mode()
	mode := uint32(m.Perm())
	if m&fs.ModeSetuid != 0 {
		mode |= 0o4000
	}
	if m&fs.ModeSetgid != 0 {
		mode |= 0o2000
	}
	if m&fs.ModeSticky != 0 {
		mode |= 0o1000
	}
	return map[string]any{"path": rel, "type": "file", "mode": fmt.Sprintf("%04o", mode), "digest": "sha256:" + hex.EncodeToString(h.Sum(nil))}, nil
}

// testHookAfterCopy, when set by a test, runs after a file is hashed and
// before the change checks. It is a package global: a test that sets it must
// not call t.Parallel, or a concurrent DigestDir would run its hook.
var testHookAfterCopy func(p string)

// changed classifies an I/O error on an entry the walk listed: one that no
// longer exists was removed during the walk (digest_changed); any other
// error (permission, I/O, ENOTDIR, ESTALE) is returned as is and still fails.
func changed(err error) error {
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: %w", ErrChanged, err)
	}
	return err
}

// writeJCS writes v in RFC 8785 form: members sorted by UTF-16 code units,
// numbers as ECMAScript Number.prototype.toString, minimal string escapes.
func writeJCS(buf *bytes.Buffer, v any) error {
	switch v := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		buf.WriteString(strconv.FormatBool(v))
	case string:
		writeJCSString(buf, v)
	case json.Number:
		f, err := strconv.ParseFloat(string(v), 64)
		if err != nil {
			return err
		}
		buf.WriteString(es6Number(f))
	case []any:
		buf.WriteByte('[')
		for i, e := range v {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeJCS(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		type key struct {
			s     string
			units []uint16
		}
		keys := make([]key, 0, len(v))
		for k := range v {
			keys = append(keys, key{k, utf16.Encode([]rune(k))}) // encoded once, not per comparison
		}
		slices.SortFunc(keys, func(a, b key) int { return slices.Compare(a.units, b.units) })
		buf.WriteByte('{')
		for i, kk := range keys {
			k := kk.s
			if i > 0 {
				buf.WriteByte(',')
			}
			writeJCSString(buf, k)
			buf.WriteByte(':')
			if err := writeJCS(buf, v[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return ErrNotJSON
	}
	return nil
}

func writeJCSString(buf *bytes.Buffer, s string) {
	const hex = "0123456789abcdef"
	buf.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			buf.WriteByte('\\')
			buf.WriteRune(r)
		case r == '\b':
			buf.WriteString(`\b`)
		case r == '\t':
			buf.WriteString(`\t`)
		case r == '\n':
			buf.WriteString(`\n`)
		case r == '\f':
			buf.WriteString(`\f`)
		case r == '\r':
			buf.WriteString(`\r`)
		case r < 0x20:
			buf.WriteString(`\u00`)
			buf.WriteByte(hex[r>>4])
			buf.WriteByte(hex[r&0xf])
		default:
			buf.WriteRune(r)
		}
	}
	buf.WriteByte('"')
}

// es6Number formats f as ECMAScript Number.prototype.toString does, from
// Go's shortest round-trip digits.
func es6Number(f float64) string {
	if f == 0 {
		return "0" // also -0
	}
	sign := ""
	if f < 0 {
		sign, f = "-", -f
	}
	mant, exp, _ := strings.Cut(strconv.FormatFloat(f, 'e', -1, 64), "e")
	digits := strings.Replace(mant, ".", "", 1)
	e, err := strconv.Atoi(exp)
	if err != nil {
		panic(err) // unreachable: FormatFloat 'e' always has an integer exponent
	}
	k, n := len(digits), e+1 // value = 0.digits * 10^n
	switch {
	case k <= n && n <= 21:
		return sign + digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		return sign + digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		return sign + "0." + strings.Repeat("0", -n) + digits
	}
	out := sign + digits[:1]
	if k > 1 {
		out += "." + digits[1:]
	}
	if n-1 >= 0 {
		return out + "e+" + strconv.Itoa(n-1)
	}
	return out + "e-" + strconv.Itoa(1-n)
}
