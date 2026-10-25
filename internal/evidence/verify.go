package evidence

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
)

// Verify errors. Each returned error wraps exactly one of them and names the
// 1-based line.
var (
	ErrEmpty       = errors.New("empty chain")
	ErrTruncated   = errors.New("final line incomplete")
	ErrTooLong     = errors.New("line too long")
	ErrMalformed   = errors.New("malformed line")
	ErrUnsupported = errors.New("unsupported record version")
	ErrTampered    = errors.New("chain broken")
)

// Summary describes a verified chain file. A file without chain_end is
// unterminated (Terminated false, no error). LastHash and Records are what a
// signed run manifest binds: the chain alone cannot detect an edit of the
// final line of an unterminated file or a cut at a line boundary.
type Summary struct {
	Chain      string
	RunID      string
	Segment    bool // the file starts with chain_break (a later segment)
	FirstSeq   int64
	LastSeq    int64
	LastHash   string
	Records    int
	Evals      int
	Breaks     int
	Terminated bool
}

// MaxLine is the largest line (LF excluded) the writer emits and Verify reads.
const MaxLine = 1 << 20

var (
	reCanonInt = regexp.MustCompile(`^(0|[1-9][0-9]{0,14})$`)
	reChainID  = regexp.MustCompile(`^c_[0-9]{13}_[0-9a-f]{16}$`)
)

func hashLine(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

type header struct {
	Chain    string
	Kind     Kind
	LastGood *Link
	LastSeq  *int64
	Prev     *string
	Run      json.RawMessage
	Seq      int64
}

// rawHeader decodes the header with pointers so null and absent are caught.
type rawHeader struct {
	Chain    *string         `json:"chain"`
	Kind     *Kind           `json:"kind"`
	LastGood *Link           `json:"last_good"`
	LastSeq  *int64          `json:"last_seq"`
	Prev     *string         `json:"prev"`
	Run      json.RawMessage `json:"run"`
	Seq      *int64          `json:"seq"`
	TS       *string         `json:"ts"`
	V        *int            `json:"v"`
}

// Verify checks one chain file: canonical form of every line, seq
// continuity, every prev link, chain and run constancy, and the chain_break
// and chain_end rules. It does not validate records against the JSON Schema
// and ignores keys it does not know.
func Verify(r io.Reader) (Summary, error) {
	var (
		sum   Summary
		first header
		run   []byte
		prev  []byte
		ended bool
	)
	br := bufio.NewReaderSize(r, 64<<10)
	for n := 1; ; n++ {
		line, err := readLine(br)
		fail := func(kind error, why string) (Summary, error) {
			return sum, fmt.Errorf("evidence: line %d: %w: %s", n, kind, why)
		}
		switch {
		case err == io.EOF && n == 1:
			return fail(ErrEmpty, "no lines")
		case err == io.EOF:
			return sum, nil
		case errors.Is(err, ErrTruncated), errors.Is(err, ErrTooLong):
			return fail(err, "at end of input")
		case err != nil:
			return sum, fmt.Errorf("evidence: line %d: read: %w", n, err)
		}
		h, err := parseLine(line)
		if err != nil {
			if errors.Is(err, ErrUnsupported) {
				return fail(ErrUnsupported, "v is not 1")
			}
			return fail(ErrMalformed, err.Error())
		}
		if ended {
			return fail(ErrTampered, "record after chain_end")
		}
		if n == 1 {
			switch {
			case h.Kind == KindChainStart && h.Seq == 0 && h.Prev == nil:
			case h.Kind == KindChainBreak && h.Seq > 0 && h.Prev != nil:
				sum.Segment = true
			default:
				return fail(ErrTampered, "first line is not chain_start or chain_break")
			}
			if !reChainID.MatchString(h.Chain) {
				return fail(ErrMalformed, "bad chain id")
			}
			first, run = h, h.Run
			sum.Chain, sum.FirstSeq = h.Chain, h.Seq
			var rr Run
			if err := json.Unmarshal(h.Run, &rr); err != nil {
				return fail(ErrMalformed, "bad run")
			}
			sum.RunID = rr.ID
		} else {
			switch {
			case h.Chain != first.Chain:
				return fail(ErrTampered, "chain id changed")
			case !bytes.Equal(h.Run, run):
				return fail(ErrTampered, "run changed")
			case h.Seq != sum.LastSeq+1:
				return fail(ErrTampered, "seq not continuous")
			case h.Prev == nil || *h.Prev != hashLine(prev):
				return fail(ErrTampered, "prev does not match the previous line")
			case h.Kind == KindChainStart:
				return fail(ErrTampered, "chain_start after line 1")
			}
		}
		switch h.Kind {
		case KindChainBreak:
			if h.LastGood == nil || h.LastGood.Seq != h.Seq-1 || h.LastGood.Hash != *h.Prev {
				return fail(ErrTampered, "last_good does not match the previous line")
			}
			sum.Breaks++
		case KindChainEnd:
			if h.LastSeq == nil || *h.LastSeq != h.Seq-1 {
				return fail(ErrTampered, "last_seq does not match")
			}
			ended, sum.Terminated = true, true
		case KindEval:
			sum.Evals++
		}
		prev = line
		sum.Records++
		sum.LastSeq, sum.LastHash = h.Seq, hashLine(line)
	}
}

// readLine returns the next line without its LF, io.EOF at a clean end,
// ErrTruncated for trailing bytes without LF, ErrTooLong past MaxLine.
func readLine(br *bufio.Reader) ([]byte, error) {
	var acc []byte
	for {
		chunk, err := br.ReadSlice('\n')
		acc = append(acc, chunk...)
		if len(acc) > MaxLine+1 || (len(acc) == MaxLine+1 && acc[MaxLine] != '\n') {
			return nil, ErrTooLong
		}
		switch {
		case err == nil:
			return acc[:len(acc)-1], nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case err == io.EOF && len(acc) == 0:
			return nil, io.EOF
		case err == io.EOF:
			return nil, ErrTruncated
		default:
			return nil, err
		}
	}
}

// parseLine requires the line to be its own canonical encoding (no escapes,
// sorted unique keys, no whitespace, canonical integers) and decodes the
// header fields.
func parseLine(line []byte) (header, error) {
	var h header
	if bytes.IndexByte(line, '\\') >= 0 {
		return h, errors.New("escape sequence")
	}
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil || dec.InputOffset() != int64(len(line)) {
		return h, errors.New("not a single JSON object")
	}
	if !canonNumbers(m) {
		return h, errors.New("non-canonical number")
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil || !bytes.Equal(bytes.TrimSuffix(buf.Bytes(), []byte("\n")), line) {
		return h, errors.New("not in canonical form")
	}
	if _, ok := m["prev"]; !ok {
		return h, errors.New("missing header field")
	}
	var raw rawHeader
	if err := json.Unmarshal(line, &raw); err != nil {
		return h, errors.New("bad header field type")
	}
	if raw.V == nil || raw.Kind == nil || raw.Chain == nil || raw.Seq == nil || raw.TS == nil ||
		len(raw.Run) == 0 || raw.Run[0] != '{' {
		return h, errors.New("missing or null header field")
	}
	if *raw.V != 1 {
		return h, ErrUnsupported
	}
	h = header{Chain: *raw.Chain, Kind: *raw.Kind, LastGood: raw.LastGood, LastSeq: raw.LastSeq,
		Prev: raw.Prev, Run: raw.Run, Seq: *raw.Seq}
	switch h.Kind {
	case KindChainStart, KindConfigure, KindEval, KindChainBreak, KindChainEnd:
	default:
		return h, errors.New("unknown kind")
	}
	return h, nil
}

func canonNumbers(v any) bool {
	switch t := v.(type) {
	case json.Number:
		return reCanonInt.MatchString(string(t))
	case map[string]any:
		for _, e := range t {
			if !canonNumbers(e) {
				return false
			}
		}
	case []any:
		for _, e := range t {
			if !canonNumbers(e) {
				return false
			}
		}
	}
	return true
}
