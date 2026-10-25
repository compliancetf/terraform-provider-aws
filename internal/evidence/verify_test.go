package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The chain goldens are the oracle: Verify results per file.
func TestVerifyGoldens(t *testing.T) {
	cases := []struct {
		file       string
		err        error
		line       int // line number in the error message
		records    int
		breaks     int
		terminated bool
		segment    bool
	}{
		{file: "chain-good.jsonl", records: 5, terminated: true},
		{file: "chain-edited.jsonl", err: ErrTampered, line: 4},
		{file: "chain-truncated.jsonl", err: ErrTruncated, line: 3, records: 2},
		{file: "chain-break.jsonl", records: 5, breaks: 1, terminated: true},
		{file: "chain-segment.jsonl", records: 3, breaks: 1, terminated: true, segment: true},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			f, err := os.Open(filepath.Join("testdata", tc.file))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			sum, err := Verify(f)
			if !errors.Is(err, tc.err) {
				t.Fatalf("Verify error = %v, want %v", err, tc.err)
			}
			if err != nil && !strings.Contains(err.Error(), "line "+strconv.Itoa(tc.line)+":") {
				t.Errorf("error %q does not name line %d", err, tc.line)
			}
			if err != nil && tc.err != ErrTruncated {
				return
			}
			if sum.Records != tc.records || sum.Breaks != tc.breaks || sum.Terminated != tc.terminated || sum.Segment != tc.segment {
				t.Errorf("summary = %+v", sum)
			}
		})
	}
}

func readFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// lines of chain-good.jsonl, without LF.
func goodLines(t *testing.T) [][]byte {
	t.Helper()
	b := readFile(t, filepath.Join("testdata", "chain-good.jsonl"))
	return bytes.Split(bytes.TrimSuffix(b, []byte("\n")), []byte("\n"))
}

func join(lines [][]byte) []byte { return append(bytes.Join(lines, []byte("\n")), '\n') }

func hashOf(b []byte) string { s := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(s[:]) }

func TestVerifyFailureModes(t *testing.T) {
	good := goodLines(t)
	mut := func(f func(l [][]byte) [][]byte) []byte {
		c := make([][]byte, len(good))
		for i := range good {
			c[i] = append([]byte(nil), good[i]...)
		}
		return join(f(c))
	}
	// relink re-hashes every prev after line i so only the targeted rule fails.
	relink := func(l [][]byte) [][]byte {
		for i := 1; i < len(l); i++ {
			old := string(l[i])
			j := strings.Index(old, `"prev":"`)
			l[i] = []byte(old[:j+8] + hashOf(l[i-1]) + old[j+8+71:])
		}
		return l
	}
	cases := []struct {
		name string
		in   []byte
		want error
	}{
		{"empty", nil, ErrEmpty},
		{"no final LF", bytes.TrimSuffix(join(good), []byte("\n")), ErrTruncated},
		{"unterminated is not an error", join(good[:4]), nil},
		{"dropped middle line", mut(func(l [][]byte) [][]byte { return append(l[:2], l[3:]...) }), ErrTampered},
		{"reordered", mut(func(l [][]byte) [][]byte { l[2], l[3] = l[3], l[2]; return l }), ErrTampered},
		{"record after end", join(append(append([][]byte{}, good...), good[4])), ErrTampered},
		{"whitespace", mut(func(l [][]byte) [][]byte { l[1] = bytes.Replace(l[1], []byte(`":`), []byte(`": `), 1); return l }), ErrMalformed},
		{"escape", mut(func(l [][]byte) [][]byte {
			l[1] = bytes.Replace(l[1], []byte(`"configure"`), []byte(`"configur\u0065"`), 1)
			return l
		}), ErrMalformed},
		{"duplicate key", mut(func(l [][]byte) [][]byte {
			l[1] = bytes.Replace(l[1], []byte(`"chain":"c_`), []byte(`"chain":"x","chain":"c_`), 1)
			return l
		}), ErrMalformed},
		{"float seq", mut(func(l [][]byte) [][]byte {
			l[1] = bytes.Replace(l[1], []byte(`"seq":1,`), []byte(`"seq":1.0,`), 1)
			return l
		}), ErrMalformed},
		{"null seq", mut(func(l [][]byte) [][]byte {
			l[1] = bytes.Replace(l[1], []byte(`"seq":1,`), []byte(`"seq":null,`), 1)
			return l
		}), ErrMalformed},
		{"absent prev", mut(func(l [][]byte) [][]byte { l[0] = bytes.Replace(l[0], []byte(`"prev":null,`), nil, 1); return l }), ErrMalformed},
		{"CRLF", mut(func(l [][]byte) [][]byte { l[1] = append(l[1], '\r'); return l }), ErrMalformed},
		{"unsupported v", mut(func(l [][]byte) [][]byte {
			l[0] = bytes.Replace(l[0], []byte(`"v":1`), []byte(`"v":2`), 1)
			return relink(l)
		}), ErrUnsupported},
		{"chain id changed", mut(func(l [][]byte) [][]byte {
			l[2] = bytes.Replace(l[2], []byte(`"chain":"c_`), []byte(`"chain":"c_9`), 1)
			l[2] = bytes.Replace(l[2], []byte(`_0101010101010101"`), []byte(`_010101010101010"`), 1)
			return relink(l)
		}), ErrTampered},
		{"run changed", mut(func(l [][]byte) [][]byte {
			l[2] = bytes.Replace(l[2], []byte(`bobthecorp-run-1`), []byte(`bobthecorp-run-2`), 1)
			return relink(l)
		}), ErrTampered},
		{"bad last_seq", mut(func(l [][]byte) [][]byte {
			l[4] = bytes.Replace(l[4], []byte(`"last_seq":3`), []byte(`"last_seq":2`), 1)
			return l
		}), ErrTampered},
		{"too long", append(bytes.Repeat([]byte("a"), MaxLine+1), '\n'), ErrTooLong},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Verify(bytes.NewReader(tc.in))
			if !errors.Is(err, tc.want) {
				t.Fatalf("Verify = %v, want %v", err, tc.want)
			}
		})
	}
}
