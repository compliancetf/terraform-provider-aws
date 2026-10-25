//go:build ctftest

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// tamperCmd writes the tampered archive set (the oracle) next to a
// fresh build of src: each <case>.tar.gz breaks exactly one reader rule.
// ctftest builds only; the output is reproducible.
func tamperCmd(src, keySpec, outDir string) error {
	key, err := loadKey(keySpec)
	if err != nil {
		return err
	}
	good, err := build(src, key)
	if err != nil {
		return err
	}
	cases, err := tamperSet(good)
	if err != nil {
		return err
	}
	for name, data := range cases {
		if err := os.WriteFile(filepath.Join(outDir, name+".tar.gz"), data, 0o644); err != nil { //nolint:gosec // public fixtures
			return err
		}
	}
	return nil
}

type entry struct {
	h    *tar.Header // nil: raw is written as is
	body []byte
	raw  []byte
}

func goodEntries(archive []byte) ([]entry, []byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, nil, err
	}
	tarBytes, err := io.ReadAll(zr)
	if err != nil {
		return nil, nil, err
	}
	tr := tar.NewReader(bytes.NewReader(tarBytes))
	var out []entry
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out, tarBytes, nil
		}
		if err != nil {
			return nil, nil, err
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, entry{h: &tar.Header{Name: h.Name, Typeflag: tar.TypeReg, Size: h.Size}, body: body})
	}
}

// tarOf writes entries (headers via tar.Writer, raw blocks verbatim).
func tarOf(es []entry) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range es {
		if e.h == nil {
			if err := tw.Flush(); err != nil {
				return nil, err
			}
			buf.Write(e.raw)
			continue
		}
		h := *e.h
		if err := writeEntry(tw, &h, e.body); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// rawHeader is a hand-built header block for types tar.Writer will not emit.
func rawHeader(name string, typeflag byte, size int, gnu bool) []byte {
	b := make([]byte, 512)
	copy(b[0:], name)
	copy(b[100:], "0000644\x00")
	copy(b[108:], "0000000\x00")
	copy(b[116:], "0000000\x00")
	copy(b[124:], fmt.Sprintf("%011o\x00", size))
	copy(b[136:], "00000000000\x00")
	b[156] = typeflag
	if gnu {
		copy(b[257:], "ustar  \x00")
	} else {
		copy(b[257:], "ustar\x0000")
	}
	copy(b[148:], "        ")
	sum := 0
	for _, c := range b {
		sum += int(c)
	}
	copy(b[148:], fmt.Sprintf("%06o\x00 ", sum))
	return b
}

// padded returns body padded to whole 512-byte blocks.
func padded(body []byte) []byte {
	return append(body, make([]byte, (512-len(body)%512)%512)...)
}

// paxEntry is a raw PAX extended header followed by a USTAR entry.
func paxEntry(records [][2]string, name string, body []byte) []byte {
	var rec strings.Builder
	for _, r := range records {
		line := " " + r[0] + "=" + r[1] + "\n"
		n := len(line) + 1 // the length counts its own digits
		for len(fmt.Sprint(n))+len(line) != n {
			n = len(fmt.Sprint(n)) + len(line)
		}
		fmt.Fprintf(&rec, "%d%s", n, line)
	}
	out := append(rawHeader("PaxHeader", 'x', rec.Len(), false), padded([]byte(rec.String()))...)
	out = append(out, rawHeader(name, '0', len(body), false)...)
	return append(out, padded(append([]byte(nil), body...))...)
}

func tamperSet(good []byte) (map[string][]byte, error) {
	es, goodTar, err := goodEntries(good)
	if err != nil {
		return nil, err
	}
	if len(es) != 3 {
		return nil, errors.New("tamper needs a source with controls.json and revocations.json")
	}
	m, c, r := es[0], es[1], es[2]
	with := func(e entry, f func(h *tar.Header)) entry {
		h := *e.h
		f(&h)
		return entry{h: &h, body: e.body}
	}
	named := func(n string) entry { return with(c, func(h *tar.Header) { h.Name = n }) }
	flipped := append([]byte{c.body[0] ^ 1}, c.body[1:]...)
	badSig := bytes.Replace(m.body, []byte(`"sig":"`), []byte(`"sig":"AA`), 1)
	extra := append([]byte(nil), c.body...)
	sets := map[string][]entry{
		"tamper-digest":   {m, {h: c.h, body: flipped}, r},
		"unlisted-file":   {m, c, r, with(r, func(h *tar.Header) { h.Name = "extra.json" })},
		"duplicate-entry": {m, c, r, c},
		"wrong-first":     {c, m, r},
		"traversal":       {m, named("../controls.json"), r},
		"absolute":        {m, named("/controls.json"), r},
		"case-variant":    {m, named("Controls.json"), r},
		"symlink":         {m, {h: &tar.Header{Name: "controls.json", Typeflag: tar.TypeSymlink, Linkname: "revocations.json"}}, r},
		"hardlink":        {m, r, {h: &tar.Header{Name: "controls.json", Typeflag: tar.TypeLink, Linkname: "revocations.json"}}},
		"oldgnu-sparse":   {m, {raw: append(rawHeader("controls.json", 'S', len(c.body), true), padded(append([]byte(nil), c.body...))...)}, r},
		"pax-sparse": {m, {raw: paxEntry([][2]string{{"GNU.sparse.numblocks", "1"}, {"GNU.sparse.map", "0," + fmt.Sprint(len(c.body))},
			{"GNU.sparse.size", fmt.Sprint(len(c.body))}}, "controls.json", c.body)}, r},
		"pax-path":      {m, {raw: paxEntry([][2]string{{"path", "controls.json"}}, "x", c.body)}, r},
		"gnu-longname":  {m, with(c, func(h *tar.Header) { h.Name = strings.Repeat("d/", 60) + "controls.json"; h.Format = tar.FormatGNU }), r},
		"oversize":      {m, {h: &tar.Header{Name: "controls.json", Typeflag: tar.TypeReg, Size: maxFile + 1<<20}, body: make([]byte, maxFile+1<<20)}, r},
		"size-mismatch": {m, {h: &tar.Header{Name: "controls.json", Typeflag: tar.TypeReg, Size: int64(len(extra) + 1)}, body: append(extra, '\n')}, r},
		"missing-file":  {m, c},
		"bad-signature": {{h: &tar.Header{Name: m.h.Name, Typeflag: tar.TypeReg, Size: int64(len(badSig))}, body: badSig}, c, r},
	}
	out := map[string][]byte{}
	for name, set := range sets {
		t, err := tarOf(set)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		out[name] = gzipBytes(t)
	}
	// Stream-level cases on the good tar.
	out["gzip-bomb"] = gzipBytes(append(append([]byte(nil), goodTar...), make([]byte, maxDecompressed)...))
	out["trailing-gzip-member"] = append(append([]byte(nil), good...), gzipBytes(nil)...)
	out["trailing-garbage"] = append(append([]byte(nil), good...), "garbage"...)
	more, err := tarOf([]entry{{h: &tar.Header{Name: "extra.json", Typeflag: tar.TypeReg, Size: 2}, body: []byte("{}")}})
	if err != nil {
		return nil, err
	}
	// A PAX header after the last entry: tar.Reader consumes it and reports EOF.
	pax, err := tarOf([]entry{m, c, r, {raw: paxEntry([][2]string{{"comment", "x"}}, "", nil)[:1024]}})
	if err != nil {
		return nil, err
	}
	out["trailing-pax"] = gzipBytes(pax)
	// The same without the end marker: the PAX blocks are all that follows.
	out["trailing-pax-no-marker"] = gzipBytes(pax[:len(pax)-1024])
	// A non-zero byte in the block padding after controls.json.
	dirty := append([]byte(nil), goodTar...)
	dirty[512+(len(m.body)+511)/512*512+512+len(c.body)] = 'X'
	out["nonzero-padding"] = gzipBytes(dirty)
	out["trailing-tar-data"] = gzipBytes(append(append([]byte(nil), goodTar...), more...))
	return out, nil
}
