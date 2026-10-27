package evidence

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/fsutil"
)

// Write error classes, for "evidence write failed: <class>".
const (
	ClassOpen    = "open"
	ClassInvalid = "invalid"
	ClassWrite   = "write"
	ClassSync    = "sync"
	ClassClosed  = "closed"
)

// WriteError is a value-free writer error.
type WriteError struct {
	Class string
	Err   error
}

func (e *WriteError) Error() string {
	return "evidence write failed: " + e.Class + ": " + e.Err.Error()
}
func (e *WriteError) Unwrap() error { return e.Err }

func werr(class string, err error) error { return &WriteError{Class: class, Err: err} }

var reRunToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// RunFromEnv derives the run id from the first valid CI variable, else a
// random id. Ids that are not a safe path component are skipped.
func RunFromEnv(getenv func(string) string) Run {
	gh := getenv("GITHUB_RUN_ID")
	if gh != "" {
		attempt := getenv("GITHUB_RUN_ATTEMPT")
		if attempt == "" {
			attempt = "1"
		}
		gh += "-" + attempt
	}
	run := Run{}
	if c := getenv("COMPLIANCETF_RUN_CLASS"); reRunToken.MatchString(c) {
		run.ClassClaimed = &c
	}
	for _, s := range [][2]string{
		{getenv("COMPLIANCETF_RUN_ID"), "compliancetf"},
		{gh, "github"},
		{getenv("TFC_RUN_ID"), "tfc"},
		{getenv("SPACELIFT_RUN_ID"), "spacelift"},
		{getenv("CI_PIPELINE_ID"), "gitlab"},
	} {
		if reRunToken.MatchString(s[0]) {
			run.ID, run.IDSource = s[0], s[1]
			return run
		}
	}
	run.ID, run.IDSource = stampID("r", time.Now(), rand.Reader), "random"
	return run
}

func stampID(prefix string, now time.Time, rnd io.Reader) string {
	var b [8]byte
	if _, err := io.ReadFull(rnd, b[:]); err != nil {
		panic("evidence: random source: " + err.Error())
	}
	return fmt.Sprintf("%s_%013d_%s", prefix, now.UnixMilli(), hex.EncodeToString(b[:]))
}

// Options configure Open. Now and Rand default to the real clock and
// crypto/rand; tests inject them for goldens.
type Options struct {
	Dir      string
	Run      Run
	Provider Provider
	Now      func() time.Time
	Rand     io.Reader
	dirSync  func(*os.File) error // test seam; nil means syncDir
}

// segFile is the part of *os.File the writer uses (a test seam).
type segFile interface {
	io.Writer
	Stat() (os.FileInfo, error)
	Sync() error
	Close() error
}

// Writer appends records to one chain. Safe for concurrent use. A failed
// write is never retried; the next write starts a new segment with
// chain_break, in the same file when nothing reached it, else in a new file
// <chain>.<n>.jsonl. Files are never truncated.
type Writer struct {
	mu         sync.Mutex
	root       *os.Root
	runDir     *os.File
	f          segFile
	chain      string
	run        Run
	now        func() time.Time
	seg        int
	off        int64
	seq        int64   // seq of the next line
	prev       *string // hash of the last committed line
	dirty      bool
	dirPending bool // the run dir entry of the current file is not fsynced yet
	dirSync    func(*os.File) error
	closed     bool
}

// Open creates <Dir>/<run id>/<chain id>.jsonl and writes chain_start.
func Open(o Options) (*Writer, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Rand == nil {
		o.Rand = rand.Reader
	}
	if !reRunToken.MatchString(o.Run.ID) {
		return nil, werr(ClassOpen, errors.New("run id is not a safe path component"))
	}
	if o.dirSync == nil {
		o.dirSync = syncDir
	}
	w := &Writer{run: o.Run, now: o.Now, chain: stampID("c", o.Now(), o.Rand), dirSync: o.dirSync}
	if err := w.openDirs(o.Dir); err != nil {
		return nil, errors.Join(werr(ClassOpen, err), w.closeFiles())
	}
	if err := w.newFile(); err != nil {
		return nil, errors.Join(err, w.closeFiles())
	}
	if err := w.write(Record{Kind: KindChainStart, Provider: &o.Provider}, true); err != nil {
		return nil, errors.Join(err, w.closeFiles())
	}
	return w, nil
}

// mkdirAllSync is os.MkdirAll (fsutil.MkdirPrivate: mode 0700, a private
// DACL on Windows) that also fsyncs the parent of
// every directory on the path it creates, so a crash cannot drop a new
// ancestor of evidence_dir. A dir that a sibling process created first is
// treated as created here: the sibling may not have fsynced it yet.
// Ancestors are operator configuration, looked up by path and followed
// through symlinks as os.MkdirAll does; the owner and mode checks run later
// on the opened evidence and run dir handles.
func mkdirAllSync(dir string, sync func(*os.File) error) error {
	dir = filepath.Clean(dir)
	fi, err := os.Stat(dir)
	if err == nil {
		if !fi.IsDir() {
			return fmt.Errorf("%s: not a directory", dir)
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(dir)
	if parent != dir {
		if err := mkdirAllSync(parent, sync); err != nil {
			return err
		}
	}
	if err := fsutil.MkdirPrivate(dir); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
			return fmt.Errorf("%s: not a directory", dir)
		}
	}
	p, err := os.Open(parent) //nolint:gosec // evidence_dir is operator configuration
	if err != nil {
		return err
	}
	return errors.Join(sync(p), p.Close())
}

func (w *Writer) openDirs(dir string) error {
	if err := mkdirAllSync(dir, w.dirSync); err != nil {
		return err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	w.root = root
	top, err := openDir(root, ".", 0o022)
	if err != nil {
		return fmt.Errorf("evidence dir: %w", err)
	}
	// The run dir may have been created by a sibling process that has not
	// fsynced it yet, so the evidence dir is fsynced either way.
	err = mkdirRun(root, dir, w.run.ID)
	if err == nil || errors.Is(err, os.ErrExist) {
		err = w.dirSync(top)
	}
	if err = errors.Join(err, top.Close()); err != nil {
		return err
	}
	if w.runDir, err = openDir(root, w.run.ID, 0o077); err != nil {
		return fmt.Errorf("run dir: %w", err)
	}
	return nil
}

// openDir opens a directory and checks the opened handle (no re-lookup by
// path): a directory, owned by us, no permission bits in deny.
func openDir(root *os.Root, name string, deny os.FileMode) (*os.File, error) {
	d, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	fi, err := d.Stat()
	if err == nil && !fi.IsDir() {
		err = errors.New("not a directory")
	}
	if err == nil {
		err = checkOwner(d, fi, deny)
	}
	if err != nil {
		return nil, errors.Join(err, d.Close())
	}
	return d, nil
}

func (w *Writer) newFile() error {
	name := w.chain + ".jsonl"
	if w.seg > 0 {
		name = w.chain + "." + strconv.Itoa(w.seg) + ".jsonl"
	}
	f, err := w.root.OpenFile(w.run.ID+"/"+name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_APPEND, 0o600)
	if err != nil {
		return werr(ClassOpen, err)
	}
	// A failed dir fsync is not an error here: the record still gets
	// written, and the next durable write retries the fsync.
	w.f, w.off = f, 0
	w.dirPending = w.dirSync(w.runDir) != nil
	return nil
}

// Append writes one record.
func (w *Writer) Append(r Record) error { return w.append(r, false) }

// AppendSync writes one record and fsyncs it (profile evidence.required).
// On a sync error (class sync) the record is committed to the chain but may
// not be durable; callers must not retry it, since a retry is a new record.
func (w *Writer) AppendSync(r Record) error { return w.append(r, true) }

func (w *Writer) append(r Record, durable bool) error {
	if r.Kind != KindConfigure && r.Kind != KindEval {
		return werr(ClassInvalid, errors.New("invalid kind"))
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return werr(ClassClosed, errors.New("writer closed"))
	}
	if err := w.recover(); err != nil {
		return err
	}
	return w.write(r, durable)
}

// recover starts a new segment after a failed write.
func (w *Writer) recover() error {
	if !w.dirty {
		return nil
	}
	if fi, err := w.f.Stat(); err != nil || fi.Size() != w.off {
		// The abandoned file keeps what it has; a close error changes nothing.
		_ = w.f.Close() //nolint:errcheck // see above
		w.seg++
		if err := w.newFile(); err != nil {
			return err
		}
	}
	last := Link{Seq: w.seq - 1, Hash: *w.prev}
	if err := w.write(Record{Kind: KindChainBreak, LastGood: &last}, false); err != nil {
		return err
	}
	w.dirty = false
	return nil
}

// write stamps the header, encodes and appends one line. The caller holds mu.
func (w *Writer) write(r Record, durable bool) error {
	r.V, r.Chain, r.Seq, r.Prev, r.Run = 1, w.chain, w.seq, w.prev, w.run
	r.TS = w.now().UTC().Format("2006-01-02T15:04:05.000Z")
	r.Results = slices.Clone(r.Results) // the Paths fill below must not touch the caller's slice
	if r.Kind == KindEval && r.Results == nil {
		r.Results = []Result{}
	}
	for i := range r.Results {
		if r.Results[i].Paths == nil {
			r.Results[i].Paths = []string{}
		}
	}
	if r.Digests != nil {
		d := *r.Digests // never modify the caller's value
		r.Digests = &d
		if d.Bundles == nil {
			d.Bundles = []string{}
		}
		if d.Exceptions == nil {
			d.Exceptions = []string{}
		}
	}
	if err := validate(&r); err != nil {
		return werr(ClassInvalid, err)
	}
	line, err := encode(&r)
	if err != nil {
		return werr(ClassInvalid, err)
	}
	n, err := w.f.Write(line)
	if err == nil && n != len(line) {
		err = io.ErrShortWrite
	}
	if err == nil {
		var fi os.FileInfo
		if fi, err = w.f.Stat(); err == nil && fi.Size() != w.off+int64(len(line)) {
			err = errors.New("file size changed outside the writer")
		}
	}
	if err != nil {
		w.dirty = true
		return werr(ClassWrite, err)
	}
	w.off += int64(len(line))
	h := hashLine(line[:len(line)-1])
	w.prev = &h
	w.seq++
	if durable {
		if err := w.f.Sync(); err != nil {
			return werr(ClassSync, err)
		}
		if w.dirPending {
			if err := w.dirSync(w.runDir); err != nil {
				return werr(ClassSync, err)
			}
			w.dirPending = false
		}
	}
	return nil
}

// encode returns the canonical line with its LF. A line that would need an
// escape sequence (quote, backslash, control character, U+2028/9, invalid
// UTF-8) or exceeds MaxLine is rejected.
func encode(r *Record) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r); err != nil {
		return nil, errors.New("encode failed")
	}
	line := buf.Bytes()
	// encoding/json escapes quote, backslash, controls and U+2028/9, and
	// replaces invalid UTF-8 with U+FFFD; all of them are refused here.
	if bytes.IndexByte(line, '\\') >= 0 || bytes.IndexByte(line, 0x7f) >= 0 || bytes.Contains(line, []byte("\uFFFD")) {
		return nil, errors.New("string needs escaping")
	}
	if len(line)-1 > MaxLine {
		return nil, errors.New("line too long")
	}
	return line, nil
}

// Close writes chain_end and closes the chain. It is idempotent. If chain_end
// cannot be written the chain stays unterminated and the error is returned.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	err := w.recover()
	if err == nil {
		last := w.seq - 1
		err = w.write(Record{Kind: KindChainEnd, LastSeq: &last}, true)
	}
	return errors.Join(err, w.closeFiles())
}

func (w *Writer) closeFiles() error {
	var errs []error
	if w.f != nil {
		errs = append(errs, w.f.Close())
	}
	if w.runDir != nil {
		errs = append(errs, w.runDir.Close())
	}
	if w.root != nil {
		errs = append(errs, w.root.Close())
	}
	return errors.Join(errs...)
}
