package trust

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/compliancetf/terraform-provider-aws/internal/fsutil"
)

const (
	stateFileName = "trust-state.json"
	stateLockName = "trust-state.lock"
	maxStateBytes = 16 << 20
	// maxStateRevocations caps each merged revocation list. The set only grows,
	// so an over-cap merge is an error (never truncated: dropping a revocation
	// would un-revoke it).
	maxStateRevocations = 4 * maxRevocationsList
	maxStateEntries     = 4096
)

// ErrStateNotSaved wraps an UpdateState error after the existing state was
// read and merged but could not be persisted. Only with this error is the
// returned state usable (warn and continue); any other error is fatal.
var ErrStateNotSaved = errors.New("trust state not saved")

// FloorMark is the per-org floor high-water (Floor statement). Its acceptance
// rules live with the floor verifier; the state file only stores it.
type FloorMark struct {
	Generation      int64     `json:"generation"`
	Epoch           int64     `json:"epoch"`
	RevocationEpoch int64     `json:"revocation_epoch"`
	IssuedAt        time.Time `json:"issued_at"` // of the latest accepted statement: the air-gap time
	// PendingIssuedAt is the issued_at of a statement refused as
	// revocation-pending, kept only while later than IssuedAt. It bounds
	// later statements and resets like IssuedAt (highIssuedAt) but never
	// times the air-gap clock. Absent is zero.
	PendingIssuedAt time.Time `json:"pending_issued_at,omitzero"`
	RetiredKeys     []string  `json:"retired_keys"`
	ResetIssuedAt   time.Time `json:"reset_issued_at,omitzero"` // issued_at of the last applied floor reset
	// ResetUnrecorded: the reset at ResetIssuedAt was applied but no
	// configure record carries floor_reset yet. Absent is false.
	ResetUnrecorded bool `json:"reset_unrecorded,omitempty"`
	// MinWrapperVersion is the highest min_wrapper_version accepted; a later
	// floor (or a reset) never lowers it.
	MinWrapperVersion string `json:"min_wrapper_version,omitempty"`
}

// State is the local anti-rollback state (trust-state.json). It holds versions
// and the merged revocation set only, never profile fields. Every merge is
// monotonic: nothing in it ever drops.
//
// A State literal is a delta for UpdateState or MergeState. Only a state
// returned by LoadState, UpdateState or MergeState is loaded; the minimum
// queries refuse any other, so the zero State (returned with a fatal error)
// cannot lower a minimum.
type State struct {
	Bundles     map[string]int64     // bundle_id -> highest accepted version
	Profiles    map[string]int64     // org_id -> highest accepted profile version
	Revocations Revocations          // merged; zero value is treated as empty in a delta
	Floors      map[string]FloorMark // org_id -> floor high-water
	loaded      bool
}

type stateRevocations struct {
	Epoch    int64                `json:"epoch"`
	Keys     map[string]time.Time `json:"keys"`
	Bundles  map[string]int64     `json:"bundles"`
	Controls map[string][]int64   `json:"controls"`
}

type stateFile struct {
	Bundles     map[string]int64     `json:"bundles"`
	Profiles    map[string]int64     `json:"profiles"`
	Revocations stateRevocations     `json:"revocations"`
	Floors      map[string]FloorMark `json:"floors"`
}

// StateDir returns $COMPLIANCETF_STATE_DIR, else os.UserConfigDir()/compliancetf.
func StateDir() (string, error) {
	if d := os.Getenv("COMPLIANCETF_STATE_DIR"); d != "" {
		return d, nil
	}
	d, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("trust state: %w", err)
	}
	return filepath.Join(d, "compliancetf"), nil
}

// LoadState reads dir/trust-state.json under the state lock. A missing dir or
// file is an empty state; a malformed one, or a dir that fails the
// fsutil.OpenTree checks, is an error.
func LoadState(dir string) (State, error) {
	r, err := openStateDir(dir, false)
	if errors.Is(err, fs.ErrNotExist) {
		return mergeState(State{}, State{})
	}
	if err != nil {
		return State{}, err
	}
	defer r.Close() //nolint:errcheck // dir handle
	unlock, err := lockState(r, false)
	if err != nil {
		return State{}, err
	}
	defer unlock()
	return readState(r, dir)
}

// openStateDir opens the state dir through fsutil.OpenTree: not a symlink,
// owned by this user, not writable by others (a writer tightens it to 0700).
// Every later read, lock and write goes through the returned handle, so the
// dir cannot be swapped after the check. The state is the anti-rollback
// anchor: another local user must not be able to replace it.
func openStateDir(dir string, writer bool) (*os.Root, error) {
	r, err := fsutil.OpenTree(dir, dir, writer)
	if err != nil {
		return nil, fmt.Errorf("trust state dir: %w", err)
	}
	return r, nil
}

// UpdateState merges delta into the state file under an exclusive lock and
// writes it by temp file + rename (mode 0600). It returns the merged state.
//
// Errors come in two kinds:
//   - errors.Is(err, ErrStateNotSaved): the existing state was read and the
//     returned state is it merged with delta, but it was not persisted. The
//     caller may warn and continue with the returned state.
//   - any other error: the existing state could not be read (or delta is
//     invalid). The returned state is the zero State, which fails closed
//     (every key revoked, Min*Version errors); the caller must fail closed.
//
// An unreadable or over-cap state file is never overwritten.
func UpdateState(dir string, delta State) (State, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return mergeReadable(dir, delta, err)
	}
	r, err := openStateDir(dir, true)
	if err != nil {
		return mergeReadable(dir, delta, err)
	}
	defer r.Close() //nolint:errcheck // dir handle
	unlock, err := lockState(r, true)
	if err != nil {
		return mergeReadable(dir, delta, err)
	}
	defer unlock()
	cur, err := readState(r, dir)
	if err != nil {
		return State{}, err
	}
	return persistMerge(cur, delta, func(data []byte) error { return writeAtomic(r, data) })
}

// mergeReadable handles a writer that cannot create the dir or take the lock:
// the state as a reader sees it plus delta, never persisted. If the reader
// cannot load it either, the result is fatal.
func mergeReadable(dir string, delta State, cause error) (State, error) {
	cur, err := LoadState(dir)
	if err != nil {
		return State{}, fmt.Errorf("trust state: cannot write (%v) or read existing state: %w", cause, err)
	}
	return persistMerge(cur, delta, func([]byte) error { return cause })
}

// persistMerge merges delta into cur (read from disk) and persists it with
// write. Every failure after a successful merge wraps ErrStateNotSaved; an
// over-cap merge returns the uncapped merge (the run still honors every
// revocation it has seen) without writing it.
func persistMerge(cur, delta State, write func([]byte) error) (State, error) {
	for org, m := range delta.Floors { // an invalid delta is fatal, never "not saved"
		if err := checkFloorMark(org, m); err != nil {
			return State{}, fmt.Errorf("trust state delta: %w", err)
		}
	}
	merged, err := MergeState(cur, delta)
	if err != nil {
		m, merr := mergeState(cur, delta)
		if merr != nil {
			return State{}, merr
		}
		return m, fmt.Errorf("%w: %w", ErrStateNotSaved, err)
	}
	data, err := encodeState(merged)
	if err == nil {
		err = write(data)
	}
	if err != nil {
		return merged, fmt.Errorf("%w: %w", ErrStateNotSaved, err)
	}
	return merged, nil
}

// MergeState returns a new state holding the max of every version, the merged
// revocation set (Merge: max epoch, set union) and the field-wise max of each
// floor mark with the union of retired keys. It errors when the merged
// revocation lists exceed the cap.
func MergeState(a, b State) (State, error) {
	m, err := mergeState(a, b)
	if err != nil {
		return State{}, err
	}
	if n := max(len(m.Revocations.keys), len(m.Revocations.bundles), len(m.Revocations.controls)); n > maxStateRevocations {
		return State{}, fmt.Errorf("trust state: merged revocation list has %d entries, cap %d", n, maxStateRevocations)
	}
	if n := max(len(m.Bundles), len(m.Profiles), len(m.Floors)); n > maxStateEntries {
		return State{}, fmt.Errorf("trust state: merged state has %d entries in one map, cap %d", n, maxStateEntries)
	}
	return m, nil
}

func mergeState(a, b State) (State, error) {
	rev, err := Merge(orEmpty(a.Revocations), orEmpty(b.Revocations))
	if err != nil {
		return State{}, err
	}
	m := State{Bundles: maxMerge(a.Bundles, b.Bundles), Profiles: maxMerge(a.Profiles, b.Profiles),
		Revocations: rev, Floors: maps.Clone(a.Floors), loaded: true}
	if m.Floors == nil {
		m.Floors = map[string]FloorMark{}
	}
	for org, f := range b.Floors {
		m.Floors[org] = mergeFloor(m.Floors[org], f)
	}
	return m, nil
}

// orEmpty maps the zero Revocations (no set recorded) to the empty set. Any
// set built by ParseRevocations, NoRevocations or Merge passes through.
func orEmpty(r Revocations) Revocations {
	if !r.valid && r.keys == nil && r.bundles == nil && r.controls == nil && r.epoch == 0 {
		return NoRevocations()
	}
	return r
}

func maxMerge(a, b map[string]int64) map[string]int64 {
	m := maps.Clone(a)
	if m == nil {
		m = map[string]int64{}
	}
	for k, v := range b {
		m[k] = max(m[k], v)
	}
	return m
}

// mergeFloor is the field-wise max, except that the epoch of a mark issued
// before the latest floor reset is dropped: a delta verified before a reset
// (another process, same state dir) cannot raise the lowered epoch back.
// Each side is one statement's mark or a stored mark, so its epoch and
// issued_at belong together; this is not an aggregator of several deltas.
// The merged issued_at may still come from a side whose epoch was dropped;
// it is a signed issuer time and only moves forward. The pending issued_at
// is dropped once the accepted one reaches it.
func mergeFloor(a, b FloorMark) FloorMark {
	issued := latest(a.IssuedAt, b.IssuedAt)
	pending := latest(a.PendingIssuedAt, b.PendingIssuedAt)
	if !pending.After(issued) {
		pending = time.Time{}
	}
	reset := latest(a.ResetIssuedAt, b.ResetIssuedAt)
	var epoch int64
	for _, m := range []FloorMark{a, b} {
		if m.ResetIssuedAt.Equal(reset) || m.highIssuedAt().After(reset) {
			epoch = max(epoch, m.Epoch)
		}
	}
	// The unrecorded flag holds only when every side at the latest reset
	// carries it: a stale side cannot set it again after it was cleared.
	unrecorded := !reset.IsZero()
	for _, m := range []FloorMark{a, b} {
		if m.ResetIssuedAt.Equal(reset) {
			unrecorded = unrecorded && m.ResetUnrecorded
		}
	}
	keys := slices.Concat(a.RetiredKeys, b.RetiredKeys)
	slices.Sort(keys)
	return FloorMark{
		Generation:        max(a.Generation, b.Generation),
		Epoch:             epoch,
		RevocationEpoch:   max(a.RevocationEpoch, b.RevocationEpoch),
		IssuedAt:          issued.UTC(),
		PendingIssuedAt:   pending.UTC(),
		RetiredKeys:       slices.Compact(keys),
		ResetIssuedAt:     reset.UTC(),
		ResetUnrecorded:   unrecorded,
		MinWrapperVersion: maxWrapper(a.MinWrapperVersion, b.MinWrapperVersion),
	}
}

// highIssuedAt is the latest issued_at seen for the org, accepted or
// pending: the anti-rollback bound for floor statements and resets.
func (m FloorMark) highIssuedAt() time.Time { return latest(m.IssuedAt, m.PendingIssuedAt) }

func latest(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// MinBundleVersion returns the effective minimum for bundleID: the max of the
// state, COMPLIANCETF_MIN_BUNDLE_VERSION and the other floors passed in. The
// env value only raises; a malformed one is an error, never ignored.
func (s State) MinBundleVersion(bundleID string, floors ...int64) (int64, error) {
	return effectiveMin("COMPLIANCETF_MIN_BUNDLE_VERSION", s.loaded, s.Bundles[bundleID], floors)
}

// MinProfileVersion is MinBundleVersion for orgID's profile with
// COMPLIANCETF_MIN_PROFILE_VERSION.
func (s State) MinProfileVersion(orgID string, floors ...int64) (int64, error) {
	return effectiveMin("COMPLIANCETF_MIN_PROFILE_VERSION", s.loaded, s.Profiles[orgID], floors)
}

func effectiveMin(env string, loaded bool, state int64, floors []int64) (int64, error) {
	if !loaded {
		// MaxInt64: a caller that drops the error still rejects every version.
		return math.MaxInt64, errors.New("trust state: not loaded (fail closed)")
	}
	m := state
	for _, f := range floors {
		m = max(m, f)
	}
	v := os.Getenv(env)
	if v == "" {
		return m, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		// m, not 0: a caller that drops the error still keeps every other floor.
		return m, fmt.Errorf("%s=%q: want a non-negative integer", env, v)
	}
	return max(m, n), nil
}

// readState reads the state file through r, the checked state dir; a
// symlinked or non-regular state file is an error, never followed.
func readState(r *os.Root, dir string) (State, error) {
	data, err := fsutil.ReadFile(r, stateFileName, maxStateBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return mergeState(State{}, State{})
	}
	if err != nil {
		return State{}, fmt.Errorf("trust state: %w", err)
	}
	s, err := decodeState(data)
	if err != nil {
		return State{}, fmt.Errorf("trust state %s: %w (fix or remove it)", filepath.Join(dir, stateFileName), err)
	}
	return s, nil
}

func decodeState(data []byte) (State, error) {
	// Local and unsigned: no checkJSON here, since its case-folded duplicate
	// check would reject distinct ids such as "CIS" and "cis" in map keys.
	if !utf8.Valid(data) {
		return State{}, errors.New("invalid UTF-8")
	}
	var f stateFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return State{}, err
	}
	if len(f.Bundles) > maxStateEntries || len(f.Profiles) > maxStateEntries || len(f.Floors) > maxStateEntries {
		return State{}, errors.New("too many entries")
	}
	for _, m := range []map[string]int64{f.Bundles, f.Profiles, f.Revocations.Bundles} {
		for k, v := range m {
			if k == "" || v < 0 {
				return State{}, fmt.Errorf("bad version entry %q: %d", k, v)
			}
		}
	}
	if err := checkUnrecordedRaw(data); err != nil {
		return State{}, err
	}
	for org, m := range f.Floors {
		if err := checkFloorMark(org, m); err != nil {
			return State{}, err
		}
	}
	r := NoRevocations()
	r.epoch = f.Revocations.Epoch
	if r.epoch < 0 {
		return State{}, errors.New("negative revocation epoch")
	}
	for kid, at := range f.Revocations.Keys {
		if !kidRE.MatchString(kid) {
			return State{}, fmt.Errorf("bad revoked kid %q", kid)
		}
		r.keys[kid] = at
	}
	maps.Copy(r.bundles, f.Revocations.Bundles)
	for id, vs := range f.Revocations.Controls {
		for _, v := range vs {
			r.controls[controlRef{id, v}] = true
		}
	}
	if n := max(len(r.keys), len(r.bundles), len(r.controls)); n > maxStateRevocations {
		return State{}, fmt.Errorf("revocation list has %d entries, cap %d", n, maxStateRevocations)
	}
	s := State{Bundles: f.Bundles, Profiles: f.Profiles, Revocations: r, Floors: f.Floors}
	return mergeState(s, State{}) // normalise nil maps, sort retired keys
}

// checkUnrecordedRaw rejects a reset_unrecorded that is present but not a
// JSON boolean: encoding/json reads null as false, which would drop a
// pending floor_reset attestation instead of failing closed.
func checkUnrecordedRaw(data []byte) error {
	var raw struct {
		Floors map[string]map[string]json.RawMessage `json:"floors"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for _, m := range raw.Floors {
		for k, v := range m { // the struct decoder matches field names case-insensitively
			if strings.EqualFold(k, "reset_unrecorded") && string(v) != "true" && string(v) != "false" {
				return errors.New("floor mark: reset_unrecorded is not a boolean")
			}
		}
	}
	return nil
}

// checkFloorMark rejects a stored floor mark that no accepted floor statement
// could have produced. The load then fails (fail closed): a corrupt
// high-water must not be read as a lower one. Values are not echoed.
func checkFloorMark(org string, m FloorMark) error {
	switch {
	case !floorIDRE.MatchString(org):
		return errors.New("floor mark: invalid org id")
	case m.Generation < 1 || m.Epoch < 1 || m.RevocationEpoch < 0:
		return errors.New("floor mark: generation and epoch must be >= 1, revocation_epoch >= 0")
	case m.ResetUnrecorded && m.ResetIssuedAt.IsZero():
		return errors.New("floor mark: reset_unrecorded without reset_issued_at")
	case m.MinWrapperVersion != "" && !semverRE.MatchString(m.MinWrapperVersion):
		return errors.New("floor mark: min_wrapper_version is not a semantic version")
	}
	for _, kid := range m.RetiredKeys {
		if !kidRE.MatchString(kid) {
			return errors.New("floor mark: invalid retired key")
		}
	}
	return nil
}

func encodeState(s State) ([]byte, error) {
	r := s.Revocations
	f := stateFile{Bundles: s.Bundles, Profiles: s.Profiles, Floors: s.Floors,
		Revocations: stateRevocations{Epoch: r.epoch, Keys: r.keys, Bundles: r.bundles, Controls: map[string][]int64{}}}
	for c := range r.controls {
		f.Revocations.Controls[c.id] = append(f.Revocations.Controls[c.id], c.version)
	}
	for _, vs := range f.Revocations.Controls {
		slices.Sort(vs)
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("trust state: %w", err)
	}
	data = append(data, '\n')
	// Never write what readState would reject.
	if len(data) > maxStateBytes {
		return nil, errors.New("trust state: encoded state too large")
	}
	if _, err := decodeState(data); err != nil {
		return nil, fmt.Errorf("trust state: encoded state does not reload: %w", err)
	}
	return data, nil
}

func writeAtomic(r *os.Root, data []byte) error {
	var rnd [8]byte
	rand.Read(rnd[:]) //nolint:errcheck,gosec // never fails
	name := ".trust-state-" + hex.EncodeToString(rnd[:])
	tmp, err := r.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("trust state: %w", err)
	}
	defer r.Remove(name) //nolint:errcheck // no-op after a successful rename
	_, werr := tmp.Write(data)
	if werr == nil {
		werr = tmp.Sync()
	}
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = r.Rename(name, stateFileName)
	}
	if werr != nil {
		return fmt.Errorf("trust state: %w", werr)
	}
	return nil
}

// openLockFile opens or creates the lock file read-write in r. os.Root's
// O_CREATE without O_EXCL can fail with ENOENT while another process creates
// the same file (seen on darwin, Go 1.27), so it opens an existing file, else
// creates it exclusively, and retries when it lost the create race.
func openLockFile(r *os.Root) (*os.File, error) {
	for range 8 {
		f, err := r.OpenFile(stateLockName, os.O_RDWR, 0)
		if !errors.Is(err, fs.ErrNotExist) {
			return f, err
		}
		f, err = r.OpenFile(stateLockName, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if !errors.Is(err, fs.ErrExist) {
			return f, err
		}
	}
	return nil, errors.New("lock file keeps appearing and disappearing")
}

// lockState takes the cross-process state lock on dir/trust-state.lock. A
// separate lock file is used because rename replaces the state file's inode.
// Readers lock too: on Windows a reader holding the file open would make the
// writer's rename fail. A reader that cannot create or write the lock file
// (read-only state dir) locks it read-only. It reads unlocked only when the
// lock file does not exist, i.e. no writer has ever written there (a writer
// creates the lock before the state file); any other error is returned.
func lockState(r *os.Root, writer bool) (func(), error) {
	f, err := openLockFile(r)
	if err != nil && !writer {
		f, err = r.Open(stateLockName)
		if errors.Is(err, fs.ErrNotExist) {
			return func() {}, nil // no lock file: no writer has written here
		}
	}
	if err != nil {
		return nil, fmt.Errorf("trust state lock: %w", err)
	}
	if err := lockFile(f); err != nil {
		f.Close() //nolint:errcheck // lock failed; nothing written
		return nil, fmt.Errorf("trust state lock: %w", err)
	}
	return func() {
		unlockFile(f) //nolint:errcheck // Close below releases it anyway
		f.Close()     //nolint:errcheck // lock file, nothing written
	}, nil
}
