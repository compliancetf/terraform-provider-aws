package trust

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"slices"
	"time"

	"github.com/compliancetf/terraform-provider-aws/internal/fsutil"
)

const (
	floorResetFormat   = "compliancetf.floor-reset/v1"
	floorResetFile     = "floor-reset.dsse.json"
	maxResetLifetime   = 24 * time.Hour
	errResetNotApplied = "floor reset not applied"
)

// ErrFloorResetIgnored wraps the reason a present floor reset artifact was
// not applied. The caller warns and continues with the returned state.
var ErrFloorResetIgnored = errors.New("floor reset ignored")

// errResetConsumed: the reset is not newer than the last applied one (a
// replay of it, or an older reset). Silent: the file may stay in place.
var errResetConsumed = errors.New("floor reset already applied")

type resetPayload struct {
	Format          string `json:"format"`
	OrgID           string `json:"org_id"`
	KeyringDigest   string `json:"keyring_digest"`
	FromEpoch       *int64 `json:"from_epoch"`
	ToEpoch         *int64 `json:"to_epoch"`
	RevocationEpoch *int64 `json:"revocation_epoch"`
	IssuedAt        string `json:"issued_at"`
	ExpiresAt       string `json:"expires_at"`
}

// ApplyFloorReset applies dir/floor-reset.dsse.json, the only way to lower
// the floor epoch high-water (Floor statement). Call it before VerifyFloor
// and pass the returned state to VerifyFloor. The reset lowers the epoch of
// in.OrgID from from_epoch to to_epoch once and records its issued_at as the
// consumed-reset marker; generation, issued_at and retired_keys stay. A reset
// is not a revocation: a compromised floor key must also be revoked, else it
// can raise the epoch again; the reset's signed revocation_epoch makes the
// provider load that revocation before it lowers the epoch.
//
// Results:
//   - no file, or a reset already applied: (state, false, nil);
//   - applied: (written state, true, nil); the caller records floor_reset;
//     the written mark carries ResetUnrecorded until ClearUnrecordedReset;
//   - ignored (bad signature, purpose, org, keyring, lifetime, from_epoch,
//     retired key, issued no later than the accepted statement, ...): (state, false, err) with errors.Is(err,
//     ErrFloorResetIgnored); warn and continue;
//   - pending (otherwise valid, but the merged revocations of the state and
//     in.Revs are below its revocation_epoch): (state, false, err) with
//     errors.Is(err, ErrFloorRevocationPending); fail closed, the state is
//     unchanged;
//   - not persisted (state dir not lockable or writable): (state, false, err)
//     with errors.Is(err, ErrStateNotSaved); the reset is not applied;
//   - unreadable state: (zero State, false, err); fail closed.
func ApplyFloorReset(dir string, in FloorInput) (State, bool, error) {
	kr, err := Embedded()
	if err != nil {
		return State{}, false, err
	}
	return kr.applyFloorReset(dir, in, KeyringDigest())
}

func (k *Keyring) applyFloorReset(dir string, in FloorInput, keyringDigest string) (State, bool, error) {
	if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
		return in.State, false, nil // no state dir, so no reset file
	}
	r, err := openStateDir(dir, true)
	if err != nil {
		return notApplied(dir, in, err)
	}
	defer r.Close() //nolint:errcheck // dir handle
	// The reset file is read through the checked handle: a regular file, not
	// a symlink, FIFO or swapped name.
	env, err := fsutil.ReadFile(r, floorResetFile, MaxEnvelopeBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return in.State, false, nil
	}
	if err != nil {
		return in.State, false, fmt.Errorf("%w for %s: %w", ErrFloorResetIgnored, in.OrgID, err)
	}
	unlock, err := lockState(r, true)
	if err != nil {
		return notApplied(dir, in, err)
	}
	defer unlock()
	disk, err := readState(r, dir)
	if err != nil {
		return State{}, false, err
	}
	// Check and write against the disk state merged with what the caller
	// merged but did not persist (it only raises): an unsaved floor mark,
	// retired key or revocation still counts. The mergeFloor reset guard
	// keeps a lowered epoch lowered.
	cur, err := mergeState(disk, in.State)
	if err != nil {
		return State{}, false, err
	}
	to, issued, err := k.checkFloorReset(env, in, cur, keyringDigest)
	switch {
	case errors.Is(err, errResetConsumed):
		return cur, false, nil
	case errors.Is(err, ErrFloorRevocationPending):
		return cur, false, err
	case err != nil:
		return cur, false, fmt.Errorf("%w for %s: %w", ErrFloorResetIgnored, in.OrgID, err)
	}
	next := cur
	next.Floors = maps.Clone(cur.Floors)
	mark := next.Floors[in.OrgID]
	mark.Epoch, mark.ResetIssuedAt, mark.ResetUnrecorded = to, issued, true
	next.Floors[in.OrgID] = mark
	data, err := encodeState(next)
	if err == nil {
		err = writeAtomic(r, data)
	}
	if err != nil {
		return cur, false, fmt.Errorf("%w: %s: %w", ErrStateNotSaved, errResetNotApplied, err)
	}
	return next, true, nil
}

// ClearUnrecordedReset clears ResetUnrecorded of org's floor mark once a
// configure record carrying floor_reset is written. It is a
// locked read-modify-write and only clears the flag of the reset issued at
// at: a newer reset applied meanwhile stays unrecorded. A missing state or
// mark, or a flag already clear, is a no-op.
func ClearUnrecordedReset(dir, org string, at time.Time) error {
	if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	r, err := openStateDir(dir, true)
	if err != nil {
		return err
	}
	defer r.Close() //nolint:errcheck // dir handle
	unlock, err := lockState(r, true)
	if err != nil {
		return err
	}
	defer unlock()
	s, err := readState(r, dir)
	if err != nil {
		return err
	}
	mark, ok := s.Floors[org]
	if !ok || !mark.ResetUnrecorded || !mark.ResetIssuedAt.Equal(at) {
		return nil
	}
	mark.ResetUnrecorded = false
	s.Floors = maps.Clone(s.Floors)
	s.Floors[org] = mark
	data, err := encodeState(s)
	if err != nil {
		return err
	}
	return writeAtomic(r, data)
}

// notApplied is the reset path when the state dir cannot be opened as a
// writer or locked: like UpdateState, the state is read through a checked
// reader handle and merged with in.State, so the caller never continues with
// less than is on disk. If that read fails too, the result is fatal.
func notApplied(dir string, in FloorInput, cause error) (State, bool, error) {
	disk, err := LoadState(dir)
	if err != nil {
		return State{}, false, fmt.Errorf("trust state: cannot write (%v) or read existing state: %w", cause, err)
	}
	cur, err := mergeState(disk, in.State)
	if err != nil {
		return State{}, false, err
	}
	return cur, false, fmt.Errorf("%w: %s: %w", ErrStateNotSaved, errResetNotApplied, cause)
}

// checkFloorReset runs every reset check against cur, the state read under
// the exclusive lock, and returns the new epoch and the reset's issued_at.
func (k *Keyring) checkFloorReset(env []byte, in FloorInput, cur State, keyringDigest string) (int64, time.Time, error) {
	revs, err := Merge(orEmpty(cur.Revocations), in.Revs)
	if err != nil {
		return 0, time.Time{}, err
	}
	v, err := k.Verify(env, PayloadFloorReset, revs)
	if err != nil {
		return 0, time.Time{}, err
	}
	var p resetPayload
	if err := strictUnmarshal(v.Payload, nil, &p); err != nil {
		return 0, time.Time{}, err
	}
	if p.FromEpoch == nil || p.ToEpoch == nil || p.RevocationEpoch == nil {
		return 0, time.Time{}, errors.New("from_epoch, to_epoch and revocation_epoch are required")
	}
	if *p.RevocationEpoch < 0 {
		return 0, time.Time{}, fmt.Errorf("revocation_epoch %d must be >= 0", *p.RevocationEpoch)
	}
	issued, err := time.Parse(time.RFC3339, p.IssuedAt)
	if err != nil {
		return 0, time.Time{}, errNotRFC3339("issued_at")
	}
	expires, err := time.Parse(time.RFC3339, p.ExpiresAt)
	if err != nil {
		return 0, time.Time{}, errNotRFC3339("expires_at")
	}
	issued, expires = issued.UTC(), expires.UTC()
	from, to := *p.FromEpoch, *p.ToEpoch
	switch {
	case p.Format != floorResetFormat:
		return 0, time.Time{}, fmt.Errorf("format is not %q", floorResetFormat) // signed values are not echoed
	case p.OrgID != in.OrgID:
		return 0, time.Time{}, fmt.Errorf("reset is for another org, not %q", in.OrgID)
	case p.KeyringDigest != keyringDigest:
		return 0, time.Time{}, fmt.Errorf("reset names another keyring than the %s this provider embeds", keyringDigest)
	}
	mark, ok := cur.Floors[in.OrgID]
	// Checked before expiry, so a consumed reset left in place stays silent.
	if ok && !issued.After(mark.ResetIssuedAt) {
		return 0, time.Time{}, errResetConsumed
	}
	switch {
	case !ok:
		return 0, time.Time{}, errors.New("no floor high-water to reset")
	case !expires.After(issued) || expires.Sub(issued) > maxResetLifetime:
		return 0, time.Time{}, fmt.Errorf("lifetime %s exceeds %s", expires.Sub(issued), maxResetLifetime)
	case issued.After(in.Now.Add(floorSkew)):
		return 0, time.Time{}, fmt.Errorf("issued_at %s is in the future", issued.Format(time.RFC3339))
	case !in.Now.Before(expires):
		return 0, time.Time{}, fmt.Errorf("reset expired %s", expires.Format(time.RFC3339))
	}
	gen := k.byKID[v.KeyID].Generation
	switch {
	case gen < mark.Generation || slices.Contains(mark.RetiredKeys, v.KeyID):
		return 0, time.Time{}, fmt.Errorf("floor key %s (generation %d) is retired: accepted generation %d", v.KeyID, gen, mark.Generation)
	case !issued.After(mark.IssuedAt):
		// An accepted statement issued after the reset could raise the
		// epoch straight back (it is after the reset marker).
		return 0, time.Time{}, fmt.Errorf("reset issued %s is not after the accepted floor statement %s",
			issued.Format(time.RFC3339), mark.IssuedAt.Format(time.RFC3339))
	case from != mark.Epoch:
		return 0, time.Time{}, fmt.Errorf("from_epoch %d does not match the stored epoch %d", from, mark.Epoch)
	case to < 1 || to >= from:
		return 0, time.Time{}, fmt.Errorf("to_epoch %d must be >= 1 and below from_epoch %d", to, from)
	}
	// Last, so only an otherwise valid reset fails closed.
	if have := revs.Epoch(); *p.RevocationEpoch > have {
		return 0, time.Time{}, fmt.Errorf("%w: floor reset for %s needs revocation epoch %d, provider has %d: fail closed until a bundle carrying the newer revocations loads",
			ErrFloorRevocationPending, in.OrgID, *p.RevocationEpoch, have)
	}
	return to, issued, nil
}
