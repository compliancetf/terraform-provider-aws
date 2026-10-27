package trust

import (
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"time"
)

// Floor modes (the signed profile floor_mode).
const (
	FloorOnline = "online"
	FloorAirgap = "airgap"
)

const (
	floorFormat       = "compliancetf.floor/v1"
	maxOnlineLifetime = 24 * time.Hour
	maxAirgapLifetime = 7 * 24 * time.Hour
	floorSkew         = 5 * time.Minute
	maxFloorBundles   = 256
	maxRetiredKeys    = 64
)

var floorIDRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// ErrFloorRevocationPending: the floor names a revocation epoch the provider
// has not merged yet. Fail closed until a bundle carrying it loads. Callers
// merge every available revocation set before VerifyFloor (see
// FloorInput.Revs), so this means no loaded bundle carries the epoch.
var ErrFloorRevocationPending = errors.New("floor revocation epoch pending")

// Floor is an accepted floor statement. Only VerifyFloor builds one; the
// effective minimums ignore any other Floor value.
type Floor struct {
	OrgID             string
	MinProfileVersion int64
	Bundles           map[string]int64
	MinWrapperVersion string
	Epoch             int64
	RevocationEpoch   int64
	RetiredKeys       []string
	IssuedAt          time.Time
	ExpiresAt         time.Time
	KeyID             string
	Generation        int64  // from the compiled keyring entry of KeyID
	mode              string // set only by VerifyFloor
}

// FloorInput is the run context of VerifyFloor. OrgID is the org resolved by
// profile.ResolveOrg (pin enforced), Mode the floor_mode of the verified
// profile, ProviderVersion the compiled provider version, Now the process
// clock, State the loaded trust state. None of them comes from HCL or env.
//
// Revs is the state revocation set merged with the revocations.json of every
// candidate bundle whose manifest verifies against that set, loaded before
// VerifyFloor and regardless of floor minimums (a merge only adds
// revocations). Such a bundle's controls and minimums are used only after it
// passes the accepted floor minimums.
type FloorInput struct {
	OrgID           string
	Mode            string
	ProviderVersion string
	Now             time.Time
	Revs            Revocations
	State           State
}

type floorPayload struct {
	Format            string           `json:"format"`
	OrgID             string           `json:"org_id"`
	MinProfileVersion *int64           `json:"min_profile_version"`
	Bundles           map[string]int64 `json:"bundles"`
	MinWrapperVersion *string          `json:"min_wrapper_version"`
	KeyringDigest     string           `json:"keyring_digest"`
	Epoch             int64            `json:"epoch"`
	RevocationEpoch   *int64           `json:"revocation_epoch"`
	RetiredKeys       []string         `json:"retired_keys"`
	IssuedAt          string           `json:"issued_at"`
	ExpiresAt         string           `json:"expires_at"`
}

// VerifyFloor verifies a floor statement against the compiled keyring and
// the run context. On success it returns the floor and the state delta to
// persist with UpdateState (floor high-water and floor minimums). On
// ErrFloorRevocationPending it returns no floor but a delta holding only the
// statement's generation, epoch and issued_at (as PendingIssuedAt, so it
// never sets the air-gap time): the caller persists it, then
// fails Configure, so the older floor file stays refused while the revocation
// bundle is withheld. On any other error it returns neither. in.State is the
// state returned by ApplyFloorReset.
func VerifyFloor(env []byte, in FloorInput) (*Floor, State, error) {
	kr, err := Embedded()
	if err != nil {
		return nil, State{}, err
	}
	if err := kr.checkFloorKeys(); err != nil {
		return nil, State{}, fmt.Errorf("floor for %s: %w (fail closed)", in.OrgID, err)
	}
	return kr.verifyFloor(env, in, KeyringDigest())
}

// checkFloorKeys: the keyring holds exactly the current and the next floor
// key, both ES256, of consecutive generations (Floor key rotation).
func (k *Keyring) checkFloorKeys() error {
	var gens []int64
	for _, key := range k.keys {
		if key.Purpose != PurposeFloor {
			continue
		}
		if key.Alg != AlgES256 {
			return fmt.Errorf("keyring: floor key %s is %s, want ES256", key.KID, key.Alg)
		}
		gens = append(gens, key.Generation)
	}
	if len(gens) != 2 {
		return fmt.Errorf("keyring: want exactly 2 floor keys (current and next), have %d", len(gens))
	}
	if lo, hi := min(gens[0], gens[1]), max(gens[0], gens[1]); hi != lo+1 {
		return fmt.Errorf("keyring: floor key generations %d and %d are not consecutive", lo, hi)
	}
	return nil
}

// verifyFloor does not check the floor key count (checkFloorKeys); VerifyFloor
// does, so unit tests can use synthetic keyrings with more generations.
func (k *Keyring) verifyFloor(env []byte, in FloorInput, keyringDigest string) (*Floor, State, error) {
	org := in.OrgID
	if !in.State.loaded {
		return nil, State{}, errors.New("floor: trust state not loaded (fail closed)")
	}
	var maxLife time.Duration
	switch in.Mode {
	case FloorOnline:
		maxLife = maxOnlineLifetime
	case FloorAirgap:
		maxLife = maxAirgapLifetime
	default:
		return nil, State{}, errors.New("floor: floor_mode must be online or airgap")
	}
	mark, hasMark := in.State.Floors[org]
	if hasMark && (mark.Generation < 1 || mark.Epoch < 1) {
		return nil, State{}, fmt.Errorf("floor: stored high-water for %s is corrupt (fix or remove the trust state)", org)
	}
	// The state's revocations always count, whatever the caller merged.
	revs, err := Merge(orEmpty(in.State.Revocations), in.Revs)
	if err != nil {
		return nil, State{}, fmt.Errorf("floor for %s: %w", org, err)
	}
	v, err := k.Verify(env, PayloadFloor, revs)
	if err != nil {
		return nil, State{}, fmt.Errorf("floor for %s: %w", org, err)
	}
	f, err := parseFloor(v.Payload)
	if err != nil {
		return nil, State{}, fmt.Errorf("floor for %s: %w", org, err)
	}
	f.KeyID, f.Generation, f.mode = v.KeyID, k.byKID[v.KeyID].Generation, in.Mode

	switch {
	case f.OrgID != org:
		return nil, State{}, fmt.Errorf("floor is for another org, not %q", org)
	case f.keyringDigest != keyringDigest:
		return nil, State{}, fmt.Errorf("org floor names another keyring than the %s this provider embeds: upgrade the provider", keyringDigest)
	case !f.ExpiresAt.After(f.IssuedAt) || f.ExpiresAt.Sub(f.IssuedAt) > maxLife:
		return nil, State{}, fmt.Errorf("floor for %s: lifetime %s exceeds %s for floor_mode %s", org, f.ExpiresAt.Sub(f.IssuedAt), maxLife, in.Mode)
	case f.IssuedAt.After(in.Now.Add(floorSkew)):
		return nil, State{}, fmt.Errorf("floor for %s: issued_at %s is in the future", org, f.IssuedAt.Format(time.RFC3339))
	case !in.Now.Before(f.ExpiresAt):
		return nil, State{}, fmt.Errorf("floor for %s expired %s", org, f.ExpiresAt.Format(time.RFC3339))
	case slices.Contains(f.RetiredKeys, f.KeyID):
		return nil, State{}, fmt.Errorf("floor for %s is signed by %s, which it lists as retired", org, f.KeyID)
	}
	// Generations come from the compiled keyring, never the statement: a key
	// may retire only older generations, so a compromised current key cannot
	// retire the next key that the emergency path switches to.
	for _, kid := range f.RetiredKeys {
		if r := k.byKID[kid]; r != nil && r.Purpose == PurposeFloor && r.Generation >= f.Generation {
			return nil, State{}, fmt.Errorf("floor for %s signed by generation %d retires a key of generation %d", org, f.Generation, r.Generation)
		}
	}
	if hasMark {
		if err := acceptFloor(f, mark); err != nil {
			return nil, State{}, err
		}
	}
	// The wrapper minimum is a high-water: a later floor never lowers it.
	minWrapper := maxWrapper(mark.MinWrapperVersion, f.MinWrapperVersion)
	if err := CheckWrapper(in.ProviderVersion, minWrapper); err != nil {
		return nil, State{}, err
	}
	if have := revs.Epoch(); f.RevocationEpoch > have {
		// Keep (generation, epoch) only: a pending statement must not pin a
		// revocation epoch or retired keys that a reset cannot lower. Its
		// issued_at is pending, never the accepted one (the air-gap time).
		pending := State{Floors: map[string]FloorMark{org: {Generation: f.Generation, Epoch: f.Epoch, PendingIssuedAt: f.IssuedAt}}}
		return nil, pending, fmt.Errorf("%w: floor for %s needs revocation epoch %d, provider has %d: fail closed until a bundle carrying the newer revocations loads",
			ErrFloorRevocationPending, org, f.RevocationEpoch, have)
	}
	delta := State{
		Bundles:  maps.Clone(f.Bundles),
		Profiles: map[string]int64{org: f.MinProfileVersion},
		Floors: map[string]FloorMark{org: {Generation: f.Generation, Epoch: f.Epoch,
			RevocationEpoch: f.RevocationEpoch, IssuedAt: f.IssuedAt, RetiredKeys: slices.Clone(f.RetiredKeys),
			MinWrapperVersion: minWrapper}},
	}
	return &f.Floor, delta, nil
}

// acceptFloor applies the floor high-water acceptance table (Floor
// statement). Only ApplyFloorReset lowers the epoch; afterwards a statement
// must be issued strictly after that reset.
func acceptFloor(f *parsedFloor, h FloorMark) error {
	org := f.OrgID
	if !h.ResetIssuedAt.IsZero() && !f.IssuedAt.After(h.ResetIssuedAt) {
		return fmt.Errorf("floor statement for %s issued %s is not after the floor reset %s", org,
			f.IssuedAt.Format(time.RFC3339), h.ResetIssuedAt.Format(time.RFC3339))
	}
	if f.Generation < h.Generation || slices.Contains(h.RetiredKeys, f.KeyID) {
		return fmt.Errorf("floor key %s (generation %d) is retired for %s: accepted generation %d", f.KeyID, f.Generation, org, h.Generation)
	}
	advances := f.Epoch > h.Epoch && f.Generation <= h.Generation+1
	equals := f.Epoch == h.Epoch && f.Generation == h.Generation
	if !advances && !equals || f.RevocationEpoch < h.RevocationEpoch {
		return fmt.Errorf("floor epoch %d is below the accepted high-water %d for %s", f.Epoch, h.Epoch, org)
	}
	if hi := h.highIssuedAt(); f.IssuedAt.Before(hi) {
		return fmt.Errorf("floor statement for %s issued %s is earlier than the accepted %s", org,
			f.IssuedAt.Format(time.RFC3339), hi.Format(time.RFC3339))
	}
	for _, kid := range h.RetiredKeys {
		if _, ok := slices.BinarySearch(f.RetiredKeys, kid); !ok {
			return fmt.Errorf("floor statement for %s drops retired key %s", org, kid)
		}
	}
	return nil
}

type parsedFloor struct {
	Floor
	keyringDigest string
}

func parseFloor(payload []byte) (*parsedFloor, error) {
	// Bundle ids are map keys, so no name allowlist; unknown fields still fail.
	var p floorPayload
	if err := strictUnmarshal(payload, nil, &p); err != nil {
		return nil, err
	}
	if p.Format != floorFormat {
		return nil, fmt.Errorf("format is not %q", floorFormat) // signed values are not echoed
	}
	if p.MinProfileVersion == nil || p.MinWrapperVersion == nil || p.RevocationEpoch == nil || p.Bundles == nil || p.RetiredKeys == nil {
		return nil, errors.New("min_profile_version, bundles, min_wrapper_version, revocation_epoch and retired_keys are required")
	}
	switch {
	case !floorIDRE.MatchString(p.OrgID):
		return nil, errors.New("org_id is invalid")
	case !kidRE.MatchString(p.KeyringDigest):
		return nil, errors.New("keyring_digest is invalid")
	case p.Epoch < 1 || *p.RevocationEpoch < 0 || *p.MinProfileVersion < 0:
		return nil, errors.New("epoch must be >= 1, revocation_epoch and min_profile_version >= 0")
	case *p.MinWrapperVersion != "" && !semverRE.MatchString(*p.MinWrapperVersion):
		return nil, errors.New("min_wrapper_version is not a semantic version")
	case len(p.Bundles) > maxFloorBundles || len(p.RetiredKeys) > maxRetiredKeys:
		return nil, errors.New("too many bundles or retired_keys")
	}
	for id, v := range p.Bundles {
		if !floorIDRE.MatchString(id) || v < 1 {
			return nil, errors.New("bundles has an invalid id or a version below 1")
		}
	}
	for i, kid := range p.RetiredKeys {
		if !kidRE.MatchString(kid) || i > 0 && kid <= p.RetiredKeys[i-1] {
			return nil, errors.New("retired_keys must be sorted, unique sha256 kids")
		}
	}
	issued, err := time.Parse(time.RFC3339, p.IssuedAt)
	if err != nil {
		return nil, errNotRFC3339("issued_at")
	}
	expires, err := time.Parse(time.RFC3339, p.ExpiresAt)
	if err != nil {
		return nil, errNotRFC3339("expires_at")
	}
	return &parsedFloor{keyringDigest: p.KeyringDigest, Floor: Floor{
		OrgID: p.OrgID, MinProfileVersion: *p.MinProfileVersion, Bundles: p.Bundles,
		MinWrapperVersion: *p.MinWrapperVersion, Epoch: p.Epoch, RevocationEpoch: *p.RevocationEpoch,
		RetiredKeys: p.RetiredKeys, IssuedAt: issued.UTC(), ExpiresAt: expires.UTC(),
	}}, nil
}
