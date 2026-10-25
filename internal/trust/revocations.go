package trust

import (
	"errors"
	"fmt"
	"maps"
	"time"
)

const (
	revocationsFormat   = "compliancetf.revocations/v1"
	maxRevocationsBytes = 1 << 20
	maxRevocationsList  = 4096
)

type controlRef struct {
	id      string
	version int64
}

// Revocations is an immutable revocation set. The zero value is invalid and
// makes Verify fail closed; build one with ParseRevocations, NoRevocations or
// Merge.
type Revocations struct {
	valid    bool
	epoch    int64
	keys     map[string]time.Time
	bundles  map[string]int64
	controls map[controlRef]bool
}

type revocationsFile struct {
	Format      string `json:"format"`
	Epoch       int64  `json:"epoch"`
	RevokedKeys []struct {
		KID       string `json:"kid"`
		RevokedAt string `json:"revoked_at"`
	} `json:"revoked_keys"`
	RevokedBundles []struct {
		BundleID     string `json:"bundle_id"`
		BelowVersion int64  `json:"below_version"`
	} `json:"revoked_bundles"`
	RevokedControls []struct {
		ID      string `json:"id"`
		Version int64  `json:"version"`
	} `json:"revoked_controls"`
}

var revocationsNames = names("format", "epoch", "revoked_keys", "kid", "revoked_at",
	"revoked_bundles", "bundle_id", "below_version", "revoked_controls", "id", "version")

// NoRevocations returns a valid, empty set.
func NoRevocations() Revocations {
	return Revocations{valid: true, keys: map[string]time.Time{}, bundles: map[string]int64{}, controls: map[controlRef]bool{}}
}

// ParseRevocations parses a revocations.json file. Callers pass only bytes
// whose digest was checked against a verified bundle manifest (the archive
// reader enforces that binding). A parse error never yields an empty set.
func ParseRevocations(data []byte) (Revocations, error) {
	if len(data) > maxRevocationsBytes {
		return Revocations{}, errors.New("revocations: file too large")
	}
	var f revocationsFile
	if err := strictUnmarshal(data, revocationsNames, &f); err != nil {
		return Revocations{}, fmt.Errorf("revocations: %w", err)
	}
	if f.Format != revocationsFormat {
		return Revocations{}, fmt.Errorf("revocations: format is not %q", revocationsFormat) // values are not echoed
	}
	if f.Epoch < 1 {
		return Revocations{}, errors.New("revocations: epoch must be >= 1")
	}
	if len(f.RevokedKeys) > maxRevocationsList || len(f.RevokedBundles) > maxRevocationsList || len(f.RevokedControls) > maxRevocationsList {
		return Revocations{}, fmt.Errorf("revocations: list longer than %d", maxRevocationsList)
	}
	r := NoRevocations()
	r.epoch = f.Epoch
	for _, k := range f.RevokedKeys {
		if !kidRE.MatchString(k.KID) {
			return Revocations{}, errors.New("revocations: a revoked kid is not a sha256 kid")
		}
		at, err := time.Parse(time.RFC3339, k.RevokedAt)
		if err != nil {
			return Revocations{}, fmt.Errorf("revocations: %w", errNotRFC3339("revoked_at"))
		}
		if _, dup := r.keys[k.KID]; dup {
			return Revocations{}, errors.New("revocations: duplicate kid")
		}
		r.keys[k.KID] = at
	}
	for _, b := range f.RevokedBundles {
		if b.BundleID == "" || b.BelowVersion < 1 {
			return Revocations{}, errors.New("revocations: bundle entry needs bundle_id and below_version >= 1")
		}
		if _, dup := r.bundles[b.BundleID]; dup {
			return Revocations{}, errors.New("revocations: duplicate bundle_id")
		}
		r.bundles[b.BundleID] = b.BelowVersion
	}
	for _, c := range f.RevokedControls {
		ref := controlRef{c.ID, c.Version}
		if c.ID == "" || c.Version < 1 {
			return Revocations{}, errors.New("revocations: control entry needs id and version >= 1")
		}
		if r.controls[ref] {
			return Revocations{}, errors.New("revocations: duplicate control")
		}
		r.controls[ref] = true
	}
	return r, nil
}

// Merge returns a new set: max epoch and the union of every list. A kid keeps
// its earliest revoked_at, a bundle its highest below_version. Nothing is ever
// un-revoked.
func Merge(a, b Revocations) (Revocations, error) {
	if !a.valid || !b.valid {
		return Revocations{}, errors.New("revocations: merge of an invalid set")
	}
	r := Revocations{valid: true, epoch: max(a.epoch, b.epoch),
		keys: maps.Clone(a.keys), bundles: maps.Clone(a.bundles), controls: maps.Clone(a.controls)}
	for kid, at := range b.keys {
		if old, ok := r.keys[kid]; !ok || at.Before(old) {
			r.keys[kid] = at
		}
	}
	for id, v := range b.bundles {
		r.bundles[id] = max(r.bundles[id], v)
	}
	maps.Copy(r.controls, b.controls)
	return r, nil
}

// Epoch returns the revocation epoch (0 for NoRevocations).
func (r Revocations) Epoch() int64 { return r.epoch }

// The queries below report everything revoked on an invalid (zero-value) set,
// so a caller that skipped ParseRevocations fails closed.

// KeyRevoked reports whether kid is revoked. revoked_at does not limit it: a
// revoked key's signatures are rejected whatever their issued_at.
func (r Revocations) KeyRevoked(kid string) bool {
	_, ok := r.keys[kid]
	return ok || !r.valid
}

// BundleRevoked reports whether version of bundleID is below its revoked floor.
func (r Revocations) BundleRevoked(bundleID string, version int64) bool {
	return version < r.bundles[bundleID] || !r.valid
}

// ControlRevoked reports whether the exact control id@version is revoked.
func (r Revocations) ControlRevoked(id string, version int64) bool {
	return r.controls[controlRef{id, version}] || !r.valid
}
