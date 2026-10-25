package trust

import (
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

// ExtKey is a customer KMS key from a floor-validated signed profile
// (exceptions.grant_keys). It is trusted only to sign exception grants.
type ExtKey struct {
	KID       string
	Alg       string
	SPKI      []byte // DER
	NotBefore time.Time
	NotAfter  time.Time
}

const maxExtKeys = 64

// ExceptionKeyring returns compiled plus every ext key with purpose
// exception, so an ext key verifies only exception grants (owner
// 2026-10-06). Each ext key goes through the keyring entry checks (kid =
// sha256 of the SPKI DER, ES256 on P-256, window). Ext keys are ES256 only,
// also under ctftest. Any bad, duplicate or compiled-shadowing ext key fails
// the whole set: a profile copy of a compiled key could otherwise change its
// purpose or window.
func ExceptionKeyring(compiled *Keyring, ext []ExtKey) (*Keyring, error) {
	if compiled == nil {
		return nil, errors.New("exception keyring: no compiled keyring")
	}
	if len(ext) > maxExtKeys {
		return nil, fmt.Errorf("exception keyring: more than %d grant keys", maxExtKeys)
	}
	keys := make([]Key, 0, len(ext))
	for i, x := range ext {
		if x.NotBefore.IsZero() || x.NotAfter.IsZero() {
			return nil, fmt.Errorf("exception keyring: grant key %d: missing validity window", i)
		}
		e := keyEntry{KID: x.KID, Alg: x.Alg, Purpose: []string{PurposeException},
			PublicKey: base64.StdEncoding.EncodeToString(x.SPKI),
			NotBefore: x.NotBefore.UTC().Format(time.RFC3339Nano), NotAfter: x.NotAfter.UTC().Format(time.RFC3339Nano)}
		k, err := parseKeyEntry(&e, false)
		if err != nil {
			return nil, fmt.Errorf("exception keyring: grant key %d: %w", i, err)
		}
		keys = append(keys, k)
	}
	kr, err := newKeyring(compiled.keys, keys) // a duplicate or shadowing kid fails
	if err != nil {
		return nil, fmt.Errorf("exception keyring: %w", err)
	}
	return kr, nil
}

// Valid reports whether r is a usable revocation set (the zero value is not).
func (r Revocations) Valid() bool { return r.valid }
