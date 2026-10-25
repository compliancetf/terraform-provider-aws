package trust

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// Algorithms. ES256 is the only release algorithm; Ed25519 is accepted only
// from keyring_test.json under the ctftest build tag.
const (
	AlgES256   = "ES256"
	AlgEd25519 = "Ed25519"
)

// Key purposes.
const (
	PurposeBundle    = "bundle"
	PurposeProfile   = "profile"
	PurposeFloor     = "floor"
	PurposeException = "exception"
)

const (
	keyringFormat   = "compliancetf.keyring/v1"
	maxKeyringBytes = 1 << 20
	maxKeyringKeys  = 64
)

var kidRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Key is one trusted public key. Generation is set only for floor keys.
type Key struct {
	KID        string
	Alg        string
	Purpose    string
	Generation int64
	NotBefore  time.Time
	NotAfter   time.Time
	pub        crypto.PublicKey
}

// Keyring is an immutable set of trusted keys indexed by kid.
type Keyring struct {
	keys  []Key
	byKID map[string]*Key
}

// Keys returns a copy of the keys in keyring order.
func (k *Keyring) Keys() []Key {
	return append([]Key(nil), k.keys...)
}

// KIDFromSPKI returns "sha256:" + hex(sha256(spkiDER)).
func KIDFromSPKI(spkiDER []byte) string {
	sum := sha256.Sum256(spkiDER)
	return "sha256:" + hex.EncodeToString(sum[:])
}

type keyringFile struct {
	Format string     `json:"format"`
	Keys   []keyEntry `json:"keys"`
}

type keyEntry struct {
	KID        string   `json:"kid"`
	Alg        string   `json:"alg"`
	Purpose    []string `json:"purpose"`
	Generation *int64   `json:"generation"`
	PublicKey  string   `json:"public_key"`
	NotBefore  string   `json:"not_before"`
	NotAfter   string   `json:"not_after"`
}

var keyringNames = names("format", "keys", "kid", "alg", "purpose", "generation", "public_key", "not_before", "not_after")

// parseKeyring parses one keyring file. Any bad entry fails the whole file.
// Unexported on purpose: only the embedded files are trust anchors.
func parseKeyring(data []byte, allowEd25519 bool) ([]Key, error) {
	if len(data) > maxKeyringBytes {
		return nil, errors.New("keyring: file too large")
	}
	var f keyringFile
	if err := strictUnmarshal(data, keyringNames, &f); err != nil {
		return nil, fmt.Errorf("keyring: %w", err)
	}
	if f.Format != keyringFormat {
		return nil, fmt.Errorf("keyring: format %q, want %q", f.Format, keyringFormat)
	}
	if len(f.Keys) > maxKeyringKeys {
		return nil, fmt.Errorf("keyring: more than %d keys", maxKeyringKeys)
	}
	keys := make([]Key, 0, len(f.Keys))
	for i := range f.Keys {
		k, err := parseKeyEntry(&f.Keys[i], allowEd25519)
		if err != nil {
			return nil, fmt.Errorf("keyring: key %d: %w", i, err)
		}
		keys = append(keys, k)
	}
	return keys, nil
}

func parseKeyEntry(e *keyEntry, allowEd25519 bool) (Key, error) {
	k := Key{KID: e.KID, Alg: e.Alg}
	if !kidRE.MatchString(e.KID) {
		return k, fmt.Errorf("kid %q is not sha256:<64 lowercase hex>", e.KID)
	}
	der, err := base64.StdEncoding.Strict().DecodeString(e.PublicKey)
	if err != nil {
		return k, fmt.Errorf("public_key: %w", err)
	}
	if KIDFromSPKI(der) != e.KID {
		return k, fmt.Errorf("kid %s does not match public_key", e.KID)
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return k, fmt.Errorf("public_key: %w", err)
	}
	switch e.Alg {
	case AlgES256:
		ec, ok := pub.(*ecdsa.PublicKey)
		if !ok || ec.Curve != elliptic.P256() {
			return k, errors.New("ES256 key is not ECDSA P-256")
		}
	case AlgEd25519:
		if !allowEd25519 {
			return k, errors.New("alg Ed25519 is not trusted in this build")
		}
		if _, ok := pub.(ed25519.PublicKey); !ok {
			return k, errors.New("Ed25519 key has the wrong type")
		}
	default:
		return k, fmt.Errorf("alg %q not allowed", e.Alg)
	}
	k.pub = pub
	if len(e.Purpose) != 1 {
		return k, errors.New("purpose must list exactly one entry")
	}
	k.Purpose = e.Purpose[0]
	switch k.Purpose {
	case PurposeBundle, PurposeProfile, PurposeException:
		if e.Generation != nil {
			return k, errors.New("generation is only allowed on floor keys")
		}
	case PurposeFloor:
		if e.Generation == nil || *e.Generation < 1 {
			return k, errors.New("floor key needs generation >= 1")
		}
		k.Generation = *e.Generation
	default:
		return k, fmt.Errorf("unknown purpose %q", k.Purpose)
	}
	if k.NotBefore, err = time.Parse(time.RFC3339, e.NotBefore); err != nil {
		return k, fmt.Errorf("not_before: %w", err)
	}
	if k.NotAfter, err = time.Parse(time.RFC3339, e.NotAfter); err != nil {
		return k, fmt.Errorf("not_after: %w", err)
	}
	if !k.NotBefore.Before(k.NotAfter) {
		return k, errors.New("not_before must be before not_after")
	}
	return k, nil
}

// newKeyring joins key lists; a kid present twice fails.
func newKeyring(lists ...[]Key) (*Keyring, error) {
	kr := &Keyring{byKID: map[string]*Key{}}
	for _, l := range lists {
		kr.keys = append(kr.keys, l...)
	}
	for i := range kr.keys {
		k := &kr.keys[i]
		if kr.byKID[k.KID] != nil {
			return nil, fmt.Errorf("keyring: duplicate kid %s", k.KID)
		}
		kr.byKID[k.KID] = k
	}
	return kr, nil
}
