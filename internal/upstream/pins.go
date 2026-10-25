package upstream

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Pins format constants (the v1 pins format).
const (
	PinsFormat   = "compliancetf.upstream-pins/v1"
	PinsProtocol = 5
	// HashiCorpFingerprint is the primary key fingerprint of the HashiCorp
	// release signing key. A key file that does not carry exactly this key is
	// rejected, so swapping the key file alone cannot change the trust anchor.
	HashiCorpFingerprint = "C874011F0AB405110D02105534365D9472D7468F"
)

// Pins is the content of pins.json: one exact upstream version per wrapper
// release, with checksums taken from HashiCorp's signed SHA256SUMS.
type Pins struct {
	Format                string                 `json:"format"`
	Upstream              string                 `json:"upstream"`
	Version               string                 `json:"version"`
	Protocol              int                    `json:"protocol"`
	SigningKeyFingerprint string                 `json:"signing_key_fingerprint"`
	SHA256SumsSHA256      string                 `json:"sha256sums_sha256"`
	Platforms             map[string]PlatformPin `json:"platforms"`

	src Source // the Source ParsePins checked Upstream against
}

// Source is the upstream ParsePins checked the pins against; the zero Source
// for pins not returned by ParsePins.
func (p *Pins) Source() Source { return p.src }

// PlatformPin pins the release zip and the binary inside it for one os_arch.
type PlatformPin struct {
	Zip          string `json:"zip"`
	ZipSHA256    string `json:"zip_sha256"`
	Binary       string `json:"binary"`
	BinarySHA256 string `json:"binary_sha256"`
}

var (
	versionRe     = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	sha256Re      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	fingerprintRe = regexp.MustCompile(`^[0-9A-F]{40}$`)
	osArchRe      = regexp.MustCompile(`^([a-z0-9]+)_([a-z0-9]+)$`)
)

// ValidVersion reports whether v is an exact x.y.z upstream version.
func ValidVersion(v string) bool { return versionRe.MatchString(v) }

// conformancePins is set only by conformance builds (pins_conformance.go); it
// returns replacement pins, or nil to keep the given ones.
var conformancePins func() ([]byte, error)

// loadPins parses data (wrapper Config.UpstreamPins) for src against the
// compiled HashiCorp fingerprint; a conformance build may replace data.
func loadPins(data []byte, src Source) (*Pins, error) {
	if conformancePins != nil {
		b, err := conformancePins()
		if err != nil {
			return nil, fmt.Errorf("pins: %w", err)
		}
		if b != nil {
			data = b
		}
	}
	return ParsePins(data, src, HashiCorpFingerprint)
}

// MarshalPins returns the canonical encoding written by tools/pinupstream:
// fixed field order, sorted platform keys, 2-space indent, trailing newline.
func MarshalPins(p *Pins) ([]byte, error) {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// ParsePins decodes and validates pins. The input must be byte-equal to its
// canonical re-encoding, which rejects duplicate members, unknown fields,
// reordering and trailing data. The upstream must be src, and every zip and
// binary name must be the one src derives; a zero src fails.
func ParsePins(data []byte, src Source, expectedFingerprint string) (*Pins, error) {
	if err := src.valid(); err != nil {
		return nil, fmt.Errorf("pins: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var p Pins
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("pins: %w", err)
	}
	canon, err := MarshalPins(&p)
	if err != nil {
		return nil, fmt.Errorf("pins: %w", err)
	}
	if !bytes.Equal(canon, data) {
		return nil, errors.New("pins: not in canonical form")
	}
	if err := p.validate(src, expectedFingerprint); err != nil {
		return nil, fmt.Errorf("pins: %w", err)
	}
	p.src = src
	return &p, nil
}

func (p *Pins) validate(src Source, expectedFingerprint string) error {
	switch {
	case p.Format != PinsFormat:
		return fmt.Errorf("format %q", p.Format)
	case p.Upstream != src.String():
		return fmt.Errorf("upstream %q", p.Upstream)
	case !ValidVersion(p.Version):
		return fmt.Errorf("version %q", p.Version)
	case p.Protocol != PinsProtocol:
		return fmt.Errorf("protocol %d", p.Protocol)
	case !fingerprintRe.MatchString(p.SigningKeyFingerprint) || p.SigningKeyFingerprint != strings.ToUpper(expectedFingerprint):
		return fmt.Errorf("signing_key_fingerprint %q is not the pinned key", p.SigningKeyFingerprint)
	case !sha256Re.MatchString(p.SHA256SumsSHA256):
		return errors.New("sha256sums_sha256 is not a lowercase sha256")
	case len(p.Platforms) == 0:
		return errors.New("no platforms")
	}
	for key, pl := range p.Platforms {
		m := osArchRe.FindStringSubmatch(key)
		if m == nil {
			return fmt.Errorf("platform key %q", key)
		}
		if pl.Zip != src.ZipName(p.Version, m[1], m[2]) || pl.Binary != src.BinaryName(p.Version, m[1], p.Protocol) {
			return fmt.Errorf("platform %s: names do not match version", key)
		}
		if !sha256Re.MatchString(pl.ZipSHA256) || !sha256Re.MatchString(pl.BinarySHA256) {
			return fmt.Errorf("platform %s: bad sha256", key)
		}
	}
	return nil
}
