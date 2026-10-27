// Package wrapper is the per-provider wrapper configuration:
// wrapper.json v1 plus the embedded upstream pins, trust
// anchor and CIS bundle, checked together by Load. Load fails closed: any
// error returns the zero Config.
package wrapper

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	tfaddr "github.com/hashicorp/terraform-registry-address"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
	"github.com/compliancetf/terraform-provider-aws/internal/upstream"
)

// Format is the wrapper.json format id.
const Format = "compliancetf.wrapper/v1"

// SupportedProtocol is the only plugin protocol this SDK serves.
const SupportedProtocol = 5

// Address and upstream registries every wrapper must use.
const (
	AddressHost       = "registry.compliance.tf"
	AddressNamespace  = "compliancetf"
	UpstreamHost      = "registry.terraform.io"
	UpstreamNamespace = "hashicorp"
)

// Input size caps, checked before any decoding. The CIS bundle keeps the
// bundle.ReadArchive caps.
const (
	MaxWrapperJSONBytes = 64 << 10
	MaxPinsBytes        = 1 << 20
	MaxAnchorBytes      = 64 << 10
)

// ErrProtocolUnsupported matches (errors.Is) the Load error for a protocol
// other than SupportedProtocol.
var ErrProtocolUnsupported = errors.New("wrapper: protocol not supported")

// Config is a loaded wrapper: identity from wrapper.json, and the verified
// embedded inputs (copies, so the caller cannot change them after Load).
type Config struct {
	Address        tfaddr.Provider // registry.compliance.tf/compliancetf/<type>
	Upstream       tfaddr.Provider // registry.terraform.io/hashicorp/<type>
	Protocol       int             // always SupportedProtocol
	ResourcePrefix string          // "<type>_"; every CIS bundle control targets it
	UpstreamPins   []byte          // pins.json (compliancetf.upstream-pins/v1)
	TrustAnchors   [][]byte        // ASCII-armored OpenPGP public keys
	CISBundle      []byte          // signed bundle 2.0 archive
}

// file is wrapper.json v1. Field order is the canonical order.
type file struct {
	Format          string `json:"format"`
	Address         string `json:"address"`
	Upstream        string `json:"upstream"`
	Protocol        int    `json:"protocol"`
	ResourcePrefix  string `json:"resource_prefix"`
	CISBundleID     string `json:"cis_bundle_id"`
	CISFramework    string `json:"cis_framework"`
	CatalogProvider string `json:"catalog_provider"`
	VerdictKMS      string `json:"verdict_kms"`
}

// catalogProviders maps an upstream type to its catalog provider name.
var catalogProviders = map[string]string{"aws": "aws", "azurerm": "azure", "google": "gcp"}

var (
	verdictKMS  = map[string]bool{"aws_kms": true, "azure_key_vault": true, "gcp_kms": true}
	bundleIDRe  = regexp.MustCompile(`^cis-[a-z0-9]+$`)
	frameworkRe = regexp.MustCompile(`^cis_[a-z0-9_]+$`)
)

type protocolError struct {
	protocol int
	upstream string
}

func (e protocolError) Error() string {
	return fmt.Sprintf("wrapper: protocol %d is not supported by this SDK; upstream %s must advertise 5.0", e.protocol, e.upstream)
}

func (e protocolError) Unwrap() error { return ErrProtocolUnsupported }

// Load parses wrapper.json and checks it against the embedded pins, trust
// anchor and CIS bundle. The bundle signature is verified against the
// compiled keyring here; revocation and expiry stay with Configure.
func Load(wrapperJSON, pins []byte, anchors [][]byte, cis []byte) (Config, error) {
	f, up, addr, err := parseFile(wrapperJSON)
	if err != nil {
		return Config{}, err
	}
	if err := checkPins(pins, up); err != nil {
		return Config{}, err
	}
	if err := checkAnchors(anchors); err != nil {
		return Config{}, err
	}
	if err := checkCIS(cis, f, up); err != nil {
		return Config{}, err
	}
	cfg := Config{
		Address:        addr,
		Upstream:       up,
		Protocol:       f.Protocol,
		ResourcePrefix: f.ResourcePrefix,
		UpstreamPins:   bytes.Clone(pins),
		CISBundle:      bytes.Clone(cis),
	}
	for _, a := range anchors {
		cfg.TrustAnchors = append(cfg.TrustAnchors, bytes.Clone(a))
	}
	return cfg, nil
}

// parseFile decodes wrapper.json and validates every field. The input must be
// byte-equal to its canonical encoding (as pins.json), which rejects unknown
// and duplicate members, reordering and trailing data.
func parseFile(data []byte) (file, tfaddr.Provider, tfaddr.Provider, error) {
	var f file
	if len(data) == 0 || len(data) > MaxWrapperJSONBytes {
		return f, tfaddr.Provider{}, tfaddr.Provider{}, fmt.Errorf("wrapper: wrapper.json is %d bytes, want 1 to %d", len(data), MaxWrapperJSONBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return f, tfaddr.Provider{}, tfaddr.Provider{}, fmt.Errorf("wrapper: wrapper.json: %w", err)
	}
	canon, err := json.MarshalIndent(&f, "", "  ")
	if err != nil {
		return f, tfaddr.Provider{}, tfaddr.Provider{}, fmt.Errorf("wrapper: wrapper.json: %w", err)
	}
	if !bytes.Equal(append(canon, '\n'), data) {
		return f, tfaddr.Provider{}, tfaddr.Provider{}, errors.New("wrapper: wrapper.json is not in canonical form")
	}
	up, addr, err := f.validate()
	return f, up, addr, err
}

func (f *file) validate() (up, addr tfaddr.Provider, err error) {
	if f.Format != Format {
		return up, addr, fmt.Errorf("wrapper: format %q, want %q", f.Format, Format)
	}
	if up, err = parseProvider("upstream", f.Upstream); err != nil {
		return up, addr, err
	}
	if addr, err = parseProvider("address", f.Address); err != nil {
		return up, addr, err
	}
	if f.Protocol != SupportedProtocol {
		return up, addr, protocolError{f.Protocol, f.Upstream}
	}
	switch {
	case addr.Hostname.String() != AddressHost:
		return up, addr, fmt.Errorf("wrapper: address %s is not under %s", f.Address, AddressHost)
	case addr.Namespace != AddressNamespace:
		return up, addr, fmt.Errorf("wrapper: address %s is not in namespace %s", f.Address, AddressNamespace)
	case up.Hostname.String() != UpstreamHost || up.Namespace != UpstreamNamespace:
		return up, addr, fmt.Errorf("wrapper: upstream %s is not under %s/%s", f.Upstream, UpstreamHost, UpstreamNamespace)
	case addr.Type != up.Type:
		return up, addr, fmt.Errorf("wrapper: address type %s does not match upstream type %s", addr.Type, up.Type)
	case f.ResourcePrefix != up.Type+"_":
		return up, addr, fmt.Errorf("wrapper: resource_prefix %q, want %q", f.ResourcePrefix, up.Type+"_")
	case catalogProviders[up.Type] == "":
		return up, addr, fmt.Errorf("wrapper: upstream type %s has no catalog provider", up.Type)
	case f.CatalogProvider != catalogProviders[up.Type]:
		return up, addr, fmt.Errorf("wrapper: catalog_provider %q, want %q for upstream type %s", f.CatalogProvider, catalogProviders[up.Type], up.Type)
	case !bundleIDRe.MatchString(f.CISBundleID):
		return up, addr, fmt.Errorf("wrapper: cis_bundle_id %q does not match %s", f.CISBundleID, bundleIDRe)
	case !frameworkRe.MatchString(f.CISFramework):
		return up, addr, fmt.Errorf("wrapper: cis_framework %q does not match %s", f.CISFramework, frameworkRe)
	case !verdictKMS[f.VerdictKMS]:
		return up, addr, fmt.Errorf("wrapper: verdict_kms %q is not a known KMS type", f.VerdictKMS)
	}
	return up, addr, nil
}

// parseProvider accepts only the full hostname/namespace/type form already in
// canonical spelling, so no default host, case or IDNA rewrite is implied.
func parseProvider(field, s string) (tfaddr.Provider, error) {
	p, err := tfaddr.ParseProviderSource(s)
	if err != nil || strings.Count(s, "/") != 2 || p.String() != s {
		return tfaddr.Provider{}, fmt.Errorf("wrapper: %s %q is not a canonical hostname/namespace/type provider address", field, s)
	}
	return p, nil
}

// checkPins compares the pins upstream with wrapper.json, then runs the full
// v1 pins format check (canonical form, compiled HashiCorp fingerprint, names
// derived from the upstream type).
func checkPins(pins []byte, up tfaddr.Provider) error {
	if len(pins) == 0 || len(pins) > MaxPinsBytes {
		return fmt.Errorf("wrapper: pins.json is %d bytes, want 1 to %d", len(pins), MaxPinsBytes)
	}
	var head struct {
		Upstream string `json:"upstream"`
	}
	if err := json.Unmarshal(pins, &head); err != nil {
		return fmt.Errorf("wrapper: pins.json: %w", err)
	}
	if head.Upstream != up.String() {
		return fmt.Errorf("wrapper: pins.json is for %s, wrapper.json says %s", head.Upstream, up)
	}
	src, err := upstream.NewSource(up)
	if err != nil {
		return fmt.Errorf("wrapper: %w", err)
	}
	if _, err := upstream.ParsePins(pins, src, upstream.HashiCorpFingerprint); err != nil {
		return fmt.Errorf("wrapper: %w", err)
	}
	return nil
}

// checkAnchors requires exactly the one HashiCorp release key the pins name:
// the compiled fingerprint is the only accepted one, so a second anchor could
// never be used.
func checkAnchors(anchors [][]byte) error {
	if len(anchors) != 1 {
		return fmt.Errorf("wrapper: %d trust anchors, want exactly 1", len(anchors))
	}
	if len(anchors[0]) == 0 || len(anchors[0]) > MaxAnchorBytes {
		return fmt.Errorf("wrapper: trust anchor is %d bytes, want 1 to %d", len(anchors[0]), MaxAnchorBytes)
	}
	if _, err := upstream.LoadKey(anchors[0], upstream.HashiCorpFingerprint); err != nil {
		return fmt.Errorf("wrapper: trust anchor: %w", err)
	}
	return nil
}

// checkCIS verifies the CIS bundle signature (the bundle error is returned
// unchanged), binds its identity and framework to wrapper.json and keeps
// every control inside resource_prefix.
func checkCIS(cis []byte, f file, up tfaddr.Provider) error {
	b, err := bundle.ReadArchive(cis, func(env []byte, payloadType string) (trust.Verified, error) {
		return trust.Verify(env, payloadType, trust.NoRevocations())
	})
	if err != nil {
		return err
	}
	m := b.Manifest
	if m.BundleID != f.CISBundleID {
		return fmt.Errorf("wrapper: CIS bundle is %q, wrapper.json says %s", m.BundleID, f.CISBundleID)
	}
	if m.Provider.Address != f.Address {
		return fmt.Errorf("wrapper: CIS bundle is for provider %q, wrapper.json says %s", m.Provider.Address, f.Address)
	}
	if src, err := tfaddr.ParseProviderSource(m.Upstream.Source); err != nil || src != up {
		return fmt.Errorf("wrapper: CIS bundle is for upstream %q, wrapper.json says %s", m.Upstream.Source, f.Upstream)
	}
	if err := checkPrefix(b.Controls, f.ResourcePrefix); err != nil { // bundle.ReadArchive rejects an empty controls.json
		return err
	}
	return checkFramework(b.Controls, f.CISFramework)
}

// checkFramework binds cis_framework to the signed controls: at least one
// control must carry a "<cis_framework>:<clause>" framework_ref (owner
// 2026-10-19: one ref, not all, as the catalog maps only part of the CIS set).
func checkFramework(controls []bundle.Control, framework string) error {
	for _, c := range controls {
		for _, r := range c.FrameworkRefs {
			if strings.HasPrefix(r, framework+":") {
				return nil
			}
		}
	}
	return errors.New("wrapper: no CIS bundle control has a framework_ref for wrapper.json cis_framework")
}

// checkPrefix requires every type a control targets (the graph companion
// too) to be a "<prefix><name>" type.
func checkPrefix(controls []bundle.Control, prefix string) error {
	for _, c := range controls {
		types := []string{c.ResourceType}
		if c.Graph != nil {
			types = append(types, c.Graph.CompanionType)
		}
		for _, t := range types {
			if len(t) <= len(prefix) || !strings.HasPrefix(t, prefix) {
				return fmt.Errorf("wrapper: CIS bundle control %s targets %s, outside resource_prefix %s", c.ID, t, prefix)
			}
		}
	}
	return nil
}
