package upstream

// source.go derives every upstream-specific name (release zip, binary,
// SHA256SUMS, release URL, Terraform directory) from the wrapper's upstream
// address. Nothing else in this package
// names a provider type.

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	tfaddr "github.com/hashicorp/terraform-registry-address"
)

// The only upstream registry and namespace: every pinned upstream is a
// HashiCorp release signed by HashiCorpFingerprint.
const (
	SourceHost      = "registry.terraform.io"
	SourceNamespace = "hashicorp"
)

const releasesHost = "https://releases.hashicorp.com"

var sourceTypeRe = regexp.MustCompile(`^[a-z][a-z0-9]*$`)

// Source is a validated upstream address registry.terraform.io/hashicorp/<type>.
// The zero Source is invalid and ParsePins rejects it.
type Source struct{ addr tfaddr.Provider }

// NewSource validates p: host registry.terraform.io, namespace hashicorp and a
// lowercase alphanumeric type, so every derived name is a plain file name.
func NewSource(p tfaddr.Provider) (Source, error) {
	if p.Hostname.String() != SourceHost || p.Namespace != SourceNamespace || !sourceTypeRe.MatchString(p.Type) {
		return Source{}, fmt.Errorf("upstream %q is not %s/%s/<type>", p.String(), SourceHost, SourceNamespace)
	}
	return Source{addr: p}, nil
}

// ParseSource parses s, which must already be the canonical full
// hostname/namespace/type form.
func ParseSource(s string) (Source, error) {
	p, err := tfaddr.ParseProviderSource(s)
	if err != nil || strings.Count(s, "/") != 2 || p.String() != s {
		return Source{}, fmt.Errorf("upstream %q is not a canonical hostname/namespace/type address", s)
	}
	return NewSource(p)
}

func (s Source) valid() error {
	if s.addr.Type == "" {
		return errors.New("no upstream source")
	}
	return nil
}

// Address is the upstream provider address.
func (s Source) Address() tfaddr.Provider { return s.addr }

// String is the full address, the pins.json upstream value.
func (s Source) String() string { return s.addr.String() }

// Name is "hashicorp/<type>", used in diagnostics.
func (s Source) Name() string { return s.addr.Namespace + "/" + s.addr.Type }

// ZipName is the release zip name for a version and platform.
func (s Source) ZipName(version, goos, goarch string) string {
	return fmt.Sprintf("%s_%s_%s_%s.zip", s.project(), version, goos, goarch)
}

// BinaryName is the binary name inside the release zip.
func (s Source) BinaryName(version, goos string, protocol int) string {
	name := fmt.Sprintf("%s_v%s_x%d", s.project(), version, protocol)
	if goos == "windows" {
		name += ".exe"
	}
	return name
}

// SumsName is the release SHA256SUMS file name; its signature adds ".sig".
func (s Source) SumsName(version string) string {
	return s.project() + "_" + version + "_SHA256SUMS"
}

// ReleasesURL is the HashiCorp releases base URL, without a trailing slash.
func (s Source) ReleasesURL() string { return releasesHost + "/" + s.project() }

// RegistryDir is the provider directory under a Terraform plugin or mirror
// directory: registry.terraform.io/hashicorp/<type>.
func (s Source) RegistryDir() string {
	return filepath.Join(s.addr.Hostname.String(), s.addr.Namespace, s.addr.Type)
}

func (s Source) project() string { return "terraform-provider-" + s.addr.Type }
