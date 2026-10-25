package lifecycle

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// maxSharedConfig caps the shared config file read; a larger file is not
// read and the region stays not known.
const maxSharedConfig = 1 << 20

// fallbackRegion is the region the upstream provider uses when its config
// region is null: AWS_REGION, then AWS_DEFAULT_REGION, then the
// region of the shared config profile, the aws-sdk-go-v2 config order. It
// reads env and the shared config file only: never the network (an IMDS
// region stays not known), never the credentials file. sharedSet is true
// when the provider config sets shared_config_files or
// shared_credentials_files, or a profile that is not a known non-empty
// string; the profile source is then not read. profile is the provider
// config profile: aws-sdk-go-base passes it as WithSharedConfigProfile,
// which replaces AWS_PROFILE but not the env region. Any
// ambiguous or unreadable source is not known (fail closed). The value and
// the profile name are never logged or returned in an error.
func fallbackRegion(getenv func(string) string, sharedSet bool, profile string) (string, bool) {
	for _, k := range []string{"AWS_REGION", "AWS_DEFAULT_REGION"} {
		if v := getenv(k); v != "" {
			return v, true
		}
	}
	if sharedSet {
		return "", false
	}
	return profileRegion(getenv, profile)
}

// profileRegion is the region key of profile (when empty, AWS_PROFILE, then
// AWS_DEFAULT_PROFILE, then default) in AWS_CONFIG_FILE or
// ~/.aws/config. The SDK lets a region in the shared credentials file
// override it; that file is never opened, so when it exists (or cannot be
// checked) the region is not known.
func profileRegion(getenv func(string) string, profile string) (string, bool) {
	home := getenv("HOME")
	if runtime.GOOS == "windows" {
		home = getenv("USERPROFILE")
	}
	creds := getenv("AWS_SHARED_CREDENTIALS_FILE")
	if creds == "" && home != "" {
		creds = filepath.Join(home, ".aws", "credentials")
	}
	if creds == "" {
		return "", false
	}
	if _, err := os.Lstat(creds); !errors.Is(err, fs.ErrNotExist) {
		return "", false
	}
	cfg := getenv("AWS_CONFIG_FILE")
	if cfg == "" && home != "" {
		cfg = filepath.Join(home, ".aws", "config")
	}
	if cfg == "" {
		return "", false
	}
	b, err := readCapped(cfg)
	if err != nil {
		return "", false
	}
	name := profile
	if name == "" {
		name = getenv("AWS_PROFILE")
	}
	if name == "" {
		name = getenv("AWS_DEFAULT_PROFILE")
	}
	if name == "" {
		name = "default"
	}
	return iniRegion(b, name)
}

func readCapped(path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // the shared config path the SDK reads
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only
	b, err := io.ReadAll(io.LimitReader(f, maxSharedConfig+1))
	if err == nil && len(b) > maxSharedConfig {
		err = errors.New("shared config too large")
	}
	return b, err
}

var (
	// iniHeader is a simple section header: [name] or [profile name].
	iniHeader = regexp.MustCompile(`^\[(profile )?([A-Za-z0-9_.@+-]+)\]$`)
	// iniKey is a simple property: a bare key, "=" and a value.
	iniKey = regexp.MustCompile(`^([A-Za-z0-9_]+)[ \t]*=[ \t]*(.*)$`)
	// iniRegionValue is a region value with no comment, quote or space.
	iniRegionValue = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]+$`)
)

// inertKeys are the keys the target profile may hold beside region: AWS CLI
// settings that aws-sdk-go-v2 config v1.33.4 never parses, so they cannot
// make it refuse the profile. Any other key (credentials, role, sso,
// retry, endpoint settings) can, so the region is then not known.
var inertKeys = map[string]bool{
	"region": true, "output": true, "cli_pager": true, "cli_auto_prompt": true,
	"cli_timestamp_format": true, "cli_binary_format": true, "cli_history": true,
}

// iniRegion is the region of profile name in a shared config file. The SDK
// parser accepts forms (":" separators, continuation lines, malformed
// headers that keep the previous section open, inline comments) whose
// result is hard to predict, so a region is read only from a simple file
// Every non-blank line is a comment, a header
// exactly [name] or [profile name], or a non-indented key = value with "="
// the only separator; no line is indented. The profile has exactly one
// section ([default] or [profile default] for default, no header equal to
// it ignoring case) and exactly one key spelled region, whose value is a
// plain region name, and every other key is inert (panel round 2: a key
// the SDK parses can make it refuse the profile). Anything else is not
// known.
func iniRegion(b []byte, name string) (string, bool) {
	var (
		in              bool
		sections, found int
		region          string
	)
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 4096), maxSharedConfig)
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "":
			continue
		case line != trimmed:
			return "", false // indented or trailing space
		case line[0] == '#' || line[0] == ';':
			continue
		case line[0] == '[':
			m := iniHeader.FindStringSubmatch(line)
			if m == nil {
				return "", false
			}
			exact := m[2] == name && (m[1] != "" || name == "default")
			if !exact && strings.EqualFold(m[2], name) {
				return "", false // equal ignoring case
			}
			in = exact
			if exact {
				sections++
			}
			continue
		}
		m := iniKey.FindStringSubmatch(line)
		if m == nil {
			return "", false
		}
		if !in {
			continue
		}
		if !inertKeys[m[1]] {
			return "", false
		}
		if m[1] != "region" {
			continue
		}
		if !iniRegionValue.MatchString(m[2]) {
			return "", false
		}
		found++
		region = m[2]
	}
	if sc.Err() != nil || sections != 1 || found != 1 {
		return "", false
	}
	return region, true
}
