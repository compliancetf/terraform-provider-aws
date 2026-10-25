package lifecycle

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/hook"
	"github.com/compliancetf/terraform-provider-aws/test/scrub/scrubtest"
)

// home is a temp HOME with an optional ~/.aws/config; the getenv it returns
// reads env and maps HOME (USERPROFILE on Windows) to it.
func home(t *testing.T, config string, env map[string]string) (string, func(string) string) {
	t.Helper()
	dir := t.TempDir()
	if config != "" {
		writeText(t, filepath.Join(dir, ".aws", "config"), config)
	}
	return dir, func(k string) string {
		if k == "HOME" || (runtime.GOOS == "windows" && k == "USERPROFILE") {
			return dir
		}
		return env[k]
	}
}

func writeText(t *testing.T, p, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestFallbackRegion: with a null config region the
// binding follows the aws-sdk-go-v2 order: AWS_REGION, AWS_DEFAULT_REGION,
// then the shared config profile region. An env value is taken as set, never
// skipped when malformed (the SDK would use it). A known provider config
// profile replaces AWS_PROFILE and AWS_DEFAULT_PROFILE, never the env
// region; the profile is not read when the provider config sets its own
// files or a profile that is not a known non-empty string.
func TestFallbackRegion(t *testing.T) {
	const cfg = "[default]\nregion = eu-west-1\n[profile cn]\nregion = cn-north-1\n[profile gov]\nregion = us-gov-west-1\n"
	for _, c := range []struct {
		name      string
		env       map[string]string
		sharedSet bool
		profile   string
		want      string
		known     bool
	}{
		{"AWS_REGION first", map[string]string{"AWS_REGION": "us-east-1", "AWS_DEFAULT_REGION": "cn-north-1", "AWS_PROFILE": "gov"}, false, "", "us-east-1", true},
		{"AWS_DEFAULT_REGION second", map[string]string{"AWS_DEFAULT_REGION": "cn-north-1", "AWS_PROFILE": "gov"}, false, "", "cn-north-1", true},
		{"malformed AWS_REGION is still taken", map[string]string{"AWS_REGION": "EU-WEST-1", "AWS_DEFAULT_REGION": "cn-north-1"}, false, "", "EU-WEST-1", true},
		{"default profile", nil, false, "", "eu-west-1", true},
		{"AWS_PROFILE", map[string]string{"AWS_PROFILE": "cn", "AWS_DEFAULT_PROFILE": "gov"}, false, "", "cn-north-1", true},
		{"AWS_DEFAULT_PROFILE", map[string]string{"AWS_DEFAULT_PROFILE": "gov"}, false, "", "us-gov-west-1", true},
		{"AWS_SHARED_CONFIG_FILES selects nothing", map[string]string{"AWS_SHARED_CONFIG_FILES": "/nonexistent"}, false, "", "eu-west-1", true},
		{"AWS_PROFILE not in the file", map[string]string{"AWS_PROFILE": "missing"}, false, "", "", false},
		{"env wins over a config profile", map[string]string{"AWS_REGION": "us-east-1"}, true, "", "us-east-1", true},
		{"config files or unknown profile: shared config not read", nil, true, "", "", false},
		{"config profile", nil, false, "cn", "cn-north-1", true},
		{"config profile replaces AWS_PROFILE", map[string]string{"AWS_PROFILE": "gov", "AWS_DEFAULT_PROFILE": "gov"}, false, "cn", "cn-north-1", true},
		{"config profile default", map[string]string{"AWS_PROFILE": "gov"}, false, "default", "eu-west-1", true},
		{"AWS_REGION wins over a config profile", map[string]string{"AWS_REGION": "us-east-1"}, false, "cn", "us-east-1", true},
		{"AWS_DEFAULT_REGION wins over a config profile", map[string]string{"AWS_DEFAULT_REGION": "ap-south-1"}, false, "cn", "ap-south-1", true},
		{"config profile not in the file", map[string]string{"AWS_PROFILE": "gov"}, false, "missing", "", false},
		{"config profile with config files", nil, true, "cn", "", false},
	} {
		_, getenv := home(t, cfg, c.env)
		got, known := fallbackRegion(getenv, c.sharedSet, c.profile)
		if got != c.want || known != c.known {
			t.Errorf("%s: fallbackRegion = %q, %v; want %q, %v", c.name, got, known, c.want, c.known)
		}
	}
}

// TestProfileRegionFiles: AWS_CONFIG_FILE replaces ~/.aws/config;
// an existing credentials file (it may override the region and is never
// opened), a missing, unreadable or oversized config file, or no home makes
// the region not known.
func TestProfileRegionFiles(t *testing.T) {
	const cfg = "[default]\nregion = eu-west-1\n"
	alt := filepath.Join(t.TempDir(), "alt-config")
	writeText(t, alt, "[default]\nregion = cn-north-1\n")
	big := filepath.Join(t.TempDir(), "big-config")
	writeText(t, big, cfg+"# "+strings.Repeat("x", maxSharedConfig)+"\n")
	creds := filepath.Join(t.TempDir(), "creds")
	writeText(t, creds, "")

	for _, c := range []struct {
		name    string
		config  string
		env     map[string]string
		prepare func(t *testing.T, home string)
		want    string
		known   bool
	}{
		{name: "AWS_CONFIG_FILE", config: cfg, env: map[string]string{"AWS_CONFIG_FILE": alt}, want: "cn-north-1", known: true},
		{name: "no config file", known: false},
		{name: "AWS_CONFIG_FILE missing", config: cfg, env: map[string]string{"AWS_CONFIG_FILE": alt + "-missing"}},
		{name: "config is a directory", env: map[string]string{"AWS_CONFIG_FILE": t.TempDir()}},
		{name: "oversized config", env: map[string]string{"AWS_CONFIG_FILE": big}},
		{name: "default credentials file exists", config: cfg, prepare: func(t *testing.T, h string) {
			writeText(t, filepath.Join(h, ".aws", "credentials"), "")
		}},
		{name: "AWS_SHARED_CREDENTIALS_FILE exists", config: cfg, env: map[string]string{"AWS_SHARED_CREDENTIALS_FILE": creds}},
		{name: "AWS_SHARED_CREDENTIALS_FILE missing", config: cfg, env: map[string]string{"AWS_SHARED_CREDENTIALS_FILE": creds + "-missing"}, want: "eu-west-1", known: true},
		{name: "credentials path is a directory", config: cfg, prepare: func(t *testing.T, h string) {
			if err := os.MkdirAll(filepath.Join(h, ".aws", "credentials"), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		h, getenv := home(t, c.config, c.env)
		if c.prepare != nil {
			c.prepare(t, h)
		}
		got, known := fallbackRegion(getenv, false, "")
		if got != c.want || known != c.known {
			t.Errorf("%s: fallbackRegion = %q, %v; want %q, %v", c.name, got, known, c.want, c.known)
		}
	}

	// No home and no explicit paths: nothing to read.
	if got, known := fallbackRegion(func(string) string { return "" }, false, ""); known {
		t.Errorf("no home: fallbackRegion = %q, known", got)
	}
	if runtime.GOOS != "windows" && os.Getuid() != 0 {
		locked := filepath.Join(t.TempDir(), "locked")
		writeText(t, locked, cfg)
		if err := os.Chmod(locked, 0); err != nil {
			t.Fatal(err)
		}
		_, getenv := home(t, "", map[string]string{"AWS_CONFIG_FILE": locked})
		if got, known := fallbackRegion(getenv, false, ""); known {
			t.Errorf("unreadable config: fallbackRegion = %q, known", got)
		}
	}
}

// TestINIRegion: exactly one section and one region key are
// read; anything the SDK could read differently is not known.
func TestINIRegion(t *testing.T) {
	for _, c := range []struct {
		name, ini, profile, want string
		known                    bool
	}{
		{"default", "[default]\nregion = eu-west-1\n", "default", "eu-west-1", true},
		{"profile default", "[profile default]\nregion = eu-west-1\n", "default", "eu-west-1", true},
		{"named", "[default]\nregion = eu-west-1\n[profile p]\n# c\n; c\n\nregion=cn-north-1\noutput = json\n", "p", "cn-north-1", true},
		{"other profiles ignored", "[profile q]\nregion = us-east-1\n[profile p]\nregion = eu-west-1\n[default]\nregion = us-east-1\n", "p", "eu-west-1", true},
		{"sso-session header is not simple", "[profile p]\nregion = eu-west-1\n[sso-session p]\nsso_region = us-east-1\n", "p", "", false},
		{"nested block is not simple", "[profile p]\nregion = eu-west-1\ns3 =\n  max_concurrent_requests = 10\n", "p", "", false},
		{"region with a dash suffix", "[profile p]\nregion = us-gov-west-1\n", "p", "us-gov-west-1", true},
		{"no region", "[profile p]\noutput = json\n", "p", "", false},
		{"empty region", "[profile p]\nregion =\n", "p", "", false},
		{"no section", "[profile q]\nregion = eu-west-1\n", "p", "", false},
		{"bare name is not a profile", "[p]\nregion = eu-west-1\n", "p", "", false},
		{"default and profile default", "[default]\nregion = eu-west-1\n[profile default]\nregion = us-east-1\n", "default", "", false},
		{"duplicate section", "[profile p]\nregion = eu-west-1\n[profile p]\noutput = json\n", "p", "", false},
		{"duplicate region", "[profile p]\nregion = eu-west-1\nregion = us-east-1\n", "p", "", false},
		{"case differs", "[DEFAULT]\nregion = eu-west-1\n", "default", "", false},
		{"profile case differs", "[profile P]\nregion = eu-west-1\n[profile p]\nregion = us-east-1\n", "p", "", false},
		{"spacing differs", "[profile  p]\nregion = eu-west-1\n", "p", "", false},
		{"header with a comment", "[profile p] # c\nregion = eu-west-1\n", "p", "", false},
		{"key case differs", "[profile p]\nRegion = eu-west-1\n", "p", "", false},
		{"continuation", "[profile p]\nregion = eu-west-1\n  us-east-1\n", "p", "", false},
		{"indented region", "[profile p]\ns3 =\n  region = eu-west-1\n", "p", "", false},
		{"trailing space", "[profile p]\nregion = eu-west-1 \n", "p", "", false},
		{"quoted region", "[profile p]\nregion = \"eu-west-1\"\n", "p", "", false},
		{"indented comment", "[profile p]\n  # c\nregion = eu-west-1\n", "p", "", false},
		// Panel round 1: inputs where the SDK reads a region other than the
		// one a looser parser returns. All are not known.
		{"colon separator", "[default]\nregion = us-east-1\nregion: cn-north-1\n", "default", "", false},
		{"promoted indented property", "[default]\noutput = json\n  region: cn-north-1\n", "default", "", false},
		{"hash in header", "[default]\nregion = us-east-1\n[other#x]\nregion = cn-north-1\n", "default", "", false},
		{"semicolon in header", "[default]\nregion = us-east-1\n[profile o ; c]\nregion = cn-north-1\n", "default", "", false},
		{"unclosed header", "[default]\nregion = us-east-1\n[x\nregion = cn-north-1\n", "default", "", false},
		{"trailing header text", "[default]\nregion = us-east-1\n[x] y\nregion = cn-north-1\n", "default", "", false},
		{"continuation after a bare line", "[default]\nregion = cn-north-1\nignored\n  extra\n", "default", "", false},
		{"inline comment", "[profile p]\nregion = eu-west-1 # c\n", "p", "", false},
		// Panel round 2: the SDK refuses these profiles; a key the SDK
		// parses is never inert.
		{"missing sso session", "[default]\nregion = us-east-1\nsso_session = x\n", "default", "", false},
		{"missing source profile", "[profile p]\nregion = us-east-1\nrole_arn = arn:aws:iam::1:role/r\nsource_profile = q\n", "p", "", false},
		{"bad max_attempts", "[default]\nregion = us-east-1\nmax_attempts = abc\n", "default", "", false},
		{"cli keys are inert", "[default]\noutput = json\ncli_pager =\nregion = us-east-1\n", "default", "us-east-1", true},
		{"other sections may hold any key", "[profile q]\nrole_arn = r\n[default]\nregion = us-east-1\n", "default", "us-east-1", true},
		{"crlf", "[profile p]\r\nregion = eu-west-1\r\n", "p", "eu-west-1", true},
		{"line too long", "[profile p]\nregion = eu-west-1\n# " + strings.Repeat("x", maxSharedConfig) + "\n", "p", "", false},
	} {
		got, known := iniRegion([]byte(c.ini), c.profile)
		if got != c.want || known != c.known {
			t.Errorf("%s: iniRegion = %q, %v; want %q, %v", c.name, got, known, c.want, c.known)
		}
	}
}

// TestUpstreamRegion: only a null config region falls back; an
// unknown one stays unknown, a set one is used as set. providerInfo binds
// the region with its partition and never the account.
func TestUpstreamRegion(t *testing.T) {
	_, getenv := home(t, "", map[string]string{"AWS_REGION": "cn-north-1"})
	for _, c := range []struct {
		name string
		req  hook.ConfigureRequest
		want engine.ProviderInfo
	}{
		{"set", hook.ConfigureRequest{Region: "eu-west-1", RegionKnown: true}, engine.ProviderInfo{Region: "eu-west-1", RegionKnown: true, Partition: "aws", PartitionKnown: true}},
		{"null", hook.ConfigureRequest{RegionNull: true}, engine.ProviderInfo{Region: "cn-north-1", RegionKnown: true, Partition: "aws-cn", PartitionKnown: true}},
		{"null with config profile", hook.ConfigureRequest{RegionNull: true, SharedConfigSet: true}, engine.ProviderInfo{Region: "cn-north-1", RegionKnown: true, Partition: "aws-cn", PartitionKnown: true}},
		{"unknown", hook.ConfigureRequest{}, engine.ProviderInfo{}},
		{"set, no partition", hook.ConfigureRequest{Region: "us-iso-east-1", RegionKnown: true}, engine.ProviderInfo{}},
	} {
		if got := providerInfo(upstreamRegion(&c.req, getenv)); got != c.want {
			t.Errorf("%s: provider %+v, want %+v", c.name, got, c.want)
		}
	}

	// a config profile is read in place of AWS_PROFILE, with the
	// same credentials file rule.
	h, getenv := home(t, "[profile p]\nregion = cn-north-1\n", map[string]string{"AWS_PROFILE": "q"})
	req := &hook.ConfigureRequest{RegionNull: true, Profile: "p"}
	if got, want := providerInfo(upstreamRegion(req, getenv)), (engine.ProviderInfo{Region: "cn-north-1", RegionKnown: true, Partition: "aws-cn", PartitionKnown: true}); got != want {
		t.Errorf("config profile: provider %+v, want %+v", got, want)
	}
	writeText(t, filepath.Join(h, ".aws", "credentials"), "")
	if got := providerInfo(upstreamRegion(req, getenv)); got != (engine.ProviderInfo{}) {
		t.Errorf("config profile with a credentials file: provider %+v, want unknown", got)
	}
}

// TestRegionValueFree: env and shared config values that do not
// resolve to a partition never reach the binding, a log or stderr; only a
// resolved region and its partition id are bound.
func TestRegionValueFree(t *testing.T) {
	logs := scrubtest.CaptureLogs(t)
	m := scrubtest.Marker
	ini := fmt.Sprintf("[default]\nregion = %s\naws_access_key_id = %s\n[profile %s]\nregion = eu-west-1\n[profile p]\nregion = %s\nrole_arn = %s\n",
		m(1), m(2), m(3), m(4), m(5))
	envs := []map[string]string{
		{"AWS_REGION": m(6)},
		{"AWS_DEFAULT_REGION": m(7)},
		{"AWS_PROFILE": "p"},
		{},
		{"AWS_PROFILE": m(8)},
		{"AWS_PROFILE": "p", "AWS_SHARED_CREDENTIALS_FILE": m(9)},
	}
	// a config profile that names a marked section, or is
	// itself marked, is not known and never echoed.
	profiles := []string{"", "", "", "", "", "", "p", m(3) + "x", m(10), "default"}
	envs = append(envs, map[string]string{}, map[string]string{}, map[string]string{"AWS_PROFILE": m(3)}, map[string]string{})
	for i, env := range envs {
		_, getenv := home(t, ini, env)
		got := providerInfo(upstreamRegion(&hook.ConfigureRequest{RegionNull: true, Profile: profiles[i]}, getenv))
		scrubtest.NoMarker(t, fmt.Sprintf("binding %d", i), fmt.Sprintf("%+v", got))
		if got != (engine.ProviderInfo{}) {
			t.Errorf("env %d: binding %s, want unknown", i, scrubtest.Mask(fmt.Sprintf("%+v", got)))
		}
	}
	scrubtest.NoMarker(t, "log", logs())
}

// TestINIRegionMatchesSDK: whenever
// iniRegion returns a region for a corpus file, the SDK loads the profile
// and reads that region; when the SDK refuses the profile, iniRegion is
// not known. test/sdkregion checks the corpus against the SDK itself.
func TestINIRegionMatchesSDK(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "sdkregion", "corpus.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus []struct {
		Name, INI, Profile, SDK string
		Error                   bool
	}
	if err := json.Unmarshal(b, &corpus); err != nil {
		t.Fatal(err)
	}
	known := 0
	for _, e := range corpus {
		got, ok := iniRegion([]byte(e.INI), e.Profile)
		if ok && (e.Error || got != e.SDK) {
			t.Errorf("%s: iniRegion = %q, the SDK reads %q (error %v)", e.Name, got, e.SDK, e.Error)
		}
		if ok {
			known++
		}
	}
	if known < 8 {
		t.Errorf("only %d corpus files resolve; the corpus lost its simple files", known)
	}
}
