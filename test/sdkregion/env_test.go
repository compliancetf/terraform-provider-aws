package sdkregion

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
)

// helperEnv marks the child process of TestLoadDefaultConfigRegion;
// profileEnv carries the provider config profile it passes as
// WithSharedConfigProfile.
const (
	helperEnv  = "SDKREGION_HELPER"
	profileEnv = "SDKREGION_PROFILE"
)

// TestLoadDefaultConfigRegion pins the region order
// internal/lifecycle fallbackRegion follows against config.LoadDefaultConfig,
// as hashicorp/aws (aws-sdk-go-base v2) calls it when the provider region is
// null: AWS_REGION, AWS_DEFAULT_REGION, then the profile from AWS_PROFILE,
// else AWS_DEFAULT_PROFILE, else default, read from AWS_CONFIG_FILE or
// $HOME/.aws/config. AWS_SHARED_CONFIG_FILES and AWS_SDK_LOAD_CONFIG select
// nothing. A region in the credentials file overrides the config file, which
// is why the provider leaves the region unknown when that file exists.
// A provider config profile is passed as WithSharedConfigProfile (as
// aws-sdk-go-base does): it replaces AWS_PROFILE and AWS_DEFAULT_PROFILE,
// the env region still wins, and a profile missing from the file fails the
// load.
//
// The SDK fixes its default file paths at package init from HOME, so each
// case runs the SDK in a child process with an env built from scratch and
// HOME in a temp dir: no real AWS file or env var is read.
func TestLoadDefaultConfigRegion(t *testing.T) {
	if os.Getenv(helperEnv) != "" {
		t.Skip("child process")
	}
	const ini = "[default]\nregion = eu-west-1\n[profile p]\nregion = cn-north-1\n[profile d]\nregion = us-gov-west-1\n"
	for _, c := range []struct {
		name    string
		env     map[string]string
		profile string // the provider config profile
		creds   string // written to $HOME/.aws/credentials when set
		want    string // "ERROR" when LoadDefaultConfig fails
	}{
		{name: "default profile", want: "eu-west-1"},
		{name: "AWS_REGION first", env: map[string]string{"AWS_REGION": "us-east-1", "AWS_DEFAULT_REGION": "ap-south-1", "AWS_PROFILE": "p"}, want: "us-east-1"},
		{name: "AWS_DEFAULT_REGION second", env: map[string]string{"AWS_DEFAULT_REGION": "ap-south-1", "AWS_PROFILE": "p"}, want: "ap-south-1"},
		{name: "AWS_PROFILE before AWS_DEFAULT_PROFILE", env: map[string]string{"AWS_PROFILE": "p", "AWS_DEFAULT_PROFILE": "d"}, want: "cn-north-1"},
		{name: "AWS_DEFAULT_PROFILE without AWS_PROFILE", env: map[string]string{"AWS_DEFAULT_PROFILE": "d"}, want: "us-gov-west-1"},
		{name: "AWS_CONFIG_FILE replaces the home file", env: map[string]string{"AWS_CONFIG_FILE": "OTHER"}, want: "sa-east-1"},
		{name: "AWS_SHARED_CONFIG_FILES is not read", env: map[string]string{"AWS_SHARED_CONFIG_FILES": "OTHER"}, want: "eu-west-1"},
		{name: "AWS_SDK_LOAD_CONFIG changes nothing", env: map[string]string{"AWS_SDK_LOAD_CONFIG": "0"}, want: "eu-west-1"},
		{name: "credentials file region overrides", creds: "[default]\nregion = ap-south-1\n", want: "ap-south-1"},
		{name: "config profile", profile: "p", want: "cn-north-1"},
		{name: "config profile replaces AWS_PROFILE", profile: "p", env: map[string]string{"AWS_PROFILE": "d", "AWS_DEFAULT_PROFILE": "d"}, want: "cn-north-1"},
		{name: "config profile default replaces AWS_PROFILE", profile: "default", env: map[string]string{"AWS_PROFILE": "p"}, want: "eu-west-1"},
		{name: "AWS_REGION wins over a config profile", profile: "p", env: map[string]string{"AWS_REGION": "us-east-1"}, want: "us-east-1"},
		{name: "AWS_DEFAULT_REGION wins over a config profile", profile: "p", env: map[string]string{"AWS_DEFAULT_REGION": "ap-south-1"}, want: "ap-south-1"},
		{name: "config profile from AWS_CONFIG_FILE", profile: "default", env: map[string]string{"AWS_CONFIG_FILE": "OTHER"}, want: "sa-east-1"},
		{name: "config profile missing fails", profile: "missing", env: map[string]string{"AWS_PROFILE": "p"}, want: "ERROR"},
		{name: "credentials file region overrides a config profile", profile: "p", creds: "[p]\nregion = ap-south-1\n", want: "ap-south-1"},
	} {
		t.Run(c.name, func(t *testing.T) {
			home := t.TempDir()
			write := func(p, s string) {
				if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			write(filepath.Join(home, ".aws", "config"), ini)
			if c.creds != "" {
				write(filepath.Join(home, ".aws", "credentials"), c.creds)
			}
			other := filepath.Join(t.TempDir(), "other")
			write(other, "[default]\nregion = sa-east-1\n")
			env := []string{helperEnv + "=1", "HOME=" + home, "USERPROFILE=" + home, "AWS_EC2_METADATA_DISABLED=true"}
			if runtime.GOOS == "windows" {
				env = append(env, "SystemRoot="+os.Getenv("SystemRoot"))
			}
			if c.profile != "" {
				env = append(env, profileEnv+"="+c.profile)
			}
			for k, v := range c.env {
				if v == "OTHER" {
					v = other
				}
				env = append(env, k+"="+v)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestSDKRegionHelper$", "-test.count=1") //nolint:gosec // the test binary itself
			cmd.Env = env
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("child: %v\n%s", err, out)
			}
			got := ""
			for _, l := range strings.Split(string(out), "\n") {
				if r, ok := strings.CutPrefix(l, "REGION="); ok {
					got = r
				}
			}
			if got != c.want {
				t.Errorf("region %q, want %q", got, c.want)
			}
		})
	}
}

// TestSDKRegionHelper is the child process: it prints the region
// LoadDefaultConfig resolves from its env, or ERROR when it fails.
func TestSDKRegionHelper(t *testing.T) {
	if os.Getenv(helperEnv) == "" {
		t.Skip("run by TestLoadDefaultConfigRegion")
	}
	var opts []func(*config.LoadOptions) error
	if p := os.Getenv(profileEnv); p != "" {
		opts = append(opts, config.WithSharedConfigProfile(p))
	}
	cfg, err := config.LoadDefaultConfig(context.Background(), opts...)
	if err != nil {
		fmt.Println("REGION=ERROR")
		return
	}
	fmt.Printf("REGION=%s\n", cfg.Region)
}
