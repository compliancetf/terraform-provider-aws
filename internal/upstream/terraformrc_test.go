package upstream

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseCLIConfig_PluginCacheDir(t *testing.T) {
	hcl := `plugin_cache_dir = "/tmp/terraform-cache"`

	tmpFile := writeTempHCL(t, hcl)

	cfg, err := ParseCLIConfig(tmpFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.PluginCacheDir != "/tmp/terraform-cache" {
		t.Fatalf("expected plugin_cache_dir %q, got %q", "/tmp/terraform-cache", cfg.PluginCacheDir)
	}
}

func TestParseCLIConfig_DevOverrides(t *testing.T) {
	hcl := `
provider_installation {
  dev_overrides {
    "hashicorp/aws" = "/home/user/providers/aws"
    "compliancetf/aws" = "/opt/ctf/providers/aws"
  }
  direct {}
}
`
	tmpFile := writeTempHCL(t, hcl)

	cfg, err := ParseCLIConfig(tmpFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}

	if len(cfg.DevOverrides) != 2 {
		t.Fatalf("expected 2 dev_overrides entries, got %d", len(cfg.DevOverrides))
	}

	expected := map[string]string{
		"hashicorp/aws":    "/home/user/providers/aws",
		"compliancetf/aws": "/opt/ctf/providers/aws",
	}
	for k, v := range expected {
		got, ok := cfg.DevOverrides[k]
		if !ok {
			t.Fatalf("missing dev_overrides key %q", k)
		}
		if got != v {
			t.Fatalf("dev_overrides[%q]: expected %q, got %q", k, v, got)
		}
	}
}

func TestParseCLIConfig_FilesystemMirror(t *testing.T) {
	hcl := `
provider_installation {
  filesystem_mirror {
    path    = "/usr/share/terraform/providers"
    include = ["hashicorp/*"]
  }
  filesystem_mirror {
    path = "/opt/custom/providers"
  }
  direct {}
}
`
	tmpFile := writeTempHCL(t, hcl)

	cfg, err := ParseCLIConfig(tmpFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}

	if len(cfg.FilesystemMirrors) != 2 {
		t.Fatalf("expected 2 filesystem_mirror paths, got %d: %v", len(cfg.FilesystemMirrors), cfg.FilesystemMirrors)
	}

	expectedPaths := []string{"/usr/share/terraform/providers", "/opt/custom/providers"}
	for _, ep := range expectedPaths {
		found := false
		for _, got := range cfg.FilesystemMirrors {
			if got == ep {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected filesystem_mirror path %q not found in %v", ep, cfg.FilesystemMirrors)
		}
	}
}

func TestParseCLIConfig_FullConfig(t *testing.T) {
	hcl := `
plugin_cache_dir = "/tmp/terraform-cache"

provider_installation {
  dev_overrides {
    "compliancetf/aws" = "/Users/dev/ctf/terraform-provider-aws"
  }
  filesystem_mirror {
    path = "/usr/share/terraform/providers"
  }
  direct {}
}
`
	tmpFile := writeTempHCL(t, hcl)

	cfg, err := ParseCLIConfig(tmpFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}

	if cfg.PluginCacheDir != "/tmp/terraform-cache" {
		t.Fatalf("plugin_cache_dir: expected %q, got %q", "/tmp/terraform-cache", cfg.PluginCacheDir)
	}

	if got := cfg.DevOverrides["compliancetf/aws"]; got != "/Users/dev/ctf/terraform-provider-aws" {
		t.Fatalf("dev_overrides[compliancetf/aws]: expected %q, got %q",
			"/Users/dev/ctf/terraform-provider-aws", got)
	}

	if len(cfg.FilesystemMirrors) != 1 || cfg.FilesystemMirrors[0] != "/usr/share/terraform/providers" {
		t.Fatalf("filesystem_mirrors: expected [/usr/share/terraform/providers], got %v", cfg.FilesystemMirrors)
	}
}

func TestParseCLIConfig_NonexistentFile(t *testing.T) {
	cfg, err := ParseCLIConfig("/nonexistent/path/to/.terraformrc")
	if err != nil {
		t.Fatalf("expected no error for nonexistent file, got: %v", err)
	}
	if cfg != nil {
		t.Fatalf("expected nil config for nonexistent file, got: %+v", cfg)
	}
}

func TestParseCLIConfig_EmptyPath(t *testing.T) {
	cfg, err := ParseCLIConfig("")
	if err != nil {
		t.Fatalf("expected no error for empty path, got: %v", err)
	}
	if cfg != nil {
		t.Fatalf("expected nil config for empty path, got: %+v", cfg)
	}
}

func TestParseCLIConfig_InvalidHCL(t *testing.T) {
	tmpFile := writeTempHCL(t, "this is not { valid HCL }{{{")

	cfg, err := ParseCLIConfig(tmpFile)
	if err != nil {
		t.Fatalf("expected no error for invalid HCL (graceful degradation), got: %v", err)
	}
	if cfg != nil {
		t.Fatalf("expected nil config for invalid HCL, got: %+v", cfg)
	}
}

func TestParseCLIConfig_EmptyFile(t *testing.T) {
	tmpFile := writeTempHCL(t, "")

	cfg, err := ParseCLIConfig(tmpFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config for empty file")
	}
	// Empty file should produce a valid but empty config.
	if cfg.PluginCacheDir != "" {
		t.Fatalf("expected empty plugin_cache_dir, got %q", cfg.PluginCacheDir)
	}
	if len(cfg.DevOverrides) != 0 {
		t.Fatalf("expected empty dev_overrides, got %v", cfg.DevOverrides)
	}
	if len(cfg.FilesystemMirrors) != 0 {
		t.Fatalf("expected empty filesystem_mirrors, got %v", cfg.FilesystemMirrors)
	}
}

func TestFindCLIConfigPath_EnvOverride(t *testing.T) {
	customPath := "/custom/path/to/terraformrc"
	t.Setenv("TF_CLI_CONFIG_FILE", customPath)
	// Clear deprecated env to avoid interference.
	t.Setenv("TERRAFORM_CONFIG", "")

	got := FindCLIConfigPath()
	if got != customPath {
		t.Fatalf("expected %q, got %q", customPath, got)
	}
}

func TestFindCLIConfigPath_DeprecatedEnv(t *testing.T) {
	t.Setenv("TF_CLI_CONFIG_FILE", "")
	t.Setenv("TERRAFORM_CONFIG", "/deprecated/config/path")

	got := FindCLIConfigPath()
	if got != "/deprecated/config/path" {
		t.Fatalf("expected %q, got %q", "/deprecated/config/path", got)
	}
}

func TestFindCLIConfigPath_DefaultFallback(t *testing.T) {
	t.Setenv("TF_CLI_CONFIG_FILE", "")
	t.Setenv("TERRAFORM_CONFIG", "")

	got := FindCLIConfigPath()
	if got == "" {
		t.Fatal("expected a default path, got empty string")
	}

	// On non-Windows, should end with .terraformrc
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("cannot determine home directory: %v", err)
	}

	expected := filepath.Join(home, ".terraformrc")
	if got != expected {
		t.Fatalf("expected %q, got %q", expected, got)
	}
}

func TestFindCLIConfigPath_TFCLIConfigTakesPriority(t *testing.T) {
	t.Setenv("TF_CLI_CONFIG_FILE", "/primary/path")
	t.Setenv("TERRAFORM_CONFIG", "/deprecated/path")

	got := FindCLIConfigPath()
	if got != "/primary/path" {
		t.Fatalf("expected TF_CLI_CONFIG_FILE to take priority, got %q", got)
	}
}

// writeTempHCL writes HCL content to a temporary file and returns its path.
func writeTempHCL(t *testing.T, content string) string {
	t.Helper()

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, ".terraformrc")
	if err := os.WriteFile(tmpFile, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return tmpFile
}
