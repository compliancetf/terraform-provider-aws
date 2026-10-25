package upstream

// terraformrc.go provides a focused HCL parser for the Terraform CLI
// configuration file (.terraformrc / terraform.rc). It extracts only the
// fields needed for upstream provider discovery: plugin_cache_dir,
// dev_overrides, and filesystem_mirror paths.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// TerraformCLIConfig holds the subset of Terraform CLI configuration
// relevant to provider discovery.
type TerraformCLIConfig struct {
	PluginCacheDir    string            // plugin_cache_dir — global cache directory
	DevOverrides      map[string]string // provider source → directory path
	FilesystemMirrors []string          // filesystem_mirror path values
}

// FindCLIConfigPath resolves the Terraform CLI configuration file path.
//
// Search order:
//  1. TF_CLI_CONFIG_FILE environment variable (explicit path)
//  2. TERRAFORM_CONFIG environment variable (deprecated)
//  3. ~/.terraformrc (macOS/Linux) or %APPDATA%\terraform.rc (Windows)
func FindCLIConfigPath() string {
	// 1. TF_CLI_CONFIG_FILE takes highest priority.
	if p := os.Getenv("TF_CLI_CONFIG_FILE"); p != "" {
		return p
	}

	// 2. TERRAFORM_CONFIG (deprecated, but still honored by Terraform).
	if p := os.Getenv("TERRAFORM_CONFIG"); p != "" {
		return p
	}

	// 3. Platform-specific default.
	if runtime.GOOS == "windows" {
		if appdata := os.Getenv("APPDATA"); appdata != "" {
			return filepath.Join(appdata, "terraform.rc")
		}
		return ""
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".terraformrc")
}

// ParseCLIConfig reads and parses a Terraform CLI configuration file,
// extracting only the fields needed for provider discovery.
//
// Graceful degradation: returns (nil, nil) if the path is empty, the file
// does not exist, or the HCL content cannot be parsed. This ensures provider
// discovery never fails due to an unreadable CLI config.
func ParseCLIConfig(path string) (*TerraformCLIConfig, error) {
	if path == "" {
		return nil, nil
	}

	src, err := os.ReadFile(path) //nolint:gosec // user config file path is intentional
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, nil // graceful degradation on any read error
	}

	// Pre-process: HCL2 native syntax does not support quoted attribute
	// names, but Terraform's .terraformrc uses them for dev_overrides
	// entries (e.g. "hashicorp/aws" = "/path"). We replace quoted keys
	// with placeholder identifiers before parsing, then restore them.
	processed, keyMap := unquoteHCLAttrNames(src)

	// Parse the HCL native syntax. The .terraformrc file uses HCL native
	// syntax regardless of its file extension.
	file, diags := hclsyntax.ParseConfig(processed, path, hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return nil, nil // graceful degradation on parse error
	}

	return extractCLIConfig(file.Body, keyMap)
}

// quotedAttrNameRe matches HCL lines where the attribute name is a quoted
// string (e.g. `  "hashicorp/aws" = "/path"`). It captures the leading
// whitespace and the quoted key.
var quotedAttrNameRe = regexp.MustCompile(`(?m)^(\s*)"([^"]+)"\s*=`)

// validIdentRe matches strings that are already valid HCL identifiers.
var validIdentRe = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// unquoteHCLAttrNames rewrites quoted attribute names into placeholder
// identifiers so that HCL2 native syntax can parse them. Returns the
// rewritten source and a mapping from placeholder to original key.
//
// Example:
//
//	"hashicorp/aws" = "/path"  →  _qk_0 = "/path"
//	keyMap: {"_qk_0": "hashicorp/aws"}
func unquoteHCLAttrNames(src []byte) ([]byte, map[string]string) {
	keyMap := make(map[string]string)
	counter := 0

	result := quotedAttrNameRe.ReplaceAllFunc(src, func(match []byte) []byte {
		submatches := quotedAttrNameRe.FindSubmatch(match)
		if len(submatches) < 3 {
			return match
		}

		// If the key is already a valid identifier, leave it alone.
		if validIdentRe.Match(submatches[2]) {
			return match
		}

		indent := string(submatches[1])
		originalKey := string(submatches[2])

		placeholder := fmt.Sprintf("_qk_%d", counter)
		counter++
		keyMap[placeholder] = originalKey

		return []byte(fmt.Sprintf("%s%s =", indent, placeholder))
	})

	return result, keyMap
}

// extractCLIConfig walks the parsed HCL body and extracts the fields we need.
// We use low-level HCL body content APIs rather than gohcl struct decoding
// because the dev_overrides block uses a map-like pattern that doesn't map
// cleanly to Go struct tags.
func extractCLIConfig(body hcl.Body, keyMap map[string]string) (*TerraformCLIConfig, error) {
	cfg := &TerraformCLIConfig{
		DevOverrides: make(map[string]string),
	}

	// Define the schema we want to extract. Everything else is ignored
	// via the PartialContent call.
	schema := &hcl.BodySchema{
		Attributes: []hcl.AttributeSchema{
			{Name: "plugin_cache_dir"},
		},
		Blocks: []hcl.BlockHeaderSchema{
			{Type: "provider_installation"},
		},
	}

	content, _, diags := body.PartialContent(schema)
	if diags.HasErrors() {
		return nil, nil // graceful degradation
	}

	// Extract plugin_cache_dir attribute.
	if attr, ok := content.Attributes["plugin_cache_dir"]; ok {
		val, valDiags := attr.Expr.Value(nil)
		if !valDiags.HasErrors() && val.Type() == cty.String {
			cfg.PluginCacheDir = val.AsString()
		}
	}

	// Extract provider_installation blocks.
	for _, block := range content.Blocks {
		if block.Type != "provider_installation" {
			continue
		}
		parseProviderInstallation(block.Body, cfg, keyMap)
	}

	return cfg, nil
}

// parseProviderInstallation extracts dev_overrides and filesystem_mirror
// from a provider_installation block.
func parseProviderInstallation(body hcl.Body, cfg *TerraformCLIConfig, keyMap map[string]string) {
	schema := &hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{
			{Type: "dev_overrides"},
			{Type: "filesystem_mirror"},
		},
	}

	// Use PartialContent so unknown blocks (like "direct {}") are ignored.
	content, _, diags := body.PartialContent(schema)
	if diags.HasErrors() {
		return
	}

	for _, block := range content.Blocks {
		switch block.Type {
		case "dev_overrides":
			parseDevOverrides(block.Body, cfg, keyMap)
		case "filesystem_mirror":
			parseFilesystemMirror(block.Body, cfg)
		}
	}
}

// parseDevOverrides extracts the key-value pairs from a dev_overrides block.
// The block body contains attributes where each key is a provider source
// address and each value is a directory path string. Keys that were
// rewritten during pre-processing are restored via keyMap.
func parseDevOverrides(body hcl.Body, cfg *TerraformCLIConfig, keyMap map[string]string) {
	attrs, diags := body.JustAttributes()
	if diags.HasErrors() {
		return
	}

	for name, attr := range attrs {
		val, valDiags := attr.Expr.Value(nil)
		if valDiags.HasErrors() || val.Type() != cty.String {
			continue
		}

		// Restore the original key if it was replaced during pre-processing.
		key := name
		if original, ok := keyMap[name]; ok {
			key = original
		}
		cfg.DevOverrides[key] = val.AsString()
	}
}

// parseFilesystemMirror extracts the path attribute from a filesystem_mirror block.
func parseFilesystemMirror(body hcl.Body, cfg *TerraformCLIConfig) {
	schema := &hcl.BodySchema{
		Attributes: []hcl.AttributeSchema{
			{Name: "path"},
		},
	}

	content, _, diags := body.PartialContent(schema)
	if diags.HasErrors() {
		return
	}

	if attr, ok := content.Attributes["path"]; ok {
		val, valDiags := attr.Expr.Value(nil)
		if !valDiags.HasErrors() && val.Type() == cty.String {
			cfg.FilesystemMirrors = append(cfg.FilesystemMirrors, val.AsString())
		}
	}
}
