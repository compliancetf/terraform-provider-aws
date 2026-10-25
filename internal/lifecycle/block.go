package lifecycle

import (
	"fmt"
	"os"

	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// blockAttrs are the compliance {} attributes of block v2, all optional
// strings. control_bundle_url and
// audit_log_path are removed. internal/proxy/schema.go advertises BlockType.
var blockAttrs = []string{
	"enforcement_mode", "org_id", "control_profile", "control_bundle_path", "profile_path",
	"exceptions_file", "exception_grants_dir", "environment", "evidence_dir", "data_sources", "baseline_file",
}

const defaultEvidenceDir = ".terraform/compliancetf/evidence"

// BlockType is the tftypes type of the v2 compliance block.
func BlockType() tftypes.Object {
	t := tftypes.Object{AttributeTypes: map[string]tftypes.Type{}}
	for _, a := range blockAttrs {
		t.AttributeTypes[a] = tftypes.String
	}
	return t
}

// Block is the compliance block merged with its env overrides. HCL and env
// modes and environments stay separate: only the mode table combines them.
type Block struct {
	HCLMode, EnvMode               string
	HCLOrg, EnvOrg                 string
	ControlProfile                 string
	BundlePath                     string // env wins
	HCLProfilePath, EnvProfilePath string // both are profile candidates
	ExceptionsFile                 string // env wins
	GrantsDir                      string // env wins
	BaselineFile                   string // signed baseline, env wins
	HCLEnvironment, EnvEnvironment string
	Workspace                      string // COMPLIANCETF_WORKSPACE, untrusted
	EvidenceDir                    string // env wins
	HCLDataSources, EnvDataSources string // data_sources, COMPLIANCETF_DATA_SOURCES: raise only
}

// parseBlock reads the stripped compliance object (null = no block) and the
// env overrides. An unknown attribute value fails closed.
func parseBlock(v tftypes.Value) (Block, error) {
	hcl := map[string]string{}
	if !v.IsNull() {
		var attrs map[string]tftypes.Value
		if err := v.As(&attrs); err != nil {
			return Block{}, fmt.Errorf("compliance block: %w", err)
		}
		for name, av := range attrs {
			if !av.IsKnown() {
				return Block{}, fmt.Errorf("compliance.%s is unknown at configure: use a value known before plan", name)
			}
			var s *string
			if err := av.As(&s); err != nil {
				return Block{}, fmt.Errorf("compliance.%s: %w", name, err)
			}
			if s != nil {
				hcl[name] = *s
			}
		}
	}
	envWins := func(attr, env string) string {
		if e := os.Getenv(env); e != "" {
			return e
		}
		return hcl[attr]
	}
	b := Block{
		HCLMode: hcl["enforcement_mode"], EnvMode: os.Getenv("COMPLIANCETF_ENFORCEMENT_MODE"),
		HCLOrg: hcl["org_id"], EnvOrg: os.Getenv("COMPLIANCETF_ORG_ID"),
		ControlProfile: hcl["control_profile"],
		BundlePath:     envWins("control_bundle_path", "COMPLIANCETF_BUNDLE_PATH"),
		HCLProfilePath: hcl["profile_path"], EnvProfilePath: os.Getenv("COMPLIANCETF_PROFILE_PATH"),
		ExceptionsFile: envWins("exceptions_file", "COMPLIANCETF_EXCEPTIONS_FILE"),
		GrantsDir:      envWins("exception_grants_dir", "COMPLIANCETF_EXCEPTION_GRANTS"),
		BaselineFile:   envWins("baseline_file", "COMPLIANCETF_BASELINE_FILE"),
		HCLEnvironment: hcl["environment"], EnvEnvironment: os.Getenv("COMPLIANCETF_ENVIRONMENT"),
		Workspace:      os.Getenv("COMPLIANCETF_WORKSPACE"),
		EvidenceDir:    envWins("evidence_dir", "COMPLIANCETF_EVIDENCE_DIR"),
		HCLDataSources: hcl["data_sources"], EnvDataSources: os.Getenv("COMPLIANCETF_DATA_SOURCES"),
	}
	if b.EvidenceDir == "" {
		b.EvidenceDir = defaultEvidenceDir
	}
	// One control profile ships, the embedded CIS bundle; org bundles
	// come only from the signed profile bundles list.
	switch b.ControlProfile {
	case "":
		b.ControlProfile = "cis"
	case "cis":
	default:
		return Block{}, fmt.Errorf("control_profile %q: only cis is available; org bundles come from the signed org profile", b.ControlProfile)
	}
	return b, nil
}
