package lifecycle

import (
	"strings"
	"testing"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/profile"
)

func TestParseFields(t *testing.T) {
	all := presets["full"]
	for _, tc := range []struct {
		in   string
		want Field
		warn string // substring; "" = no warning
	}{
		{"", presets["default"], ""},
		{"  ", presets["default"], ""},
		{"default", presets["default"], ""},
		{"MINIMAL", FieldFix, ""},
		{" full ", all, ""},
		{"fix", FieldFix, ""},
		{"frameworks, fix", FieldFix | FieldFrameworks, ""},
		{"fix,,docs,fix", FieldFix | FieldDocs, ""},
		{"fix,color", FieldFix, "ignored color;"},
		{"full,severity", FieldSeverity, "ignored full;"},
		{"bogus", presets["default"], "ignored bogus;"},
		{"nope,also", presets["default"], "ignored nope, also;"},
	} {
		got, warn := parseFields(tc.in)
		if got != tc.want {
			t.Errorf("parseFields(%q) = %07b, want %07b", tc.in, got, tc.want)
		}
		if (tc.warn == "") != (warn == "") || !strings.Contains(warn, tc.warn) {
			t.Errorf("parseFields(%q) warning %q, want %q", tc.in, warn, tc.warn)
		}
	}
}

func TestDetailLines(t *testing.T) {
	ctl := &bundle.Control{ID: "rds_db_instance_encryption_at_rest_enabled", Severity: "critical", ResourceType: "aws_db_instance",
		Fix: "Set storage_encrypted = true.", FrameworkRefs: []string{"cis_aws:2.3.1", "cis_v600:3"}}
	const (
		fix   = "Fix: Set storage_encrypted = true."
		docs  = "Docs: https://compliance.tf/docs/controls/aws/rds_db_instance_encryption_at_rest_enabled/"
		waive = "To waive: add an exception for rds_db_instance_encryption_at_rest_enabled in exceptions.hcl"
	)
	for name, tc := range map[string]struct {
		show shown
		want []string
	}{
		"zero_is_default":   {shown{}, []string{fix, docs}},
		"default_waivable":  {shown{presets["default"], "exceptions.hcl"}, []string{fix, docs, waive}},
		"minimal":           {shown{FieldFix, "exceptions.hcl"}, []string{fix}},
		"waive_not_offered": {shown{FieldWaive, ""}, nil},
		"full": {shown{presets["full"], "exceptions.hcl"}, []string{fix, docs, waive, "Severity: critical", "Mode: hard_fail",
			"Stage: plan", "Frameworks: cis_aws:2.3.1, cis_v600:3"}},
		"list_prints_in_field_order": {shown{FieldFrameworks | FieldFix, ""}, []string{fix, "Frameworks: cis_aws:2.3.1, cis_v600:3"}},
	} {
		got := detailLines(ctl, profile.HardFail, StagePlan, tc.show)
		if strings.Join(got, "\n") != strings.Join(tc.want, "\n") {
			t.Errorf("%s:\n got %q\nwant %q", name, got, tc.want)
		}
	}
}
