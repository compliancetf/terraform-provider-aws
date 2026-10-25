package bundle_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/bundle"
	"github.com/compliancetf/terraform-provider-aws/internal/engine/celeng"
)

// TestPhase2KindRules: one case per kind-rule error text
// that a single controls.json can raise, through the provider load path
// (ParseControls, then celeng.Load). The cross-bundle text is
// TestControlSetDedupe. data_source and ephemeral controls with matching
// schemas load.
func TestPhase2KindRules(t *testing.T) {
	str := tftypes.String
	schema := &tfprotov5.GetProviderSchemaResponse{
		ResourceSchemas: map[string]*tfprotov5.Schema{"aws_db_instance": {Block: &tfprotov5.SchemaBlock{Attributes: []*tfprotov5.SchemaAttribute{
			{Name: "identifier", Type: str, Optional: true, Computed: true},
		}}}},
		DataSourceSchemas: map[string]*tfprotov5.Schema{"aws_s3_bucket": {Block: &tfprotov5.SchemaBlock{Attributes: []*tfprotov5.SchemaAttribute{
			{Name: "bucket", Type: str, Required: true},
			{Name: "arn", Type: str, Computed: true},
		}}}},
		EphemeralResourceSchemas: map[string]*tfprotov5.Schema{"aws_secretsmanager_secret_version": {Block: &tfprotov5.SchemaBlock{Attributes: []*tfprotov5.SchemaAttribute{
			{Name: "secret_id", Type: str, Required: true},
			{Name: "secret_string", Type: str, Computed: true, Sensitive: true},
		}}}},
	}
	const tail = `, "action": "deny", "severity": "high", "message": "m"}]`
	for _, tc := range []struct {
		name, controls, want string
	}{
		{"data source loads", `[{"id": "s3_bucket_arn_known", "version": "1.0.0", "kind": "data_source", "resource_type": "aws_s3_bucket",
			"reads": ["arn"], "presence_mode": "effective", "expr": "resource.arn != ''"` + tail, ""},
		{"ephemeral loads", `[{"id": "secret_id_set", "version": "1.0.0", "kind": "ephemeral", "resource_type": "aws_secretsmanager_secret_version",
			"reads": ["secret_id"], "expr": "config.secret_id != ''"` + tail, ""},
		{"unknown data source", `[{"id": "s3_bucket_arn_known", "version": "1.0.0", "kind": "data_source", "resource_type": "aws_db_instance",
			"reads": ["identifier"], "presence_mode": "configured", "expr": "config.identifier != ''"` + tail,
			"control s3_bucket_arn_known: control_data_source_unknown: targets unknown data source aws_db_instance"},
		{"ephemeral result", `[{"id": "secret_id_set", "version": "1.0.0", "kind": "ephemeral", "resource_type": "aws_secretsmanager_secret_version",
			"reads": ["secret_string"], "expr": "config.secret_string != ''", "action": "warn", "severity": "high", "message": "m"}]`,
			"control secret_id_set: control_ephemeral_result: ephemeral control reads result attribute config.secret_string"},
		{"deletion guard on", `[{"id": "rds_guard", "version": "1.0.0", "kind": "deletion_guard", "resource_type": "aws_db_instance",
			"reads": ["identifier"], "on": ["create", "delete"], "expr": "prior.identifier != ''"` + tail,
			`control rds_guard: deletion guard must set on = ["delete"] (control_on)`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cs, err := bundle.ParseControls([]byte(tc.controls))
			if err == nil {
				_, _, err = celeng.Load(cs, schema)
			}
			got := ""
			if err != nil {
				got = err.Error()
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			var d *celeng.LoadDiag
			var e *bundle.Error
			if err != nil && !errors.As(err, &d) && !errors.As(err, &e) {
				t.Fatalf("want a coded load error, got %T", err)
			}
			if strings.Contains(got, "needs provider >=") {
				t.Fatal("provider version gate on data_source or ephemeral still active")
			}
		})
	}
}
