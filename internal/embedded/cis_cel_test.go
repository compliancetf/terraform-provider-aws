package embedded

import (
	"bytes"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/compliancetf/terraform-provider-aws/internal/engine"
	"github.com/compliancetf/terraform-provider-aws/internal/trust"
)

// TestEmbeddedNoPredicate: cis/ and the signed test archive carry
// only CEL expr controls; the v0.1 operator engine is gone.
// loadTest verifies the archive signature against the test bundle key.
func TestEmbeddedNoPredicate(t *testing.T) {
	src, err := os.ReadFile("cis/controls.json")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(src, []byte(`"predicate"`)) {
		t.Error("cis/controls.json still has a predicate control")
	}
	b, _ := loadTest(t, cisIssued, trust.NoRevocations())
	for _, c := range b.Controls {
		if c.Expr == nil {
			t.Errorf("%s (%s): not a CEL expr control", c.ID, c.ResourceType)
		}
	}
}

// TestEmbeddedVerdicts: each non-SG CIS control gives the verdict
// its v0.1 predicate gave (opv1: a null value fails a positive operator and
// passes a negated one, an unknown is unknown) on the same inputs, through
// the CEL engine with the captured hashicorp/aws schema. The SG family is
// TestEmbeddedSGRemoteAdmin and TestEmbeddedSGFamilyRemoteAdmin.
func TestEmbeddedVerdicts(t *testing.T) {
	b, _ := loadTest(t, cisIssued, trust.NoRevocations())
	progs := celPrograms(t, b)
	s := awsSchemas(t)
	const (
		P = engine.Pass
		F = engine.Fail
		U = engine.Unknown
	)
	type in struct {
		v    any // nil null, unk unknown
		want engine.State
	}
	boolTrue := []in{{true, P}, {false, F}, {nil, F}, {unk, U}}
	boolFalse := []in{{false, P}, {true, F}, {nil, F}, {unk, U}}
	retention := []in{{7, P}, {35, P}, {7.5, P}, {6, F}, {6.5, F}, {0, F}, {nil, F}, {unk, U}}
	rows := []struct {
		typ, id, attr string
		cases         []in
	}{
		{"aws_db_instance", "rds_db_instance_encryption_at_rest_enabled", "storage_encrypted", boolTrue},
		{"aws_db_instance", "rds_db_instance_prohibit_public_access", "publicly_accessible", boolFalse},
		{"aws_db_instance", "rds_db_instance_backup_retention_period_less_than_7", "backup_retention_period", retention},
		{"aws_db_instance", "rds_db_instance_deletion_protection_enabled", "deletion_protection", boolTrue},
		{"aws_rds_cluster", "rds_db_cluster_encryption_at_rest_enabled", "storage_encrypted", boolTrue},
		{"aws_rds_cluster", "rds_db_cluster_deletion_protection_enabled", "deletion_protection", boolTrue},
		{"aws_rds_cluster", "rds_db_instance_backup_retention_period_less_than_7", "backup_retention_period", retention},
		{"aws_ebs_volume", "ebs_attached_volume_encryption_enabled", "encrypted", boolTrue},
		{"aws_efs_file_system", "efs_file_system_encrypt_data_at_rest", "encrypted", boolTrue},
		{"aws_efs_file_system", "efs_file_system_encrypted_with_cmk", "kms_key_id",
			[]in{{"arn:aws:kms:us-east-1:111111111111:key/bobthecorp", P}, {"", P}, {nil, F}, {unk, U}}},
		{"aws_elasticache_replication_group", "elasticache_replication_group_encryption_at_rest_enabled", "at_rest_encryption_enabled",
			[]in{{"true", P}, {"false", F}, {"", F}, {nil, F}, {unk, U}}},
		{"aws_elasticache_replication_group", "elasticache_replication_group_encryption_in_transit_enabled", "transit_encryption_enabled", boolTrue},
		{"aws_redshift_cluster", "redshift_cluster_kms_enabled", "encrypted", []in{{"true", P}, {"false", F}, {nil, F}, {unk, U}}},
		{"aws_redshift_cluster", "redshift_cluster_prohibit_public_access", "publicly_accessible", boolFalse},
		{"aws_lb_listener", "elb_application_network_listener_uses_secure_protocol", "protocol",
			[]in{{"HTTPS", P}, {"TLS", P}, {"HTTP", F}, {"TCP", F}, {"https", F}, {nil, F}, {unk, U}}},
		{"aws_s3_bucket", "s3_bucket_restrict_public_read_access", "acl",
			[]in{{"private", P}, {"public-read-write", P}, {"public-read", F}, {nil, P}, {unk, U}}},
		{"aws_s3_bucket", "s3_bucket_restrict_public_write_access", "acl",
			[]in{{"private", P}, {"public-read", P}, {"public-read-write", F}, {nil, P}, {unk, U}}},
	}
	seen := map[string]bool{}
	for _, r := range rows {
		key := r.typ + " " + r.id
		seen[key] = true
		p := progs[key]
		if p == nil {
			t.Errorf("no control %s", key)
			continue
		}
		sc, _ := s.Resource(r.typ)
		typ := sc.ValueType().(tftypes.Object)
		for _, c := range r.cases {
			got := evalBoth(p, tv(typ, obj{r.attr: c.v}))
			if got.State != c.want || got.Err != engine.ErrNone {
				t.Errorf("%s %s=%v: got %v/%q, want %v", key, r.attr, c.v, got.State, got.Err, c.want)
			}
		}
	}
	for key := range progs {
		if !seen[key] && !bytes.Contains([]byte(key), []byte("security_group")) {
			t.Errorf("control %s has no verdict row", key)
		}
	}
}
