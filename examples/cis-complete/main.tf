# compliance.tf provider for AWS - cis-complete example
#
# Every resource type the embedded CIS bundle checks, configured to pass
# every control. Each checked setting carries the control id it satisfies.
# See README.md for how to run it and what to expect.

terraform {
  required_providers {
    aws = {
      source = "registry.compliance.tf/compliancetf/aws"
    }
  }
}

provider "aws" {
  region = "us-east-1"

  compliance {
    enforcement_mode = "hard_fail" # any violation would fail the plan
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}
data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  name = "bobthecorp-cis"
  azs  = slice(data.aws_availability_zones.available.names, 0, 2)

  # Controls read these values at plan, so they are literals: a value that
  # is known only after apply (for example aws_vpc.this.cidr_block) makes
  # the control "pending" at plan and re-checks it before apply.
  admin_cidr_ipv4 = "10.0.0.0/16"
  admin_cidr_ipv6 = "2001:db8:1234::/48"
}

################################################################################
# Network
################################################################################

resource "aws_vpc" "this" {
  cidr_block                       = local.admin_cidr_ipv4
  assign_generated_ipv6_cidr_block = true

  tags = { Name = local.name }
}

resource "aws_subnet" "private" {
  count = 2

  vpc_id            = aws_vpc.this.id
  availability_zone = local.azs[count.index]
  cidr_block        = cidrsubnet(local.admin_cidr_ipv4, 8, count.index)

  tags = { Name = "${local.name}-private-${count.index}" }
}

# Inline rules. SSH and RDP are open only to private ranges; HTTPS may be
# open to the internet, because the controls cover remote administration
# ports (22, 3389) and all-protocol rules only.
resource "aws_security_group" "app" {
  name        = "${local.name}-app"
  description = "Application tier"
  vpc_id      = aws_vpc.this.id

  ingress {
    description = "HTTPS from anywhere"
    protocol    = "tcp"
    from_port   = 443
    to_port     = 443
    cidr_blocks = ["0.0.0.0/0"] # allowed: port 443 is not an admin port
  }

  ingress {
    description      = "SSH from the private network"
    protocol         = "tcp"
    from_port        = 22
    to_port          = 22
    cidr_blocks      = [local.admin_cidr_ipv4] # vpc_security_group_remote_administration_ipv4: not 0.0.0.0/0
    ipv6_cidr_blocks = [local.admin_cidr_ipv6] # vpc_security_group_remote_administration_ipv6: not ::/0
  }

  egress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"] # egress is not checked
  }
}

# Standalone rules, the other two resource types the same controls check.
resource "aws_security_group" "admin" {
  name        = "${local.name}-admin"
  description = "Bastion access"
  vpc_id      = aws_vpc.this.id
}

resource "aws_security_group_rule" "rdp" {
  security_group_id = aws_security_group.admin.id
  type              = "ingress"
  protocol          = "tcp"
  from_port         = 3389
  to_port           = 3389
  cidr_blocks       = [local.admin_cidr_ipv4] # vpc_security_group_remote_administration_ipv4: not 0.0.0.0/0
  ipv6_cidr_blocks  = [local.admin_cidr_ipv6] # vpc_security_group_remote_administration_ipv6: not ::/0
}

resource "aws_vpc_security_group_ingress_rule" "ssh_ipv4" {
  security_group_id = aws_security_group.admin.id
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
  cidr_ipv4         = local.admin_cidr_ipv4 # vpc_security_group_remote_administration_ipv4: not a /0
}

resource "aws_vpc_security_group_ingress_rule" "ssh_ipv6" {
  security_group_id = aws_security_group.admin.id
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
  cidr_ipv6         = local.admin_cidr_ipv6 # vpc_security_group_remote_administration_ipv6: not a /0
}

################################################################################
# Databases
################################################################################

resource "aws_db_subnet_group" "this" {
  name       = local.name
  subnet_ids = aws_subnet.private[*].id
}

resource "aws_db_instance" "postgres" {
  identifier                  = "${local.name}-postgres"
  engine                      = "postgres"
  instance_class              = "db.t4g.micro"
  allocated_storage           = 20
  username                    = "app_admin"
  manage_master_user_password = true # password kept in Secrets Manager, not in state
  db_subnet_group_name        = aws_db_subnet_group.this.name
  skip_final_snapshot         = true # example only

  storage_encrypted       = true  # rds_db_instance_encryption_at_rest_enabled (CIS AWS 2.3.1)
  publicly_accessible     = false # rds_db_instance_prohibit_public_access (CIS AWS 2.3.2)
  backup_retention_period = 14    # rds_db_instance_backup_retention_period_less_than_7 (CIS AWS 2.3.3): 7 or more
  deletion_protection     = true  # rds_db_instance_deletion_protection_enabled (CIS AWS 2.3.4)
}

resource "aws_rds_cluster" "aurora" {
  cluster_identifier          = "${local.name}-aurora"
  engine                      = "aurora-postgresql"
  master_username             = "app_admin"
  manage_master_user_password = true
  db_subnet_group_name        = aws_db_subnet_group.this.name
  skip_final_snapshot         = true # example only

  storage_encrypted       = true # rds_db_cluster_encryption_at_rest_enabled (CIS AWS 2.3.1)
  backup_retention_period = 14   # rds_db_instance_backup_retention_period_less_than_7 (CIS AWS 2.3.3): 7 or more
  deletion_protection     = true # rds_db_cluster_deletion_protection_enabled (CIS AWS 2.3.4)
}

resource "aws_redshift_subnet_group" "this" {
  name       = local.name
  subnet_ids = aws_subnet.private[*].id
}

resource "aws_redshift_cluster" "warehouse" {
  cluster_identifier        = "${local.name}-warehouse"
  node_type                 = "ra3.large"
  cluster_type              = "single-node"
  master_username           = "warehouse_admin"
  manage_master_password    = true
  cluster_subnet_group_name = aws_redshift_subnet_group.this.name
  skip_final_snapshot       = true # example only

  encrypted           = "true" # redshift_cluster_kms_enabled (CIS AWS 2.5.1); a string in hashicorp/aws 6.x
  publicly_accessible = false  # redshift_cluster_prohibit_public_access (CIS AWS 2.5.2)
}

resource "aws_elasticache_subnet_group" "this" {
  name       = local.name
  subnet_ids = aws_subnet.private[*].id
}

resource "aws_elasticache_replication_group" "cache" {
  replication_group_id = "${local.name}-cache"
  description          = "Session cache"
  engine               = "valkey"
  node_type            = "cache.t4g.micro"
  num_cache_clusters   = 2
  subnet_group_name    = aws_elasticache_subnet_group.this.name

  at_rest_encryption_enabled = "true" # elasticache_replication_group_encryption_at_rest_enabled (CIS AWS 3.1.1); a string in hashicorp/aws 6.x
  transit_encryption_enabled = true   # elasticache_replication_group_encryption_in_transit_enabled (CIS AWS 3.1.2)
}

################################################################################
# Storage
################################################################################

resource "aws_ebs_volume" "data" {
  availability_zone = local.azs[0]
  size              = 20
  type              = "gp3"

  encrypted = true # ebs_volume_encryption_at_rest_enabled (CIS AWS 2.2.1)

  tags = { Name = "${local.name}-data" }
}

resource "aws_kms_key" "efs" {
  description         = "${local.name} EFS"
  enable_key_rotation = true
}

resource "aws_kms_alias" "efs" {
  name          = "alias/${local.name}-efs"
  target_key_id = aws_kms_key.efs.key_id
}

resource "aws_efs_file_system" "shared" {
  creation_token = "${local.name}-shared"

  encrypted = true # efs_file_system_encrypt_data_at_rest (CIS AWS 2.4.1)
  # efs_file_system_encrypted_with_cmk (CIS AWS 2.4.2): a customer-managed key.
  # The alias ARN is known at plan; aws_kms_key.efs.arn would be known only
  # after apply and leave the control pending at plan.
  kms_key_id = "arn:${data.aws_partition.current.partition}:kms:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:${aws_kms_alias.efs.name}"
}

resource "aws_s3_bucket" "logs" {
  bucket = "${local.name}-logs-${data.aws_caller_identity.current.account_id}"

  # s3_bucket_restrict_public_read_access (CIS AWS 2.1.1) and
  # s3_bucket_restrict_public_write_access (CIS AWS 2.1.2): no acl argument,
  # so the bucket is private. "public-read" or "public-read-write" fails.
}

################################################################################
# Load balancing
################################################################################

resource "aws_acm_certificate" "app" {
  domain_name       = "app.bobthecorp.example"
  validation_method = "DNS"
}

resource "aws_lb" "app" {
  name               = local.name
  load_balancer_type = "application"
  internal           = true
  subnets            = aws_subnet.private[*].id
  security_groups    = [aws_security_group.app.id]
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.app.arn
  port              = 443
  certificate_arn   = aws_acm_certificate.app.arn
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"

  protocol = "HTTPS" # elb_application_network_listener_uses_secure_protocol (CIS AWS 4.1.1): HTTPS or TLS

  default_action {
    type = "fixed-response"

    fixed_response {
      content_type = "text/plain"
      message_body = "ok"
      status_code  = "200"
    }
  }
}
