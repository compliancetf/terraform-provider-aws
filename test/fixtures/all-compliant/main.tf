terraform {
  required_providers {
    aws = { source = "compliancetf/aws" }
  }
}

provider "aws" {
  region = "us-east-1"
  # Offline: dummy keys, no STS or IMDS calls.
  access_key                  = "dogfood"
  secret_key                  = "dogfood"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  compliance {
    enforcement_mode = "hard_fail"
  }
}

# ---------- RDS ----------
resource "aws_db_instance" "compliant" {
  engine                  = "postgres"
  instance_class          = "db.t3.micro"
  storage_encrypted       = true
  publicly_accessible     = false
  backup_retention_period = 14
  deletion_protection     = true
}

# ---------- EBS ----------
resource "aws_ebs_volume" "compliant" {
  availability_zone = "us-east-1a"
  size              = 20
  encrypted         = true
}

# ---------- EFS ----------
resource "aws_efs_file_system" "compliant" {
  encrypted = true
}

# ---------- S3 ----------
resource "aws_s3_bucket" "compliant" {
  bucket = "my-compliant-bucket"
}

# ---------- Redshift ----------
resource "aws_redshift_cluster" "compliant" {
  cluster_identifier = "compliant-cluster"
  database_name      = "mydb"
  master_username    = "admin"
  master_password    = "SuperSecret1!"
  node_type          = "dc2.large"
  cluster_type       = "single-node"
  encrypted          = true
  publicly_accessible = false
}

# ---------- ALB Listener ----------
resource "aws_lb_listener" "compliant" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/1234567890abcdef"
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = "arn:aws:acm:us-east-1:123456789012:certificate/abcdef12-3456-7890-abcd-ef1234567890"

  default_action {
    type             = "forward"
    target_group_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/my-tg/1234567890abcdef"
  }
}
