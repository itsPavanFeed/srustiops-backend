# Prerequisites for a SrustiOps tenant on EKS, all private: a KMS key, the
# state bucket, image repositories, a PostgreSQL database, the master key's
# secret, VPC endpoints for the AWS APIs, and IRSA roles for the tenant plane
# and its runners. No secret value is ever in this state: RDS manages its
# own password, and the master key is put into Secrets Manager by the operator.

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

locals {
  tags      = merge({ "managed-by" = "srustiops-landing", "srustiops-tenant" = var.name }, var.tags)
  sa_tenant = "system:serviceaccount:${var.namespace}:${var.release}-tenant"
  sa_runner = "system:serviceaccount:${var.namespace}:${var.release}-runner"
}

resource "aws_kms_key" "this" {
  description             = "${var.name}: state, bucket, database, images and secrets"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  tags                    = local.tags
}

resource "aws_kms_alias" "this" {
  name          = "alias/${var.name}"
  target_key_id = aws_kms_key.this.key_id
}

# ---- state and plans ----

resource "aws_s3_bucket" "state" {
  bucket_prefix = "${var.name}-"
  tags          = local.tags
}

resource "aws_s3_bucket_public_access_block" "state" {
  bucket                  = aws_s3_bucket.state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.this.arn
    }
    bucket_key_enabled = true
  }
}

# Only through the VPC endpoint, only over TLS.
resource "aws_s3_bucket_policy" "state" {
  bucket = aws_s3_bucket.state.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid      = "TLSOnly", Effect = "Deny", Principal = "*", Action = "s3:*",
        Resource = [aws_s3_bucket.state.arn, "${aws_s3_bucket.state.arn}/*"],
      Condition = { Bool = { "aws:SecureTransport" = "false" } } },
      { Sid      = "VPCEndpointOnly", Effect = "Deny", Principal = "*", Action = "s3:*",
        Resource = [aws_s3_bucket.state.arn, "${aws_s3_bucket.state.arn}/*"],
      Condition = { StringNotEquals = { "aws:SourceVpce" = aws_vpc_endpoint.s3.id } } },
    ]
  })
}

# ---- images (loaded by scripts/airgap-import.sh) ----

resource "aws_ecr_repository" "image" {
  for_each             = toset(["srustiops-server", "srustiops-runner"])
  name                 = "${var.name}/${each.key}"
  image_tag_mutability = "IMMUTABLE"
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.this.arn
  }
  image_scanning_configuration { scan_on_push = true }
  tags = local.tags
}

# ---- the master key: the operator puts the value (openssl rand -base64 32) ----

resource "aws_secretsmanager_secret" "master_key" {
  name_prefix = "${var.name}-master-key-"
  kms_key_id  = aws_kms_key.this.arn
  tags        = local.tags
}

# ---- PostgreSQL ----

resource "aws_security_group" "db" {
  name_prefix = "${var.name}-db-"
  vpc_id      = var.vpc_id
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }
  tags = local.tags
}

resource "aws_db_subnet_group" "db" {
  name_prefix = "${var.name}-"
  subnet_ids  = var.private_subnet_ids
  tags        = local.tags
}

resource "aws_db_instance" "db" {
  identifier_prefix                   = "${var.name}-"
  engine                              = "postgres"
  engine_version                      = "16"
  instance_class                      = var.db_instance_class
  allocated_storage                   = 50
  max_allocated_storage               = 500
  storage_encrypted                   = true
  kms_key_id                          = aws_kms_key.this.arn
  db_name                             = "srustiops"
  username                            = "srustiops"
  manage_master_user_password         = true # in Secrets Manager, never in this state
  master_user_secret_kms_key_id       = aws_kms_key.this.arn
  db_subnet_group_name                = aws_db_subnet_group.db.name
  vpc_security_group_ids              = [aws_security_group.db.id]
  publicly_accessible                 = false
  multi_az                            = true
  backup_retention_period             = 14
  deletion_protection                 = true
  copy_tags_to_snapshot               = true
  iam_database_authentication_enabled = true
  final_snapshot_identifier           = "${var.name}-final"
  tags                                = local.tags
}

# ---- private AWS APIs ----

resource "aws_security_group" "endpoints" {
  name_prefix = "${var.name}-endpoints-"
  vpc_id      = var.vpc_id
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }
  tags = local.tags
}

resource "aws_vpc_endpoint" "interface" {
  for_each            = toset(var.interface_endpoints)
  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${data.aws_region.current.region}.${each.key}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.private_subnet_ids
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true
  tags                = merge(local.tags, { Name = "${var.name}-${each.key}" })
}

data "aws_route_tables" "vpc" {
  vpc_id = var.vpc_id
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = var.vpc_id
  service_name      = "com.amazonaws.${data.aws_region.current.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = data.aws_route_tables.vpc.ids
  tags              = merge(local.tags, { Name = "${var.name}-s3" })
}

# ---- workload identity (IRSA) ----

data "aws_iam_policy_document" "trust" {
  for_each = { tenant = local.sa_tenant, runner = local.sa_runner }
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [var.eks_oidc_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${var.eks_oidc_issuer}:sub"
      values   = [each.value]
    }
    condition {
      test     = "StringEquals"
      variable = "${var.eks_oidc_issuer}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "this" {
  for_each           = data.aws_iam_policy_document.trust
  name_prefix        = "${var.name}-${each.key}-"
  assume_role_policy = each.value.json
  tags               = local.tags
}

data "aws_iam_policy_document" "tenant" {
  statement {
    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"]
    resources = [aws_s3_bucket.state.arn, "${aws_s3_bucket.state.arn}/*"]
  }
  statement {
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = [aws_kms_key.this.arn]
  }
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.master_key.arn]
  }
}

resource "aws_iam_role_policy" "tenant" {
  role   = aws_iam_role.this["tenant"].id
  policy = data.aws_iam_policy_document.tenant.json
}

# Runners only assume the connection roles of the accounts this tenant manages.
data "aws_iam_policy_document" "runner" {
  statement {
    actions   = ["sts:AssumeRole", "sts:TagSession"]
    resources = length(var.deploy_role_arns) > 0 ? var.deploy_role_arns : ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.name}-none"]
  }
}

resource "aws_iam_role_policy" "runner" {
  role   = aws_iam_role.this["runner"].id
  policy = data.aws_iam_policy_document.runner.json
}
