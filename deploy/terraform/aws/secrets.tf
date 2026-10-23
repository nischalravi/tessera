# Secret CONTAINERS only. Terraform never sees the values: put them with the AWS CLI (README), so nothing
# sensitive lands in state. The KEK seals every signing key and secret in the database: back it up offline.

locals {
  secret_names = {
    db_owner_dsn = "${var.name}/prod/db-owner-dsn"
    db_app_dsn   = "${var.name}/prod/db-app-dsn"
    kek          = "${var.name}/prod/kek"
  }
}

resource "aws_secretsmanager_secret" "this" {
  for_each                = local.secret_names
  name                    = each.value
  recovery_window_in_days = 30
  tags                    = local.tags
}

# Audit checkpoint anchors: S3 with Object Lock (Tessera writes COMPLIANCE retention of 7 years per object).
resource "aws_s3_bucket" "anchors" {
  bucket_prefix       = "${var.name}-anchors-"
  object_lock_enabled = true
  tags                = local.tags
}

resource "aws_s3_bucket_versioning" "anchors" {
  bucket = aws_s3_bucket.anchors.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_public_access_block" "anchors" {
  bucket                  = aws_s3_bucket.anchors.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "anchors" {
  bucket = aws_s3_bucket.anchors.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}
