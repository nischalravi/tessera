# RDS for PostgreSQL 16: encrypted, TLS required (rds.force_ssl), automated backups with point-in-time recovery.
# The master password is generated and held by RDS in Secrets Manager (manage_master_user_password), so no
# password is in Terraform state. The tessera_owner and tessera_app roles are created by you (README).

resource "aws_db_subnet_group" "this" {
  name       = var.name
  subnet_ids = aws_subnet.db[*].id
  tags       = local.tags
}

resource "aws_db_parameter_group" "this" {
  name_prefix = "${var.name}-pg16-"
  family      = "postgres16"
  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
  parameter {
    name  = "log_connections"
    value = "1"
  }
  tags = local.tags
  lifecycle { create_before_destroy = true }
}

resource "aws_db_instance" "this" {
  identifier     = var.name
  engine         = "postgres"
  engine_version = "16"
  instance_class = var.db_instance_class

  db_name                     = "tessera"
  username                    = "tessera_admin"
  manage_master_user_password = true

  allocated_storage     = var.db_allocated_storage
  max_allocated_storage = var.db_allocated_storage * 4
  storage_type          = "gp3"
  storage_encrypted     = true

  multi_az               = var.db_multi_az
  db_subnet_group_name   = aws_db_subnet_group.this.name
  vpc_security_group_ids = [aws_security_group.db.id]
  publicly_accessible    = false
  parameter_group_name   = aws_db_parameter_group.this.name

  backup_retention_period         = var.db_backup_retention_days
  copy_tags_to_snapshot           = true
  deletion_protection             = var.deletion_protection
  skip_final_snapshot             = !var.deletion_protection
  final_snapshot_identifier       = var.deletion_protection ? "${var.name}-final" : null
  auto_minor_version_upgrade      = true
  performance_insights_enabled    = true
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
  ca_cert_identifier              = "rds-ca-rsa2048-g1"
  tags                            = local.tags
}
