output "alb_dns_name" {
  description = "Point the DNS record of public_url (CNAME/alias) here."
  value       = aws_lb.this.dns_name
}

output "database_endpoint" {
  value = aws_db_instance.this.address
}

output "database_master_secret_arn" {
  description = "RDS-managed master credentials (use them once to create the tessera_owner and tessera_app roles)."
  value       = aws_db_instance.this.master_user_secret[0].secret_arn
}

output "secret_arns" {
  description = "Fill these with `aws secretsmanager put-secret-value` (see README)."
  value       = { for k, s in aws_secretsmanager_secret.this : k => s.arn }
}

output "anchor_bucket" {
  value = aws_s3_bucket.anchors.bucket
}

output "ecs_cluster" {
  value = aws_ecs_cluster.this.name
}
