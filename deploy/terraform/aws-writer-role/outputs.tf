output "role_arn" {
  description = "ARN of the writer role."
  value       = aws_iam_role.writer.arn
}

output "oidc_provider_arn" {
  description = "The IAM OIDC provider the role trusts."
  value       = local.oidc_provider_arn
}
