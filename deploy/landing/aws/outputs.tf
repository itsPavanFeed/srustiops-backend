output "tenant_role_arn" {
  description = "values-eks.yaml: serviceAccountAnnotations eks.amazonaws.com/role-arn"
  value       = aws_iam_role.this["tenant"].arn
}
output "runner_role_arn" {
  description = "values-eks.yaml: runner.serviceAccountAnnotations eks.amazonaws.com/role-arn"
  value       = aws_iam_role.this["runner"].arn
}
output "bucket" {
  value = aws_s3_bucket.state.id
}
output "kms_key_arn" {
  value = aws_kms_key.this.arn
}
output "image_repositories" {
  value = { for k, r in aws_ecr_repository.image : k => r.repository_url }
}
output "database_endpoint" {
  value = aws_db_instance.db.endpoint
}
output "database_password_secret_arn" {
  description = "RDS-managed password; build SRUSTIOPS_DATABASE_URL from it"
  value       = aws_db_instance.db.master_user_secret[0].secret_arn
}
output "master_key_secret_arn" {
  description = "Put the master key here (openssl rand -base64 32); the CSI SecretProviderClass reads it"
  value       = aws_secretsmanager_secret.master_key.arn
}
