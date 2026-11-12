output "tenant_service_account" {
  description = "values-gke.yaml: serviceAccountAnnotations iam.gke.io/gcp-service-account"
  value       = google_service_account.this["tenant"].email
}
output "runner_service_account" {
  description = "values-gke.yaml: runner.serviceAccountAnnotations iam.gke.io/gcp-service-account"
  value       = google_service_account.this["runner"].email
}
output "bucket" {
  value = google_storage_bucket.state.name
}
output "kms_key" {
  value = google_kms_crypto_key.this.id
}
output "image_repository" {
  value = "${var.region}-docker.pkg.dev/${var.project}/${google_artifact_registry_repository.images.repository_id}"
}
output "database_private_ip" {
  value = google_sql_database_instance.db.private_ip_address
}
output "master_key_secret" {
  description = "Add the master key as a version (openssl rand -base64 32); the CSI SecretProviderClass reads it"
  value       = google_secret_manager_secret.master_key.id
}
