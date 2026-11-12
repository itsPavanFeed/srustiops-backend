output "tenant_client_id" {
  description = "values-aks.yaml: serviceAccountAnnotations azure.workload.identity/client-id"
  value       = azurerm_user_assigned_identity.this["tenant"].client_id
}
output "runner_client_id" {
  description = "values-aks.yaml: runner.serviceAccountAnnotations; grant it roles in the subscriptions this tenant manages"
  value       = azurerm_user_assigned_identity.this["runner"].client_id
}
output "key_vault_uri" {
  description = "Add the master key as a secret (openssl rand -base64 32); the CSI SecretProviderClass reads it"
  value       = azurerm_key_vault.this.vault_uri
}
output "storage_account" {
  value = azurerm_storage_account.state.name
}
output "registry" {
  value = azurerm_container_registry.this.login_server
}
output "database_fqdn" {
  value = azurerm_postgresql_flexible_server.db.fqdn
}
