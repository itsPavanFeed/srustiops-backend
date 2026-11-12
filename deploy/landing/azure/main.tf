# Prerequisites for a SrustiOps tenant on AKS, all private: a Key Vault for
# the master key, Blob Storage for state, a Premium container registry,
# PostgreSQL flexible server in a delegated subnet, private endpoints with
# their DNS zones, and Entra Workload ID identities for the tenant plane and
# runners. No secret value is ever in this state.

data "azurerm_client_config" "current" {}

locals {
  tags = merge({ "managed-by" = "srustiops-landing", "srustiops-tenant" = var.name }, var.tags)
  zones = {
    vault = "privatelink.vaultcore.azure.net"
    blob  = "privatelink.blob.core.windows.net"
    acr   = "privatelink.azurecr.io"
    pg    = "privatelink.postgres.database.azure.com"
  }
}

resource "azurerm_private_dns_zone" "this" {
  for_each            = local.zones
  name                = each.value
  resource_group_name = var.resource_group_name
  tags                = local.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "this" {
  for_each              = azurerm_private_dns_zone.this
  name                  = "${var.name}-${each.key}"
  resource_group_name   = var.resource_group_name
  private_dns_zone_name = each.value.name
  virtual_network_id    = var.vnet_id
}

# ---- Key Vault: the master key (the operator adds the secret value) ----

resource "azurerm_key_vault" "this" {
  name                          = "${var.name}-kv"
  resource_group_name           = var.resource_group_name
  location                      = var.location
  tenant_id                     = data.azurerm_client_config.current.tenant_id
  sku_name                      = "premium"
  rbac_authorization_enabled    = true
  purge_protection_enabled      = true
  soft_delete_retention_days    = 90
  public_network_access_enabled = false
  network_acls {
    bypass         = "None"
    default_action = "Deny"
  }
  tags = local.tags
}

# ---- Blob Storage for state and plans ----

resource "azurerm_storage_account" "state" {
  name                              = "${var.name}state"
  resource_group_name               = var.resource_group_name
  location                          = var.location
  account_tier                      = "Standard"
  account_replication_type          = "ZRS"
  min_tls_version                   = "TLS1_2"
  public_network_access_enabled     = false
  allow_nested_items_to_be_public   = false
  shared_access_key_enabled         = false # Entra ID only
  infrastructure_encryption_enabled = true
  blob_properties {
    versioning_enabled = true
    delete_retention_policy { days = 30 }
  }
  tags = local.tags
}

resource "azurerm_storage_container" "state" {
  name                  = "srustiops"
  storage_account_id    = azurerm_storage_account.state.id
  container_access_type = "private"
}

# ---- images (loaded by scripts/airgap-import.sh) ----

resource "azurerm_container_registry" "this" {
  name                          = "${var.name}acr"
  resource_group_name           = var.resource_group_name
  location                      = var.location
  sku                           = "Premium"
  admin_enabled                 = false
  public_network_access_enabled = false
  data_endpoint_enabled         = true
  tags                          = local.tags
}

# ---- private endpoints ----

locals {
  endpoints = {
    vault = { id = azurerm_key_vault.this.id, sub = "vault" }
    blob  = { id = azurerm_storage_account.state.id, sub = "blob" }
    acr   = { id = azurerm_container_registry.this.id, sub = "registry" }
  }
}

resource "azurerm_private_endpoint" "this" {
  for_each            = local.endpoints
  name                = "${var.name}-${each.key}"
  resource_group_name = var.resource_group_name
  location            = var.location
  subnet_id           = var.endpoint_subnet_id
  private_service_connection {
    name                           = "${var.name}-${each.key}"
    private_connection_resource_id = each.value.id
    subresource_names              = [each.value.sub]
    is_manual_connection           = false
  }
  private_dns_zone_group {
    name                 = each.key
    private_dns_zone_ids = [azurerm_private_dns_zone.this[each.key].id]
  }
  tags = local.tags
}

# ---- PostgreSQL flexible server, private access, Entra authentication ----

resource "azurerm_postgresql_flexible_server" "db" {
  name                          = "${var.name}-pg"
  resource_group_name           = var.resource_group_name
  location                      = var.location
  version                       = "16"
  sku_name                      = "GP_Standard_D2ds_v5"
  storage_mb                    = 65536
  delegated_subnet_id           = var.postgres_subnet_id
  private_dns_zone_id           = azurerm_private_dns_zone.this["pg"].id
  public_network_access_enabled = false
  backup_retention_days         = 14
  zone                          = "1"
  authentication {
    active_directory_auth_enabled = true
    password_auth_enabled         = false
    tenant_id                     = data.azurerm_client_config.current.tenant_id
  }
  high_availability { mode = "ZoneRedundant" }
  tags       = local.tags
  depends_on = [azurerm_private_dns_zone_virtual_network_link.this]
}

resource "azurerm_postgresql_flexible_server_active_directory_administrator" "admins" {
  server_name         = azurerm_postgresql_flexible_server.db.name
  resource_group_name = var.resource_group_name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  object_id           = var.postgres_admin_group_object_id
  principal_name      = "${var.name}-pg-admins"
  principal_type      = "Group"
}

resource "azurerm_postgresql_flexible_server_database" "srustiops" {
  name      = "srustiops"
  server_id = azurerm_postgresql_flexible_server.db.id
}

# ---- Entra Workload ID ----

resource "azurerm_user_assigned_identity" "this" {
  for_each            = toset(["tenant", "runner"])
  name                = "${var.name}-${each.key}"
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = local.tags
}

resource "azurerm_federated_identity_credential" "this" {
  for_each  = azurerm_user_assigned_identity.this
  name      = "${var.name}-${each.key}"
  parent_id = each.value.id
  issuer    = var.aks_oidc_issuer_url
  subject   = "system:serviceaccount:${var.namespace}:${var.release}-${each.key}"
  audience  = ["api://AzureADTokenExchange"]
}

resource "azurerm_role_assignment" "tenant" {
  for_each = {
    blob  = { scope = azurerm_storage_account.state.id, role = "Storage Blob Data Contributor" }
    vault = { scope = azurerm_key_vault.this.id, role = "Key Vault Secrets User" }
  }
  scope                = each.value.scope
  role_definition_name = each.value.role
  principal_id         = azurerm_user_assigned_identity.this["tenant"].principal_id
}
