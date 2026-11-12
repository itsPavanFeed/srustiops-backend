variable "name" {
  description = "Prefix for every resource, e.g. srustiopsacme (letters and digits: Key Vault, Storage and ACR names)."
  type        = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9]{2,15}$", var.name))
    error_message = "name must be 3-16 lowercase letters and digits."
  }
}
variable "resource_group_name" {
  type = string
}
variable "location" {
  type = string
}
variable "vnet_id" {
  description = "VNet of the AKS cluster: the private DNS zones are linked to it."
  type        = string
}
variable "endpoint_subnet_id" {
  description = "Subnet for the private endpoints (Key Vault, Storage, ACR)."
  type        = string
}
variable "postgres_subnet_id" {
  description = "Subnet delegated to Microsoft.DBforPostgreSQL/flexibleServers."
  type        = string
}
variable "aks_oidc_issuer_url" {
  description = "The AKS cluster's OIDC issuer URL (workload identity)."
  type        = string
}
variable "namespace" {
  type    = string
  default = "srustiops"
}
variable "release" {
  description = "Helm release name of the tenant chart."
  type        = string
  default     = "srustiops"
}
variable "postgres_admin_group_object_id" {
  description = "Entra ID group administering the database (Entra authentication; no password in this state)."
  type        = string
}
variable "tags" {
  type    = map(string)
  default = {}
}
