variable "name" {
  description = "Prefix for every resource, e.g. srustiops-acme."
  type        = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,24}$", var.name))
    error_message = "name must be lowercase letters, digits and dashes (3-25)."
  }
}
variable "project" {
  type = string
}
variable "region" {
  type = string
}
variable "network" {
  description = "Self link of the GKE cluster's VPC network (Private Google Access on its subnets)."
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
variable "deploy_service_accounts" {
  description = "Service accounts in the projects this tenant manages that runners may impersonate."
  type        = list(string)
  default     = []
}
variable "db_tier" {
  type    = string
  default = "db-custom-2-7680"
}
variable "labels" {
  type    = map(string)
  default = {}
}
