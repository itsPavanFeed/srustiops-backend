# Prerequisites for a SrustiOps tenant on GKE, all private: a Cloud KMS
# key, the state bucket, an image repository, Cloud SQL on a private IP, the
# master key's secret, private.googleapis.com DNS for Private Google Access,
# and Workload Identity service accounts for the tenant plane and runners.
# No secret value is ever in this state.

data "google_project" "this" {
  project_id = var.project
}

locals {
  labels = merge({ "managed-by" = "srustiops-landing", "srustiops-tenant" = var.name }, var.labels)
  pool   = "${var.project}.svc.id.goog"
}

resource "google_kms_key_ring" "this" {
  project  = var.project
  name     = var.name
  location = var.region
}

resource "google_kms_crypto_key" "this" {
  name            = "${var.name}-data"
  key_ring        = google_kms_key_ring.this.id
  rotation_period = "7776000s" # 90 days
  lifecycle { prevent_destroy = true }
}

# ---- state and plans (CMEK) ----

data "google_storage_project_service_account" "gcs" {
  project = var.project
}

resource "google_kms_crypto_key_iam_member" "gcs" {
  crypto_key_id = google_kms_crypto_key.this.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${data.google_storage_project_service_account.gcs.email_address}"
}

resource "google_storage_bucket" "state" {
  project                     = var.project
  name                        = "${var.name}-${data.google_project.this.number}"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  versioning { enabled = true }
  encryption { default_kms_key_name = google_kms_crypto_key.this.id }
  labels     = local.labels
  depends_on = [google_kms_crypto_key_iam_member.gcs]
}

# ---- images (loaded by scripts/airgap-import.sh) ----

resource "google_artifact_registry_repository" "images" {
  project       = var.project
  location      = var.region
  repository_id = var.name
  format        = "DOCKER"
  docker_config { immutable_tags = true }
  labels = local.labels
}

# ---- the master key: the operator adds the version (openssl rand -base64 32) ----

resource "google_secret_manager_secret" "master_key" {
  project   = var.project
  secret_id = "${var.name}-master-key"
  replication {
    user_managed {
      replicas { location = var.region }
    }
  }
  labels = local.labels
}

# ---- Cloud SQL on a private IP ----

resource "google_compute_global_address" "sql" {
  project       = var.project
  name          = "${var.name}-sql"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 20
  network       = var.network
}

resource "google_service_networking_connection" "sql" {
  network                 = var.network
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.sql.name]
}

resource "google_sql_database_instance" "db" {
  project             = var.project
  name                = var.name
  region              = var.region
  database_version    = "POSTGRES_16"
  deletion_protection = true
  settings {
    tier              = var.db_tier
    availability_type = "REGIONAL"
    ip_configuration {
      ipv4_enabled                                  = false
      private_network                               = var.network
      enable_private_path_for_google_cloud_services = true
      ssl_mode                                      = "ENCRYPTED_ONLY"
    }
    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
    }
    database_flags {
      name  = "cloudsql.iam_authentication"
      value = "on"
    }
    user_labels = local.labels
  }
  depends_on = [google_service_networking_connection.sql]
}

resource "google_sql_database" "srustiops" {
  project  = var.project
  instance = google_sql_database_instance.db.name
  name     = "srustiops"
}

# ---- Private Google Access: *.googleapis.com resolves to private.googleapis.com ----

resource "google_dns_managed_zone" "googleapis" {
  project    = var.project
  name       = "${var.name}-googleapis"
  dns_name   = "googleapis.com."
  visibility = "private"
  private_visibility_config {
    networks { network_url = var.network }
  }
  labels = local.labels
}

resource "google_dns_record_set" "private" {
  project      = var.project
  managed_zone = google_dns_managed_zone.googleapis.name
  name         = "private.googleapis.com."
  type         = "A"
  ttl          = 300
  rrdatas      = ["199.36.153.8", "199.36.153.9", "199.36.153.10", "199.36.153.11"]
}

resource "google_dns_record_set" "wildcard" {
  project      = var.project
  managed_zone = google_dns_managed_zone.googleapis.name
  name         = "*.googleapis.com."
  type         = "CNAME"
  ttl          = 300
  rrdatas      = ["private.googleapis.com."]
}

# ---- Workload Identity ----

resource "google_service_account" "this" {
  for_each     = toset(["tenant", "runner"])
  project      = var.project
  account_id   = "${var.name}-${each.key}"
  display_name = "SrustiOps ${each.key} (${var.name})"
}

resource "google_service_account_iam_member" "workload_identity" {
  for_each           = google_service_account.this
  service_account_id = each.value.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${local.pool}[${var.namespace}/${var.release}-${each.key}]"
}

resource "google_storage_bucket_iam_member" "tenant" {
  bucket = google_storage_bucket.state.name
  role   = "roles/storage.objectUser"
  member = google_service_account.this["tenant"].member
}

resource "google_kms_crypto_key_iam_member" "tenant" {
  crypto_key_id = google_kms_crypto_key.this.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = google_service_account.this["tenant"].member
}

resource "google_secret_manager_secret_iam_member" "tenant" {
  project   = var.project
  secret_id = google_secret_manager_secret.master_key.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = google_service_account.this["tenant"].member
}

resource "google_project_iam_member" "tenant_sql" {
  project = var.project
  role    = "roles/cloudsql.client"
  member  = google_service_account.this["tenant"].member
}

# Runners only impersonate the deployer service accounts of managed projects.
resource "google_service_account_iam_member" "runner_impersonates" {
  for_each           = toset(var.deploy_service_accounts)
  service_account_id = "projects/-/serviceAccounts/${each.key}"
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = google_service_account.this["runner"].member
}
