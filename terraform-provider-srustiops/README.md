# terraform-provider-srustiops

An OpenTofu and Terraform provider that manages a SrustiOps tenant's configuration as code:

| Resource | What it manages | Delete |
| --- | --- | --- |
| `srustiops_entity` | An entity (company or product line) | Refused. Entities are kept for attribution; use `tofu state rm` |
| `srustiops_business_unit` | A business unit under an entity | Refused, as for entities |
| `srustiops_member` | A role grant: tenant-wide, entity-scoped (inherited by its BUs) or BU-scoped | Revokes the grant |
| `srustiops_cloud_connection` | A keyless AWS, GCP or Azure integration, scoped to entities | Only when no environment uses it |
| `srustiops_environment` | BU + connection + tier, runner pool and destroy limits | Only when it has no stacks |
| `srustiops_policy_set` | An OPA (Rego) policy set for the tenant, an entity or a BU | Deletes it |
| `srustiops_risk_policy` | Approval steps per risk level and cost thresholds (one per tenant) | Restores the defaults |

The data source `srustiops_catalog_module` looks up an approved module and its versions.

Stacks are deliberately not provider resources. Keep them in the tenant's contracts repository (Git) or create them in the console, so every infrastructure change still goes through plans, risk classification and approvals.

## Usage

```hcl
terraform {
  required_providers {
    srustiops = { source = "itspavanfeed/srustiops" }
  }
}

provider "srustiops" {
  endpoint = "https://srustiops.example.com" # or SRUSTIOPS_ENDPOINT
  tenant   = "acme"                        # or SRUSTIOPS_TENANT
  # token: SRUSTIOPS_TOKEN, a tenant admin's API token (My tokens in the console)
  # ca_file: SRUSTIOPS_CA_FILE, if central uses a private CA
}

resource "srustiops_entity" "retail" {
  slug = "retail"
  name = "Acme Retail"
}

resource "srustiops_business_unit" "payments" {
  slug   = "payments"
  name   = "Payments"
  entity = srustiops_entity.retail.slug
}

resource "srustiops_member" "payments_dev" {
  email = "dev@acme.example"
  role  = "developer"
  bu    = srustiops_business_unit.payments.slug
}

resource "srustiops_cloud_connection" "prod" {
  name     = "aws-prod"
  entities = [srustiops_entity.retail.slug]
  cloud = jsonencode({
    provider = "aws"
    auth     = "oidc"
    aws = {
      region        = "eu-west-1"
      role_arn      = "arn:aws:iam::111122223333:role/srustiops-apply"
      plan_role_arn = "arn:aws:iam::111122223333:role/srustiops-plan"
    }
  })
}

resource "srustiops_environment" "payments_prod" {
  name       = "payments-prod"
  bu         = srustiops_business_unit.payments.slug
  tier       = "prod"
  cloud_connection = srustiops_cloud_connection.prod.name
}

resource "srustiops_policy_set" "tags" {
  name   = "require-owner-tag"
  scope  = "entity:${srustiops_entity.retail.slug}"
  module = file("policies/require-owner-tag.rego")
}
```

A complete example, used by the end-to-end test, is in [`srustiops-test-resources/provider/main.tf`](../../srustiops-test-resources/provider/main.tf).

Notes:
- `cloud` and `settings` are JSON strings, compared semantically, so key order does not matter. Leave out empty fields: the platform does not store them, and they would show as a change.
- Every change goes through the same API as the console. RBAC, validation and the audit log apply as usual, and changes show up in the audit log under the token's owner.
- Import with `tofu import srustiops_environment.x <name or id>`. Entities and BUs import by slug, members by grant ID.

## Building and local use

```bash
go build -o ~/.local/share/srustiops-provider/terraform-provider-srustiops .
cat > ~/.tofurc <<'EOF'
provider_installation {
  dev_overrides { "registry.opentofu.org/itspavanfeed/srustiops" = "/home/me/.local/share/srustiops-provider" }
  direct {}
}
EOF
```

The provider is a separate Go module, so the backend's `go.mod` stays free of the plugin framework. To publish it to the OpenTofu or Terraform registry, move this directory to its own `terraform-provider-srustiops` repository and release signed builds with GoReleaser.
