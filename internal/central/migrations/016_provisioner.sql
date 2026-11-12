-- The provisioner builds a workspace's infrastructure in the client's cloud
-- account as stacks in the platform's own tenant, then installs the tenant
-- plane there with a fresh install token. One provisioning per workspace.
CREATE TABLE provisionings (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    blueprint      text NOT NULL,
    cloud          text NOT NULL,
    mode           text NOT NULL CHECK (mode IN ('existing_cluster', 'account_only')),
    target         text NOT NULL CHECK (target IN ('kubernetes', 'vm')),
    size           text NOT NULL,
    region         text NOT NULL,
    account        text NOT NULL,          -- AWS account ID, GCP project, Azure subscription
    inputs         jsonb NOT NULL DEFAULT '{}',
    budget_usd     numeric NOT NULL,        -- monthly cap the budget guard holds plans to
    -- awaiting_trust → planning → awaiting_approval → applying → installing →
    -- active → handed_over; failed; decommissioning → decommissioned
    status         text NOT NULL DEFAULT 'awaiting_trust',
    detail         text NOT NULL DEFAULT '',
    stacks         jsonb NOT NULL DEFAULT '[]',
    approved_by    text NOT NULL DEFAULT '',
    approved_at    timestamptz,
    decommissioned_by text NOT NULL DEFAULT '',
    handed_over_at timestamptz,
    created_by     text NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX provisionings_one_per_tenant ON provisionings (tenant_id) WHERE status NOT IN ('failed', 'decommissioned');
