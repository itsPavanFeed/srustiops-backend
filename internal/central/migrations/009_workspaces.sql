-- When each person last opened each tenant, for the workspace switcher.
CREATE TABLE tenant_usage (
    user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id    uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    last_used_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, tenant_id)
);
