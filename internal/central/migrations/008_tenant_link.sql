-- Tenant link: tenants that central cannot reach directly open an outbound
-- tunnel to the gateway instead. 'direct' keeps calling backend_url.
ALTER TABLE tenants ADD COLUMN connectivity text NOT NULL DEFAULT 'direct'
    CHECK (connectivity IN ('direct', 'tunnel'));

-- One-time enrolment tokens (SHA-256 hashes only), single use, short-lived.
CREATE TABLE link_enrollments (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    token_hash  bytea NOT NULL UNIQUE,
    created_by  text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz
);

-- Every link certificate issued, so one can be revoked by serial.
CREATE TABLE link_certs (
    serial      text PRIMARY KEY,
    tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    fingerprint text NOT NULL,
    issued_via  text NOT NULL CHECK (issued_via IN ('enroll', 'renew')),
    not_after   timestamptz NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    revoked_at  timestamptz,
    revoked_by  text
);
CREATE INDEX link_certs_tenant ON link_certs (tenant_id, created_at DESC);

-- Which gateway replica holds which tunnel; replicas forward to each other.
CREATE TABLE tenant_links (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    replica      text NOT NULL,
    replica_url  text NOT NULL,
    serial       text NOT NULL,
    remote       text NOT NULL DEFAULT '',
    connected_at timestamptz NOT NULL,
    last_seen    timestamptz NOT NULL
);
CREATE INDEX tenant_links_tenant ON tenant_links (tenant_id, last_seen DESC);

-- Webhooks for a tenant whose link is down, delivered when it returns.
CREATE TABLE link_webhook_queue (
    id         bigserial PRIMARY KEY,
    tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    path       text NOT NULL,
    headers    jsonb NOT NULL DEFAULT '{}',
    body       bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    attempts   int NOT NULL DEFAULT 0
);
CREATE INDEX link_webhook_queue_tenant ON link_webhook_queue (tenant_id, id);
