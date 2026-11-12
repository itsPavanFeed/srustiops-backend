-- Connection-first onboarding. A workspace is "pending" until its cluster is
-- connected and its tenant plane answers; only then do onboarding and
-- integrations open up. Existing tenants are already connected.
ALTER TABLE tenants ADD COLUMN status text NOT NULL DEFAULT 'active' CHECK (status IN ('pending', 'active'));
ALTER TABLE tenants ADD COLUMN target text NOT NULL DEFAULT '';

-- One-time install tokens: redeemed by the bootstrap step in the customer's
-- cluster for its certificates and the link enrolment.
CREATE TABLE install_tokens (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    token_hash bytea NOT NULL UNIQUE,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    used_at    timestamptz
);

-- What the console's install timeline shows.
CREATE TABLE install_events (
    id        bigserial PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    step      text NOT NULL,
    detail    text NOT NULL DEFAULT '',
    at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX install_events_tenant ON install_events (tenant_id, id);
