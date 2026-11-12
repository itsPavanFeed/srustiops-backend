-- Tenant-controlled access. access_source 'tenant': the tenant plane decides
-- roles from its own grants; central's memberships for it become a read-only
-- directory copy, synced from the tenant, used for the workspace list.
ALTER TABLE tenants ADD COLUMN access_source text NOT NULL DEFAULT 'central'
    CHECK (access_source IN ('central', 'tenant'));
ALTER TABLE tenants ADD COLUMN require_idp boolean NOT NULL DEFAULT false;
ALTER TABLE tenants ADD COLUMN directory_synced_at timestamptz;

-- How each session signed in, passed to tenants in assertions so they can
-- apply their own sign-in policy.
ALTER TABLE api_tokens ADD COLUMN idp text NOT NULL DEFAULT 'token';
ALTER TABLE api_tokens ADD COLUMN amr text[] NOT NULL DEFAULT '{}';
ALTER TABLE api_tokens ADD COLUMN groups text[] NOT NULL DEFAULT '{}';
ALTER TABLE api_tokens ADD COLUMN auth_time timestamptz;
ALTER TABLE auth_codes ADD COLUMN idp text NOT NULL DEFAULT 'oidc';
ALTER TABLE auth_codes ADD COLUMN amr text[] NOT NULL DEFAULT '{}';
ALTER TABLE auth_codes ADD COLUMN groups text[] NOT NULL DEFAULT '{}';
ALTER TABLE auth_codes ADD COLUMN tenant_id uuid REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE auth_codes ADD COLUMN tenant_session text;

-- Sessions a tenant issued after verifying its own identity provider's token.
CREATE TABLE token_tenant_sessions (
    token_id       uuid NOT NULL REFERENCES api_tokens(id) ON DELETE CASCADE,
    tenant_id      uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    tenant_session text NOT NULL,
    PRIMARY KEY (token_id, tenant_id)
);

-- A tenant's own OpenID Connect provider. The client secret is sealed with
-- the central master key; the tenant keeps its own copy of issuer and client
-- ID and verifies every ID token itself.
CREATE TABLE tenant_idps (
    tenant_id     uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    issuer        text NOT NULL,
    client_id     text NOT NULL,
    client_secret bytea,
    label         text NOT NULL,
    group_claim   text NOT NULL DEFAULT 'groups',
    enabled       boolean NOT NULL DEFAULT true,
    updated_by    text NOT NULL,
    updated_at    timestamptz NOT NULL DEFAULT now()
);

-- Email domains a tenant proved (DNS TXT) it owns: its provider may only sign
-- in addresses there, and those addresses are sent to it at sign-in.
CREATE TABLE tenant_domains (
    domain      text PRIMARY KEY,
    tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    token       text NOT NULL,
    verified_at timestamptz,
    created_by  text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- Directory copy of support access (decided in the tenant).
CREATE TABLE tenant_support (
    id         text PRIMARY KEY,
    tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email      text NOT NULL,
    role       text NOT NULL,
    reason     text NOT NULL,
    status     text NOT NULL,
    hours      int NOT NULL,
    requested_at timestamptz NOT NULL,
    expires_at timestamptz
);
CREATE INDEX tenant_support_email ON tenant_support (email);

-- Per-tenant SCIM: tokens issued by the tenant's admins; groups and their
-- members are pushed to the tenant, which maps groups to roles itself.
CREATE TABLE tenant_scim_tokens (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name       text NOT NULL,
    token_hash bytea NOT NULL UNIQUE,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz
);
CREATE TABLE tenant_scim_groups (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        text NOT NULL,
    external_id text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);
CREATE TABLE tenant_scim_members (
    group_id uuid NOT NULL REFERENCES tenant_scim_groups(id) ON DELETE CASCADE,
    user_id  uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
);
