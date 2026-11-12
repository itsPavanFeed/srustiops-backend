-- Tenant-controlled access. When the access source is "tenant" (setting
-- "access"), this plane decides what each person may do from these tables;
-- central only says who they are.

-- Role grants: tenant-wide (no entity, no bu), on an entity, or on one BU.
CREATE TABLE access_grants (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email      text NOT NULL,
    role       text NOT NULL,
    entity     text NOT NULL DEFAULT '',
    bu         text NOT NULL DEFAULT '',
    source     text NOT NULL DEFAULT 'manual' CHECK (source IN ('manual', 'import')),
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (email, role, entity, bu)
);
CREATE INDEX access_grants_email ON access_grants (email);

-- What an identity-provider group means here: the tenant decides.
CREATE TABLE access_group_bindings (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    group_name text NOT NULL,
    role       text NOT NULL,
    entity     text NOT NULL DEFAULT '',
    bu         text NOT NULL DEFAULT '',
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (group_name, role, entity, bu)
);

-- Group members provisioned by this tenant's SCIM endpoint.
CREATE TABLE access_group_members (
    group_name text NOT NULL,
    email      text NOT NULL,
    PRIMARY KEY (group_name, email)
);
CREATE INDEX access_group_members_email ON access_group_members (email);

-- Support access: a platform admin asks, a tenant admin decides, it expires.
CREATE TABLE support_grants (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email        text NOT NULL,
    role         text NOT NULL,
    reason       text NOT NULL,
    hours        int NOT NULL CHECK (hours BETWEEN 1 AND 8),
    status       text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'declined', 'revoked')),
    requested_at timestamptz NOT NULL DEFAULT now(),
    decided_by   text,
    decided_at   timestamptz,
    expires_at   timestamptz
);
CREATE INDEX support_grants_email ON support_grants (email, status);

-- Sessions this tenant issued after verifying its own identity provider's ID
-- token; assertions for tenants that require their provider must name one.
CREATE TABLE tenant_sessions (
    id         text PRIMARY KEY,
    email      text NOT NULL,
    auth_time  timestamptz NOT NULL,
    amr        text[] NOT NULL DEFAULT '{}',
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
