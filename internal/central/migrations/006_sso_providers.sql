-- Google and GitHub sign-in, configured by a platform admin. The client
-- secret is sealed with the central master key. SSO only authenticates:
-- access still comes from roles granted in SrustiOps.
CREATE TABLE sso_providers (
    id              text PRIMARY KEY CHECK (id IN ('google', 'github')),
    client_id       text NOT NULL,
    client_secret   bytea NOT NULL,
    allowed_domains text[] NOT NULL DEFAULT '{}', -- email domains (Google: also the hd claim)
    allowed_orgs    text[] NOT NULL DEFAULT '{}', -- GitHub organisations the user must belong to
    enabled         boolean NOT NULL DEFAULT true,
    updated_by      text NOT NULL,
    updated_at      timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE auth_flows ADD COLUMN provider text NOT NULL DEFAULT 'oidc';
