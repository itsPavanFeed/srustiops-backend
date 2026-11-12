-- Enterprise sign-in providers configured in the console by platform admins:
-- any OpenID Connect provider (Okta, Entra ID, Ping, Keycloak, Auth0) and
-- SAML 2.0 identity providers. Several of each may exist. Like Google and
-- GitHub they only authenticate: access still comes from roles granted in
-- SrustiOps. Secrets (an OIDC client secret) are sealed with the master key.
CREATE TABLE sign_in_providers (
    id              text PRIMARY KEY,           -- slug, used in /auth/{kind}/{id}/...
    kind            text NOT NULL CHECK (kind IN ('oidc', 'saml')),
    label           text NOT NULL,              -- the button: "Sign in with Okta"
    config          jsonb NOT NULL,             -- oidc: issuer, client_id; saml: idp entity ID, SSO URL, certificates
    secret          bytea,                      -- oidc client secret (sealed)
    allowed_domains text[] NOT NULL DEFAULT '{}',
    enabled         boolean NOT NULL DEFAULT true,
    updated_by      text NOT NULL,
    updated_at      timestamptz NOT NULL DEFAULT now()
);

-- A tenant's own provider may speak SAML: the tenant plane verifies its
-- assertions (it keeps the IdP metadata); central relays the browser.
ALTER TABLE tenant_idps ADD COLUMN protocol text NOT NULL DEFAULT 'oidc' CHECK (protocol IN ('oidc', 'saml'));
