-- Grants are keyed on who a person is at their provider, (issuer, subject),
-- never on email alone. A grant made by email is an invitation: the first
-- verified sign-in with that email from a provider the tenant accepts binds it.
ALTER TABLE access_grants ADD COLUMN issuer text;
ALTER TABLE access_grants ADD COLUMN subject text;
ALTER TABLE access_grants ADD COLUMN idp text;
ALTER TABLE access_grants ADD COLUMN bound_at timestamptz;
CREATE INDEX access_grants_identity ON access_grants (issuer, subject);

-- Support access is for the identity that asked, not for an email.
ALTER TABLE support_grants ADD COLUMN issuer text NOT NULL DEFAULT '';
ALTER TABLE support_grants ADD COLUMN subject text NOT NULL DEFAULT '';

-- Sessions from the tenant's own provider: who, and the provider's groups.
ALTER TABLE tenant_sessions ADD COLUMN issuer text NOT NULL DEFAULT '';
ALTER TABLE tenant_sessions ADD COLUMN subject text NOT NULL DEFAULT '';
ALTER TABLE tenant_sessions ADD COLUMN groups text[] NOT NULL DEFAULT '{}';

-- The tenant runs its own OIDC flow: state, nonce and PKCE verifier stay here.
CREATE TABLE tenant_auth_flows (
    state        text PRIMARY KEY,
    verifier     text NOT NULL,
    nonce        text NOT NULL,
    redirect_uri text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- Assertion IDs already seen, shared by every replica of this tenant plane.
CREATE UNLOGGED TABLE assertion_replay (
    jti        text PRIMARY KEY,
    expires_at timestamptz NOT NULL
);
