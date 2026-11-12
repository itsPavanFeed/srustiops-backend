-- Who a person is at the provider they signed in with: (issuer, subject).
-- Tenants key grants on these, never on email alone.
ALTER TABLE api_tokens ADD COLUMN uid_iss text NOT NULL DEFAULT '';
ALTER TABLE api_tokens ADD COLUMN uid_sub text NOT NULL DEFAULT '';
ALTER TABLE api_tokens ADD COLUMN email_verified boolean NOT NULL DEFAULT true;
ALTER TABLE auth_codes ADD COLUMN uid_iss text NOT NULL DEFAULT '';
ALTER TABLE auth_codes ADD COLUMN uid_sub text NOT NULL DEFAULT '';
ALTER TABLE auth_codes ADD COLUMN email_verified boolean NOT NULL DEFAULT true;

-- Tenants run their own sign-in: the client secret lives in the tenant, and
-- central keeps only what home-realm discovery and the egress relay need.
UPDATE tenant_idps SET client_secret = NULL, client_id = '';
