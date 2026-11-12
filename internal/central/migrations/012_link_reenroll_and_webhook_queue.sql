-- What each tunnel reports over its control stream.
ALTER TABLE tenant_links ADD COLUMN version text NOT NULL DEFAULT '';
ALTER TABLE tenant_links ADD COLUMN mode text NOT NULL DEFAULT 'tunnel';
ALTER TABLE tenant_links ADD COLUMN clock_skew_ms bigint NOT NULL DEFAULT 0;

-- The tenant's directory keys, pinned on first contact over the link:
-- the signing key checks directory snapshots (newer seq only); queued
-- webhooks are sealed to the encryption key, so central cannot read them.
ALTER TABLE tenants ADD COLUMN dir_sign_key text NOT NULL DEFAULT '';
ALTER TABLE tenants ADD COLUMN dir_enc_key text NOT NULL DEFAULT '';
ALTER TABLE tenants ADD COLUMN directory_seq bigint NOT NULL DEFAULT 0;
-- Webhooks dropped from a full offline queue, reported on reconnect.
ALTER TABLE tenants ADD COLUMN webhooks_dropped int NOT NULL DEFAULT 0;

-- Hosts the egress relay may reach for the tenant: its identity provider's
-- issuer, token and key endpoints (from its discovery document).
ALTER TABLE tenant_idps ADD COLUMN egress_hosts text[] NOT NULL DEFAULT '{}';

-- Queued payloads were sealed with the central master key before; they are
-- now sealed to the tenant. Drop the old ones rather than keep readable copies.
DELETE FROM link_webhook_queue;

-- Certificates issued by re-enrolment after an offline expiry.
ALTER TABLE link_certs DROP CONSTRAINT link_certs_issued_via_check;
ALTER TABLE link_certs ADD CONSTRAINT link_certs_issued_via_check CHECK (issued_via IN ('enroll', 'renew', 'reenroll'));
