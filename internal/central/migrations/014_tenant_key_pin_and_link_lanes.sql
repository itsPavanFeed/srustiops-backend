-- The tenant API's public key, pinned when its cluster bootstraps (the key
-- is made there and never leaves). Central checks it on every call besides
-- the tenant server CA, so that CA's key alone cannot impersonate a tenant.
-- Changing the tenant's URL or CA clears it.
ALTER TABLE tenants ADD COLUMN server_key_pin text NOT NULL DEFAULT '';

-- The traffic lane each tunnel carries (interactive, bulk, or '' for any).
ALTER TABLE tenant_links ADD COLUMN lane text NOT NULL DEFAULT '';
