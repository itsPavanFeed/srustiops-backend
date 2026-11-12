-- When a tenant's link agent was last heard from, kept after its tunnels
-- close, so the console can say how long a workspace has been offline.
ALTER TABLE tenants ADD COLUMN link_seen_at timestamptz;
UPDATE tenants t SET link_seen_at = (SELECT max(last_seen) FROM tenant_links l WHERE l.tenant_id = t.id);
