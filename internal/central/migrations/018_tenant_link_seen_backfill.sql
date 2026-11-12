-- Tenants whose tunnels had closed before link_seen_at existed: the last
-- link event in the audit log (connect, renew, disconnect) is when their
-- agent was last heard from.
UPDATE tenants t SET link_seen_at = a.last
FROM (SELECT entity, max(ts) AS last FROM audit_events WHERE action LIKE 'link.%' AND entity <> '' GROUP BY entity) a
WHERE a.entity = t.slug AND (t.link_seen_at IS NULL OR t.link_seen_at < a.last);
