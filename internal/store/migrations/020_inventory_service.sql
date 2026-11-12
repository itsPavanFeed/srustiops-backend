-- Inventory is browsed provider -> connection -> service -> resources. The
-- service is the part of the type before ':' (AWS "s3:bucket") or '/' (GCP
-- "storage.googleapis.com/Bucket", Azure "microsoft.storage/storageaccounts").
ALTER TABLE inventory ADD COLUMN service text NOT NULL DEFAULT '';
UPDATE inventory SET service = CASE WHEN position(':' in type) > 0 THEN split_part(type, ':', 1) ELSE split_part(type, '/', 1) END;
CREATE INDEX inventory_service ON inventory (connection_id, service);
CREATE INDEX cloud_events_resource ON cloud_events (connection_id, lower(resource_id));
