-- The Runs page (newest first across stacks), audit date ranges, and the
-- last apply per stack shown on every stack.
CREATE INDEX IF NOT EXISTS runs_created_idx ON runs (created_at DESC);
CREATE INDEX IF NOT EXISTS runs_applied_idx ON runs (stack_id, finished_at DESC) WHERE status = 'applied';
CREATE INDEX IF NOT EXISTS audit_events_ts_idx ON audit_events (ts);
CREATE INDEX IF NOT EXISTS notifications_created_idx ON notifications (created_at);

-- Audit search (substring of action, target or actor) with trigram indexes,
-- when the database allows the pg_trgm extension; without it search still
-- works, as a scan.
DO $$
BEGIN
    CREATE EXTENSION IF NOT EXISTS pg_trgm;
    CREATE INDEX IF NOT EXISTS audit_events_search_idx ON audit_events USING gin (action gin_trgm_ops, target gin_trgm_ops, actor gin_trgm_ops);
EXCEPTION WHEN insufficient_privilege OR feature_not_supported OR undefined_file THEN
    RAISE NOTICE 'pg_trgm is not available: audit search is not indexed';
END $$;
