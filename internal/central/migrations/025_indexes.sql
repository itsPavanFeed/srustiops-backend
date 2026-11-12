-- Platform audit date ranges and search (trigram, when pg_trgm is allowed).
CREATE INDEX IF NOT EXISTS audit_events_ts_idx ON audit_events (ts);
DO $$
BEGIN
    CREATE EXTENSION IF NOT EXISTS pg_trgm;
    CREATE INDEX IF NOT EXISTS audit_events_search_idx ON audit_events USING gin (action gin_trgm_ops, target gin_trgm_ops, actor gin_trgm_ops);
EXCEPTION WHEN insufficient_privilege OR feature_not_supported OR undefined_file THEN
    RAISE NOTICE 'pg_trgm is not available: audit search is not indexed';
END $$;
