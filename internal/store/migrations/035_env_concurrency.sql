-- At most this many plans and applies at once in an environment (0 = no cap),
-- e.g. to protect a shared API quota or a fragile production.
ALTER TABLE environments ADD COLUMN max_concurrent_runs int NOT NULL DEFAULT 0 CHECK (max_concurrent_runs >= 0);
