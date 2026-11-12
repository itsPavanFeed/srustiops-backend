-- Sealed (master key) checkpoints of the audit chain: verification starts
-- from the newest one, and a chain rewritten up to it no longer matches.
CREATE TABLE audit_checkpoints (
    id         bigint PRIMARY KEY,   -- the audit event it vouches for
    sealed     bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
