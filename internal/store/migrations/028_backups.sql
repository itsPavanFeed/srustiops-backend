-- Backups of this tenant plane: the database and the bucket objects it
-- points at, sealed with the master key, kept in the tenant's bucket (or a
-- backup directory). drill is the last restore drill's report.
CREATE TABLE backups (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    key         text NOT NULL UNIQUE,
    size        bigint NOT NULL,
    tables      int NOT NULL,
    rows        bigint NOT NULL,
    objects     int NOT NULL,
    created_by  text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    drill       jsonb,
    drilled_at  timestamptz
);
