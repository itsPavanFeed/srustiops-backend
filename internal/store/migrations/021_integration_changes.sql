-- Editing or deleting an integration (GitHub, Slack, secret store, contracts
-- repository, cloud connection, organisation, event source) is a request that
-- another tenant admin or DevOps engineer approves before it is applied. The
-- request body is sealed (it can hold credentials); a redacted preview is kept
-- for reviewers.
CREATE TABLE integration_changes (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    action        text NOT NULL,            -- e.g. connection.update, github.delete
    target        text NOT NULL DEFAULT '', -- the integration's name ('' for tenant-wide ones)
    path_values   jsonb NOT NULL DEFAULT '{}',
    body          bytea,                    -- sealed request body
    preview       jsonb,                    -- request body with secrets hidden
    requested_by  text NOT NULL,
    reason        text NOT NULL DEFAULT '',
    status        text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'applied', 'failed', 'rejected', 'cancelled')),
    decided_by    text,
    decision      text,                     -- approve | override | reject | cancel
    decision_reason text,
    error         text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    decided_at    timestamptz
);
CREATE INDEX integration_changes_status ON integration_changes (status, created_at DESC);
-- One pending change per integration at a time.
CREATE UNIQUE INDEX integration_changes_one_pending ON integration_changes (split_part(action, '.', 1), target) WHERE status = 'pending';
