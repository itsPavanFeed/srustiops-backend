-- Plans: named sets of usage limits a platform admin gives workspaces (no
-- payments). A workspace without a plan has no limits. Limits are pushed to
-- the tenant plane, which enforces them; central enforces the people limit.
CREATE TABLE plans (
    name        text PRIMARY KEY CHECK (name ~ '^[a-z][a-z0-9-]{0,39}$'),
    description text NOT NULL DEFAULT '',
    limits      jsonb NOT NULL DEFAULT '{}',
    created_by  text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);
INSERT INTO plans (name, description, limits, created_by) VALUES
    ('trial', 'For trying SrustiOps out', '{"stacks": 10, "environments": 3, "connections": 2, "runners": 2, "runs_per_month": 500, "people": 5}', 'system'),
    ('team', 'For one product team', '{"stacks": 200, "environments": 20, "connections": 10, "runners": 10, "runs_per_month": 10000, "people": 50}', 'system'),
    ('enterprise', 'No limits', '{}', 'system');

ALTER TABLE tenants ADD COLUMN plan text REFERENCES plans(name) ON UPDATE CASCADE;
-- When the plane last took the current limits; NULL means it still has to.
ALTER TABLE tenants ADD COLUMN plan_synced_at timestamptz;
ALTER TABLE tenants ADD COLUMN plan_sync_error text NOT NULL DEFAULT '';
