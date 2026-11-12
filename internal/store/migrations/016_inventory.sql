-- Inventory: what exists in each connected account, project or subscription,
-- read from the cloud's own index (Resource Explorer, Cloud Asset Inventory,
-- Resource Graph) when a person starts a scan. Rows are replaced per scan.
CREATE TABLE inventory_scans (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    connection_id uuid NOT NULL REFERENCES cloud_connections(id) ON DELETE CASCADE,
    status        text NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'succeeded', 'failed')),
    error         text,
    found         int NOT NULL DEFAULT 0,
    started_by    text NOT NULL,
    started_at    timestamptz NOT NULL DEFAULT now(),
    finished_at   timestamptz
);
CREATE INDEX inventory_scans_conn ON inventory_scans (connection_id, started_at DESC);
-- One scan per connection at a time.
CREATE UNIQUE INDEX inventory_scans_running ON inventory_scans (connection_id) WHERE status = 'running';

CREATE TABLE inventory (
    connection_id uuid NOT NULL REFERENCES cloud_connections(id) ON DELETE CASCADE,
    resource_id   text NOT NULL,
    type          text NOT NULL,
    name          text NOT NULL,
    region        text NOT NULL DEFAULT '',
    account       text NOT NULL DEFAULT '',
    project       text NOT NULL DEFAULT '',
    tags          jsonb NOT NULL DEFAULT '{}',
    kind          text NOT NULL DEFAULT '',   -- the kind that can adopt it ('' = none yet)
    stack         text NOT NULL DEFAULT '',   -- the stack managing it ('' = unmanaged)
    adopted_by    text NOT NULL DEFAULT '',   -- who started adopting it
    first_seen    timestamptz NOT NULL DEFAULT now(),
    last_seen     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (connection_id, resource_id)
);
CREATE INDEX inventory_type ON inventory (type);
CREATE INDEX inventory_stack ON inventory (stack);
