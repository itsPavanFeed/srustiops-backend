-- Event tracking: clouds push change events (CloudTrail through EventBridge,
-- audit logs through a Pub/Sub sink, Event Grid) for a connection. Changes
-- made outside the platform flag the managing stack and notify; nothing is
-- changed automatically.
CREATE TABLE event_sources (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name          text NOT NULL UNIQUE,
    connection_id uuid NOT NULL REFERENCES cloud_connections(id) ON DELETE CASCADE,
    token_hash    bytea NOT NULL,
    ignore_actors text[] NOT NULL DEFAULT '{}',
    created_by    text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_event_at timestamptz
);

CREATE TABLE cloud_events (
    id            bigserial PRIMARY KEY,
    source_id     uuid NOT NULL REFERENCES event_sources(id) ON DELETE CASCADE,
    connection_id uuid NOT NULL,
    received_at   timestamptz NOT NULL DEFAULT now(),
    event_time    timestamptz,
    action        text NOT NULL,          -- create | update | delete
    event_name    text NOT NULL,
    resource_id   text NOT NULL,
    actor         text NOT NULL DEFAULT '',
    stack         text NOT NULL DEFAULT '',  -- the managing stack ('' = unmanaged)
    bu            text NOT NULL DEFAULT '',
    ignored       text NOT NULL DEFAULT '',  -- why it does not flag the stack (the platform's own identity, ...)
    notified      boolean NOT NULL DEFAULT false
);
CREATE INDEX cloud_events_stack ON cloud_events (stack, received_at DESC);
CREATE INDEX cloud_events_time ON cloud_events (received_at DESC);
