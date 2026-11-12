-- The version each workspace's plane runs (as last seen), the version it
-- should run (set by a rollout), and staged rollouts across the fleet.
ALTER TABLE tenants ADD COLUMN plane_version text NOT NULL DEFAULT '';
ALTER TABLE tenants ADD COLUMN version_seen_at timestamptz;
ALTER TABLE tenants ADD COLUMN desired_version text NOT NULL DEFAULT '';

CREATE TABLE fleet_rollouts (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    version         text NOT NULL,
    waves           jsonb NOT NULL,           -- [{name, tenants: [...]} | {name, percent}]
    soak_minutes    int NOT NULL DEFAULT 60,  -- a wave must be healthy this long before the next starts
    status          text NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'paused', 'done', 'aborted')),
    current_wave    int NOT NULL DEFAULT 0,
    wave_started_at timestamptz NOT NULL DEFAULT now(),
    wave_done_at    timestamptz,             -- when every workspace of the current wave ran the version
    detail          text NOT NULL DEFAULT '',
    created_by      text NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);
-- At most one rollout in progress.
CREATE UNIQUE INDEX fleet_rollouts_active ON fleet_rollouts ((true)) WHERE status IN ('running', 'paused');
