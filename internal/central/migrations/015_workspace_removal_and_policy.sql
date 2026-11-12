-- Removing a workspace deregisters it: its link, tokens and memberships go,
-- the row stays (audit refers to it, the slug is not reused). The tenant's
-- own data, in its cluster and cloud account, is never touched.
ALTER TABLE tenants DROP CONSTRAINT tenants_status_check;
ALTER TABLE tenants ADD CONSTRAINT tenants_status_check CHECK (status IN ('pending', 'active', 'removed'));
ALTER TABLE tenants ADD COLUMN removed_at timestamptz;
ALTER TABLE tenants ADD COLUMN removed_by text NOT NULL DEFAULT '';

-- Workspace creation policy: trials are created at once within quotas and
-- expire; production workspaces need a platform admin's approval.
ALTER TABLE tenants ADD COLUMN kind text NOT NULL DEFAULT 'production' CHECK (kind IN ('trial', 'production'));
ALTER TABLE tenants ADD COLUMN trial_ends_at timestamptz;

CREATE TABLE platform_settings (
    key        text PRIMARY KEY,
    value      jsonb NOT NULL,
    updated_by text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE workspace_requests (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    slug         text NOT NULL,
    name         text NOT NULL,
    target       text NOT NULL DEFAULT '',
    reason       text NOT NULL DEFAULT '',
    requested_by text NOT NULL,
    status       text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'withdrawn')),
    decided_by   text NOT NULL DEFAULT '',
    decision     text NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now(),
    decided_at   timestamptz
);
-- One open request per slug.
CREATE UNIQUE INDEX workspace_requests_open_slug ON workspace_requests (slug) WHERE status = 'pending';
