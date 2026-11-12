-- Teams: a named group of people that holds roles, so access is granted to
-- the team once instead of person by person. A person's roles in a tenant
-- are their own memberships plus those of every team they are in.
CREATE TABLE teams (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    slug        text NOT NULL,
    name        text NOT NULL,
    description text NOT NULL DEFAULT '',
    created_by  text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, slug)
);

CREATE TABLE team_members (
    team_id  uuid NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id  uuid NOT NULL REFERENCES users(id),
    added_by text NOT NULL,
    added_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (team_id, user_id)
);
CREATE INDEX team_members_user ON team_members (user_id);

CREATE TABLE team_roles (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id    uuid NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    entity_id  uuid REFERENCES entities(id),
    bu_id      uuid REFERENCES business_units(id),
    role       text NOT NULL,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (entity_id IS NULL OR bu_id IS NULL),
    UNIQUE NULLS NOT DISTINCT (team_id, entity_id, bu_id, role)
);

-- When each person was last active (any authenticated request, recorded at
-- most every few minutes), and invitations: a person added who has never
-- signed in is invited until invite_expires_at, when their access lapses.
ALTER TABLE users ADD COLUMN last_seen_at timestamptz;
ALTER TABLE users ADD COLUMN invited_at timestamptz;
ALTER TABLE users ADD COLUMN invite_expires_at timestamptz;
UPDATE users u SET last_seen_at = (SELECT max(last_used_at) FROM api_tokens t WHERE t.user_id = u.id);
