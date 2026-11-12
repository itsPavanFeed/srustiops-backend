-- Organisations: an AWS Organization, GCP organization or Azure management
-- group whose accounts, projects or subscriptions are onboarded as
-- connections from a template. OUs, folders and groups map to entities;
-- an account belongs to the entity of its nearest mapped ancestor.
CREATE TABLE cloud_orgs (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name          text NOT NULL UNIQUE,
    provider      text NOT NULL CHECK (provider IN ('aws', 'gcp', 'azure')),
    discovery     jsonb NOT NULL,   -- read-only identity that lists the organisation
    template      jsonb NOT NULL,   -- connection cloud config with {{account}}/{{project}}/{{subscription}}
    name_template text NOT NULL,    -- connection name, e.g. aws-{{name}}
    synced_at     timestamptz,
    sync_error    text,
    created_by    text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE cloud_org_units (
    org_id        uuid NOT NULL REFERENCES cloud_orgs(id) ON DELETE CASCADE,
    unit_id       text NOT NULL,
    parent_id     text NOT NULL DEFAULT '',
    name          text NOT NULL,
    kind          text NOT NULL,
    external      text NOT NULL DEFAULT '',
    state         text NOT NULL DEFAULT '',
    entity        text NOT NULL DEFAULT '',  -- mapped entity ('' = inherit from the parent)
    connection_id uuid REFERENCES cloud_connections(id) ON DELETE SET NULL,
    PRIMARY KEY (org_id, unit_id)
);
