-- Resource outputs a stack exports for other stacks (stack/<stack>/<resource>.<output>),
-- reported by the runner after each apply and kept sealed.
CREATE TABLE stack_outputs (
    stack_id   uuid NOT NULL REFERENCES stacks(id) ON DELETE CASCADE,
    name       text NOT NULL,            -- <module>.<output>
    value      bytea NOT NULL,           -- sealed JSON value
    run_id     uuid REFERENCES runs(id) ON DELETE SET NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (stack_id, name)
);

-- Plans waiting for the stacks they reference to be applied (the DAG):
-- created as soon as every referenced output exists.
CREATE TABLE pending_runs (
    stack_id     uuid PRIMARY KEY REFERENCES stacks(id) ON DELETE CASCADE,
    requested_by text NOT NULL,
    reason       text NOT NULL DEFAULT '',
    waits_on     text[] NOT NULL DEFAULT '{}', -- stack names
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- Which resource (module instance) of its stack an adopted item became, so
-- dependents can reference its outputs.
ALTER TABLE inventory ADD COLUMN adopted_module text NOT NULL DEFAULT '';

-- Import addresses already applied (or found in state): Git contracts keep
-- their import blocks, so only the others count as pending imports.
ALTER TABLE stacks ADD COLUMN settled_imports text[] NOT NULL DEFAULT '{}';
-- Backfill: the imports of applied runs that carried their own contract
-- (pull requests, matched contracts) are done.
UPDATE stacks s SET settled_imports = ARRAY(
    SELECT DISTINCT imp->>'to'
      FROM runs r, jsonb_array_elements(r.spec->'imports') imp
     WHERE r.stack_id = s.id AND r.status = 'applied' AND jsonb_typeof(r.spec->'imports') = 'array');
