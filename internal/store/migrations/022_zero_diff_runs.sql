-- Runs that test a contract matched to the live resources (live -> code, or
-- adopting resources as they exist) must change nothing: the zero-diff gate
-- holds them like an import. source_run is the run they were derived from.
ALTER TABLE runs ADD COLUMN zero_diff boolean NOT NULL DEFAULT false;
ALTER TABLE runs ADD COLUMN source_run uuid REFERENCES runs(id) ON DELETE SET NULL;

-- Pull requests the platform opened from live -> code: their plans are held
-- to the zero-diff gate, and they may take over the console stack they match
-- (it becomes managed through Git once the pull request is applied).
CREATE TABLE zero_diff_prs (
    number     integer PRIMARY KEY,
    stack_id   uuid NOT NULL REFERENCES stacks(id) ON DELETE CASCADE,
    source_run uuid REFERENCES runs(id) ON DELETE SET NULL,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
