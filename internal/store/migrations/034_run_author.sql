-- Who authored a pull request's change in SrustiOps (from pr_proposers when
-- the run was queued); they cannot approve its plan.
ALTER TABLE runs ADD COLUMN IF NOT EXISTS author_subject text NOT NULL DEFAULT '';
