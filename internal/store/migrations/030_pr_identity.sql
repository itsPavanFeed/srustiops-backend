-- A pull request is identified by its host and repository as well as its
-- number: numbers repeat across hosts and repositories. repo_key is
-- "<provider>:<owner/repo>", lowercased. Rows from before were all GitHub.
ALTER TABLE pull_requests ADD COLUMN repo_key text NOT NULL DEFAULT '';
UPDATE pull_requests SET repo_key = 'github:' || lower(repo);
ALTER TABLE pull_requests DROP CONSTRAINT pull_requests_pkey;
ALTER TABLE pull_requests ADD PRIMARY KEY (repo_key, number);
ALTER TABLE runs ADD COLUMN pr_repo text;
UPDATE runs r SET pr_repo = p.repo_key FROM pull_requests p WHERE p.number = r.pr_number;
ALTER TABLE stacks ADD COLUMN pr_repo text;
UPDATE stacks s SET pr_repo = p.repo_key FROM pull_requests p WHERE p.number = s.pr_number;
DROP INDEX runs_pr_idx;
CREATE INDEX runs_pr_idx ON runs (pr_repo, pr_number) WHERE pr_number IS NOT NULL;

-- Separation of duties on pull requests: who proposed one in SrustiOps (it
-- is opened on the host with the workspace's token), and which host logins
-- belong to which person. Neither may approve the plans it produced.
CREATE TABLE pr_proposers (
    repo_key   text NOT NULL,
    number     integer NOT NULL,
    subject    text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (repo_key, number)
);
CREATE TABLE git_identities (
    provider   text NOT NULL,
    login      text NOT NULL,          -- lowercased
    subject    text NOT NULL,          -- the person in SrustiOps
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, login)
);
CREATE INDEX git_identities_subject ON git_identities (subject);
