-- Everyday delivery features.

-- Schedules per environment (opt-in, off by default): detect-only drift
-- checks and inventory rescans, with quiet hours. Scheduled checks only flag
-- stacks and notify; fixing drift stays a person's choice.
ALTER TABLE environments ADD COLUMN schedule jsonb NOT NULL DEFAULT '{}';

-- A stack can be locked by a person (no new plans or applies until
-- unlocked), lists the resources its last plan or apply saw, can be deleted
-- once it manages nothing, and remembers the stack it was cloned from.
ALTER TABLE stacks ADD COLUMN locked_by text;
ALTER TABLE stacks ADD COLUMN locked_reason text NOT NULL DEFAULT '';
ALTER TABLE stacks ADD COLUMN locked_at timestamptz;
ALTER TABLE stacks ADD COLUMN resources jsonb;
ALTER TABLE stacks ADD COLUMN resources_at timestamptz;
ALTER TABLE stacks ADD COLUMN deleted_at timestamptz;
ALTER TABLE stacks ADD COLUMN deleted_by text;
ALTER TABLE stacks ADD COLUMN cloned_from uuid REFERENCES stacks(id) ON DELETE SET NULL;
ALTER TABLE stacks ADD COLUMN template text NOT NULL DEFAULT '';
-- Deleted stacks keep their history but give their name back.
ALTER TABLE stacks DROP CONSTRAINT stacks_name_key;
CREATE UNIQUE INDEX stacks_name_live ON stacks (name) WHERE deleted_at IS NULL;

-- Cancelling a plan or apply that is running: the runner sees the request on
-- its next log heartbeat, interrupts OpenTofu (which stops cleanly and saves
-- state) and reports; the run ends as cancelled.
ALTER TABLE runs ADD COLUMN cancel_requested_by text;
ALTER TABLE runs ADD COLUMN cancel_requested_at timestamptz;

-- Stack templates: a reusable spec, offered when creating a stack.
CREATE TABLE stack_templates (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text NOT NULL UNIQUE,
    description text NOT NULL DEFAULT '',
    entity      text NOT NULL DEFAULT '',   -- '' = every product
    spec        jsonb NOT NULL,
    source_stack text NOT NULL DEFAULT '',
    created_by  text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- Each person's notification preferences. visible_bus is what they could see
-- when last active, so email is only ever sent about what they may read.
CREATE TABLE notification_prefs (
    subject       text PRIMARY KEY,
    email_enabled boolean NOT NULL DEFAULT false,
    email_kinds   text[] NOT NULL DEFAULT '{}',  -- empty = every kind not muted
    muted         text[] NOT NULL DEFAULT '{}',  -- kinds hidden from the bell and never emailed
    visible_bus   text[] NOT NULL DEFAULT '{}',
    all_bus       boolean NOT NULL DEFAULT false,
    updated_at    timestamptz NOT NULL DEFAULT now()
);

-- Emails waiting to go out (sent by one replica, retried on failure).
CREATE TABLE email_outbox (
    id         bigserial PRIMARY KEY,
    recipient  text NOT NULL,
    subject    text NOT NULL,
    body       text NOT NULL,
    attempts   int NOT NULL DEFAULT 0,
    last_error text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    sent_at    timestamptz
);
CREATE INDEX email_outbox_pending ON email_outbox (id) WHERE sent_at IS NULL;
