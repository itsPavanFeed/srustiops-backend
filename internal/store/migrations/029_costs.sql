-- Actual cloud cost by month, connection, BU and stack (from the billing
-- APIs, by the srustiops-bu / srustiops-stack tags), and budgets per BU.
CREATE TABLE cost_actuals (
    month         text NOT NULL CHECK (month ~ '^\d{4}-\d{2}$'),
    connection_id uuid NOT NULL REFERENCES cloud_connections(id) ON DELETE CASCADE,
    bu            text NOT NULL DEFAULT '',
    stack         text NOT NULL DEFAULT '',
    amount        numeric NOT NULL,
    currency      text NOT NULL DEFAULT 'USD',
    fetched_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (month, connection_id, bu, stack)
);
CREATE TABLE cost_fetches (
    connection_id uuid PRIMARY KEY REFERENCES cloud_connections(id) ON DELETE CASCADE,
    fetched_at    timestamptz NOT NULL DEFAULT now(),
    ok            boolean NOT NULL,
    lines         int NOT NULL DEFAULT 0,
    error         text NOT NULL DEFAULT ''
);
CREATE TABLE bu_budgets (
    bu         text PRIMARY KEY,
    monthly    numeric NOT NULL CHECK (monthly > 0),
    alert_at   int[] NOT NULL DEFAULT '{80,100}',
    updated_by text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);
-- One alert per BU, month and threshold.
CREATE TABLE bu_budget_alerts (
    bu        text NOT NULL,
    month     text NOT NULL,
    threshold int NOT NULL,
    spent     numeric NOT NULL,
    sent_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (bu, month, threshold)
);
