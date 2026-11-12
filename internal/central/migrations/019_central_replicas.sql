-- Central replicas announce themselves here every 15 seconds, so each one
-- knows how many share the traffic (rate limits are split between them).
CREATE TABLE central_replicas (
    id      text PRIMARY KEY,
    seen_at timestamptz NOT NULL DEFAULT now()
);
