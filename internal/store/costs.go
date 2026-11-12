package store

import (
	"context"
	"time"
)

type CostLine struct {
	Month      string  `json:"month"`
	Connection string  `json:"connection,omitempty"`
	BU         string  `json:"bu"`
	Stack      string  `json:"stack"`
	Amount     float64 `json:"amount"`
	Currency   string  `json:"currency"`
}

type CostFetch struct {
	Connection string    `json:"connection"`
	FetchedAt  time.Time `json:"fetched_at"`
	OK         bool      `json:"ok"`
	Lines      int       `json:"lines"`
	Error      string    `json:"error,omitempty"`
}

type Budget struct {
	BU        string    `json:"bu"`
	Monthly   float64   `json:"monthly"`
	AlertAt   []int32   `json:"alert_at"`
	UpdatedBy string    `json:"updated_by"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ReplaceCosts swaps a connection's lines for the given months; a stack's
// BU is the workspace's own when the stack is known (tags can be stale or
// missing), else the tag's.
func (s *Store) ReplaceCosts(ctx context.Context, connID string, months []string, lines []CostLine) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM cost_actuals WHERE connection_id = $1 AND month = ANY($2)`, connID, months); err != nil {
		return err
	}
	for _, l := range lines {
		if _, err := tx.Exec(ctx, `INSERT INTO cost_actuals (month, connection_id, bu, stack, amount, currency)
			VALUES ($1, $2, coalesce((SELECT bu FROM stacks WHERE name = $4 AND $4 <> '' ORDER BY deleted_at NULLS FIRST LIMIT 1), $3), $4, $5, $6)
			ON CONFLICT (month, connection_id, bu, stack) DO UPDATE SET amount = cost_actuals.amount + EXCLUDED.amount`,
			l.Month, connID, l.BU, l.Stack, l.Amount, l.Currency); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO cost_fetches (connection_id, ok, lines) VALUES ($1, true, $2)
		ON CONFLICT (connection_id) DO UPDATE SET fetched_at = now(), ok = true, lines = $2, error = ''`, connID, len(lines)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) CostFetchFailed(ctx context.Context, connID, msg string) {
	s.db.Exec(ctx, `INSERT INTO cost_fetches (connection_id, ok, error) VALUES ($1, false, $2)
		ON CONFLICT (connection_id) DO UPDATE SET fetched_at = now(), ok = false, error = $2`, connID, msg)
}

func (s *Store) CostFetches(ctx context.Context) ([]CostFetch, error) {
	rows, err := s.db.Query(ctx, `SELECT c.name, f.fetched_at, f.ok, f.lines, f.error FROM cost_fetches f JOIN cloud_connections c ON c.id = f.connection_id ORDER BY c.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CostFetch{}
	for rows.Next() {
		var f CostFetch
		if err := rows.Scan(&f.Connection, &f.FetchedAt, &f.OK, &f.Lines, &f.Error); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// LastCostFetch is the oldest connection read, or nil when a connection
// with a cloud has never been read (it is due now).
func (s *Store) LastCostFetch(ctx context.Context) (t *time.Time) {
	s.db.QueryRow(ctx, `SELECT CASE WHEN EXISTS (SELECT 1 FROM cloud_connections c WHERE coalesce(c.cloud->>'provider', '') NOT IN ('', 'none')
			AND NOT EXISTS (SELECT 1 FROM cost_fetches f WHERE f.connection_id = c.id)) THEN NULL ELSE (SELECT min(fetched_at) FROM cost_fetches) END`).Scan(&t)
	return
}

// Costs are one month's lines, summed over connections.
func (s *Store) Costs(ctx context.Context, month string) ([]CostLine, error) {
	rows, err := s.db.Query(ctx, `SELECT a.bu, a.stack, sum(a.amount)::float8, a.currency FROM cost_actuals a WHERE a.month = $1
		GROUP BY a.bu, a.stack, a.currency ORDER BY a.bu, a.stack`, month)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CostLine{}
	for rows.Next() {
		l := CostLine{Month: month}
		if err := rows.Scan(&l.BU, &l.Stack, &l.Amount, &l.Currency); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// BUSpend is what a BU spent in a month, in the currency it spent most in
// (amounts in different currencies are never added together).
func (s *Store) BUSpend(ctx context.Context, bu, month string) (spent float64) {
	s.db.QueryRow(ctx, `SELECT sum(amount)::float8 FROM cost_actuals WHERE bu = $1 AND month = $2
		GROUP BY currency ORDER BY sum(amount) DESC LIMIT 1`, bu, month).Scan(&spent)
	return
}

func (s *Store) Budgets(ctx context.Context) ([]Budget, error) {
	rows, err := s.db.Query(ctx, `SELECT bu, monthly::float8, alert_at, updated_by, updated_at FROM bu_budgets ORDER BY bu`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Budget{}
	for rows.Next() {
		var b Budget
		if err := rows.Scan(&b.BU, &b.Monthly, &b.AlertAt, &b.UpdatedBy, &b.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *Store) Budget(ctx context.Context, bu string) (*Budget, error) {
	var b Budget
	err := s.db.QueryRow(ctx, `SELECT bu, monthly::float8, alert_at, updated_by, updated_at FROM bu_budgets WHERE bu = $1`, bu).
		Scan(&b.BU, &b.Monthly, &b.AlertAt, &b.UpdatedBy, &b.UpdatedAt)
	return &b, NotFound(err)
}

func (s *Store) PutBudget(ctx context.Context, b *Budget) error {
	_, err := s.db.Exec(ctx, `INSERT INTO bu_budgets (bu, monthly, alert_at, updated_by) VALUES ($1, $2, $3, $4)
		ON CONFLICT (bu) DO UPDATE SET monthly = $2, alert_at = $3, updated_by = $4, updated_at = now()`, b.BU, b.Monthly, b.AlertAt, b.UpdatedBy)
	return err
}

func (s *Store) DeleteBudget(ctx context.Context, bu string) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM bu_budgets WHERE bu = $1`, bu)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// ClaimBudgetAlert records an alert once; false when it was already sent.
func (s *Store) ClaimBudgetAlert(ctx context.Context, bu, month string, threshold int, spent float64) bool {
	tag, err := s.db.Exec(ctx, `INSERT INTO bu_budget_alerts (bu, month, threshold, spent) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`, bu, month, threshold, spent)
	return err == nil && tag.RowsAffected() == 1
}
