package store

import (
	"context"
	"strings"
)

// ---- stack outputs (for other stacks' references) ----

// PutStackOutputs replaces a stack's exported outputs with those of an apply.
// Values are sealed by the caller.
func (s *Store) PutStackOutputs(ctx context.Context, stackID, runID string, sealed map[string][]byte) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM stack_outputs WHERE stack_id = $1`, stackID); err != nil {
		return err
	}
	for name, v := range sealed {
		if _, err := tx.Exec(ctx, `INSERT INTO stack_outputs (stack_id, name, value, run_id) VALUES ($1, $2, $3, $4)`, stackID, name, v, runID); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// StackOutputs returns a stack's sealed outputs by <module>.<output>.
func (s *Store) StackOutputs(ctx context.Context, stackID string) (map[string][]byte, error) {
	rows, err := s.db.Query(ctx, `SELECT name, value FROM stack_outputs WHERE stack_id = $1`, stackID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]byte{}
	for rows.Next() {
		var n string
		var v []byte
		if err := rows.Scan(&n, &v); err != nil {
			return nil, err
		}
		out[n] = v
	}
	return out, rows.Err()
}

// ---- the dependency graph between stacks ----

// StackSpecs returns every stack's name and spec (for the dependency graph).
func (s *Store) StackSpecs(ctx context.Context) (map[string][]byte, error) {
	rows, err := s.db.Query(ctx, `SELECT name, spec FROM stacks WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]byte{}
	for rows.Next() {
		var n string
		var sp []byte
		if err := rows.Scan(&n, &sp); err != nil {
			return nil, err
		}
		out[n] = sp
	}
	return out, rows.Err()
}

// Dependents lists the stacks whose spec references stack name.
func (s *Store) Dependents(ctx context.Context, name string) ([]string, error) {
	rows, err := s.db.Query(ctx, `SELECT name FROM stacks WHERE deleted_at IS NULL AND spec::text LIKE '%' || $1 || '%' ORDER BY name`, `"stack/`+name+`/`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		rows.Scan(&n)
		out = append(out, n)
	}
	return out, rows.Err()
}

// PendingRun is a plan waiting for the stacks it references to be applied.
type PendingRun struct {
	StackID     string
	RequestedBy string
	Reason      string
	WaitsOn     []string
}

func (s *Store) AddPendingRun(ctx context.Context, stackID, by, reason string, waitsOn []string) error {
	_, err := s.db.Exec(ctx, `INSERT INTO pending_runs (stack_id, requested_by, reason, waits_on) VALUES ($1, $2, $3, $4)
		ON CONFLICT (stack_id) DO UPDATE SET waits_on = EXCLUDED.waits_on, reason = EXCLUDED.reason`, stackID, by, reason, waitsOn)
	return err
}

func (s *Store) PendingRuns(ctx context.Context) ([]*PendingRun, error) {
	rows, err := s.db.Query(ctx, `SELECT stack_id, requested_by, reason, waits_on FROM pending_runs ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*PendingRun
	for rows.Next() {
		var p PendingRun
		if err := rows.Scan(&p.StackID, &p.RequestedBy, &p.Reason, &p.WaitsOn); err != nil {
			return nil, err
		}
		out = append(out, &p)
	}
	return out, rows.Err()
}

func (s *Store) PendingRunFor(ctx context.Context, stackID string) (*PendingRun, error) {
	var p PendingRun
	err := s.db.QueryRow(ctx, `SELECT stack_id, requested_by, reason, waits_on FROM pending_runs WHERE stack_id = $1`, stackID).
		Scan(&p.StackID, &p.RequestedBy, &p.Reason, &p.WaitsOn)
	return &p, NotFound(err)
}

func (s *Store) DeletePendingRun(ctx context.Context, stackID string) error {
	_, err := s.db.Exec(ctx, `DELETE FROM pending_runs WHERE stack_id = $1`, stackID)
	return err
}

// WaitingSummary is "a, b" for messages.
func WaitingSummary(names []string) string { return strings.Join(names, ", ") }
