package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

type IntegrationChange struct {
	ID             string            `json:"id"`
	Action         string            `json:"action"`
	Target         string            `json:"target"`
	PathValues     map[string]string `json:"-"`
	Body           []byte            `json:"-"`
	Preview        json.RawMessage   `json:"preview,omitempty"`
	RequestedBy    string            `json:"requested_by"`
	Reason         string            `json:"reason,omitempty"`
	Status         string            `json:"status"`
	DecidedBy      *string           `json:"decided_by,omitempty"`
	Decision       *string           `json:"decision,omitempty"`
	DecisionReason *string           `json:"decision_reason,omitempty"`
	Error          *string           `json:"error,omitempty"`
	CreatedAt      time.Time         `json:"created_at"`
	DecidedAt      *time.Time        `json:"decided_at,omitempty"`
}

const chgCols = `id, action, target, path_values, body, preview, requested_by, reason, status, decided_by, decision, decision_reason, error, created_at, decided_at`

func scanChange(r pgx.Row) (*IntegrationChange, error) {
	var x IntegrationChange
	var pv []byte
	err := r.Scan(&x.ID, &x.Action, &x.Target, &pv, &x.Body, &x.Preview, &x.RequestedBy, &x.Reason, &x.Status, &x.DecidedBy, &x.Decision, &x.DecisionReason, &x.Error, &x.CreatedAt, &x.DecidedAt)
	json.Unmarshal(pv, &x.PathValues)
	return &x, NotFound(err)
}

// CreateChange records a pending change; ErrConflict when the integration
// already has one.
func (s *Store) CreateChange(ctx context.Context, x *IntegrationChange) (*IntegrationChange, error) {
	pv, _ := json.Marshal(x.PathValues)
	out, err := scanChange(s.db.QueryRow(ctx, `INSERT INTO integration_changes (action, target, path_values, body, preview, requested_by, reason)
		VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING `+chgCols, x.Action, x.Target, pv, x.Body, x.Preview, x.RequestedBy, x.Reason))
	if IsUnique(err) {
		return nil, ErrConflict
	}
	return out, err
}

// SealChangeBody stores the sealed body once the change has an ID (the ID is
// the sealing context, so a body cannot be moved to another change).
func (s *Store) SealChangeBody(ctx context.Context, id string, body []byte) error {
	_, err := s.db.Exec(ctx, `UPDATE integration_changes SET body = $2 WHERE id = $1`, id, body)
	return err
}

func (s *Store) GetChange(ctx context.Context, id string) (*IntegrationChange, error) {
	return scanChange(s.db.QueryRow(ctx, `SELECT `+chgCols+` FROM integration_changes WHERE id::text = $1`, id))
}

func (s *Store) ListChanges(ctx context.Context, status string, limit int) ([]*IntegrationChange, error) {
	rows, err := s.db.Query(ctx, `SELECT `+chgCols+` FROM integration_changes WHERE ($1 = '' OR status = $1) ORDER BY created_at DESC LIMIT $2`, status, limit)
	if err != nil {
		return nil, err
	}
	return Collect(rows, scanChange)
}

// DecideChange moves a pending change to its outcome; ErrConflict when it is
// no longer pending (someone decided first).
func (s *Store) DecideChange(ctx context.Context, id, status, by, decision, reason string, applyErr *string) error {
	tag, err := s.db.Exec(ctx, `UPDATE integration_changes SET status = $2, decided_by = $3, decision = $4, decision_reason = $5, error = $6, decided_at = now(), body = NULL
		WHERE id = $1 AND status = 'pending'`, id, status, by, decision, reason, applyErr)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrConflict
	}
	return err
}

// ClaimChange takes a pending change for applying, so two approvers cannot
// apply it twice. It returns the change with its sealed body.
func (s *Store) ClaimChange(ctx context.Context, id string) (*IntegrationChange, error) {
	x, err := scanChange(s.db.QueryRow(ctx, `UPDATE integration_changes SET status = 'pending', decided_at = now()
		WHERE id = $1 AND status = 'pending' AND decided_at IS NULL RETURNING `+chgCols, id))
	if err == ErrNotFound {
		return nil, ErrConflict
	}
	return x, err
}
