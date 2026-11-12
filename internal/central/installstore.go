package central

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/itsPavanFeed/srustiops-backend/internal/store"
)

func (s *Store) CreateInstallToken(ctx context.Context, tenantID string, hash []byte, by string, expires time.Time) error {
	_, err := s.Pool().Exec(ctx, `INSERT INTO install_tokens (tenant_id, token_hash, created_by, expires_at) VALUES ($1, $2, $3, $4)`, tenantID, hash, by, expires)
	return err
}

// TakeInstallToken burns a live install token of the tenant; it works once.
func (s *Store) TakeInstallToken(ctx context.Context, slug string, hash []byte) (*Tenant, error) {
	var id string
	err := s.Pool().QueryRow(ctx, `UPDATE install_tokens i SET used_at = now() FROM tenants t
		WHERE i.tenant_id = t.id AND t.slug = $1 AND i.token_hash = $2 AND i.used_at IS NULL AND i.expires_at > now()
		RETURNING t.id`, slug, hash).Scan(&id)
	if err != nil {
		return nil, store.NotFound(err)
	}
	return s.Tenant(ctx, slug)
}

type InstallEvent struct {
	Step   string    `json:"step"`
	Detail string    `json:"detail,omitempty"`
	At     time.Time `json:"at"`
}

func (s *Store) AddInstallEvent(ctx context.Context, tenantID, step, detail string) {
	s.Pool().Exec(ctx, `INSERT INTO install_events (tenant_id, step, detail) VALUES ($1, $2, $3)`, tenantID, step, detail)
}

func (s *Store) InstallEvents(ctx context.Context, tenantID string) ([]*InstallEvent, error) {
	rows, err := s.Pool().Query(ctx, `SELECT step, detail, at FROM install_events WHERE tenant_id = $1 ORDER BY id DESC LIMIT 50`, tenantID)
	if err != nil {
		return nil, err
	}
	return store.Collect(rows, func(r pgx.Row) (*InstallEvent, error) {
		var e InstallEvent
		return &e, r.Scan(&e.Step, &e.Detail, &e.At)
	})
}

// ActivateTenant marks a pending tenant connected; false when it already was.
func (s *Store) ActivateTenant(ctx context.Context, tenantID string) bool {
	tag, err := s.Pool().Exec(ctx, `UPDATE tenants SET status = 'active', updated_at = now() WHERE id = $1 AND status = 'pending'`, tenantID)
	return err == nil && tag.RowsAffected() == 1
}
