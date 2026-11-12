package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

type CloudOrg struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	Provider     string          `json:"provider"`
	Discovery    json.RawMessage `json:"discovery"`
	Template     json.RawMessage `json:"template"`
	NameTemplate string          `json:"name_template"`
	SyncedAt     *time.Time      `json:"synced_at,omitempty"`
	SyncError    *string         `json:"sync_error,omitempty"`
	CreatedBy    string          `json:"created_by"`
	CreatedAt    time.Time       `json:"created_at"`
}

const orgCols = `id, name, provider, discovery, template, name_template, synced_at, sync_error, created_by, created_at`

func scanOrg(r pgx.Row) (*CloudOrg, error) {
	var o CloudOrg
	if err := r.Scan(&o.ID, &o.Name, &o.Provider, &o.Discovery, &o.Template, &o.NameTemplate, &o.SyncedAt, &o.SyncError, &o.CreatedBy, &o.CreatedAt); err != nil {
		return nil, NotFound(err)
	}
	return &o, nil
}

func (s *Store) CreateOrg(ctx context.Context, o *CloudOrg) (*CloudOrg, error) {
	out, err := scanOrg(s.db.QueryRow(ctx, `INSERT INTO cloud_orgs (name, provider, discovery, template, name_template, created_by) VALUES ($1, $2, $3, $4, $5, $6) RETURNING `+orgCols,
		o.Name, o.Provider, o.Discovery, o.Template, o.NameTemplate, o.CreatedBy))
	if IsUnique(err) {
		return nil, ErrConflict
	}
	return out, err
}

func (s *Store) UpdateOrg(ctx context.Context, o *CloudOrg) (*CloudOrg, error) {
	return scanOrg(s.db.QueryRow(ctx, `UPDATE cloud_orgs SET discovery = $2, template = $3, name_template = $4 WHERE id = $1 RETURNING `+orgCols,
		o.ID, o.Discovery, o.Template, o.NameTemplate))
}

func (s *Store) GetOrg(ctx context.Context, idOrName string) (*CloudOrg, error) {
	return scanOrg(s.db.QueryRow(ctx, `SELECT `+orgCols+` FROM cloud_orgs WHERE id::text = $1 OR name = $1`, idOrName))
}

func (s *Store) ListOrgs(ctx context.Context) ([]*CloudOrg, error) {
	rows, err := s.db.Query(ctx, `SELECT `+orgCols+` FROM cloud_orgs ORDER BY name`)
	if err != nil {
		return nil, err
	}
	return Collect(rows, scanOrg)
}

func (s *Store) DeleteOrg(ctx context.Context, id string) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM cloud_orgs WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

type OrgUnit struct {
	UnitID       string  `json:"id"`
	ParentID     string  `json:"parent_id"`
	Name         string  `json:"name"`
	Kind         string  `json:"kind"`
	External     string  `json:"external"`
	State        string  `json:"state"`
	Entity       string  `json:"entity"`
	ConnectionID *string `json:"connection_id,omitempty"`
}

// SyncOrg stores the units an organisation listing returned, keeping entity
// mappings and onboarded connections; units no longer listed are removed.
func (s *Store) SyncOrg(ctx context.Context, org string, units []*OrgUnit, syncErr error) error {
	if syncErr != nil {
		_, err := s.db.Exec(ctx, `UPDATE cloud_orgs SET sync_error = $2 WHERE id = $1`, org, syncErr.Error())
		return err
	}
	return pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		ids := make([]string, 0, len(units))
		b := &pgx.Batch{}
		for _, u := range units {
			ids = append(ids, u.UnitID)
			b.Queue(`INSERT INTO cloud_org_units (org_id, unit_id, parent_id, name, kind, external, state) VALUES ($1, $2, $3, $4, $5, $6, $7)
				ON CONFLICT (org_id, unit_id) DO UPDATE SET parent_id = $3, name = $4, kind = $5, external = $6, state = $7`,
				org, u.UnitID, u.ParentID, u.Name, u.Kind, u.External, u.State)
		}
		if err := tx.SendBatch(ctx, b).Close(); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM cloud_org_units WHERE org_id = $1 AND NOT (unit_id = ANY($2))`, org, ids); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE cloud_orgs SET synced_at = now(), sync_error = NULL WHERE id = $1`, org)
		return err
	})
}

func (s *Store) ListOrgUnits(ctx context.Context, org string) ([]*OrgUnit, error) {
	rows, err := s.db.Query(ctx, `SELECT unit_id, parent_id, name, kind, external, state, entity, connection_id FROM cloud_org_units WHERE org_id = $1 ORDER BY kind <> 'root', name`, org)
	if err != nil {
		return nil, err
	}
	return Collect(rows, func(r pgx.Row) (*OrgUnit, error) {
		var u OrgUnit
		return &u, r.Scan(&u.UnitID, &u.ParentID, &u.Name, &u.Kind, &u.External, &u.State, &u.Entity, &u.ConnectionID)
	})
}

func (s *Store) SetUnitEntity(ctx context.Context, org, unit, entity string) error {
	tag, err := s.db.Exec(ctx, `UPDATE cloud_org_units SET entity = $3 WHERE org_id = $1 AND unit_id = $2`, org, unit, entity)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (s *Store) SetUnitConnection(ctx context.Context, org, unit, conn string) error {
	_, err := s.db.Exec(ctx, `UPDATE cloud_org_units SET connection_id = $3 WHERE org_id = $1 AND unit_id = $2`, org, unit, conn)
	return err
}
