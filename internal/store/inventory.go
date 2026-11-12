package store

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type InventoryScan struct {
	ID           string     `json:"id"`
	ConnectionID string     `json:"connection_id"`
	Status       string     `json:"status"`
	Error        *string    `json:"error,omitempty"`
	Found        int        `json:"found"`
	StartedBy    string     `json:"started_by"`
	StartedAt    time.Time  `json:"started_at"`
	FinishedAt   *time.Time `json:"finished_at,omitempty"`
}

const scanCols = `id, connection_id, status, error, found, started_by, started_at, finished_at`

func scanScan(r pgx.Row) (*InventoryScan, error) {
	var x InventoryScan
	if err := r.Scan(&x.ID, &x.ConnectionID, &x.Status, &x.Error, &x.Found, &x.StartedBy, &x.StartedAt, &x.FinishedAt); err != nil {
		return nil, NotFound(err)
	}
	return &x, nil
}

// StartScan records a running scan; ErrConflict when one is already running.
func (s *Store) StartScan(ctx context.Context, conn, by string) (*InventoryScan, error) {
	x, err := scanScan(s.db.QueryRow(ctx, `INSERT INTO inventory_scans (connection_id, started_by) VALUES ($1, $2) RETURNING `+scanCols, conn, by))
	if IsUnique(err) {
		return nil, ErrConflict
	}
	return x, err
}

// FailStaleScans ends scans left running by a restart.
func (s *Store) FailStaleScans(ctx context.Context) error {
	_, err := s.db.Exec(ctx, `UPDATE inventory_scans SET status = 'failed', error = 'interrupted by a restart', finished_at = now() WHERE status = 'running'`)
	return err
}

func (s *Store) FinishScan(ctx context.Context, id string, found int, scanErr error) error {
	if scanErr != nil {
		msg := scanErr.Error()
		_, err := s.db.Exec(ctx, `UPDATE inventory_scans SET status = 'failed', error = $2, finished_at = now() WHERE id = $1`, id, msg)
		return err
	}
	_, err := s.db.Exec(ctx, `UPDATE inventory_scans SET status = 'succeeded', found = $2, finished_at = now() WHERE id = $1`, id, found)
	return err
}

func (s *Store) ListScans(ctx context.Context, conn string, limit int) ([]*InventoryScan, error) {
	rows, err := s.db.Query(ctx, `SELECT `+scanCols+` FROM inventory_scans WHERE ($1 = '' OR connection_id::text = $1) ORDER BY started_at DESC LIMIT $2`, conn, limit)
	if err != nil {
		return nil, err
	}
	return Collect(rows, scanScan)
}

type InventoryItem struct {
	ConnectionID string            `json:"connection_id"`
	ResourceID   string            `json:"resource_id"`
	Type         string            `json:"type"`
	Service      string            `json:"service"`
	Name         string            `json:"name"`
	Region       string            `json:"region"`
	Account      string            `json:"account"`
	Project      string            `json:"project"`
	Tags         map[string]string `json:"tags"`
	Kind         string            `json:"kind"`
	Stack        string            `json:"stack"`
	AdoptedBy    string            `json:"adopted_by,omitempty"`
	AdoptedAs    string            `json:"adopted_module,omitempty"` // the resource (module instance) in its stack
	FirstSeen    time.Time         `json:"first_seen"`
	LastSeen     time.Time         `json:"last_seen"`
}

const invCols = `connection_id, resource_id, type, service, name, region, account, project, tags, kind, stack, adopted_by, adopted_module, first_seen, last_seen`

func scanInv(r pgx.Row) (*InventoryItem, error) {
	var x InventoryItem
	var tags []byte
	if err := r.Scan(&x.ConnectionID, &x.ResourceID, &x.Type, &x.Service, &x.Name, &x.Region, &x.Account, &x.Project, &tags, &x.Kind, &x.Stack, &x.AdoptedBy, &x.AdoptedAs, &x.FirstSeen, &x.LastSeen); err != nil {
		return nil, NotFound(err)
	}
	json.Unmarshal(tags, &x.Tags)
	return &x, nil
}

// ReplaceInventory stores a connection's scan result: items are upserted
// (keeping first_seen and adoption), and items the scan no longer saw are
// removed. A stack recorded by an adoption is kept unless the labels say
// otherwise.
func (s *Store) ReplaceInventory(ctx context.Context, conn string, items []*InventoryItem) error {
	return pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		now := time.Now()
		b := &pgx.Batch{}
		for _, it := range items {
			tags, _ := json.Marshal(it.Tags)
			b.Queue(`INSERT INTO inventory (connection_id, resource_id, type, name, region, account, project, tags, kind, stack, last_seen, service)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
				ON CONFLICT (connection_id, resource_id) DO UPDATE SET type = $3, name = $4, region = $5, account = $6, project = $7, tags = $8, kind = $9,
				  stack = CASE WHEN $10 <> '' THEN $10 ELSE inventory.stack END, last_seen = $11, service = $12`,
				conn, it.ResourceID, it.Type, it.Name, it.Region, it.Account, it.Project, tags, it.Kind, it.Stack, now, ServiceOf(it.Type))
		}
		if err := tx.SendBatch(ctx, b).Close(); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM inventory WHERE connection_id = $1 AND last_seen < $2`, conn, now)
		return err
	})
}

// ServiceOf is the cloud service a resource type belongs to.
func ServiceOf(typ string) string {
	if i := strings.IndexByte(typ, ':'); i >= 0 {
		return typ[:i]
	}
	if i := strings.IndexByte(typ, '/'); i >= 0 {
		return typ[:i]
	}
	return typ
}

type InventoryFilter struct {
	Connections []string // connections the caller may see; nil = all
	Connection  string
	Service     string
	Type        string
	Kind        string
	Managed     string // "" | "yes" | "no"
	Query       string
	Limit       int
	Offset      int
}

func (s *Store) ListInventory(ctx context.Context, f InventoryFilter) ([]*InventoryItem, int, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	where := `($1::text[] IS NULL OR connection_id::text = ANY($1)) AND ($2 = '' OR connection_id::text = $2) AND ($3 = '' OR kind = $3 OR ($3 = '-' AND kind = ''))
		AND ($4 = '' OR ($4 IN ('yes', 'no') AND ($4 = 'yes') = (stack <> '')) OR ($4 = 'adoptable' AND stack = '' AND kind <> ''))
		AND ($5 = '' OR name ILIKE '%' || $5 || '%' OR resource_id ILIKE '%' || $5 || '%' OR type ILIKE '%' || $5 || '%')
		AND ($8 = '' OR service = $8) AND ($9 = '' OR type = $9)`
	args := []any{f.Connections, f.Connection, f.Kind, f.Managed, f.Query}
	args = append(args, f.Limit, f.Offset, f.Service, f.Type)
	var total int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM inventory WHERE $6::int > -1 AND $7::int > -1 AND `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(ctx, `SELECT `+invCols+` FROM inventory WHERE `+where+` ORDER BY (stack <> ''), (kind = ''), type, name LIMIT $6 OFFSET $7`, args...)
	if err != nil {
		return nil, 0, err
	}
	items, err := Collect(rows, scanInv)
	return items, total, err
}

// FindInventoryItem finds a connection's item by a reference to it: its full
// ID (ARN), the last part of it (sg-…, a key's UUID) or its name.
func (s *Store) FindInventoryItem(ctx context.Context, conn, ref string) (*InventoryItem, error) {
	return scanInv(s.db.QueryRow(ctx, `SELECT `+invCols+` FROM inventory WHERE connection_id::text = $1
		AND (resource_id = $2 OR resource_id LIKE '%/' || $2 OR resource_id LIKE '%:' || $2 OR name = $2)
		ORDER BY (resource_id = $2) DESC, (kind <> '') DESC LIMIT 1`, conn, ref))
}

func (s *Store) GetInventoryItem(ctx context.Context, conn, id string) (*InventoryItem, error) {
	return scanInv(s.db.QueryRow(ctx, `SELECT `+invCols+` FROM inventory WHERE connection_id::text = $1 AND resource_id = $2`, conn, id))
}

// MarkAdopted records the stack that now manages an item.
func (s *Store) MarkAdopted(ctx context.Context, conn, id, stack, module, by string) error {
	_, err := s.db.Exec(ctx, `UPDATE inventory SET stack = $3, adopted_module = $4, adopted_by = $5 WHERE connection_id::text = $1 AND resource_id = $2`, conn, id, stack, module, by)
	return err
}

// InventoryCounts are totals for a connection, a service or a type.
type InventoryCounts struct {
	Total     int `json:"total"`
	Managed   int `json:"managed"`
	Adoptable int `json:"adoptable"` // unmanaged with a kind that can adopt it
}

const countCols = `count(*), count(*) FILTER (WHERE stack <> ''), count(*) FILTER (WHERE stack = '' AND kind <> '')`

// InventorySummary counts resources and services per connection.
func (s *Store) InventorySummary(ctx context.Context, conns []string) (map[string]InventoryCounts, map[string]int, error) {
	rows, err := s.db.Query(ctx, `SELECT connection_id::text, `+countCols+`, count(DISTINCT service) FROM inventory WHERE connection_id::text = ANY($1) GROUP BY 1`, conns)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	counts, services := map[string]InventoryCounts{}, map[string]int{}
	for rows.Next() {
		var id string
		var c InventoryCounts
		var n int
		if err := rows.Scan(&id, &c.Total, &c.Managed, &c.Adoptable, &n); err != nil {
			return nil, nil, err
		}
		counts[id], services[id] = c, n
	}
	return counts, services, rows.Err()
}

type InventoryType struct {
	Type string `json:"type"`
	Kind string `json:"kind,omitempty"` // the kind that adopts it
	InventoryCounts
}

type InventoryService struct {
	Service string          `json:"service"`
	Types   []InventoryType `json:"types"`
	InventoryCounts
}

// InventoryServices lists a connection's services with their resource types.
// InventoryAccounts is the cloud account each connection's last scan saw,
// for connections whose settings do not name it (Vault-issued credentials).
func (s *Store) InventoryAccounts(ctx context.Context, conns []string) map[string]string {
	out := map[string]string{}
	rows, err := s.db.Query(ctx, `SELECT DISTINCT ON (connection_id) connection_id::text, account FROM inventory
		WHERE connection_id = ANY($1::uuid[]) AND account <> '' ORDER BY connection_id, account`, conns)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var c, a string
		if rows.Scan(&c, &a) == nil {
			out[c] = a
		}
	}
	return out
}

func (s *Store) InventoryServices(ctx context.Context, conn string) ([]*InventoryService, error) {
	rows, err := s.db.Query(ctx, `SELECT service, type, max(kind), `+countCols+` FROM inventory WHERE connection_id = $1 GROUP BY service, type ORDER BY service, type`, conn)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*InventoryService
	for rows.Next() {
		var svc string
		var t InventoryType
		if err := rows.Scan(&svc, &t.Type, &t.Kind, &t.Total, &t.Managed, &t.Adoptable); err != nil {
			return nil, err
		}
		if len(out) == 0 || out[len(out)-1].Service != svc {
			out = append(out, &InventoryService{Service: svc, Types: []InventoryType{}})
		}
		cur := out[len(out)-1]
		cur.Types = append(cur.Types, t)
		cur.Total += t.Total
		cur.Managed += t.Managed
		cur.Adoptable += t.Adoptable
	}
	return out, rows.Err()
}
