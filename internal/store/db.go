package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/itsPavanFeed/srustiops-backend/internal/audit"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
)

// Connect opens a PostgreSQL pool and checks it is reachable.
func Connect(ctx context.Context, url string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, err
	}
	// pool_max_conns in the URL wins; else SRUSTIOPS_DB_MAX_CONNS; else 20.
	if !strings.Contains(url, "pool_max_conns") {
		cfg.MaxConns = 20
		if n, err := strconv.Atoi(os.Getenv("SRUSTIOPS_DB_MAX_CONNS")); err == nil && n >= 4 && n <= 1000 {
			cfg.MaxConns = int32(n)
		}
	}
	db, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("connecting to PostgreSQL: %w", err)
	}
	return db, nil
}

// Migrate applies the *.sql files in fsys in name order, once each, under an
// advisory lock so concurrent replicas do not race.
func Migrate(ctx context.Context, db *pgxpool.Pool, fsys fs.FS) error {
	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(7001)`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	names, err := fs.Glob(fsys, "*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, n := range names {
		var done bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE name = $1)`, n).Scan(&done); err != nil {
			return err
		}
		if done {
			continue
		}
		sql, _ := fs.ReadFile(fsys, n)
		if _, err := tx.Exec(ctx, string(sql)); err != nil {
			return fmt.Errorf("migration %s: %w", n, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (name) VALUES ($1)`, n); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// Base holds what both planes' databases share: key/value metadata (sealed
// signing keys) and the hash-chained audit log. Both schemas define
// schema_meta and audit_events identically.
type Base struct {
	db       *pgxpool.Pool
	scopeCol string // audit_events column holding the event's scope
}

// NewBase is for the central schema, where audit events are scoped by tenant slug.
func NewBase(db *pgxpool.Pool) Base { return Base{db: db, scopeCol: "entity"} }

func (b *Base) Close()              { b.db.Close() }
func (b *Base) Pool() *pgxpool.Pool { return b.db }

func IsUnique(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505"
}

// IsReferenced reports a foreign-key violation: the row is still in use.
func IsReferenced(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23503"
}

func NotFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func (b *Base) GetMeta(ctx context.Context, key string) ([]byte, error) {
	var v []byte
	err := b.db.QueryRow(ctx, `SELECT value FROM schema_meta WHERE key = $1`, key).Scan(&v)
	return v, NotFound(err)
}

// PutMetaIfAbsent stores a value unless one exists, and returns the stored value.
func (b *Base) PutMetaIfAbsent(ctx context.Context, key string, v []byte) ([]byte, error) {
	if _, err := b.db.Exec(ctx, `INSERT INTO schema_meta (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING`, key, v); err != nil {
		return nil, err
	}
	return b.GetMeta(ctx, key)
}

// AppendAudit adds an event to the hash chain and returns once it is
// committed. Writers are grouped: whoever finds no write in progress takes
// the chain's lock for everyone waiting, appends up to auditBatch events in
// one transaction and tells each caller, so a burst of changes costs one
// lock and one commit instead of one each. A transaction-scoped advisory
// lock still serialises writers across processes, so the chain never forks.
func (b *Base) AppendAudit(ctx context.Context, actor, action, target, scope string, payload any) error {
	p, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	e := audit.Event{TS: time.Now(), Actor: actor, Action: action, Target: target, Scope: scope, Payload: p}
	audit.Normalize(&e)
	req := &auditReq{e: e, done: make(chan error, 1)}
	a := b.auditor()
	a.mu.Lock()
	a.queue = append(a.queue, req)
	lead := !a.writing
	a.writing = true
	a.mu.Unlock()
	if lead {
		b.writeAudits(context.WithoutCancel(ctx), a)
	}
	return <-req.done
}

const auditBatch = 200

type auditReq struct {
	e    audit.Event
	done chan error
}

type auditWriter struct {
	mu      sync.Mutex
	queue   []*auditReq
	writing bool
}

// auditors holds one writer per database pool (Base is copied by value).
var auditors sync.Map // *pgxpool.Pool -> *auditWriter

func (b *Base) auditor() *auditWriter {
	v, _ := auditors.LoadOrStore(b.db, &auditWriter{})
	return v.(*auditWriter)
}

// writeAudits drains the queue in batches until it is empty.
func (b *Base) writeAudits(ctx context.Context, a *auditWriter) {
	for {
		a.mu.Lock()
		n := min(len(a.queue), auditBatch)
		if n == 0 {
			a.writing = false
			a.mu.Unlock()
			return
		}
		batch := a.queue[:n:n]
		a.queue = a.queue[n:]
		a.mu.Unlock()
		err := b.appendBatch(ctx, batch)
		for _, r := range batch {
			r.done <- err
		}
	}
}

func (b *Base) appendBatch(ctx context.Context, batch []*auditReq) error {
	tx, err := b.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(7002)`); err != nil {
		return err
	}
	prev := audit.Genesis
	if err := tx.QueryRow(ctx, `SELECT hash FROM audit_events ORDER BY id DESC LIMIT 1`).Scan(&prev); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	for _, r := range batch {
		e := r.e
		h := audit.Hash(prev, e)
		if _, err := tx.Exec(ctx, `INSERT INTO audit_events (ts, actor, action, target, `+b.scopeCol+`, payload, prev_hash, hash) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			e.TS, e.Actor, e.Action, e.Target, e.Scope, string(e.Payload), prev, h); err != nil {
			return err
		}
		prev = h
	}
	return tx.Commit(ctx)
}

type AuditQuery struct {
	Before int64
	Limit  int
	Filter string
	Scopes []string  // nil = every event; otherwise events in these scopes only
	Since  time.Time // zero = no lower bound (inclusive)
	Until  time.Time // zero = no upper bound (exclusive)
}

func (b *Base) ListAudit(ctx context.Context, q AuditQuery) ([]audit.Event, error) {
	sql := `SELECT id, ts, actor, action, target, ` + b.scopeCol + `, payload::text, prev_hash, hash FROM audit_events WHERE ($1 = 0 OR id < $1)`
	args := []any{q.Before, q.Limit}
	if q.Scopes != nil {
		args = append(args, q.Scopes)
		sql += fmt.Sprintf(` AND `+b.scopeCol+` = ANY($%d)`, len(args))
	}
	if q.Filter != "" {
		args = append(args, "%"+strings.NewReplacer("%", "", "_", "").Replace(q.Filter)+"%")
		sql += fmt.Sprintf(` AND (action LIKE $%[1]d OR target LIKE $%[1]d OR actor LIKE $%[1]d)`, len(args))
	}
	if !q.Since.IsZero() {
		args = append(args, q.Since)
		sql += fmt.Sprintf(` AND ts >= $%d`, len(args))
	}
	if !q.Until.IsZero() {
		args = append(args, q.Until)
		sql += fmt.Sprintf(` AND ts < $%d`, len(args))
	}
	rows, err := b.db.Query(ctx, sql+` ORDER BY id DESC LIMIT $2`, args...)
	if err != nil {
		return nil, err
	}
	return scanAudit(rows)
}

// AuditAfter returns up to limit events with id > after, oldest first (for exports).
func (b *Base) AuditAfter(ctx context.Context, after int64, limit int) ([]audit.Event, error) {
	rows, err := b.db.Query(ctx, `SELECT id, ts, actor, action, target, `+b.scopeCol+`, payload::text, prev_hash, hash FROM audit_events WHERE id > $1 ORDER BY id LIMIT $2`, after, limit)
	if err != nil {
		return nil, err
	}
	return scanAudit(rows)
}

// LastAuditID is the newest event's id (0 when empty).
func (b *Base) LastAuditID(ctx context.Context) int64 {
	var id int64
	b.db.QueryRow(ctx, `SELECT COALESCE(max(id), 0) FROM audit_events`).Scan(&id)
	return id
}

// VerifyAudit walks the whole chain in pages and returns the first broken id (0 = intact).
func (b *Base) VerifyAudit(ctx context.Context) (checked int, broken int64, err error) {
	prev := audit.Genesis
	var after int64
	for {
		rows, err := b.db.Query(ctx, `SELECT id, ts, actor, action, target, `+b.scopeCol+`, payload::text, prev_hash, hash FROM audit_events WHERE id > $1 ORDER BY id LIMIT 5000`, after)
		if err != nil {
			return checked, 0, err
		}
		evs, err := scanAudit(rows)
		if err != nil {
			return checked, 0, err
		}
		if len(evs) == 0 {
			return checked, 0, nil
		}
		if b := audit.Verify(evs, prev); b != 0 {
			return checked, b, nil
		}
		checked += len(evs)
		prev = evs[len(evs)-1].Hash
		after = evs[len(evs)-1].ID
	}
}

func scanAudit(rows pgx.Rows) ([]audit.Event, error) {
	defer rows.Close()
	out := []audit.Event{}
	for rows.Next() {
		var e audit.Event
		var p string
		if err := rows.Scan(&e.ID, &e.TS, &e.Actor, &e.Action, &e.Target, &e.Scope, &p, &e.PrevHash, &e.Hash); err != nil {
			return nil, err
		}
		e.Payload = json.RawMessage(p)
		out = append(out, e)
	}
	return out, rows.Err()
}

// Collect scans every row with scan.
func Collect[T any](rows pgx.Rows, scan func(pgx.Row) (*T, error)) ([]*T, error) {
	defer rows.Close()
	out := []*T{}
	for rows.Next() {
		x, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}
