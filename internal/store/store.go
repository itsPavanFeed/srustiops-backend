// Package store is the PostgreSQL persistence layer. Store is a tenant plane's
// database: cloud connections, environments, stacks, runs, approvals, state and
// the audit log of one tenant. Rows are scoped to a business unit (BU) and also
// record the BU's entity.
package store

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
)

//go:embed migrations/*.sql
var migrations embed.FS

type Store struct {
	Base
	prScope atomic.Pointer[string] // the contracts repository pull requests belong to (repo_key)
}

// SetPRScope names the contracts repository (provider and owner/repo):
// pull-request reads and writes see only its pull requests.
func (s *Store) SetPRScope(provider, repo string) {
	if provider == "" {
		provider = "github"
	}
	k := strings.ToLower(provider + ":" + repo)
	if cur := s.prScope.Load(); cur == nil || *cur != k {
		s.prScope.Store(&k)
	}
}

func (s *Store) prKey() string {
	if k := s.prScope.Load(); k != nil {
		return *k
	}
	return ""
}

func Open(ctx context.Context, url string) (*Store, error) {
	db, err := Connect(ctx, url)
	if err != nil {
		return nil, err
	}
	return &Store{Base: Base{db: db, scopeCol: "bu"}}, nil
}

func (s *Store) Migrate(ctx context.Context) error {
	sub, _ := fs.Sub(migrations, "migrations")
	return Migrate(ctx, s.db, sub)
}

// buFilter returns a SQL condition on col for a visible-BUs list (nil = all).
func buFilter(col string, bus []string, args *[]any) string {
	if bus == nil {
		return "true"
	}
	*args = append(*args, bus)
	return fmt.Sprintf("%s = ANY($%d)", col, len(*args))
}

// ---- runners (tenant-wide) ----

type Runner struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Pool       string     `json:"pool"`
	CreatedAt  time.Time  `json:"created_at"`
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

const runnerCols = `id, name, pool, created_at, last_seen_at, revoked_at`

func scanRunner(r pgx.Row) (*Runner, error) {
	var x Runner
	err := r.Scan(&x.ID, &x.Name, &x.Pool, &x.CreatedAt, &x.LastSeenAt, &x.RevokedAt)
	return &x, NotFound(err)
}

func (s *Store) CreateRunner(ctx context.Context, name, pool string, hash []byte) (*Runner, error) {
	if err := s.checkLimit(ctx, "runners"); err != nil {
		return nil, err
	}
	r, err := scanRunner(s.db.QueryRow(ctx, `INSERT INTO runners (name, pool, token_hash) VALUES ($1, $2, $3) RETURNING `+runnerCols, name, pool, hash))
	if IsUnique(err) {
		return nil, ErrConflict
	}
	return r, err
}

func (s *Store) RunnerByHash(ctx context.Context, hash []byte) (*Runner, error) {
	return scanRunner(s.db.QueryRow(ctx, `UPDATE runners SET last_seen_at = now()
		WHERE token_hash = $1 AND revoked_at IS NULL RETURNING `+runnerCols, hash))
}

func (s *Store) ListRunners(ctx context.Context) ([]*Runner, error) {
	rows, err := s.db.Query(ctx, `SELECT `+runnerCols+` FROM runners ORDER BY name`)
	if err != nil {
		return nil, err
	}
	return Collect(rows, scanRunner)
}

func (s *Store) RevokeRunner(ctx context.Context, id string) error {
	tag, err := s.db.Exec(ctx, `UPDATE runners SET revoked_at = now() WHERE id::text = $1 AND revoked_at IS NULL`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// ---- cloud connections (tenant-wide) ----

// Connection is a cloud account, project or subscription registered once per
// tenant. It holds identifiers only; Entities limits which entities may use it.
type Connection struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Cloud    json.RawMessage `json:"cloud"`
	Entities []string        `json:"entities"` // empty = every entity
	// Environment is the one environment using it ("entity:name"; "" = none).
	EnvironmentID *string   `json:"environment_id,omitempty"`
	Environment   string    `json:"environment,omitempty"`
	CreatedBy     string    `json:"created_by"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

const connCols = `id, name, cloud, entities, environment_id,
	COALESCE((SELECT e.entity || ':' || e.name FROM environments e WHERE e.id = environment_id), ''), created_by, created_at, updated_at`

func scanConn(r pgx.Row) (*Connection, error) {
	var c Connection
	err := r.Scan(&c.ID, &c.Name, &c.Cloud, &c.Entities, &c.EnvironmentID, &c.Environment, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt)
	if c.Entities == nil {
		c.Entities = []string{}
	}
	return &c, NotFound(err)
}

// Allows reports whether an entity may use the connection.
func (c *Connection) Allows(entity string) bool {
	if len(c.Entities) == 0 {
		return true
	}
	return containsStr(c.Entities, entity)
}

func (s *Store) CreateConnection(ctx context.Context, c *Connection) (*Connection, error) {
	if err := s.checkLimit(ctx, "connections"); err != nil {
		return nil, err
	}
	out, err := scanConn(s.db.QueryRow(ctx, `INSERT INTO cloud_connections (name, cloud, entities, created_by) VALUES ($1, $2, $3, $4) RETURNING `+connCols,
		c.Name, c.Cloud, c.Entities, c.CreatedBy))
	if IsUnique(err) {
		return nil, ErrConflict
	}
	return out, err
}

func (s *Store) UpdateConnection(ctx context.Context, c *Connection) (*Connection, error) {
	return scanConn(s.db.QueryRow(ctx, `UPDATE cloud_connections SET cloud = $2, entities = $3, updated_at = now() WHERE id = $1 RETURNING `+connCols,
		c.ID, c.Cloud, c.Entities))
}

func (s *Store) GetConnection(ctx context.Context, idOrName string) (*Connection, error) {
	return scanConn(s.db.QueryRow(ctx, `SELECT `+connCols+` FROM cloud_connections WHERE id::text = $1 OR name = $1`, idOrName))
}

func (s *Store) ListConnections(ctx context.Context) ([]*Connection, error) {
	rows, err := s.db.Query(ctx, `SELECT `+connCols+` FROM cloud_connections ORDER BY name`)
	if err != nil {
		return nil, err
	}
	return Collect(rows, scanConn)
}

// ConnectionPage lists connections of one cloud ("" = all), a page at a time,
// with the total count and the count per cloud.
func (s *Store) ConnectionPage(ctx context.Context, provider string, limit, offset int) ([]*Connection, int, map[string]int, error) {
	counts := map[string]int{}
	rows, err := s.db.Query(ctx, `SELECT cloud->>'provider', count(*) FROM cloud_connections GROUP BY 1`)
	if err != nil {
		return nil, 0, nil, err
	}
	for rows.Next() {
		var p *string
		var n int
		if err := rows.Scan(&p, &n); err != nil {
			rows.Close()
			return nil, 0, nil, err
		}
		if p != nil {
			counts[*p] = n
		}
	}
	rows.Close()
	total := 0
	for k, n := range counts {
		if provider == "" || k == provider {
			total += n
		}
	}
	rows, err = s.db.Query(ctx, `SELECT `+connCols+` FROM cloud_connections WHERE $1 = '' OR cloud->>'provider' = $1
		ORDER BY name LIMIT $2 OFFSET $3`, provider, limit, offset)
	if err != nil {
		return nil, 0, nil, err
	}
	cs, err := Collect(rows, scanConn)
	return cs, total, counts, err
}

// ---- environments ----

// Environment is a deployment target of an entity (product), shared by all of
// its business units: a cloud connection (or none) plus a tier and guardrails.
// Cloud is read from the connection. Names are unique within the entity.
type Environment struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Entity string `json:"entity"`
	Tier   string `json:"tier"`
	// Connections are the cloud connections of this environment; each
	// belongs to this environment only. ConnectionID, Connection and Cloud
	// are the one a stack deploys to: the environment's only connection, or
	// the stack's choice (see ForConnection).
	Connections  []EnvConnection `json:"connections"`
	ConnectionID *string         `json:"connection_id,omitempty"`
	Connection   string          `json:"connection,omitempty"`
	Cloud        json.RawMessage `json:"cloud"`
	RunnerPool   string          `json:"runner_pool"`
	MaxDestroys  int             `json:"max_destroys"`
	MaxCreates   int             `json:"max_creates"`         // per run; 0 = no limit
	MaxImports   int             `json:"max_imports"`         // per run; 0 = no limit
	MaxRunning   int             `json:"max_concurrent_runs"` // plans and applies at once; 0 = no cap
	AllowDestroy bool            `json:"allow_destroy"`
	Schedule     json.RawMessage `json:"schedule"` // see api.envSchedule
	CreatedBy    string          `json:"created_by"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

type EnvConnection struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Provider string          `json:"provider"`
	Cloud    json.RawMessage `json:"-"`
}

const envSelect = `SELECT e.id, e.name, e.entity, e.tier,
	COALESCE((SELECT jsonb_agg(jsonb_build_object('id', c.id, 'name', c.name, 'provider', c.cloud->>'provider', 'cloud', c.cloud) ORDER BY c.name)
	  FROM cloud_connections c WHERE c.environment_id = e.id), '[]'::jsonb),
	e.runner_pool, e.max_destroys, e.max_creates, e.max_imports, e.allow_destroy, e.schedule, e.created_by, e.created_at, e.updated_at, e.max_concurrent_runs
	FROM environments e`

var noCloud = json.RawMessage(`{"provider":"none"}`)

func scanEnv(r pgx.Row) (*Environment, error) {
	var e Environment
	var conns []byte
	err := r.Scan(&e.ID, &e.Name, &e.Entity, &e.Tier, &conns, &e.RunnerPool, &e.MaxDestroys, &e.MaxCreates, &e.MaxImports, &e.AllowDestroy, &e.Schedule, &e.CreatedBy, &e.CreatedAt, &e.UpdatedAt, &e.MaxRunning)
	if err != nil {
		return nil, NotFound(err)
	}
	var raw []struct {
		ID, Name, Provider string
		Cloud              json.RawMessage
	}
	json.Unmarshal(conns, &raw)
	e.Connections = make([]EnvConnection, 0, len(raw))
	for _, c := range raw {
		e.Connections = append(e.Connections, EnvConnection{ID: c.ID, Name: c.Name, Provider: c.Provider, Cloud: c.Cloud})
	}
	e.Cloud = noCloud
	if len(e.Connections) == 1 {
		e.use(&e.Connections[0])
	}
	return &e, nil
}

func (e *Environment) use(c *EnvConnection) {
	id := c.ID
	e.ConnectionID, e.Connection, e.Cloud = &id, c.Name, c.Cloud
}

// ForConnection returns a copy of the environment that deploys to one of its
// connections (by ID or name). "" keeps the default: the only connection,
// or none when there are several.
func (e *Environment) ForConnection(conn string) (*Environment, bool) {
	cp := *e
	if conn == "" {
		return &cp, true
	}
	for i := range e.Connections {
		if e.Connections[i].ID == conn || e.Connections[i].Name == conn {
			cp.use(&e.Connections[i])
			return &cp, true
		}
	}
	return nil, false
}

// SetEnvironmentConnections makes these the environment's connections.
// ErrConflict names a connection already used by another environment, or one
// still used by a stack of this environment.
func (s *Store) SetEnvironmentConnections(ctx context.Context, env string, ids []string) error {
	return pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		var taken string
		err := tx.QueryRow(ctx, `SELECT c.name FROM cloud_connections c WHERE c.id::text = ANY($2) AND c.environment_id IS NOT NULL AND c.environment_id <> $1 LIMIT 1 FOR UPDATE`, env, ids).Scan(&taken)
		if err == nil {
			return fmt.Errorf("%w: connection %s already belongs to another environment", ErrConflict, taken)
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var used string
		err = tx.QueryRow(ctx, `SELECT c.name FROM stacks st JOIN cloud_connections c ON c.id = st.connection_id
			WHERE st.environment_id = $1 AND NOT (st.connection_id::text = ANY($2)) LIMIT 1`, env, ids).Scan(&used)
		if err == nil {
			return fmt.Errorf("%w: connection %s is still used by stacks of this environment", ErrConflict, used)
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE cloud_connections SET environment_id = NULL WHERE environment_id = $1 AND NOT (id::text = ANY($2))`, env, ids); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE cloud_connections SET environment_id = $1 WHERE id::text = ANY($2)`, env, ids)
		return err
	})
}

func (s *Store) CreateEnvironment(ctx context.Context, e *Environment) (*Environment, error) {
	if err := s.checkLimit(ctx, "environments"); err != nil {
		return nil, err
	}
	var id string
	err := s.db.QueryRow(ctx, `INSERT INTO environments (name, entity, tier, runner_pool, max_destroys, max_creates, max_imports, allow_destroy, created_by, max_concurrent_runs)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id`, e.Name, e.Entity, e.Tier, e.RunnerPool, e.MaxDestroys, e.MaxCreates, e.MaxImports, e.AllowDestroy, e.CreatedBy, e.MaxRunning).Scan(&id)
	if IsUnique(err) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	return s.GetEnvironment(ctx, id)
}

func (s *Store) UpdateEnvironment(ctx context.Context, e *Environment) (*Environment, error) {
	tag, err := s.db.Exec(ctx, `UPDATE environments SET tier = $2, runner_pool = $3, max_destroys = $4, allow_destroy = $5,
		max_creates = $6, max_imports = $7, max_concurrent_runs = $8, updated_at = now() WHERE id = $1`, e.ID, e.Tier, e.RunnerPool, e.MaxDestroys, e.AllowDestroy, e.MaxCreates, e.MaxImports, e.MaxRunning)
	if err == nil && tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return s.GetEnvironment(ctx, e.ID)
}

// GetEnvironment finds an environment by ID, by "entity:name", or by a bare
// name when exactly one entity has an environment of that name.
func (s *Store) GetEnvironment(ctx context.Context, ref string) (*Environment, error) {
	if entity, name, ok := strings.Cut(ref, ":"); ok {
		return s.EntityEnvironment(ctx, entity, name)
	}
	rows, err := s.db.Query(ctx, envSelect+` WHERE e.id::text = $1 OR e.name = $1 LIMIT 2`, ref)
	if err != nil {
		return nil, err
	}
	es, err := Collect(rows, scanEnv)
	if err != nil {
		return nil, err
	}
	if len(es) != 1 {
		return nil, ErrNotFound // unknown, or ambiguous without the entity
	}
	return es[0], nil
}

// EntityEnvironment finds an entity's environment by name.
func (s *Store) EntityEnvironment(ctx context.Context, entity, name string) (*Environment, error) {
	return scanEnv(s.db.QueryRow(ctx, envSelect+` WHERE e.entity = $1 AND e.name = $2`, entity, name))
}

// ListEnvironments lists the environments of the given entities (nil = all).
func (s *Store) ListEnvironments(ctx context.Context, entities []string) ([]*Environment, error) {
	args := []any{}
	rows, err := s.db.Query(ctx, envSelect+` WHERE `+buFilter("e.entity", entities, &args)+` ORDER BY e.entity, e.name`, args...)
	if err != nil {
		return nil, err
	}
	return Collect(rows, scanEnv)
}

// ---- stacks ----

type Stack struct {
	ID            string          `json:"id"`
	Name          string          `json:"name"`
	BU            string          `json:"bu"`
	Entity        string          `json:"entity"`
	EnvironmentID string          `json:"environment_id"`
	Environment   string          `json:"environment"`
	ConnectionID  *string         `json:"connection_id,omitempty"` // the environment connection it deploys to
	Connection    string          `json:"connection,omitempty"`
	Spec          json.RawMessage `json:"spec"`
	CreatedBy     string          `json:"created_by"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
	LastRun       *RunBrief       `json:"last_run,omitempty"`
	Drift         DriftSettings   `json:"drift"`
	ManagedBy     string          `json:"managed_by"`           // ui | git
	SourceRef     string          `json:"source_ref,omitempty"` // contracts repo commit for Git-managed stacks
	PRNumber      *int            `json:"pr_number,omitempty"`  // proposed by this open pull request, not applied yet
	LastAppliedAt *time.Time      `json:"last_applied_at,omitempty"`
	// ImportsPending counts import blocks of the spec not applied yet (Git
	// contracts keep applied ones; they are settled and not counted).
	ImportsPending int `json:"imports_pending"`
	// WaitsOn: a plan of this stack is deferred until these stacks (which it
	// references) have applied the outputs it needs.
	WaitsOn []string `json:"waits_on,omitempty"`
	// Lock: while set, no plan or apply starts (drift checks still may).
	Lock *StackLock `json:"lock,omitempty"`
	// Resources the last plan or apply saw in the stack (from state).
	Resources   json.RawMessage `json:"resources,omitempty"`
	ResourcesAt *time.Time      `json:"resources_at,omitempty"`
	DeletedAt   *time.Time      `json:"deleted_at,omitempty"`
	ClonedFrom  *string         `json:"cloned_from,omitempty"` // stack ID
	ClonedName  string          `json:"cloned_from_name,omitempty"`
	Template    string          `json:"template,omitempty"`
}

type StackLock struct {
	By     string    `json:"by"`
	Reason string    `json:"reason"`
	At     time.Time `json:"at"`
}

type DriftSettings struct {
	IntervalMinutes int        `json:"interval_minutes"` // 0 = no scheduled checks
	AutoRemediate   bool       `json:"auto_remediate"`   // queue a corrective plan (still approved) when drift is found
	LastCheck       *time.Time `json:"last_check,omitempty"`
}

type RunBrief struct {
	ID        string    `json:"id"`
	Status    string    `json:"status"`
	Operation string    `json:"operation"`
	CreatedAt time.Time `json:"created_at"`
}

const stackSelect = `SELECT s.id, s.name, s.bu, s.entity, s.environment_id, e.name, s.connection_id, COALESCE((SELECT c.name FROM cloud_connections c WHERE c.id = s.connection_id), ''), s.spec, s.created_by, s.created_at, s.updated_at,
	s.drift_interval_minutes, s.drift_auto_remediate, s.last_drift_check, s.managed_by, s.source_ref, s.pr_number, s.settled_imports,
	(SELECT waits_on FROM pending_runs WHERE stack_id = s.id),
	lr.id, lr.status, lr.operation, lr.created_at,
	(SELECT max(finished_at) FROM runs WHERE stack_id = s.id AND status = 'applied'),
	s.locked_by, s.locked_reason, s.locked_at, s.resources, s.resources_at, s.deleted_at, s.cloned_from::text,
	COALESCE((SELECT c.name FROM stacks c WHERE c.id = s.cloned_from), ''), s.template
	FROM stacks s JOIN environments e ON e.id = s.environment_id
	LEFT JOIN LATERAL (SELECT id, status, operation, created_at FROM runs WHERE stack_id = s.id ORDER BY created_at DESC LIMIT 1) lr ON true`

func scanStack(r pgx.Row) (*Stack, error) {
	var x Stack
	var rid, rstatus, rop *string
	var rat *time.Time
	var settled []string
	var lockBy *string
	var lockReason string
	var lockAt *time.Time
	err := r.Scan(&x.ID, &x.Name, &x.BU, &x.Entity, &x.EnvironmentID, &x.Environment, &x.ConnectionID, &x.Connection, &x.Spec, &x.CreatedBy, &x.CreatedAt, &x.UpdatedAt,
		&x.Drift.IntervalMinutes, &x.Drift.AutoRemediate, &x.Drift.LastCheck, &x.ManagedBy, &x.SourceRef, &x.PRNumber, &settled, &x.WaitsOn, &rid, &rstatus, &rop, &rat, &x.LastAppliedAt,
		&lockBy, &lockReason, &lockAt, &x.Resources, &x.ResourcesAt, &x.DeletedAt, &x.ClonedFrom, &x.ClonedName, &x.Template)
	if lockBy != nil && lockAt != nil {
		x.Lock = &StackLock{By: *lockBy, Reason: lockReason, At: *lockAt}
	}
	if rid != nil {
		x.LastRun = &RunBrief{ID: *rid, Status: *rstatus, Operation: *rop, CreatedAt: *rat}
	}
	var sp struct {
		Imports []struct {
			To string `json:"to"`
		} `json:"imports"`
	}
	json.Unmarshal(x.Spec, &sp)
	done := map[string]bool{}
	for _, a := range settled {
		done[a] = true
	}
	for _, im := range sp.Imports {
		if !done[im.To] {
			x.ImportsPending++
		}
	}
	return &x, NotFound(err)
}

// SettleImports records import addresses that are applied (or in state).
func (s *Store) SettleImports(ctx context.Context, stackID string, addrs []string) error {
	if len(addrs) == 0 {
		return nil
	}
	_, err := s.db.Exec(ctx, `UPDATE stacks SET settled_imports = ARRAY(SELECT DISTINCT unnest(settled_imports || $2::text[])) WHERE id = $1`, stackID, addrs)
	return err
}

func (s *Store) CreateStack(ctx context.Context, name, bu, entity, envID string, conn *string, spec []byte, by string) (*Stack, error) {
	return s.CreateManagedStack(ctx, name, bu, entity, envID, conn, spec, by, "ui", "")
}

// CreateManagedStack creates a stack owned by the UI or by the contracts repository.
func (s *Store) CreateManagedStack(ctx context.Context, name, bu, entity, envID string, conn *string, spec []byte, by, managedBy, ref string) (*Stack, error) {
	if err := s.checkLimit(ctx, "stacks"); err != nil {
		return nil, err
	}
	var id string
	err := s.db.QueryRow(ctx, `INSERT INTO stacks (name, bu, entity, environment_id, connection_id, spec, created_by, managed_by, source_ref) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
		name, bu, entity, envID, conn, spec, by, managedBy, ref).Scan(&id)
	if IsUnique(err) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	return s.GetStack(ctx, id)
}

// UpdateStack replaces a stack's spec. It fails while a run is active, so a
// plan can never be applied against a spec it was not made from.
func (s *Store) UpdateStack(ctx context.Context, id string, spec []byte) error {
	tag, err := s.db.Exec(ctx, `UPDATE stacks SET spec = $2, updated_at = now() WHERE id = $1
		AND NOT EXISTS (SELECT 1 FROM runs WHERE stack_id = $1 AND status IN ('queued','planning','planned','apply_queued','applying'))`, id, spec)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrConflict
	}
	return err
}

// UpdateGitStack replaces a Git-managed stack's spec at a new commit (refused
// while a run is active, like UpdateStack).
// SetStackConnection moves a stack (with no active run) to another
// connection of its environment.
func (s *Store) SetStackConnection(ctx context.Context, id string, conn *string) error {
	_, err := s.db.Exec(ctx, `UPDATE stacks SET connection_id = $2, updated_at = now() WHERE id = $1`, id, conn)
	return err
}

func (s *Store) UpdateGitStack(ctx context.Context, id string, spec []byte, ref string) error {
	tag, err := s.db.Exec(ctx, `UPDATE stacks SET spec = $2, source_ref = $3, pr_number = NULL, updated_at = now() WHERE id = $1 AND managed_by = 'git'
		AND NOT EXISTS (SELECT 1 FROM runs WHERE stack_id = $1 AND status IN ('queued','planning','planned','apply_queued','applying'))`, id, spec, ref)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrConflict
	}
	return err
}

func (s *Store) GetStack(ctx context.Context, idOrName string) (*Stack, error) {
	// By ID a deleted stack is still found (its runs link to it); by name only live ones.
	return scanStack(s.db.QueryRow(ctx, stackSelect+` WHERE s.id::text = $1 OR (s.name = $1 AND s.deleted_at IS NULL) ORDER BY s.deleted_at NULLS FIRST LIMIT 1`, idOrName))
}

// stackSummarySelect is stackSelect without the heavy columns: the spec
// keeps each module's name, kind and source and the import targets (what
// lists and counts need), and resources are left out.
var stackSummarySelect = strings.NewReplacer(
	"s.environment_id, e.name, s.connection_id, COALESCE((SELECT c.name FROM cloud_connections c WHERE c.id = s.connection_id), ''), s.spec,",
	`s.environment_id, e.name, s.connection_id, COALESCE((SELECT c.name FROM cloud_connections c WHERE c.id = s.connection_id), ''),
	jsonb_build_object('modules', COALESCE((SELECT jsonb_agg(jsonb_build_object('name', m->'name', 'kind', m->'kind', 'module', m->'module'))
		FROM jsonb_array_elements(CASE WHEN jsonb_typeof(s.spec->'modules') = 'array' THEN s.spec->'modules' ELSE '[]' END) m), '[]'),
		'imports', COALESCE((SELECT jsonb_agg(jsonb_build_object('to', i->'to'))
		FROM jsonb_array_elements(CASE WHEN jsonb_typeof(s.spec->'imports') = 'array' THEN s.spec->'imports' ELSE '[]' END) i), '[]')),`,
	"s.locked_at, s.resources,", "s.locked_at, NULL::jsonb,",
).Replace(stackSelect)

// ListStackSummaries lists stacks for pages that show many: slim specs, no
// resources, a page at a time (limit 0 = all) with the total.
func (s *Store) ListStackSummaries(ctx context.Context, bus []string, limit, offset int) ([]*Stack, int, error) {
	args := []any{}
	where := ` WHERE s.deleted_at IS NULL AND ` + buFilter("s.bu", bus, &args)
	var total int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM stacks s`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	q := stackSummarySelect + where + ` ORDER BY s.entity, s.bu, s.name`
	if limit > 0 {
		args = append(args, limit, offset)
		q += fmt.Sprintf(` LIMIT $%d OFFSET $%d`, len(args)-1, len(args))
	}
	rows, err := s.db.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	out, err := Collect(rows, scanStack)
	return out, total, err
}

func (s *Store) ListStacks(ctx context.Context, bus []string) ([]*Stack, error) {
	args := []any{}
	rows, err := s.db.Query(ctx, stackSelect+` WHERE s.deleted_at IS NULL AND `+buFilter("s.bu", bus, &args)+` ORDER BY s.entity, s.bu, s.name`, args...)
	if err != nil {
		return nil, err
	}
	return Collect(rows, scanStack)
}

// ---- runs ----

type Approval struct {
	Step      string    `json:"step"`
	Approver  string    `json:"approver"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
}

type Run struct {
	ID                string          `json:"id"`
	StackID           string          `json:"stack_id"`
	StackName         string          `json:"stack"`
	BU                string          `json:"bu"`
	Entity            string          `json:"entity"`
	Environment       string          `json:"environment"`
	Operation         string          `json:"operation"`
	Status            string          `json:"status"`
	CreatedBy         string          `json:"created_by"`
	ConfigHash        string          `json:"config_hash"`
	StateSerial       *int64          `json:"state_serial,omitempty"`
	PlanSHA256        *string         `json:"plan_sha256,omitempty"`
	PlanSummary       json.RawMessage `json:"plan_summary,omitempty"`
	PolicyResult      json.RawMessage `json:"policy_result,omitempty"`
	Risk              json.RawMessage `json:"risk,omitempty"`
	Cost              json.RawMessage `json:"cost,omitempty"`
	RequiredApprovals []string        `json:"required_approvals"`
	Approvals         []Approval      `json:"approvals"`
	Error             *string         `json:"error,omitempty"`
	RunnerID          *string         `json:"runner_id,omitempty"`
	CreatedAt         time.Time       `json:"created_at"`
	UpdatedAt         time.Time       `json:"updated_at"`
	PlannedAt         *time.Time      `json:"planned_at,omitempty"`
	FinishedAt        *time.Time      `json:"finished_at,omitempty"`
	// Pull-request runs plan the pull request's spec, not the stack's.
	Spec     json.RawMessage `json:"spec,omitempty"`
	PRNumber *int            `json:"pr_number,omitempty"`
	PRSha    *string         `json:"pr_sha,omitempty"`
	PRURL    *string         `json:"pr_url,omitempty"`
	// ZeroDiff runs test a contract matched to the live resources: they must
	// change nothing. SourceRun is the run they were derived from.
	ZeroDiff  bool    `json:"zero_diff,omitempty"`
	SourceRun *string `json:"source_run,omitempty"`
	// CancelRequestedBy: someone asked to cancel this plan or apply; the
	// runner interrupts OpenTofu at its next check-in.
	CancelRequestedBy *string `json:"cancel_requested_by,omitempty"`
}

const runSelect = `SELECT r.id, r.stack_id, s.name, s.bu, s.entity, e.name, r.operation, r.status, r.created_by,
	r.config_hash, r.state_serial, r.plan_sha256, r.plan_summary, r.policy_result, r.risk, r.cost, r.required_approvals, r.error, r.runner_id,
	r.created_at, r.updated_at, r.planned_at, r.finished_at, r.spec, r.pr_number, r.pr_sha,
	(SELECT p.html_url FROM pull_requests p WHERE p.repo_key = r.pr_repo AND p.number = r.pr_number), r.zero_diff, r.source_run::text, r.cancel_requested_by,
	COALESCE((SELECT json_agg(json_build_object('step', a.step, 'approver', a.approver, 'reason', a.reason, 'created_at', a.created_at) ORDER BY a.created_at)
	          FROM run_approvals a WHERE a.run_id = r.id), '[]')
	FROM runs r JOIN stacks s ON s.id = r.stack_id JOIN environments e ON e.id = s.environment_id`

func scanRun(r pgx.Row) (*Run, error) {
	var x Run
	var approvals []byte
	err := r.Scan(&x.ID, &x.StackID, &x.StackName, &x.BU, &x.Entity, &x.Environment, &x.Operation, &x.Status, &x.CreatedBy,
		&x.ConfigHash, &x.StateSerial, &x.PlanSHA256, &x.PlanSummary, &x.PolicyResult, &x.Risk, &x.Cost, &x.RequiredApprovals, &x.Error, &x.RunnerID,
		&x.CreatedAt, &x.UpdatedAt, &x.PlannedAt, &x.FinishedAt, &x.Spec, &x.PRNumber, &x.PRSha, &x.PRURL, &x.ZeroDiff, &x.SourceRun, &x.CancelRequestedBy, &approvals)
	if err == nil {
		json.Unmarshal(approvals, &x.Approvals)
	}
	if x.Approvals == nil {
		x.Approvals = []Approval{}
	}
	if x.RequiredApprovals == nil {
		x.RequiredApprovals = []string{}
	}
	return &x, NotFound(err)
}

// Terminal run statuses.
var Terminal = []string{"no_changes", "policy_failed", "applied", "failed", "discarded", "no_drift", "drifted", "cancelled"}

func (s *Store) CreateRun(ctx context.Context, stackID, op, by, configHash string) (*Run, error) {
	if err := s.checkRunnable(ctx, stackID, op); err != nil {
		return nil, err
	}
	var id string
	err := s.db.QueryRow(ctx, `INSERT INTO runs (stack_id, operation, status, created_by, config_hash) VALUES ($1, $2, 'queued', $3, $4) RETURNING id`,
		stackID, op, by, configHash).Scan(&id)
	if IsUnique(err) {
		return nil, ErrConflict // another run holds the stack
	}
	if err != nil {
		return nil, err
	}
	return s.GetRun(ctx, id)
}

func (s *Store) GetRun(ctx context.Context, id string) (*Run, error) {
	return scanRun(s.db.QueryRow(ctx, runSelect+` WHERE r.id::text = $1`, id))
}

func (s *Store) ListRuns(ctx context.Context, stackID string, bus []string, limit int) ([]*Run, error) {
	return s.QueryRuns(ctx, RunQuery{StackID: stackID, BUs: bus, Limit: limit})
}

// RunQuery filters a page of runs, newest first. Before is the created_at of
// the last run of the previous page (exclusive).
type RunQuery struct {
	StackID    string
	BUs        []string
	Limit      int
	Before     time.Time
	Operations []string
	Statuses   []string
	Stack      string // part of the stack name
}

func (s *Store) QueryRuns(ctx context.Context, q RunQuery) ([]*Run, error) {
	args := []any{q.Limit}
	where := buFilter("s.bu", q.BUs, &args)
	if q.StackID != "" {
		args = append(args, q.StackID)
		where += fmt.Sprintf(` AND r.stack_id::text = $%d`, len(args))
	}
	if !q.Before.IsZero() {
		args = append(args, q.Before)
		where += fmt.Sprintf(` AND r.created_at < $%d`, len(args))
	}
	if len(q.Operations) > 0 {
		args = append(args, q.Operations)
		where += fmt.Sprintf(` AND r.operation = ANY($%d)`, len(args))
	}
	if len(q.Statuses) > 0 {
		args = append(args, q.Statuses)
		where += fmt.Sprintf(` AND r.status = ANY($%d)`, len(args))
	}
	if q.Stack != "" {
		args = append(args, "%"+strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(q.Stack)+"%")
		where += fmt.Sprintf(` AND s.name ILIKE $%d`, len(args))
	}
	rows, err := s.db.Query(ctx, runSelect+` WHERE `+where+` ORDER BY r.created_at DESC LIMIT $1`, args...)
	if err != nil {
		return nil, err
	}
	return Collect(rows, scanRun)
}

// ClaimRun hands a queued run in a pool to a runner (applies first, then
// fairly across BUs, oldest first). Plans move
// queued -> planning, approved applies move apply_queued -> applying. The run
// token is replaced on every claim, so a plan-phase token cannot apply.
func (s *Store) ClaimRun(ctx context.Context, runnerID, pool string, tokenHash []byte, ttl time.Duration) (*Run, error) {
	var id string
	err := s.db.QueryRow(ctx, `UPDATE runs SET
			status = CASE status WHEN 'queued' THEN 'planning' ELSE 'applying' END,
			runner_id = $1, run_token_hash = $3, run_token_expires_at = now() + $4::interval, updated_at = now()
		WHERE id = (
			WITH busy AS (SELECT sb.bu, count(*) AS n FROM runs a JOIN stacks sb ON sb.id = a.stack_id
				WHERE a.status IN ('planning', 'applying') GROUP BY sb.bu)
			SELECT r.id FROM runs r
			JOIN stacks s ON s.id = r.stack_id JOIN environments e ON e.id = s.environment_id
			LEFT JOIN busy b ON b.bu = s.bu
			WHERE r.status IN ('queued', 'apply_queued') AND e.runner_pool = $2
			  AND (e.max_concurrent_runs = 0 OR e.max_concurrent_runs > (SELECT count(*) FROM runs a JOIN stacks sa ON sa.id = a.stack_id
			       WHERE sa.environment_id = e.id AND a.status IN ('planning', 'applying')))
			-- Approved applies first; then the BU with the fewest runs in
			-- progress, so one BU's burst cannot hold the others back; then age.
			ORDER BY (r.status = 'apply_queued') DESC, COALESCE(b.n, 0), r.created_at
			LIMIT 1 FOR UPDATE OF r SKIP LOCKED)
		RETURNING id`, runnerID, pool, tokenHash, fmt.Sprintf("%d seconds", int(ttl.Seconds()))).Scan(&id)
	if err != nil {
		return nil, NotFound(err)
	}
	return s.GetRun(ctx, id)
}

// RunByToken resolves a run token to its active run.
func (s *Store) RunByToken(ctx context.Context, hash []byte) (*Run, error) {
	var id string
	err := s.db.QueryRow(ctx, `SELECT id FROM runs WHERE run_token_hash = $1 AND run_token_expires_at > now()
		AND status IN ('planning', 'applying')`, hash).Scan(&id)
	if err != nil {
		return nil, NotFound(err)
	}
	return s.GetRun(ctx, id)
}

func (s *Store) AppendLog(ctx context.Context, runID, chunk string) error {
	// The run is marked alive at most every 30 seconds, not on every chunk:
	// runs is the busiest table, and the reaper waits minutes.
	_, err := s.db.Exec(ctx, `WITH t AS (UPDATE runs SET updated_at = now() WHERE id = $1 AND updated_at < now() - interval '30 seconds')
		INSERT INTO run_logs (run_id, chunk) VALUES ($1, $2)`, runID, chunk)
	return err
}

// LogsArchived reports whether a run's log has moved to the bucket.
func (s *Store) LogsArchived(ctx context.Context, runID string) bool {
	var a bool
	s.db.QueryRow(ctx, `SELECT logs_archived FROM runs WHERE id::text = $1`, runID).Scan(&a)
	return a
}

// MarkLogsArchived flags a run's log as moved to the bucket and drops its rows.
func (s *Store) MarkLogsArchived(ctx context.Context, runID string) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `UPDATE runs SET logs_archived = true WHERE id = $1`, runID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM run_logs WHERE run_id = $1`, runID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// RunsToArchive lists finished runs whose logs are still in the database.
func (s *Store) RunsToArchive(ctx context.Context, olderThan time.Duration, limit int) ([]string, error) {
	rows, err := s.db.Query(ctx, `SELECT id::text FROM runs WHERE NOT logs_archived AND status = ANY($1)
		AND updated_at < now() - $2::interval ORDER BY updated_at LIMIT $3`, Terminal, fmt.Sprintf("%d seconds", int(olderThan.Seconds())), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			out = append(out, id)
		}
	}
	return out, rows.Err()
}

type LogChunk struct {
	Seq   int64     `json:"seq"`
	TS    time.Time `json:"ts"`
	Chunk string    `json:"chunk"`
}

func (s *Store) Logs(ctx context.Context, runID string, after int64) ([]LogChunk, error) {
	rows, err := s.db.Query(ctx, `SELECT seq, ts, chunk FROM run_logs WHERE run_id::text = $1 AND seq > $2 ORDER BY seq LIMIT 1000`, runID, after)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LogChunk{}
	for rows.Next() {
		var c LogChunk
		if err := rows.Scan(&c.Seq, &c.TS, &c.Chunk); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Planned is what a finished plan records.
type Planned struct {
	Status   string // planned | no_changes | policy_failed | no_drift | drifted
	Sealed   []byte
	SHA256   string
	Summary  []byte
	Policy   []byte
	Risk     []byte
	Cost     []byte
	Object   string // bucket key when the sealed plan lives in object storage
	Required []string
	Serial   int64
}

func (s *Store) SetPlanned(ctx context.Context, runID string, p Planned) error {
	terminal := p.Status != "planned"
	tag, err := s.db.Exec(ctx, `UPDATE runs SET status = $2, plan_sealed = $3, plan_sha256 = $4, plan_summary = $5, policy_result = $6,
			risk = $7, required_approvals = $8, state_serial = $9, planned_at = now(), updated_at = now(),
			run_token_hash = NULL, run_token_expires_at = NULL,
			finished_at = CASE WHEN $10 THEN now() END, cost = $11, plan_object = NULLIF($12, '')
		WHERE id = $1 AND status = 'planning'`, runID, p.Status, p.Sealed, p.SHA256, p.Summary, p.Policy, p.Risk, p.Required, p.Serial, terminal, p.Cost, p.Object)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrConflict
	}
	return err
}

// PlanBlob returns a run's sealed plan (or the bucket key holding it) and its checksum.
func (s *Store) PlanBlob(ctx context.Context, runID string) (sealed []byte, object, sha string, err error) {
	var obj, sum *string
	err = s.db.QueryRow(ctx, `SELECT plan_sealed, plan_object, plan_sha256 FROM runs WHERE id = $1`, runID).Scan(&sealed, &obj, &sum)
	if err != nil || sum == nil || (sealed == nil && obj == nil) {
		return nil, "", "", ErrNotFound
	}
	if obj != nil {
		object = *obj
	}
	return sealed, object, *sum, nil
}

var (
	ErrNotPlanned      = errors.New("only planned runs can be approved")
	ErrStepNotRequired = errors.New("this run does not need that approval")
	ErrStepDone        = errors.New("that approval step is already signed")
	ErrSelfApproval    = errors.New("separation of duties: the person who started a run cannot approve it")
	ErrTwoSteps        = errors.New("separation of duties: one person may sign only one approval step of a run")
)

// Approve signs one step under a row lock. It returns true when this signature
// completed the chain and the run moved to apply_queued.
func (s *Store) Approve(ctx context.Context, runID, step, approver, reason string) (bool, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var status, createdBy, author, prRepo string
	var required []string
	if err := tx.QueryRow(ctx, `SELECT status, created_by, required_approvals, author_subject, COALESCE(pr_repo, '') FROM runs WHERE id = $1 FOR UPDATE`, runID).
		Scan(&status, &createdBy, &required, &author, &prRepo); err != nil {
		return false, NotFound(err)
	}
	// A pull request's plan: its author is whoever proposed it in SrustiOps,
	// or the person a host login (git:pr#N:<login>) is linked to.
	if author == "" && strings.HasPrefix(createdBy, "git:pr#") && prRepo != "" {
		// Recorded after the pull request opened; a plan may have started first.
		tx.QueryRow(ctx, `SELECT p.subject FROM pr_proposers p JOIN runs r ON r.pr_repo = p.repo_key AND r.pr_number = p.number WHERE r.id = $1`, runID).Scan(&author)
	}
	if author == "" && strings.HasPrefix(createdBy, "git:pr#") && prRepo != "" {
		login := createdBy[strings.LastIndex(createdBy, ":")+1:]
		provider, _, _ := strings.Cut(prRepo, ":")
		tx.QueryRow(ctx, `SELECT subject FROM git_identities WHERE provider = $1 AND login = lower($2) AND subject = $3`, provider, login, approver).Scan(&author)
	}
	if author == approver {
		createdBy = approver
	}
	var locked bool
	if err := tx.QueryRow(ctx, `SELECT s.locked_by IS NOT NULL OR s.deleted_at IS NOT NULL FROM runs r JOIN stacks s ON s.id = r.stack_id WHERE r.id = $1`, runID).Scan(&locked); err != nil {
		return false, err
	}
	switch {
	case status != "planned":
		return false, ErrNotPlanned
	case locked:
		return false, ErrLocked
	case createdBy == approver:
		return false, ErrSelfApproval
	case !containsStr(required, step):
		return false, ErrStepNotRequired
	}
	done := map[string]string{}
	rows, err := tx.Query(ctx, `SELECT step, approver FROM run_approvals WHERE run_id = $1`, runID)
	if err != nil {
		return false, err
	}
	for rows.Next() {
		var st, by string
		rows.Scan(&st, &by)
		done[st] = by
	}
	rows.Close()
	if _, ok := done[step]; ok {
		return false, ErrStepDone
	}
	for _, by := range done {
		if by == approver {
			return false, ErrTwoSteps
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO run_approvals (run_id, step, approver, reason) VALUES ($1, $2, $3, $4)`, runID, step, approver, reason); err != nil {
		return false, err
	}
	done[step] = approver
	complete := true
	for _, r := range required {
		if _, ok := done[r]; !ok {
			complete = false
		}
	}
	if complete {
		if _, err := tx.Exec(ctx, `UPDATE runs SET status = 'apply_queued', updated_at = now() WHERE id = $1`, runID); err != nil {
			return false, err
		}
	}
	return complete, tx.Commit(ctx)
}

func (s *Store) Discard(ctx context.Context, runID, reason string) error {
	tag, err := s.db.Exec(ctx, `UPDATE runs SET status = 'discarded', error = $2, updated_at = now(), finished_at = now(),
		run_token_hash = NULL, plan_sealed = NULL WHERE id::text = $1 AND status IN ('queued', 'planned')`, runID, reason)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrConflict
	}
	return err
}

// FinishRun ends a run from planning or applying. Saved plans are deleted once
// a run is over: they contain the full proposed state.
func (s *Store) FinishRun(ctx context.Context, runID, status, errMsg string) error {
	var e *string
	if errMsg != "" {
		e = &errMsg
	}
	tag, err := s.db.Exec(ctx, `UPDATE runs SET status = $2, error = $3, updated_at = now(), finished_at = now(),
		run_token_hash = NULL, run_token_expires_at = NULL, plan_sealed = NULL
		WHERE id = $1 AND status IN ('planning', 'applying')`, runID, status, e)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrConflict
	}
	return err
}

// SetRunError sets the error text (a note) of a run that has ended.
func (s *Store) SetRunError(ctx context.Context, runID, errMsg string) error {
	_, err := s.db.Exec(ctx, `UPDATE runs SET error = $2 WHERE id = $1 AND status IN ('failed', 'policy_failed')`, runID, errMsg)
	return err
}

// Expire moves a run from one of the given statuses to a terminal one,
// reporting whether it did (false if the run had already moved on).
func (s *Store) Expire(ctx context.Context, runID string, from []string, to, reason string) (bool, error) {
	tag, err := s.db.Exec(ctx, `UPDATE runs SET status = $3, error = $4, finished_at = now(), updated_at = now(),
		run_token_hash = NULL, run_token_expires_at = NULL, plan_sealed = NULL
		WHERE id::text = $1 AND status = ANY($2)`, runID, from, to, reason)
	return err == nil && tag.RowsAffected() == 1, err
}

// Reap fails runs whose runner went silent and discards plans nobody approved in time.
func (s *Store) Reap(ctx context.Context, silentFor, planTTL time.Duration) ([]string, error) {
	rows, err := s.db.Query(ctx, `UPDATE runs SET
			status = CASE WHEN status = 'planned' THEN 'discarded' ELSE 'failed' END,
			error = CASE WHEN status = 'planned' THEN 'plan expired before approval' ELSE 'runner stopped reporting' END,
			finished_at = now(), updated_at = now(), run_token_hash = NULL, plan_sealed = NULL
		WHERE (status IN ('planning', 'applying') AND updated_at < now() - $1::interval)
		   OR (status = 'planned' AND planned_at < now() - $2::interval)
		RETURNING id`, fmt.Sprintf("%d seconds", int(silentFor.Seconds())), fmt.Sprintf("%d seconds", int(planTTL.Seconds())))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		rows.Scan(&id)
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ---- policy sets ----

type PolicySet struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Scope     string    `json:"scope"`
	Level     string    `json:"level"`
	Module    string    `json:"module"`
	Enabled   bool      `json:"enabled"`
	Source    string    `json:"source"` // console | release
	CreatedBy string    `json:"created_by"`
	UpdatedBy string    `json:"updated_by"`
	UpdatedAt time.Time `json:"updated_at"`
}

const psCols = `id, name, scope, level, module, enabled, source, created_by, updated_by, updated_at`

func scanPS(r pgx.Row) (*PolicySet, error) {
	var p PolicySet
	err := r.Scan(&p.ID, &p.Name, &p.Scope, &p.Level, &p.Module, &p.Enabled, &p.Source, &p.CreatedBy, &p.UpdatedBy, &p.UpdatedAt)
	return &p, NotFound(err)
}

func (s *Store) CreatePolicySet(ctx context.Context, p *PolicySet) (*PolicySet, error) {
	out, err := scanPS(s.db.QueryRow(ctx, `INSERT INTO policy_sets (name, scope, level, module, enabled, created_by, updated_by)
		VALUES ($1, $2, $3, $4, $5, $6, $6) RETURNING `+psCols, p.Name, p.Scope, p.Level, p.Module, p.Enabled, p.CreatedBy))
	if IsUnique(err) {
		return nil, ErrConflict
	}
	return out, err
}

func (s *Store) UpdatePolicySet(ctx context.Context, p *PolicySet) (*PolicySet, error) {
	return scanPS(s.db.QueryRow(ctx, `UPDATE policy_sets SET scope = $2, level = $3, module = $4, enabled = $5, updated_by = $6, updated_at = now()
		WHERE id::text = $1 OR name = $1 RETURNING `+psCols, p.ID, p.Scope, p.Level, p.Module, p.Enabled, p.UpdatedBy))
}

func (s *Store) GetPolicySet(ctx context.Context, idOrName string) (*PolicySet, error) {
	return scanPS(s.db.QueryRow(ctx, `SELECT `+psCols+` FROM policy_sets WHERE id::text = $1 OR name = $1`, idOrName))
}

func (s *Store) ListPolicySets(ctx context.Context) ([]*PolicySet, error) {
	rows, err := s.db.Query(ctx, `SELECT `+psCols+` FROM policy_sets ORDER BY name`)
	if err != nil {
		return nil, err
	}
	return Collect(rows, scanPS)
}

// FinishedPlanObjects returns bucket keys of plans whose runs have ended, so
// they can be deleted.
func (s *Store) FinishedPlanObjects(ctx context.Context) ([]string, error) {
	rows, err := s.db.Query(ctx, `UPDATE runs SET plan_object = NULL WHERE plan_object IS NOT NULL
		AND status IN ('applied','failed','discarded','no_changes','policy_failed','no_drift','drifted','cancelled') RETURNING id::text`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		rows.Scan(&id)
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ---- tenant settings ----

// Setting loads a JSON setting into v; it reports false when unset.
func (s *Store) Setting(ctx context.Context, key string, v any) (bool, error) {
	var b []byte
	err := s.db.QueryRow(ctx, `SELECT value FROM tenant_settings WHERE key = $1`, key).Scan(&b)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal(b, v)
}

func (s *Store) PutSetting(ctx context.Context, key string, v any, by string) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, `INSERT INTO tenant_settings (key, value, updated_by) VALUES ($1, $2, $3)
		ON CONFLICT (key) DO UPDATE SET value = $2, updated_by = $3, updated_at = now()`, key, b, by)
	return err
}

// ---- state (OpenTofu HTTP backend) ----

// StateRef is the latest state version: inline data or a bucket key.
type StateRef struct {
	Data   []byte
	Object string
	SHA256 string
	Serial int64
}

// LatestState returns the newest state version (Serial 0 when there is none).
func (s *Store) LatestState(ctx context.Context, stackID string) (StateRef, error) {
	var r StateRef
	var obj *string
	err := s.db.QueryRow(ctx, `SELECT data, object_key, sha256, serial FROM state_versions WHERE stack_id = $1 ORDER BY serial DESC LIMIT 1`, stackID).
		Scan(&r.Data, &obj, &r.SHA256, &r.Serial)
	if errors.Is(err, pgx.ErrNoRows) {
		return StateRef{}, nil
	}
	if obj != nil {
		r.Object = *obj
	}
	return r, err
}

// CurrentState returns inline state data and serial; callers that support
// object storage use LatestState.
func (s *Store) CurrentState(ctx context.Context, stackID string) ([]byte, int64, error) {
	r, err := s.LatestState(ctx, stackID)
	return r.Data, r.Serial, err
}

// PutState records a new state version, either inline (data) or as a bucket key (object).
func (s *Store) PutState(ctx context.Context, stackID, runID string, data []byte, object, sha string) (int64, error) {
	var serial int64
	err := s.db.QueryRow(ctx, `INSERT INTO state_versions (stack_id, serial, data, object_key, sha256, run_id)
		SELECT $1, COALESCE(MAX(serial), 0) + 1, $2, NULLIF($3, ''), $4, $5 FROM state_versions WHERE stack_id = $1 RETURNING serial`,
		stackID, data, object, sha, runID).Scan(&serial)
	return serial, err
}

type StateVersion struct {
	Serial    int64     `json:"serial"`
	SHA256    string    `json:"sha256"`
	Size      int       `json:"size"`
	RunID     *string   `json:"run_id,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *Store) StateVersions(ctx context.Context, stackID string) ([]StateVersion, error) {
	rows, err := s.db.Query(ctx, `SELECT serial, sha256, COALESCE(length(data), 0), run_id, created_at FROM state_versions WHERE stack_id = $1 ORDER BY serial DESC LIMIT 100`, stackID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []StateVersion{}
	for rows.Next() {
		var v StateVersion
		if err := rows.Scan(&v.Serial, &v.SHA256, &v.Size, &v.RunID, &v.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// Lock takes the state lock. On conflict it returns the current holder's info.
func (s *Store) Lock(ctx context.Context, stackID, lockID, runID string, info []byte) ([]byte, error) {
	tag, err := s.db.Exec(ctx, `INSERT INTO state_locks (stack_id, lock_id, info, run_id) VALUES ($1, $2, $3, $4) ON CONFLICT (stack_id) DO NOTHING`,
		stackID, lockID, info, runID)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 1 {
		return nil, nil
	}
	var cur []byte
	if err := s.db.QueryRow(ctx, `SELECT info FROM state_locks WHERE stack_id = $1`, stackID).Scan(&cur); err != nil {
		return nil, err
	}
	return cur, ErrConflict
}

func (s *Store) Unlock(ctx context.Context, stackID, lockID string) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM state_locks WHERE stack_id = $1 AND lock_id = $2`, stackID, lockID)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrConflict
	}
	return err
}

func (s *Store) LockHolder(ctx context.Context, stackID string) (lockID string, runID *string, err error) {
	err = s.db.QueryRow(ctx, `SELECT lock_id, run_id FROM state_locks WHERE stack_id = $1`, stackID).Scan(&lockID, &runID)
	return lockID, runID, NotFound(err)
}

// ReleaseRunLocks drops locks left by a run that has ended (crashed runner).
func (s *Store) ReleaseRunLocks(ctx context.Context) error {
	_, err := s.db.Exec(ctx, `DELETE FROM state_locks l USING runs r WHERE l.run_id = r.id AND r.status NOT IN ('planning', 'applying')`)
	return err
}

func containsStr(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// deleteRow removes one row by ID. A row still referenced (an environment
// with stacks, a connection with environments) is a conflict, not deleted.
func (s *Store) deleteRow(ctx context.Context, table, id string) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM `+table+` WHERE id = $1`, id)
	switch {
	case IsReferenced(err):
		return ErrConflict
	case err != nil:
		return err
	case tag.RowsAffected() == 0:
		return ErrNotFound
	}
	return nil
}

// DeleteConnection removes a connection no environment uses (ErrConflict otherwise).
func (s *Store) DeleteConnection(ctx context.Context, id string) error {
	var inUse bool
	if err := s.db.QueryRow(ctx, `SELECT environment_id IS NOT NULL FROM cloud_connections WHERE id = $1`, id).Scan(&inUse); err != nil {
		return NotFound(err)
	}
	if inUse {
		return ErrConflict
	}
	return s.deleteRow(ctx, "cloud_connections", id)
}
func (s *Store) DeleteEnvironment(ctx context.Context, id string) error {
	return s.deleteRow(ctx, "environments", id)
}
func (s *Store) DeletePolicySet(ctx context.Context, id string) error {
	return s.deleteRow(ctx, "policy_sets", id)
}

func (s *Store) DeleteSetting(ctx context.Context, key string) error {
	_, err := s.db.Exec(ctx, `DELETE FROM tenant_settings WHERE key = $1`, key)
	return err
}

// ---- webhook deliveries ----

type WebhookDelivery struct {
	ID         int64     `json:"id"`
	Provider   string    `json:"provider"`
	DeliveryID string    `json:"delivery_id"`
	Event      string    `json:"event"`
	Action     string    `json:"action"`
	Repo       string    `json:"repo"`
	Ref        string    `json:"ref"`
	Sender     string    `json:"sender"`
	Outcome    string    `json:"outcome"`
	Detail     string    `json:"detail"`
	ReceivedAt time.Time `json:"received_at"`
}

// RecordDelivery stores a delivery once; a redelivery of the same ID is a conflict.
func (s *Store) RecordDelivery(ctx context.Context, d *WebhookDelivery) error {
	_, err := s.db.Exec(ctx, `INSERT INTO webhook_deliveries (provider, delivery_id, event, action, repo, ref, sender, outcome, detail)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`, d.Provider, d.DeliveryID, d.Event, d.Action, d.Repo, d.Ref, d.Sender, d.Outcome, d.Detail)
	if IsUnique(err) {
		return ErrConflict
	}
	return err
}

// ListDeliveries returns deliveries newest first, older than before (0 = newest).
func (s *Store) ListDeliveries(ctx context.Context, limit int, before int64) ([]WebhookDelivery, error) {
	rows, err := s.db.Query(ctx, `SELECT id, provider, delivery_id, event, action, repo, ref, sender, outcome, detail, received_at
		FROM webhook_deliveries WHERE $2 = 0 OR id < $2 ORDER BY id DESC LIMIT $1`, limit, before)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []WebhookDelivery{}
	for rows.Next() {
		var d WebhookDelivery
		if err := rows.Scan(&d.ID, &d.Provider, &d.DeliveryID, &d.Event, &d.Action, &d.Repo, &d.Ref, &d.Sender, &d.Outcome, &d.Detail, &d.ReceivedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ---- pull requests ----

// CreatePRRun queues a plan of a pull request's spec for a stack.
func (s *Store) CreatePRRun(ctx context.Context, stackID, by, configHash string, spec []byte, pr int, sha string, zeroDiff bool, sourceRun *string) (*Run, error) {
	// A pull request's plan is a preview: it may run on a locked stack, but
	// its apply waits for the unlock like any other.
	if err := s.checkRunnable(ctx, stackID, "drift"); err != nil {
		return nil, err
	}
	if err := s.checkLimit(ctx, "runs_per_month"); err != nil { // a PR plan is a run like any other
		return nil, err
	}
	var id string
	err := s.db.QueryRow(ctx, `INSERT INTO runs (stack_id, operation, status, created_by, config_hash, spec, pr_number, pr_sha, zero_diff, source_run, pr_repo, author_subject)
		VALUES ($1, 'apply', 'queued', $2, $3, $4, $5, $6, $7, $8, $9, COALESCE((SELECT subject FROM pr_proposers WHERE repo_key = $9 AND number = $5), ''))
		RETURNING id`, stackID, by, configHash, spec, pr, sha, zeroDiff, sourceRun, s.prKey()).Scan(&id)
	if IsUnique(err) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	return s.GetRun(ctx, id)
}

// PRRuns lists a pull request's runs, newest first.
func (s *Store) PRRuns(ctx context.Context, pr int) ([]*Run, error) {
	rows, err := s.db.Query(ctx, runSelect+` WHERE r.pr_repo = $2 AND r.pr_number = $1 ORDER BY r.created_at DESC`, pr, s.prKey())
	if err != nil {
		return nil, err
	}
	return Collect(rows, scanRun)
}

type PullRequest struct {
	Number     int             `json:"number"`
	Repo       string          `json:"repo"`
	Title      string          `json:"title"`
	Author     string          `json:"author"`
	HTMLURL    string          `json:"html_url"`
	HeadSHA    string          `json:"head_sha"`
	State      string          `json:"state"`
	Results    json.RawMessage `json:"results"`
	CommentID  *int64          `json:"-"`
	CommentSum string          `json:"-"`
	CreatedAt  time.Time       `json:"created_at"`
	UpdatedAt  time.Time       `json:"updated_at"`
	MergedAt   *time.Time      `json:"merged_at,omitempty"`
}

const prCols = `number, repo, title, author, html_url, head_sha, state, results, comment_id, comment_sum, created_at, updated_at, merged_at`

func scanPR(r pgx.Row) (*PullRequest, error) {
	var p PullRequest
	err := r.Scan(&p.Number, &p.Repo, &p.Title, &p.Author, &p.HTMLURL, &p.HeadSHA, &p.State, &p.Results, &p.CommentID, &p.CommentSum, &p.CreatedAt, &p.UpdatedAt, &p.MergedAt)
	return &p, NotFound(err)
}

// UpsertPR records a pull request's latest head; a new head reopens it.
func (s *Store) UpsertPR(ctx context.Context, p *PullRequest) error {
	_, err := s.db.Exec(ctx, `INSERT INTO pull_requests (number, repo, title, author, html_url, head_sha, state, results, repo_key)
		VALUES ($1, $2, $3, $4, $5, $6, 'open', $7, $8)
		ON CONFLICT (repo_key, number) DO UPDATE SET repo = $2, title = $3, author = $4, html_url = $5, head_sha = $6, state = 'open', results = $7, updated_at = now()`,
		p.Number, p.Repo, p.Title, p.Author, p.HTMLURL, p.HeadSHA, p.Results, s.prKey())
	return err
}

func (s *Store) GetPR(ctx context.Context, n int) (*PullRequest, error) {
	return scanPR(s.db.QueryRow(ctx, `SELECT `+prCols+` FROM pull_requests WHERE repo_key = $2 AND number = $1`, n, s.prKey()))
}

func (s *Store) OpenPRs(ctx context.Context) ([]*PullRequest, error) {
	rows, err := s.db.Query(ctx, `SELECT `+prCols+` FROM pull_requests WHERE repo_key = $1 AND state = 'open' ORDER BY number`, s.prKey())
	if err != nil {
		return nil, err
	}
	return Collect(rows, scanPR)
}

func (s *Store) ListPRs(ctx context.Context, limit int) ([]*PullRequest, error) {
	rows, err := s.db.Query(ctx, `SELECT `+prCols+` FROM pull_requests WHERE repo_key = $2 ORDER BY updated_at DESC LIMIT $1`, limit, s.prKey())
	if err != nil {
		return nil, err
	}
	return Collect(rows, scanPR)
}

func (s *Store) SetPRState(ctx context.Context, n int, state string) error {
	_, err := s.db.Exec(ctx, `UPDATE pull_requests SET state = $2, updated_at = now(),
		merged_at = CASE WHEN $2 = 'merged' THEN now() ELSE merged_at END WHERE repo_key = $3 AND number = $1`, n, state, s.prKey())
	return err
}

func (s *Store) SetPRComment(ctx context.Context, n int, commentID int64, sum string) error {
	_, err := s.db.Exec(ctx, `UPDATE pull_requests SET comment_id = $2, comment_sum = $3 WHERE repo_key = $4 AND number = $1`, n, commentID, sum, s.prKey())
	return err
}

// CreateProposedStack creates a Git-managed stack introduced by an open pull request.
func (s *Store) CreateProposedStack(ctx context.Context, name, bu, entity, envID string, conn *string, spec []byte, by string, pr int) (*Stack, error) {
	st, err := s.CreateManagedStack(ctx, name, bu, entity, envID, conn, spec, by, "git", fmt.Sprintf("pr#%d", pr))
	if err != nil {
		return nil, err
	}
	_, err = s.db.Exec(ctx, `UPDATE stacks SET pr_number = $2, pr_repo = $3 WHERE id = $1`, st.ID, pr, s.prKey())
	return st, err
}

// AdoptPRSpec records a pull request's spec as the stack's after it was applied.
// CreateCandidateRun plans a proposed contract (spec) for a stack without
// changing the stack; SaveCandidateSpec keeps it once its plan passes.
func (s *Store) CreateCandidateRun(ctx context.Context, stackID, by, configHash string, spec []byte, sourceRun string) (*Run, error) {
	if err := s.checkRunnable(ctx, stackID, "apply"); err != nil {
		return nil, err
	}
	var id string
	err := s.db.QueryRow(ctx, `INSERT INTO runs (stack_id, operation, status, created_by, config_hash, spec, zero_diff, source_run)
		VALUES ($1, 'apply', 'queued', $2, $3, $4, true, $5) RETURNING id`, stackID, by, configHash, spec, sourceRun).Scan(&id)
	if IsUnique(err) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	return s.GetRun(ctx, id)
}

// QueueApply moves a planned run that needs no approval (a state refresh
// only) straight to apply_queued.
func (s *Store) QueueApply(ctx context.Context, runID string) error {
	tag, err := s.db.Exec(ctx, `UPDATE runs SET status = 'apply_queued', updated_at = now() WHERE id = $1 AND status = 'planned'
		AND NOT EXISTS (SELECT 1 FROM stacks s WHERE s.id = runs.stack_id AND (s.locked_by IS NOT NULL OR s.deleted_at IS NOT NULL))`, runID)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrConflict
	}
	return err
}

// LatestRuns returns a stack's most recent runs, newest first.
func (s *Store) LatestRuns(ctx context.Context, stackID string, n int) ([]*Run, error) {
	rows, err := s.db.Query(ctx, runSelect+` WHERE r.stack_id = $1 AND r.status <> 'discarded' ORDER BY r.created_at DESC LIMIT $2`, stackID, n)
	if err != nil {
		return nil, err
	}
	return Collect(rows, scanRun)
}

// ZeroDiffPR is a pull request opened from live -> code for one stack.
type ZeroDiffPR struct {
	Number    int
	StackID   string
	SourceRun *string
}

func (s *Store) AddZeroDiffPR(ctx context.Context, number int, stackID, sourceRun, by string) error {
	_, err := s.db.Exec(ctx, `INSERT INTO zero_diff_prs (number, stack_id, source_run, created_by) VALUES ($1, $2, NULLIF($3, '')::uuid, $4)
		ON CONFLICT (number) DO NOTHING`, number, stackID, sourceRun, by)
	return err
}

func (s *Store) GetZeroDiffPR(ctx context.Context, number int) (*ZeroDiffPR, error) {
	var z ZeroDiffPR
	err := s.db.QueryRow(ctx, `SELECT number, stack_id, source_run::text FROM zero_diff_prs WHERE number = $1`, number).Scan(&z.Number, &z.StackID, &z.SourceRun)
	return &z, NotFound(err)
}

// SaveCandidateSpec makes a candidate run's contract the stack's.
func (s *Store) SaveCandidateSpec(ctx context.Context, stackID string, spec []byte) error {
	_, err := s.db.Exec(ctx, `UPDATE stacks SET spec = $2, updated_at = now() WHERE id = $1`, stackID, spec)
	return err
}

// AdoptPRSpec records an applied pull request's contract; a console stack the
// pull request took over (live -> code) is managed through Git from then on.
func (s *Store) AdoptPRSpec(ctx context.Context, stackID string, spec []byte, ref string) error {
	_, err := s.db.Exec(ctx, `UPDATE stacks SET spec = $2, source_ref = $3, pr_number = NULL, managed_by = 'git', updated_at = now() WHERE id = $1`, stackID, spec, ref)
	return err
}

// DropProposedStacks deletes stacks a closed pull request proposed that never
// got state, with their runs. Stacks with state are kept.
func (s *Store) DropProposedStacks(ctx context.Context, pr int) ([]string, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT id, name FROM stacks s WHERE pr_number = $1 AND pr_repo = $2
		AND NOT EXISTS (SELECT 1 FROM state_versions v WHERE v.stack_id = s.id) FOR UPDATE`, pr, s.prKey())
	if err != nil {
		return nil, err
	}
	var ids, names []string
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			rows.Close()
			return nil, err
		}
		ids, names = append(ids, id), append(names, name)
	}
	rows.Close()
	for _, q := range []string{
		`DELETE FROM run_logs WHERE run_id IN (SELECT id FROM runs WHERE stack_id = ANY($1::uuid[]))`,
		`DELETE FROM run_approvals WHERE run_id IN (SELECT id FROM runs WHERE stack_id = ANY($1::uuid[]))`,
		`DELETE FROM state_locks WHERE stack_id = ANY($1::uuid[])`,
		`DELETE FROM runs WHERE stack_id = ANY($1::uuid[])`,
		`DELETE FROM stacks WHERE id = ANY($1::uuid[])`,
	} {
		if _, err := tx.Exec(ctx, q, ids); err != nil {
			return nil, err
		}
	}
	return names, tx.Commit(ctx)
}

// StackBusy reports whether a stack has an active run (the stack lock is held).
func (s *Store) StackBusy(ctx context.Context, stackName string) (bool, error) {
	var busy bool
	err := s.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM runs r JOIN stacks s ON s.id = r.stack_id
		WHERE s.name = $1 AND r.status IN ('queued','planning','planned','apply_queued','applying'))`, stackName).Scan(&busy)
	return busy, err
}

// ---- notifications ----

type Notification struct {
	ID        int64     `json:"id"`
	Kind      string    `json:"kind"`
	Severity  string    `json:"severity"`
	Title     string    `json:"title"`
	Body      string    `json:"body"`
	Link      string    `json:"link"`
	BU        string    `json:"bu"`
	Entity    string    `json:"entity"`
	RunID     *string   `json:"run_id,omitempty"`
	Steps     []string  `json:"steps"`
	CreatedAt time.Time `json:"created_at"`
}

const notifCols = `id, kind, severity, title, body, link, bu, entity, run_id, steps, created_at`

func scanNotif(r pgx.Row) (*Notification, error) {
	var n Notification
	err := r.Scan(&n.ID, &n.Kind, &n.Severity, &n.Title, &n.Body, &n.Link, &n.BU, &n.Entity, &n.RunID, &n.Steps, &n.CreatedAt)
	if n.Steps == nil {
		n.Steps = []string{}
	}
	return &n, NotFound(err)
}

func (s *Store) AddNotification(ctx context.Context, n *Notification) (*Notification, error) {
	if n.Steps == nil {
		n.Steps = []string{}
	}
	return scanNotif(s.db.QueryRow(ctx, `INSERT INTO notifications (kind, severity, title, body, link, bu, entity, run_id, steps)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING `+notifCols, n.Kind, n.Severity, n.Title, n.Body, n.Link, n.BU, n.Entity, n.RunID, n.Steps))
}

// visibleNotif filters to the given business units (nil = all); tenant-wide
// notifications (bu = ”) are visible to everyone in the tenant.
func visibleNotif(bus []string, args *[]any) string {
	if bus == nil {
		return "true"
	}
	*args = append(*args, bus)
	return fmt.Sprintf("(bu = '' OR bu = ANY($%d))", len(*args))
}

// ListNotifications returns notifications newest first, older than before (0 = newest).
// Kinds the person muted are left out.
func (s *Store) ListNotifications(ctx context.Context, bus []string, muted []string, before int64, limit int) ([]*Notification, error) {
	if muted == nil {
		muted = []string{}
	}
	args := []any{limit, before, muted}
	rows, err := s.db.Query(ctx, `SELECT `+notifCols+` FROM notifications WHERE ($2 = 0 OR id < $2) AND NOT (kind = ANY($3)) AND `+visibleNotif(bus, &args)+` ORDER BY id DESC LIMIT $1`, args...)
	if err != nil {
		return nil, err
	}
	return Collect(rows, scanNotif)
}

// UnreadNotifications counts visible notifications after the person's
// watermark, and returns the newest visible id and the watermark itself.
func (s *Store) UnreadNotifications(ctx context.Context, subject string, bus []string, muted []string) (n int, last, read int64, err error) {
	if err = s.db.QueryRow(ctx, `SELECT COALESCE((SELECT last_id FROM notification_reads WHERE subject = $1), 0)`, subject).Scan(&read); err != nil {
		return
	}
	if muted == nil {
		muted = []string{}
	}
	args := []any{read, muted}
	err = s.db.QueryRow(ctx, `SELECT count(*) FILTER (WHERE id > $1), COALESCE(max(id), 0) FROM notifications WHERE NOT (kind = ANY($2)) AND `+visibleNotif(bus, &args), args...).Scan(&n, &last)
	return
}

func (s *Store) MarkNotificationsRead(ctx context.Context, subject string, upTo int64) error {
	_, err := s.db.Exec(ctx, `INSERT INTO notification_reads (subject, last_id) VALUES ($1, $2)
		ON CONFLICT (subject) DO UPDATE SET last_id = GREATEST(notification_reads.last_id, $2)`, subject, upTo)
	return err
}

// NotificationsSince lists notifications newer than t, newest first.
func (s *Store) NotificationsSince(ctx context.Context, t time.Time, limit int) ([]*Notification, error) {
	rows, err := s.db.Query(ctx, `SELECT `+notifCols+` FROM notifications WHERE created_at >= $1 ORDER BY id DESC LIMIT $2`, t, limit)
	if err != nil {
		return nil, err
	}
	return Collect(rows, scanNotif)
}
