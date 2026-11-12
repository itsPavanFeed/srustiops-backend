package store

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"sync"

	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ---- stack lifecycle: lock, resources, delete, clone ----

// ErrLocked: the stack is locked (or deleted); no plan or apply may start.
var ErrLocked = errors.New("the stack is locked")

// checkRunnable refuses new runs on deleted stacks, and anything but drift
// checks on locked ones.
func (s *Store) checkRunnable(ctx context.Context, stackID, op string) error {
	var locked, deleted bool
	err := s.db.QueryRow(ctx, `SELECT locked_by IS NOT NULL, deleted_at IS NOT NULL FROM stacks WHERE id = $1`, stackID).Scan(&locked, &deleted)
	if err != nil {
		return NotFound(err)
	}
	if deleted || (locked && op != "drift") {
		return ErrLocked
	}
	// Drift checks and destroys always run: a workspace over its plan can
	// still see drift and tear things down.
	if op != "drift" && op != "destroy" {
		return s.checkLimit(ctx, "runs_per_month")
	}
	return nil
}

// LockStack stops new plans and applies on a stack until it is unlocked.
func (s *Store) LockStack(ctx context.Context, id, by, reason string) error {
	tag, err := s.db.Exec(ctx, `UPDATE stacks SET locked_by = $2, locked_reason = $3, locked_at = now() WHERE id = $1 AND deleted_at IS NULL AND locked_by IS NULL`, id, by, reason)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrConflict
	}
	return err
}

func (s *Store) UnlockStack(ctx context.Context, id string) error {
	tag, err := s.db.Exec(ctx, `UPDATE stacks SET locked_by = NULL, locked_reason = '', locked_at = NULL WHERE id = $1 AND locked_by IS NOT NULL`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrConflict
	}
	return err
}

// StackResource is one resource a stack manages, as its last plan saw it.
type StackResource struct {
	Address string `json:"address"`
	Type    string `json:"type"`
	Module  string `json:"module,omitempty"` // the stack resource (module instance) it belongs to
	ID      string `json:"id,omitempty"`     // the provider's ID
}

// SetStackResources records what a stack manages after a plan or apply that
// read its whole state.
func (s *Store) SetStackResources(ctx context.Context, id string, rs []StackResource) error {
	if rs == nil {
		rs = []StackResource{}
	}
	b, _ := json.Marshal(rs)
	_, err := s.db.Exec(ctx, `UPDATE stacks SET resources = $2, resources_at = now() WHERE id = $1`, id, b)
	return err
}

// StackHasState reports whether any state was ever written for a stack.
func (s *Store) StackHasState(ctx context.Context, id string) (bool, error) {
	var ok bool
	err := s.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM state_versions WHERE stack_id = $1)`, id).Scan(&ok)
	return ok, err
}

// LastAppliedOperation is the operation of the stack's latest applied run ("" if none).
func (s *Store) LastAppliedOperation(ctx context.Context, id string) (string, error) {
	var op string
	err := s.db.QueryRow(ctx, `SELECT operation FROM runs WHERE stack_id = $1 AND status = 'applied' ORDER BY finished_at DESC NULLS LAST LIMIT 1`, id).Scan(&op)
	if err == pgx.ErrNoRows {
		return "", nil
	}
	return op, err
}

// DeleteStack marks a stack deleted: it disappears from lists and its name is
// free again, while its runs, state versions and audit stay. It fails while a
// run is active or pending.
func (s *Store) DeleteStack(ctx context.Context, id, by string) error {
	tag, err := s.db.Exec(ctx, `UPDATE stacks SET deleted_at = now(), deleted_by = $2, locked_by = NULL, locked_at = NULL WHERE id = $1 AND deleted_at IS NULL
		AND NOT EXISTS (SELECT 1 FROM runs WHERE stack_id = $1 AND status IN ('queued','planning','planned','apply_queued','applying'))`, id, by)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrConflict
	}
	if err == nil {
		s.db.Exec(ctx, `DELETE FROM pending_runs WHERE stack_id = $1`, id)
		s.db.Exec(ctx, `DELETE FROM stack_outputs WHERE stack_id = $1`, id)
	}
	return err
}

// SetStackOrigin records the stack a clone came from and the template it was made from.
func (s *Store) SetStackOrigin(ctx context.Context, id string, clonedFrom *string, template string) error {
	_, err := s.db.Exec(ctx, `UPDATE stacks SET cloned_from = $2::uuid, template = $3 WHERE id = $1`, id, clonedFrom, template)
	return err
}

// StackClones lists live stacks cloned from a stack.
func (s *Store) StackClones(ctx context.Context, id string) ([]*Stack, error) {
	rows, err := s.db.Query(ctx, stackSelect+` WHERE s.cloned_from = $1 AND s.deleted_at IS NULL ORDER BY s.name`, id)
	if err != nil {
		return nil, err
	}
	return Collect(rows, scanStack)
}

// ---- drift checks ----

// MarkDriftChecked records when a stack's drift was last checked.
func (s *Store) MarkDriftChecked(ctx context.Context, id string) error {
	_, err := s.db.Exec(ctx, `UPDATE stacks SET last_drift_check = now() WHERE id = $1`, id)
	return err
}

// DriftCandidate is a stack whose scheduled drift check may be due.
type DriftCandidate struct {
	ID, Name, BU string
	LastCheck    *time.Time
}

// DriftCandidates lists live, unlocked stacks of an environment that have
// state and no active or deferred run, with when drift was last checked.
func (s *Store) DriftCandidates(ctx context.Context, envID string) ([]DriftCandidate, error) {
	rows, err := s.db.Query(ctx, `SELECT s.id, s.name, s.bu, GREATEST(s.last_drift_check,
			(SELECT max(created_at) FROM runs WHERE stack_id = s.id AND operation = 'drift'))
		FROM stacks s WHERE s.environment_id = $1 AND s.deleted_at IS NULL AND s.locked_by IS NULL AND s.pr_number IS NULL
		AND EXISTS (SELECT 1 FROM state_versions v WHERE v.stack_id = s.id)
		AND NOT EXISTS (SELECT 1 FROM runs r WHERE r.stack_id = s.id AND r.status IN ('queued','planning','planned','apply_queued','applying'))
		AND NOT EXISTS (SELECT 1 FROM pending_runs p WHERE p.stack_id = s.id)
		ORDER BY 4 NULLS FIRST, s.name`, envID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DriftCandidate
	for rows.Next() {
		var c DriftCandidate
		if err := rows.Scan(&c.ID, &c.Name, &c.BU, &c.LastCheck); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// LastScanStarted is when the connection's latest inventory scan started (nil if never).
func (s *Store) LastScanStarted(ctx context.Context, connID string) (*time.Time, bool, error) {
	var at *time.Time
	var running bool
	err := s.db.QueryRow(ctx, `SELECT max(started_at), bool_or(status = 'running') FROM inventory_scans WHERE connection_id = $1`, connID).Scan(&at, &running)
	return at, running, err
}

// SetEnvironmentSchedule replaces an environment's schedule.
func (s *Store) SetEnvironmentSchedule(ctx context.Context, id string, schedule []byte) error {
	tag, err := s.db.Exec(ctx, `UPDATE environments SET schedule = $2, updated_at = now() WHERE id = $1`, id, schedule)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// ScheduledEnvironments lists environments with a schedule turned on.
func (s *Store) ScheduledEnvironments(ctx context.Context) ([]*Environment, error) {
	rows, err := s.db.Query(ctx, envSelect+` WHERE (e.schedule->'drift'->>'enabled')::boolean IS TRUE OR (e.schedule->'inventory'->>'enabled')::boolean IS TRUE ORDER BY e.name`)
	if err != nil {
		return nil, err
	}
	return Collect(rows, scanEnv)
}

// ---- cancelling runs ----

// RequestCancel cancels a run. Runs not yet picked up end at once
// (cancelled); runs a runner is working on are flagged, and the runner
// interrupts OpenTofu and reports. It returns the status the run now has.
func (s *Store) RequestCancel(ctx context.Context, runID, by string) (string, error) {
	var status string
	err := s.db.QueryRow(ctx, `UPDATE runs SET status = 'cancelled', error = 'cancelled by ' || $2, updated_at = now(), finished_at = now(),
		run_token_hash = NULL, run_token_expires_at = NULL, plan_sealed = NULL, cancel_requested_by = $2, cancel_requested_at = now()
		WHERE id = $1 AND status IN ('queued', 'apply_queued') RETURNING status`, runID, by).Scan(&status)
	if err == nil {
		return status, nil
	}
	if err != pgx.ErrNoRows {
		return "", err
	}
	err = s.db.QueryRow(ctx, `UPDATE runs SET cancel_requested_by = $2, cancel_requested_at = now()
		WHERE id = $1 AND status IN ('planning', 'applying') AND cancel_requested_at IS NULL RETURNING status`, runID, by).Scan(&status)
	if err == pgx.ErrNoRows {
		return "", ErrConflict
	}
	return status, err
}

// CancelRequested says who asked to cancel a run ("" when no one did).
func (s *Store) CancelRequested(ctx context.Context, runID string) string {
	var by *string
	s.db.QueryRow(ctx, `SELECT cancel_requested_by FROM runs WHERE id = $1`, runID).Scan(&by)
	if by == nil {
		return ""
	}
	return *by
}

// ---- stack templates ----

type StackTemplate struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Entity      string          `json:"entity"`
	Spec        json.RawMessage `json:"spec"`
	SourceStack string          `json:"source_stack,omitempty"`
	CreatedBy   string          `json:"created_by"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

const templateCols = `id, name, description, entity, spec, source_stack, created_by, created_at, updated_at`

func scanTemplate(r pgx.Row) (*StackTemplate, error) {
	var t StackTemplate
	err := r.Scan(&t.ID, &t.Name, &t.Description, &t.Entity, &t.Spec, &t.SourceStack, &t.CreatedBy, &t.CreatedAt, &t.UpdatedAt)
	return &t, NotFound(err)
}

// ListTemplates returns templates for the given entities (nil = all) and the
// ones shared with every product.
func (s *Store) ListTemplates(ctx context.Context, entities []string) ([]*StackTemplate, error) {
	args := []any{}
	cond := "true"
	if entities != nil {
		args = append(args, entities)
		cond = "(entity = '' OR entity = ANY($1))"
	}
	rows, err := s.db.Query(ctx, `SELECT `+templateCols+` FROM stack_templates WHERE `+cond+` ORDER BY name`, args...)
	if err != nil {
		return nil, err
	}
	return Collect(rows, scanTemplate)
}

func (s *Store) GetTemplate(ctx context.Context, idOrName string) (*StackTemplate, error) {
	return scanTemplate(s.db.QueryRow(ctx, `SELECT `+templateCols+` FROM stack_templates WHERE id::text = $1 OR name = $1`, idOrName))
}

func (s *Store) CreateTemplate(ctx context.Context, t *StackTemplate) (*StackTemplate, error) {
	out, err := scanTemplate(s.db.QueryRow(ctx, `INSERT INTO stack_templates (name, description, entity, spec, source_stack, created_by)
		VALUES ($1, $2, $3, $4, $5, $6) RETURNING `+templateCols, t.Name, t.Description, t.Entity, t.Spec, t.SourceStack, t.CreatedBy))
	if IsUnique(err) {
		return nil, ErrConflict
	}
	return out, err
}

func (s *Store) UpdateTemplate(ctx context.Context, t *StackTemplate) (*StackTemplate, error) {
	return scanTemplate(s.db.QueryRow(ctx, `UPDATE stack_templates SET description = $2, entity = $3, spec = $4, updated_at = now()
		WHERE id = $1 RETURNING `+templateCols, t.ID, t.Description, t.Entity, t.Spec))
}

func (s *Store) DeleteTemplate(ctx context.Context, id string) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM stack_templates WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// ---- notification preferences and email ----

type NotificationPrefs struct {
	Subject      string    `json:"subject"`
	EmailEnabled bool      `json:"email_enabled"`
	EmailKinds   []string  `json:"email_kinds"`
	Muted        []string  `json:"muted"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// NotificationPrefs returns a person's preferences (defaults when unset).
func (s *Store) NotificationPrefs(ctx context.Context, subject string) (*NotificationPrefs, error) {
	p := &NotificationPrefs{Subject: subject, EmailKinds: []string{}, Muted: []string{}}
	err := s.db.QueryRow(ctx, `SELECT email_enabled, email_kinds, muted, updated_at FROM notification_prefs WHERE subject = $1`, subject).
		Scan(&p.EmailEnabled, &p.EmailKinds, &p.Muted, &p.UpdatedAt)
	if err == pgx.ErrNoRows {
		return p, nil
	}
	return p, err
}

// PutNotificationPrefs saves a person's preferences and what they can see now.
func (s *Store) PutNotificationPrefs(ctx context.Context, p *NotificationPrefs, bus []string) error {
	all := bus == nil
	if bus == nil {
		bus = []string{}
	}
	if p.EmailKinds == nil {
		p.EmailKinds = []string{}
	}
	if p.Muted == nil {
		p.Muted = []string{}
	}
	_, err := s.db.Exec(ctx, `INSERT INTO notification_prefs (subject, email_enabled, email_kinds, muted, visible_bus, all_bus) VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (subject) DO UPDATE SET email_enabled = EXCLUDED.email_enabled, email_kinds = EXCLUDED.email_kinds, muted = EXCLUDED.muted,
		visible_bus = EXCLUDED.visible_bus, all_bus = EXCLUDED.all_bus, updated_at = now()`, p.Subject, p.EmailEnabled, p.EmailKinds, p.Muted, bus, all)
	return err
}

// TouchVisibility refreshes what a person with saved preferences can see.
func (s *Store) TouchVisibility(ctx context.Context, subject string, bus []string) {
	all := bus == nil
	if bus == nil {
		bus = []string{}
	}
	s.db.Exec(ctx, `UPDATE notification_prefs SET visible_bus = $2, all_bus = $3 WHERE subject = $1 AND (visible_bus <> $2 OR all_bus <> $3)`, subject, bus, all)
}

// EmailRecipients lists who wants email about a notification: email on,
// the kind not muted (and among their chosen kinds, if any), and the BU
// among what they could see when last active.
func (s *Store) EmailRecipients(ctx context.Context, kind, bu string) ([]string, error) {
	rows, err := s.db.Query(ctx, `SELECT subject FROM notification_prefs WHERE email_enabled
		AND NOT ($1 = ANY(muted)) AND (cardinality(email_kinds) = 0 OR $1 = ANY(email_kinds))
		AND ($2 = '' OR all_bus OR $2 = ANY(visible_bus)) AND subject LIKE '%@%' ORDER BY subject`, kind, bu)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var x string
		if rows.Scan(&x) == nil {
			out = append(out, x)
		}
	}
	return out, rows.Err()
}

func (s *Store) EnqueueEmail(ctx context.Context, to, subject, body string) error {
	_, err := s.db.Exec(ctx, `INSERT INTO email_outbox (recipient, subject, body) VALUES ($1, $2, $3)`, to, subject, body)
	return err
}

type Email struct {
	ID        int64
	To        string
	Subject   string
	Body      string
	Attempts  int
	CreatedAt time.Time
}

// PendingEmails returns emails not sent yet that are due for an attempt.
func (s *Store) PendingEmails(ctx context.Context, limit int) ([]Email, error) {
	rows, err := s.db.Query(ctx, `SELECT id, recipient, subject, body, attempts, created_at FROM email_outbox WHERE sent_at IS NULL AND attempts < 5
		ORDER BY id LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Email
	for rows.Next() {
		var e Email
		if err := rows.Scan(&e.ID, &e.To, &e.Subject, &e.Body, &e.Attempts, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) EmailSent(ctx context.Context, id int64) {
	s.db.Exec(ctx, `UPDATE email_outbox SET sent_at = now(), attempts = attempts + 1, last_error = '' WHERE id = $1`, id)
}

func (s *Store) EmailFailed(ctx context.Context, id int64, msg string) {
	if len(msg) > 500 {
		msg = msg[:500]
	}
	s.db.Exec(ctx, `UPDATE email_outbox SET attempts = attempts + 1, last_error = $2 WHERE id = $1`, id, msg)
}

// EmailStats is the outbox at a glance.
func (s *Store) EmailStats(ctx context.Context) (pending, failed int, lastSent *time.Time, lastError string) {
	s.db.QueryRow(ctx, `SELECT count(*) FILTER (WHERE sent_at IS NULL AND attempts < 5), count(*) FILTER (WHERE sent_at IS NULL AND attempts >= 5),
		max(sent_at), COALESCE((SELECT last_error FROM email_outbox WHERE last_error <> '' ORDER BY id DESC LIMIT 1), '')
		FROM email_outbox`).Scan(&pending, &failed, &lastSent, &lastError)
	return
}

// PruneEmails drops sent emails after a week.
func (s *Store) PruneEmails(ctx context.Context) {
	s.db.Exec(ctx, `DELETE FROM email_outbox WHERE (sent_at IS NOT NULL OR attempts >= 5) AND created_at < now() - interval '7 days'`)
}

// ---- advisory locks for the tenant plane's loops ----

// TryLock runs fn while holding advisory lock key on one connection, and
// reports false without running it when another replica holds the lock.
func (s *Store) TryLock(ctx context.Context, key int64, fn func(context.Context)) bool {
	conn, err := s.db.Acquire(ctx)
	if err != nil {
		return false
	}
	defer conn.Release()
	var got bool
	if conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&got); !got {
		return false
	}
	defer conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, key)
	fctx, stop := fenced(ctx, conn)
	defer stop()
	heldLocks.Store(key, time.Now())
	defer heldLocks.Delete(key)
	fn(fctx)
	return true
}

// heldLocks are the single-replica jobs this process is running now.
var heldLocks sync.Map // int64 -> time.Time

// HeldLocks lists the advisory locks this process holds, with since when.
func HeldLocks() map[int64]time.Time {
	out := map[int64]time.Time{}
	heldLocks.Range(func(k, v any) bool { out[k.(int64)] = v.(time.Time); return true })
	return out
}

// fenced is ctx, cancelled as soon as the connection holding a session
// advisory lock stops answering: the lock is then gone, another replica may
// take it, so this work must stop rather than run twice.
func fenced(ctx context.Context, conn *pgxpool.Conn) (context.Context, func()) {
	fctx, cancel := context.WithCancel(ctx)
	done, exited := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(exited)
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-fctx.Done():
				return
			case <-t.C:
				pctx, pc := context.WithTimeout(ctx, 5*time.Second)
				err := conn.Ping(pctx)
				pc()
				if err != nil && ctx.Err() == nil {
					cancel()
					return
				}
			}
		}
	}()
	// stop waits for the pinger, so the connection is free for the unlock.
	return fctx, func() { close(done); <-exited; cancel() }
}

var _ = fmt.Sprintf

// WithLock runs fn holding the advisory lock key, waiting for it (up to
// ctx's deadline, at most wait): work that must happen on one replica at a
// time, whichever replica started it.
func (s *Store) WithLock(ctx context.Context, key int64, wait time.Duration, fn func(context.Context) error) error {
	conn, err := s.db.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	lctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	if _, err := conn.Exec(lctx, `SELECT pg_advisory_lock($1)`, key); err != nil {
		return fmt.Errorf("waiting for other work to finish: %w", err)
	}
	defer conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, key)
	fctx, stop := fenced(ctx, conn)
	defer stop()
	heldLocks.Store(key, time.Now())
	defer heldLocks.Delete(key)
	return fn(fctx)
}

// TouchRun marks a run as still alive (a runner heartbeat).
func (s *Store) TouchRun(ctx context.Context, runID string) {
	s.db.Exec(ctx, `UPDATE runs SET updated_at = now() WHERE id = $1 AND status IN ('planning', 'applying') AND updated_at < now() - interval '30 seconds'`, runID)
}

// NotifyChange tells open consoles that a run or stack changed in a way the
// triggers do not announce (a cancel request, a lock).
func (s *Store) NotifyChange(ctx context.Context, kind, id, bu string) {
	s.db.Exec(ctx, `SELECT pg_notify('srustiops_events', $1)`, kind+":"+id+":"+bu)
}

// StackInventory lists the inventory items the cloud tags say a stack manages.
func (s *Store) StackInventory(ctx context.Context, stack string) ([]*InventoryItem, error) {
	rows, err := s.db.Query(ctx, `SELECT `+invCols+` FROM inventory WHERE stack = $1 ORDER BY type, name LIMIT 500`, stack)
	if err != nil {
		return nil, err
	}
	return Collect(rows, scanInv)
}

// StackOutputRows lists a stack's sealed outputs with the run that wrote them.
type OutputRow struct {
	Name  string
	Value []byte
	RunID *string
}

func (s *Store) StackOutputRows(ctx context.Context, stackID string) ([]OutputRow, error) {
	rows, err := s.db.Query(ctx, `SELECT name, value, run_id::text FROM stack_outputs WHERE stack_id = $1 ORDER BY name`, stackID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OutputRow
	for rows.Next() {
		var o OutputRow
		if err := rows.Scan(&o.Name, &o.Value, &o.RunID); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// ---- backups ----

type BackupRow struct {
	ID        string          `json:"id"`
	Key       string          `json:"key"`
	Size      int64           `json:"size"`
	Tables    int             `json:"tables"`
	Rows      int64           `json:"rows"`
	Objects   int             `json:"objects"`
	Parts     int             `json:"parts"`
	CreatedBy string          `json:"created_by"`
	CreatedAt time.Time       `json:"created_at"`
	Drill     json.RawMessage `json:"drill,omitempty"`
	DrilledAt *time.Time      `json:"drilled_at,omitempty"`
}

const backupCols = `id, key, size, tables, rows, objects, parts, created_by, created_at, drill, drilled_at`

func scanBackup(r pgx.Row) (*BackupRow, error) {
	var b BackupRow
	err := r.Scan(&b.ID, &b.Key, &b.Size, &b.Tables, &b.Rows, &b.Objects, &b.Parts, &b.CreatedBy, &b.CreatedAt, &b.Drill, &b.DrilledAt)
	return &b, NotFound(err)
}

func (s *Store) AddBackup(ctx context.Context, b *BackupRow) (*BackupRow, error) {
	return scanBackup(s.db.QueryRow(ctx, `INSERT INTO backups (key, size, tables, rows, objects, parts, created_by) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING `+backupCols,
		b.Key, b.Size, b.Tables, b.Rows, b.Objects, b.Parts, b.CreatedBy))
}

func (s *Store) ListBackups(ctx context.Context) ([]*BackupRow, error) {
	rows, err := s.db.Query(ctx, `SELECT `+backupCols+` FROM backups ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	return Collect(rows, scanBackup)
}

func (s *Store) GetBackup(ctx context.Context, id string) (*BackupRow, error) {
	return scanBackup(s.db.QueryRow(ctx, `SELECT `+backupCols+` FROM backups WHERE id::text = $1`, id))
}

func (s *Store) SetDrill(ctx context.Context, id string, report any) {
	b, _ := json.Marshal(report)
	s.db.Exec(ctx, `UPDATE backups SET drill = $2, drilled_at = now() WHERE id = $1`, id, b)
}

func (s *Store) DeleteBackupRow(ctx context.Context, id string) {
	s.db.Exec(ctx, `DELETE FROM backups WHERE id = $1`, id)
}
