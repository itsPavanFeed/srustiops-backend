package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

type EventSource struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	ConnectionID string     `json:"connection_id"`
	Connection   string     `json:"connection"`
	TokenHash    []byte     `json:"-"`
	IgnoreActors []string   `json:"ignore_actors"`
	CreatedBy    string     `json:"created_by"`
	CreatedAt    time.Time  `json:"created_at"`
	LastEventAt  *time.Time `json:"last_event_at,omitempty"`
}

const srcCols = `s.id, s.name, s.connection_id, c.name, s.token_hash, s.ignore_actors, s.created_by, s.created_at, s.last_event_at`
const srcFrom = ` FROM event_sources s JOIN cloud_connections c ON c.id = s.connection_id`

func scanSource(r pgx.Row) (*EventSource, error) {
	var x EventSource
	err := r.Scan(&x.ID, &x.Name, &x.ConnectionID, &x.Connection, &x.TokenHash, &x.IgnoreActors, &x.CreatedBy, &x.CreatedAt, &x.LastEventAt)
	if x.IgnoreActors == nil {
		x.IgnoreActors = []string{}
	}
	return &x, NotFound(err)
}

func (s *Store) CreateEventSource(ctx context.Context, x *EventSource) (*EventSource, error) {
	var id string
	err := s.db.QueryRow(ctx, `INSERT INTO event_sources (name, connection_id, token_hash, ignore_actors, created_by) VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		x.Name, x.ConnectionID, x.TokenHash, x.IgnoreActors, x.CreatedBy).Scan(&id)
	if IsUnique(err) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	return s.GetEventSource(ctx, id)
}

func (s *Store) GetEventSource(ctx context.Context, idOrName string) (*EventSource, error) {
	return scanSource(s.db.QueryRow(ctx, `SELECT `+srcCols+srcFrom+` WHERE s.id::text = $1 OR s.name = $1`, idOrName))
}

func (s *Store) ListEventSources(ctx context.Context) ([]*EventSource, error) {
	rows, err := s.db.Query(ctx, `SELECT `+srcCols+srcFrom+` ORDER BY s.name`)
	if err != nil {
		return nil, err
	}
	return Collect(rows, scanSource)
}

func (s *Store) DeleteEventSource(ctx context.Context, id string) error {
	return s.deleteRow(ctx, "event_sources", id)
}

type CloudEvent struct {
	ID           int64      `json:"id"`
	SourceID     string     `json:"source_id"`
	ConnectionID string     `json:"connection_id"`
	ReceivedAt   time.Time  `json:"received_at"`
	EventTime    *time.Time `json:"event_time,omitempty"`
	Action       string     `json:"action"`
	EventName    string     `json:"event_name"`
	ResourceID   string     `json:"resource_id"`
	Actor        string     `json:"actor"`
	Stack        string     `json:"stack"`
	BU           string     `json:"bu"`
	Ignored      string     `json:"ignored,omitempty"`
	Notified     bool       `json:"notified"`
}

const evCols = `id, source_id, connection_id, received_at, event_time, action, event_name, resource_id, actor, stack, bu, ignored, notified`

func scanEvent(r pgx.Row) (*CloudEvent, error) {
	var x CloudEvent
	err := r.Scan(&x.ID, &x.SourceID, &x.ConnectionID, &x.ReceivedAt, &x.EventTime, &x.Action, &x.EventName, &x.ResourceID, &x.Actor, &x.Stack, &x.BU, &x.Ignored, &x.Notified)
	return &x, NotFound(err)
}

// RecordEvent stores one event. It is notified when it flags a stack that
// had no notified event in the last window (so a burst notifies once).
func (s *Store) RecordEvent(ctx context.Context, x *CloudEvent, window time.Duration) (*CloudEvent, error) {
	return scanEvent(s.db.QueryRow(ctx, `INSERT INTO cloud_events (source_id, connection_id, event_time, action, event_name, resource_id, actor, stack, bu, ignored, notified)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
		  $8 <> '' AND $10 = '' AND NOT EXISTS (SELECT 1 FROM cloud_events WHERE stack = $8 AND notified AND received_at > now() - make_interval(secs => $11)))
		RETURNING `+evCols,
		x.SourceID, x.ConnectionID, x.EventTime, x.Action, x.EventName, x.ResourceID, x.Actor, x.Stack, x.BU, x.Ignored, window.Seconds()))
}

func (s *Store) TouchEventSource(ctx context.Context, id string) {
	s.db.Exec(ctx, `UPDATE event_sources SET last_event_at = now() WHERE id = $1`, id)
}

type EventFilter struct {
	BUs        []string // nil = all; otherwise only events of stacks in these BUs
	Stack      string
	Connection string
	Resource   string // one resource ID (case-insensitive)
	Since      *time.Time
	Flagged    bool // only events that flag a stack
	Limit      int
}

func (s *Store) ListEvents(ctx context.Context, f EventFilter) ([]*CloudEvent, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	rows, err := s.db.Query(ctx, `SELECT `+evCols+` FROM cloud_events WHERE ($1::text[] IS NULL OR bu = ANY($1)) AND ($2 = '' OR stack = $2)
		AND ($3 = '' OR connection_id::text = $3) AND ($4::timestamptz IS NULL OR received_at > $4) AND (NOT $5 OR (stack <> '' AND ignored = ''))
		AND ($7 = '' OR lower(resource_id) = lower($7))
		ORDER BY received_at DESC, id DESC LIMIT $6`, f.BUs, f.Stack, f.Connection, f.Since, f.Flagged, f.Limit, f.Resource)
	if err != nil {
		return nil, err
	}
	return Collect(rows, scanEvent)
}

// InventoryStack finds the stack managing a resource of a connection
// (resource IDs compare case-insensitively: Azure IDs vary in case).
func (s *Store) InventoryStack(ctx context.Context, conn, resourceID string) (string, error) {
	var stack string
	err := s.db.QueryRow(ctx, `SELECT stack FROM inventory WHERE connection_id = $1 AND lower(resource_id) = lower($2) AND stack <> '' LIMIT 1`, conn, resourceID).Scan(&stack)
	if err != nil {
		return "", NotFound(err)
	}
	return stack, nil
}
