package central

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/itsPavanFeed/srustiops-backend/internal/store"
)

// ---- tenant link: enrolment, certificates, tunnels, queued webhooks ----

func (s *Store) CreateEnrollment(ctx context.Context, tenantID string, hash []byte, by string, expires time.Time) error {
	_, err := s.Pool().Exec(ctx, `INSERT INTO link_enrollments (tenant_id, token_hash, created_by, expires_at) VALUES ($1, $2, $3, $4)`, tenantID, hash, by, expires)
	return err
}

// TakeEnrollment burns a live enrolment token for the tenant; the token works once.
func (s *Store) TakeEnrollment(ctx context.Context, slug string, hash []byte) (*Tenant, error) {
	var id string
	err := s.Pool().QueryRow(ctx, `UPDATE link_enrollments e SET used_at = now() FROM tenants t
		WHERE e.tenant_id = t.id AND t.slug = $1 AND e.token_hash = $2 AND e.used_at IS NULL AND e.expires_at > now()
		RETURNING t.id`, slug, hash).Scan(&id)
	if err != nil {
		return nil, store.NotFound(err)
	}
	return s.Tenant(ctx, slug)
}

type LinkCert struct {
	Serial      string     `json:"serial"`
	Fingerprint string     `json:"fingerprint"`
	IssuedVia   string     `json:"issued_via"`
	NotAfter    time.Time  `json:"not_after"`
	CreatedAt   time.Time  `json:"created_at"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	RevokedBy   string     `json:"revoked_by,omitempty"`
}

func (s *Store) AddLinkCert(ctx context.Context, tenantID string, c *LinkCert) error {
	_, err := s.Pool().Exec(ctx, `INSERT INTO link_certs (serial, tenant_id, fingerprint, issued_via, not_after) VALUES ($1, $2, $3, $4, $5)`,
		c.Serial, tenantID, c.Fingerprint, c.IssuedVia, c.NotAfter)
	return err
}

// LinkCertValid: the serial was issued to this tenant and is not revoked.
func (s *Store) LinkCertValid(ctx context.Context, slug, serial string) bool {
	var ok bool
	err := s.Pool().QueryRow(ctx, `SELECT true FROM link_certs c JOIN tenants t ON t.id = c.tenant_id
		WHERE t.slug = $1 AND c.serial = $2 AND c.revoked_at IS NULL AND c.not_after > now()`, slug, serial).Scan(&ok)
	return err == nil && ok
}

func (s *Store) LinkCerts(ctx context.Context, tenantID string, limit int) ([]*LinkCert, error) {
	rows, err := s.Pool().Query(ctx, `SELECT serial, fingerprint, issued_via, not_after, created_at, revoked_at, COALESCE(revoked_by, '')
		FROM link_certs WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	return store.Collect(rows, func(r pgx.Row) (*LinkCert, error) {
		var c LinkCert
		err := r.Scan(&c.Serial, &c.Fingerprint, &c.IssuedVia, &c.NotAfter, &c.CreatedAt, &c.RevokedAt, &c.RevokedBy)
		return &c, err
	})
}

// RevokeLinkCerts revokes a certificate together with every live certificate
// of the same bound key (renewals and re-enrolments share it, so revoking one
// serial alone would leave the agent its newer certificate), or (serial "")
// every live certificate of the tenant. It returns the serials revoked.
func (s *Store) RevokeLinkCerts(ctx context.Context, tenantID, serial, by string) ([]string, error) {
	rows, err := s.Pool().Query(ctx, `UPDATE link_certs SET revoked_at = now(), revoked_by = $3
		WHERE tenant_id = $1 AND revoked_at IS NULL AND ($2 = '' OR fingerprint IN
			(SELECT fingerprint FROM link_certs WHERE tenant_id = $1 AND serial = $2)) RETURNING serial`, tenantID, serial, by)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

type LinkRow struct {
	Replica     string    `json:"replica"`
	ReplicaURL  string    `json:"-"`
	Serial      string    `json:"serial"`
	Remote      string    `json:"remote"`
	ConnectedAt time.Time `json:"connected_at"`
	LastSeen    time.Time `json:"last_seen"`
	Version     string    `json:"version"`
	Mode        string    `json:"mode"`
	Lane        string    `json:"lane,omitempty"`
	SkewMS      int64     `json:"clock_skew_ms"`
}

// linkFresh is how long a replica's last report of a tunnel counts as alive.
const linkFresh = 45 * time.Second

func (s *Store) UpsertLink(ctx context.Context, tenantID, id string, l *LinkRow) error {
	_, err := s.Pool().Exec(ctx, `INSERT INTO tenant_links (id, tenant_id, replica, replica_url, serial, remote, connected_at, last_seen, version, mode, clock_skew_ms, lane)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) ON CONFLICT (id) DO UPDATE SET last_seen = EXCLUDED.last_seen,
		version = EXCLUDED.version, mode = EXCLUDED.mode, clock_skew_ms = EXCLUDED.clock_skew_ms, lane = EXCLUDED.lane`,
		id, tenantID, l.Replica, l.ReplicaURL, l.Serial, l.Remote, l.ConnectedAt, l.LastSeen, l.Version, l.Mode, l.SkewMS, l.Lane)
	if err == nil {
		s.TouchLinkSeen(ctx, tenantID, l.LastSeen)
	}
	return err
}

// TouchLinkSeen records that a tenant's agent was heard from (at most once a
// minute, so heartbeats do not rewrite the tenant row each time).
func (s *Store) TouchLinkSeen(ctx context.Context, tenantID string, at time.Time) {
	s.Pool().Exec(ctx, `UPDATE tenants SET link_seen_at = $2 WHERE id = $1 AND (link_seen_at IS NULL OR link_seen_at < $2 - interval '1 minute')`, tenantID, at)
}

func (s *Store) DeleteLink(ctx context.Context, id string) error {
	_, err := s.Pool().Exec(ctx, `DELETE FROM tenant_links WHERE id = $1`, id)
	return err
}

// DeleteReplicaLinks forgets the tunnels a replica held (on its start or stop).
func (s *Store) DeleteReplicaLinks(ctx context.Context, replica string) error {
	_, err := s.Pool().Exec(ctx, `DELETE FROM tenant_links WHERE replica = $1 OR last_seen < now() - interval '1 day'`, replica)
	return err
}

// Links lists the tunnels of a tenant reported alive by any replica.
func (s *Store) Links(ctx context.Context, tenantID string) ([]*LinkRow, error) {
	rows, err := s.Pool().Query(ctx, `SELECT replica, replica_url, serial, remote, connected_at, last_seen, version, mode, clock_skew_ms, lane FROM tenant_links
		WHERE tenant_id = $1 AND last_seen > $2 ORDER BY connected_at`, tenantID, time.Now().Add(-linkFresh))
	if err != nil {
		return nil, err
	}
	return store.Collect(rows, func(r pgx.Row) (*LinkRow, error) {
		var l LinkRow
		err := r.Scan(&l.Replica, &l.ReplicaURL, &l.Serial, &l.Remote, &l.ConnectedAt, &l.LastSeen, &l.Version, &l.Mode, &l.SkewMS, &l.Lane)
		return &l, err
	})
}

// ---- queued webhooks ----

// The offline queue keeps at most WebhookQueueMax deliveries per tenant for
// at most webhookQueueTTL; beyond either, the oldest go and are counted, and
// the tenant hears how many on reconnect (a webhooks_dropped link event).
var WebhookQueueMax = 10000

const webhookQueueTTL = 72 * time.Hour

// QueuedWebhook is a delivery kept while its tenant was offline. Sealed
// holds its headers and body, encrypted with the central master key.
type QueuedWebhook struct {
	ID     int64
	Path   string
	Sealed []byte
}

// QueueWebhook keeps a delivery for later, dropping (and counting) the
// oldest when the queue is full.
func (s *Store) QueueWebhook(ctx context.Context, tenantID, path string, sealed []byte) error {
	return pgx.BeginFunc(ctx, s.Pool(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO link_webhook_queue (tenant_id, path, body) VALUES ($1, $2, $3)`, tenantID, path, sealed); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM link_webhook_queue WHERE id IN (
			SELECT id FROM link_webhook_queue WHERE tenant_id = $1 ORDER BY id DESC OFFSET $2)`, tenantID, WebhookQueueMax)
		if err != nil {
			return err
		}
		if n := tag.RowsAffected(); n > 0 {
			_, err = tx.Exec(ctx, `UPDATE tenants SET webhooks_dropped = webhooks_dropped + $2 WHERE id = $1`, tenantID, n)
		}
		return err
	})
}

// TakeWebhooksDropped returns and resets the count of dropped deliveries.
func (s *Store) TakeWebhooksDropped(ctx context.Context, tenantID string) int {
	var n int
	// The old value comes from a locked sub-select: a CTE read in RETURNING
	// is not visible there and would always give NULL.
	s.Pool().QueryRow(ctx, `UPDATE tenants t SET webhooks_dropped = 0
		FROM (SELECT id, webhooks_dropped FROM tenants WHERE id = $1 FOR UPDATE) old
		WHERE t.id = old.id RETURNING old.webhooks_dropped`, tenantID).Scan(&n)
	return n
}

func (s *Store) QueuedWebhooks(ctx context.Context, tenantID string, limit int) ([]*QueuedWebhook, error) {
	tag, err := s.Pool().Exec(ctx, `DELETE FROM link_webhook_queue WHERE tenant_id = $1 AND created_at < $2`, tenantID, time.Now().Add(-webhookQueueTTL))
	if err != nil {
		return nil, err
	}
	if n := tag.RowsAffected(); n > 0 {
		s.Pool().Exec(ctx, `UPDATE tenants SET webhooks_dropped = webhooks_dropped + $2 WHERE id = $1`, tenantID, n)
	}
	rows, err := s.Pool().Query(ctx, `SELECT id, path, body FROM link_webhook_queue WHERE tenant_id = $1 ORDER BY id LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	return store.Collect(rows, func(r pgx.Row) (*QueuedWebhook, error) {
		var q QueuedWebhook
		err := r.Scan(&q.ID, &q.Path, &q.Sealed)
		return &q, err
	})
}

func (s *Store) QueuedWebhookCount(ctx context.Context, tenantID string) int {
	var n int
	s.Pool().QueryRow(ctx, `SELECT count(*) FROM link_webhook_queue WHERE tenant_id = $1`, tenantID).Scan(&n)
	return n
}

func (s *Store) DeleteQueuedWebhook(ctx context.Context, id int64) error {
	_, err := s.Pool().Exec(ctx, `DELETE FROM link_webhook_queue WHERE id = $1`, id)
	return err
}

// LinkReenrollable: a link whose certificate expired may re-enrol with its
// bound key if that key belongs to this tenant, was never revoked, and its
// last certificate expired less than 30 days ago.
func (s *Store) LinkReenrollable(ctx context.Context, slug, fingerprint string) bool {
	var ok bool
	err := s.Pool().QueryRow(ctx, `SELECT count(*) > 0 AND coalesce(bool_and(c.revoked_at IS NULL), false) AND coalesce(max(c.not_after) > now() - interval '30 days', false)
		FROM link_certs c JOIN tenants t ON t.id = c.tenant_id WHERE t.slug = $1 AND c.fingerprint = $2`, slug, fingerprint).Scan(&ok)
	return err == nil && ok
}

func (s *Store) PinTenantKeys(ctx context.Context, tenantID, sign, enc string) error {
	_, err := s.Pool().Exec(ctx, `UPDATE tenants SET dir_sign_key = $2, dir_enc_key = $3 WHERE id = $1`, tenantID, sign, enc)
	return err
}

// AdvanceDirectorySeq records a newer directory snapshot; false for an older or replayed one.
func (s *Store) AdvanceDirectorySeq(ctx context.Context, tenantID string, seq int64) bool {
	tag, err := s.Pool().Exec(ctx, `UPDATE tenants SET directory_seq = $2 WHERE id = $1 AND directory_seq < $2`, tenantID, seq)
	return err == nil && tag.RowsAffected() == 1
}
