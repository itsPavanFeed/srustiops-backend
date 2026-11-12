package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// ---- tenant-controlled access ----

type AccessGrant struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	Entity    string    `json:"entity,omitempty"`
	BU        string    `json:"bu,omitempty"`
	Source    string    `json:"source"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	// Bound to this identity on the first verified sign-in; empty while an invitation.
	Issuer  string `json:"issuer,omitempty"`
	Subject string `json:"subject,omitempty"`
	IDP     string `json:"bound_via,omitempty"`
}

const grantCols = `id, email, role, entity, bu, source, created_by, created_at, COALESCE(issuer, ''), COALESCE(subject, ''), COALESCE(idp, '')`

func scanGrant(r pgx.Row) (*AccessGrant, error) {
	var g AccessGrant
	err := r.Scan(&g.ID, &g.Email, &g.Role, &g.Entity, &g.BU, &g.Source, &g.CreatedBy, &g.CreatedAt, &g.Issuer, &g.Subject, &g.IDP)
	return &g, NotFound(err)
}

func (s *Store) AccessGrants(ctx context.Context, email string) ([]*AccessGrant, error) {
	q, args := `SELECT `+grantCols+` FROM access_grants ORDER BY email, entity, bu, role`, []any{}
	if email != "" {
		q, args = `SELECT `+grantCols+` FROM access_grants WHERE email = $1 ORDER BY entity, bu, role`, []any{email}
	}
	rows, err := s.db.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	return Collect(rows, scanGrant)
}

// AddAccessGrant adds a grant; an identical one already present is returned as is.
func (s *Store) AddAccessGrant(ctx context.Context, g *AccessGrant) (*AccessGrant, error) {
	if g.Source == "" {
		g.Source = "manual"
	}
	if _, err := s.db.Exec(ctx, `INSERT INTO access_grants (email, role, entity, bu, source, created_by) VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (email, role, entity, bu) DO NOTHING`, g.Email, g.Role, g.Entity, g.BU, g.Source, g.CreatedBy); err != nil {
		return nil, err
	}
	return scanGrant(s.db.QueryRow(ctx, `SELECT `+grantCols+` FROM access_grants WHERE email = $1 AND role = $2 AND entity = $3 AND bu = $4`, g.Email, g.Role, g.Entity, g.BU))
}

func (s *Store) DeleteAccessGrant(ctx context.Context, id string) (*AccessGrant, error) {
	return scanGrant(s.db.QueryRow(ctx, `DELETE FROM access_grants WHERE id::text = $1 RETURNING `+grantCols, id))
}

// DeleteAccessGrantsFor removes grants of email matching role and scope
// ("" role = every role in that scope).
func (s *Store) DeleteAccessGrantsFor(ctx context.Context, email, role, entity, bu string) (int64, error) {
	tag, err := s.db.Exec(ctx, `DELETE FROM access_grants WHERE email = $1 AND ($2 = '' OR role = $2) AND entity = $3 AND bu = $4`, email, role, entity, bu)
	return tag.RowsAffected(), err
}

type GroupBinding struct {
	ID        string    `json:"id"`
	Group     string    `json:"group"`
	Role      string    `json:"role"`
	Entity    string    `json:"entity,omitempty"`
	BU        string    `json:"bu,omitempty"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	Members   int       `json:"members"` // provisioned by SCIM
}

func (s *Store) GroupBindings(ctx context.Context) ([]*GroupBinding, error) {
	rows, err := s.db.Query(ctx, `SELECT b.id, b.group_name, b.role, b.entity, b.bu, b.created_by, b.created_at,
		(SELECT count(*) FROM access_group_members m WHERE m.group_name = b.group_name)
		FROM access_group_bindings b ORDER BY b.group_name, b.role`)
	if err != nil {
		return nil, err
	}
	return Collect(rows, func(r pgx.Row) (*GroupBinding, error) {
		var b GroupBinding
		return &b, r.Scan(&b.ID, &b.Group, &b.Role, &b.Entity, &b.BU, &b.CreatedBy, &b.CreatedAt, &b.Members)
	})
}

func (s *Store) AddGroupBinding(ctx context.Context, b *GroupBinding) error {
	_, err := s.db.Exec(ctx, `INSERT INTO access_group_bindings (group_name, role, entity, bu, created_by) VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT DO NOTHING`, b.Group, b.Role, b.Entity, b.BU, b.CreatedBy)
	return err
}

func (s *Store) DeleteGroupBinding(ctx context.Context, id string) (*GroupBinding, error) {
	var b GroupBinding
	err := s.db.QueryRow(ctx, `DELETE FROM access_group_bindings WHERE id::text = $1 RETURNING id, group_name, role, entity, bu, created_by, created_at`, id).
		Scan(&b.ID, &b.Group, &b.Role, &b.Entity, &b.BU, &b.CreatedBy, &b.CreatedAt)
	return &b, NotFound(err)
}

// BindingsFor returns the bindings of the groups an email belongs to, by its
// provider's claim (claimed) or by SCIM provisioning.
func (s *Store) BindingsFor(ctx context.Context, email string, claimed []string) ([]*GroupBinding, error) {
	if claimed == nil {
		claimed = []string{}
	}
	rows, err := s.db.Query(ctx, `SELECT id, group_name, role, entity, bu, created_by, created_at, 0 FROM access_group_bindings
		WHERE group_name = ANY($2) OR group_name IN (SELECT group_name FROM access_group_members WHERE email = $1)`, email, claimed)
	if err != nil {
		return nil, err
	}
	return Collect(rows, func(r pgx.Row) (*GroupBinding, error) {
		var b GroupBinding
		return &b, r.Scan(&b.ID, &b.Group, &b.Role, &b.Entity, &b.BU, &b.CreatedBy, &b.CreatedAt, &b.Members)
	})
}

// SetGroupMembers replaces a group's provisioned members.
func (s *Store) SetGroupMembers(ctx context.Context, group string, emails []string) error {
	return pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM access_group_members WHERE group_name = $1`, group); err != nil {
			return err
		}
		for _, e := range emails {
			if _, err := tx.Exec(ctx, `INSERT INTO access_group_members (group_name, email) VALUES ($1, $2) ON CONFLICT DO NOTHING`, group, e); err != nil {
				return err
			}
		}
		return nil
	})
}

// GroupMembers lists provisioned members by group.
func (s *Store) GroupMembers(ctx context.Context) (map[string][]string, error) {
	rows, err := s.db.Query(ctx, `SELECT group_name, email FROM access_group_members ORDER BY 1, 2`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var g, e string
		if err := rows.Scan(&g, &e); err != nil {
			return nil, err
		}
		out[g] = append(out[g], e)
	}
	return out, rows.Err()
}

type SupportGrant struct {
	ID          string     `json:"id"`
	Email       string     `json:"email"`
	Role        string     `json:"role"`
	Reason      string     `json:"reason"`
	Hours       int        `json:"hours"`
	Status      string     `json:"status"` // pending | approved | declined | revoked (approved and past expires_at = expired)
	RequestedAt time.Time  `json:"requested_at"`
	DecidedBy   *string    `json:"decided_by,omitempty"`
	DecidedAt   *time.Time `json:"decided_at,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

const supportCols = `id, email, role, reason, hours, status, requested_at, decided_by, decided_at, expires_at`

func scanSupport(r pgx.Row) (*SupportGrant, error) {
	var g SupportGrant
	err := r.Scan(&g.ID, &g.Email, &g.Role, &g.Reason, &g.Hours, &g.Status, &g.RequestedAt, &g.DecidedBy, &g.DecidedAt, &g.ExpiresAt)
	return &g, NotFound(err)
}

func (s *Store) CreateSupportGrant(ctx context.Context, email, role, reason string, hours int) (*SupportGrant, error) {
	return scanSupport(s.db.QueryRow(ctx, `INSERT INTO support_grants (email, role, reason, hours) VALUES ($1, $2, $3, $4) RETURNING `+supportCols, email, role, reason, hours))
}

func (s *Store) SupportGrants(ctx context.Context, limit int) ([]*SupportGrant, error) {
	rows, err := s.db.Query(ctx, `SELECT `+supportCols+` FROM support_grants ORDER BY requested_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	return Collect(rows, scanSupport)
}

// ActiveSupport returns the approved, unexpired support grants of email.
func (s *Store) ActiveSupport(ctx context.Context, email string) ([]*SupportGrant, error) {
	rows, err := s.db.Query(ctx, `SELECT `+supportCols+` FROM support_grants WHERE email = $1 AND status = 'approved' AND expires_at > now()`, email)
	if err != nil {
		return nil, err
	}
	return Collect(rows, scanSupport)
}

// DecideSupportGrant approves (starting the clock), declines or revokes a grant.
func (s *Store) DecideSupportGrant(ctx context.Context, id, status, by string) (*SupportGrant, error) {
	from := "pending"
	if status == "revoked" {
		from = "approved"
	}
	return scanSupport(s.db.QueryRow(ctx, `UPDATE support_grants SET status = $2, decided_by = $3, decided_at = now(),
		expires_at = CASE WHEN $2 = 'approved' THEN now() + make_interval(hours => hours) WHEN $2 = 'revoked' THEN now() ELSE expires_at END
		WHERE id::text = $1 AND status = $4 RETURNING `+supportCols, id, status, by, from))
}

func (s *Store) CreateTenantSession(ctx context.Context, id, email string, authTime time.Time, amr []string, expires time.Time) error {
	if amr == nil {
		amr = []string{}
	}
	_, err := s.db.Exec(ctx, `INSERT INTO tenant_sessions (id, email, auth_time, amr, expires_at) VALUES ($1, $2, $3, $4, $5)`, id, email, authTime, amr, expires)
	s.db.Exec(ctx, `DELETE FROM tenant_sessions WHERE expires_at < now() - interval '1 day'`)
	return err
}

// TenantSessionValid reports whether a tenant-issued session is live for email.
func (s *Store) TenantSessionValid(ctx context.Context, id, email string) bool {
	var ok bool
	err := s.db.QueryRow(ctx, `SELECT true FROM tenant_sessions WHERE id = $1 AND email = $2 AND expires_at > now()`, id, email).Scan(&ok)
	return err == nil && ok
}

// ---- identity-bound grants ----

// IdentityGrants returns the grants that apply to a person: those bound to
// (issuer, subject), and invitations by email that bindable says may bind.
// Bindable invitations are bound here, so the next sign-in matches by identity.
func (s *Store) IdentityGrants(ctx context.Context, issuer, subject, email, idp string, emailVerified bool, bindable func(g *AccessGrant) bool) ([]*AccessGrant, error) {
	rows, err := s.db.Query(ctx, `SELECT `+grantCols+` FROM access_grants WHERE (issuer = $1 AND subject = $2) OR email = $3`, issuer, subject, email)
	if err != nil {
		return nil, err
	}
	all, err := Collect(rows, scanGrant)
	if err != nil {
		return nil, err
	}
	var out []*AccessGrant
	for _, g := range all {
		switch {
		case g.Issuer == issuer && g.Subject == subject && issuer != "":
			out = append(out, g)
		case emailVerified && g.Email == email && bindable(g):
			if _, err := s.db.Exec(ctx, `UPDATE access_grants SET issuer = $2, subject = $3, idp = $4, bound_at = now() WHERE id = $1`, g.ID, issuer, subject, idp); err != nil {
				return nil, err
			}
			g.Issuer, g.Subject, g.IDP = issuer, subject, idp
			out = append(out, g)
		}
	}
	return out, nil
}

// ActiveSupportFor returns approved, unexpired support grants of an identity.
func (s *Store) ActiveSupportFor(ctx context.Context, issuer, subject string) ([]*SupportGrant, error) {
	rows, err := s.db.Query(ctx, `SELECT `+supportCols+` FROM support_grants WHERE issuer = $1 AND subject = $2 AND issuer <> '' AND status = 'approved' AND expires_at > now()`, issuer, subject)
	if err != nil {
		return nil, err
	}
	return Collect(rows, scanSupport)
}

func (s *Store) SetSupportIdentity(ctx context.Context, id, issuer, subject string) error {
	_, err := s.db.Exec(ctx, `UPDATE support_grants SET issuer = $2, subject = $3 WHERE id::text = $1`, id, issuer, subject)
	return err
}

// ---- the tenant's own OIDC flow ----

func (s *Store) CreateTenantAuthFlow(ctx context.Context, state, verifier, nonce, redirect string) error {
	_, err := s.db.Exec(ctx, `INSERT INTO tenant_auth_flows (state, verifier, nonce, redirect_uri) VALUES ($1, $2, $3, $4)`, state, verifier, nonce, redirect)
	s.db.Exec(ctx, `DELETE FROM tenant_auth_flows WHERE created_at < now() - interval '1 hour'`)
	return err
}

// TakeTenantAuthFlow consumes a flow younger than ten minutes.
func (s *Store) TakeTenantAuthFlow(ctx context.Context, state string) (verifier, nonce, redirect string, err error) {
	err = s.db.QueryRow(ctx, `DELETE FROM tenant_auth_flows WHERE state = $1 AND created_at > now() - interval '10 minutes' RETURNING verifier, nonce, redirect_uri`, state).
		Scan(&verifier, &nonce, &redirect)
	return verifier, nonce, redirect, NotFound(err)
}

type TenantSession struct {
	Email, Issuer, Subject string
	AMR, Groups            []string
	AuthTime               time.Time
}

func (s *Store) CreateIdentitySession(ctx context.Context, id string, ts *TenantSession, expires time.Time) error {
	_, err := s.db.Exec(ctx, `INSERT INTO tenant_sessions (id, email, auth_time, amr, expires_at, issuer, subject, groups) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		id, ts.Email, ts.AuthTime, nzs(ts.AMR), expires, ts.Issuer, ts.Subject, nzs(ts.Groups))
	s.db.Exec(ctx, `DELETE FROM tenant_sessions WHERE expires_at < now() - interval '1 day'`)
	return err
}

// LiveTenantSession returns a live session this tenant issued.
func (s *Store) LiveTenantSession(ctx context.Context, id string) (*TenantSession, error) {
	var ts TenantSession
	err := s.db.QueryRow(ctx, `SELECT email, issuer, subject, amr, groups, auth_time FROM tenant_sessions WHERE id = $1 AND expires_at > now()`, id).
		Scan(&ts.Email, &ts.Issuer, &ts.Subject, &ts.AMR, &ts.Groups, &ts.AuthTime)
	return &ts, NotFound(err)
}

func nzs(x []string) []string {
	if x == nil {
		return []string{}
	}
	return x
}

// SeenAssertion records an assertion ID until it expires; true when it was
// already recorded (a replay), whichever replica saw it first.
func (s *Store) SeenAssertion(ctx context.Context, jti string, expires time.Time) (bool, error) {
	tag, err := s.db.Exec(ctx, `INSERT INTO assertion_replay (jti, expires_at) VALUES ($1, $2) ON CONFLICT DO NOTHING`, jti, expires)
	if err != nil {
		return false, err
	}
	if time.Now().UnixNano()%50 == 0 {
		s.db.Exec(ctx, `DELETE FROM assertion_replay WHERE expires_at < now()`)
	}
	return tag.RowsAffected() == 0, nil
}
