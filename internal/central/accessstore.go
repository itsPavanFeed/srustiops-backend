package central

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/itsPavanFeed/srustiops-backend/internal/store"
)

// AuthSession is how a session signed in: passed to tenants in assertions.
type AuthSession struct {
	TokenID       string
	IDP           string
	UserIssuer    string
	UserSubject   string
	EmailVerified bool
	AMR           []string
	Groups        []string
	AuthTime      time.Time
	TenantID      string // set when signed in through a tenant's own provider
	TenantSession string
}

func nz(xs []string) []string {
	if xs == nil {
		return []string{}
	}
	return xs
}

// SessionByToken resolves a valid token to an enabled user and how it signed in.
func (s *Store) SessionByToken(ctx context.Context, hash []byte) (*User, *AuthSession, error) {
	var u User
	var a AuthSession
	var at *time.Time
	var created time.Time
	err := s.Pool().QueryRow(ctx, `WITH t AS (
			UPDATE api_tokens SET last_used_at = now()
			WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now()
			RETURNING id, user_id, idp, amr, groups, auth_time, created_at, uid_iss, uid_sub, email_verified)
		SELECT u.id, u.email, u.name, u.platform_admin, u.platform_root, u.created_at, u.disabled_at,
			t.id, t.idp, t.amr, t.groups, t.auth_time, t.created_at, t.uid_iss, t.uid_sub, t.email_verified
		FROM users u JOIN t ON t.user_id = u.id WHERE u.disabled_at IS NULL`, hash).
		Scan(&u.ID, &u.Email, &u.Name, &u.PlatformAdmin, &u.PlatformRoot, &u.CreatedAt, &u.DisabledAt,
			&a.TokenID, &a.IDP, &a.AMR, &a.Groups, &at, &created, &a.UserIssuer, &a.UserSubject, &a.EmailVerified)
	if err != nil {
		return nil, nil, store.NotFound(err)
	}
	a.AuthTime = created
	if at != nil {
		a.AuthTime = *at
	}
	return &u, &a, nil
}

func (s *Store) CreateAuthCodeWith(ctx context.Context, hash []byte, userID string, ttl time.Duration, a *AuthSession) error {
	var tid *string
	if a.TenantID != "" {
		tid = &a.TenantID
	}
	_, err := s.Pool().Exec(ctx, `INSERT INTO auth_codes (code_hash, user_id, expires_at, idp, amr, groups, tenant_id, tenant_session, uid_iss, uid_sub, email_verified)
		VALUES ($1, $2, now() + $3::interval, $4, $5, $6, $7, $8, $9, $10, $11)`,
		hash, userID, fmt.Sprintf("%d seconds", int(ttl.Seconds())), a.IDP, nz(a.AMR), nz(a.Groups), tid, a.TenantSession, a.UserIssuer, a.UserSubject, a.EmailVerified)
	s.Pool().Exec(ctx, `DELETE FROM auth_codes WHERE expires_at < now()`)
	return err
}

// TakeAuthCodeWith consumes a one-time sign-in code: its user and how they signed in.
func (s *Store) TakeAuthCodeWith(ctx context.Context, hash []byte) (*User, *AuthSession, error) {
	var a AuthSession
	var uid string
	var tid, tsess *string
	err := s.Pool().QueryRow(ctx, `DELETE FROM auth_codes WHERE code_hash = $1 AND expires_at > now()
		RETURNING user_id, idp, amr, groups, tenant_id::text, tenant_session, uid_iss, uid_sub, email_verified`, hash).Scan(&uid, &a.IDP, &a.AMR, &a.Groups, &tid, &tsess, &a.UserIssuer, &a.UserSubject, &a.EmailVerified)
	if err != nil {
		return nil, nil, store.NotFound(err)
	}
	if tid != nil {
		a.TenantID = *tid
	}
	if tsess != nil {
		a.TenantSession = *tsess
	}
	u, err := s.UserByID(ctx, uid)
	if err != nil || u.DisabledAt != nil {
		return nil, nil, store.ErrNotFound
	}
	a.AuthTime = time.Now()
	return u, &a, nil
}

// CreateSessionToken creates a sign-in session token carrying how it signed in.
func (s *Store) CreateSessionToken(ctx context.Context, userID, name string, hash []byte, expires time.Time, a *AuthSession) (*Token, error) {
	var t Token
	err := s.Pool().QueryRow(ctx, `INSERT INTO api_tokens (user_id, name, token_hash, created_by, expires_at, idp, amr, groups, auth_time, uid_iss, uid_sub, email_verified)
		VALUES ($1, $2, $3, 'sso', $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id, name, created_by, created_at, expires_at, last_used_at, revoked_at`, userID, name, hash, expires, a.IDP, nz(a.AMR), nz(a.Groups), a.AuthTime, a.UserIssuer, a.UserSubject, a.EmailVerified).
		Scan(&t.ID, &t.Name, &t.CreatedBy, &t.CreatedAt, &t.ExpiresAt, &t.LastUsedAt, &t.RevokedAt)
	if err != nil {
		return nil, err
	}
	if a.TenantID != "" && a.TenantSession != "" {
		if err := s.BindTenantSession(ctx, t.ID, a.TenantID, a.TenantSession); err != nil {
			return nil, err
		}
	}
	return &t, nil
}

func (s *Store) BindTenantSession(ctx context.Context, tokenID, tenantID, session string) error {
	_, err := s.Pool().Exec(ctx, `INSERT INTO token_tenant_sessions (token_id, tenant_id, tenant_session) VALUES ($1, $2, $3)
		ON CONFLICT (token_id, tenant_id) DO UPDATE SET tenant_session = EXCLUDED.tenant_session`, tokenID, tenantID, session)
	return err
}

func (s *Store) TenantSessionFor(ctx context.Context, tokenID, tenantID string) string {
	var sess string
	s.Pool().QueryRow(ctx, `SELECT tenant_session FROM token_tenant_sessions WHERE token_id = $1 AND tenant_id = $2`, tokenID, tenantID).Scan(&sess)
	return sess
}

// ---- the directory copy of a tenant-controlled tenant ----

// DirGrant is one grant as the tenant reports it.
type DirGrant struct {
	Email  string `json:"email"`
	Role   string `json:"role"`
	Entity string `json:"entity"`
	BU     string `json:"bu"`
}

// ReplaceTenantMemberships makes central's memberships for a tenant exactly
// the tenant's grants (unknown entities and BUs are skipped).
func (s *Store) ReplaceTenantMemberships(ctx context.Context, tenantID string, grants []DirGrant, by string) (added, removed int, err error) {
	err = pgx.BeginFunc(ctx, s.Pool(), func(tx pgx.Tx) error {
		ents, buIDs := map[string]string{}, map[string]string{}
		rows, err := tx.Query(ctx, `SELECT slug, id::text FROM entities WHERE tenant_id = $1`, tenantID)
		if err != nil {
			return err
		}
		for rows.Next() {
			var sl, id string
			rows.Scan(&sl, &id)
			ents[sl] = id
		}
		rows.Close()
		rows, err = tx.Query(ctx, `SELECT slug, id::text FROM business_units WHERE tenant_id = $1`, tenantID)
		if err != nil {
			return err
		}
		for rows.Next() {
			var sl, id string
			rows.Scan(&sl, &id)
			buIDs[sl] = id
		}
		rows.Close()
		key := func(email, role, e, b string) string { return strings.ToLower(email) + "|" + role + "|" + e + "|" + b }
		want := map[string]DirGrant{}
		for _, g := range grants {
			if (g.Entity != "" && ents[g.Entity] == "") || (g.BU != "" && buIDs[g.BU] == "") {
				continue
			}
			want[key(g.Email, g.Role, g.Entity, g.BU)] = g
		}
		rows, err = tx.Query(ctx, `SELECT m.id::text, u.email, m.role, COALESCE(e.slug, ''), COALESCE(b.slug, '') FROM memberships m
			JOIN users u ON u.id = m.user_id LEFT JOIN entities e ON e.id = m.entity_id LEFT JOIN business_units b ON b.id = m.bu_id
			WHERE m.tenant_id = $1`, tenantID)
		if err != nil {
			return err
		}
		have := map[string]string{}
		for rows.Next() {
			var id, email, role, e, b string
			if err := rows.Scan(&id, &email, &role, &e, &b); err != nil {
				rows.Close()
				return err
			}
			have[key(email, role, e, b)] = id
		}
		rows.Close()
		for k, id := range have {
			if _, ok := want[k]; !ok {
				if _, err := tx.Exec(ctx, `DELETE FROM memberships WHERE id = $1`, id); err != nil {
					return err
				}
				removed++
			}
		}
		for k, g := range want {
			if _, ok := have[k]; ok {
				continue
			}
			var uid string
			if err := tx.QueryRow(ctx, `INSERT INTO users (email, created_by) VALUES ($1, $2) ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email RETURNING id`,
				strings.ToLower(g.Email), by).Scan(&uid); err != nil {
				return err
			}
			var eid, bid *string
			if g.Entity != "" {
				x := ents[g.Entity]
				eid = &x
			}
			if g.BU != "" {
				x := buIDs[g.BU]
				bid = &x
			}
			if _, err := tx.Exec(ctx, `INSERT INTO memberships (user_id, tenant_id, entity_id, bu_id, role, created_by) VALUES ($1, $2, $3, $4, $5, $6)`,
				uid, tenantID, eid, bid, g.Role, by); err != nil {
				return err
			}
			added++
		}
		return nil
	})
	return added, removed, err
}

type DirSupport struct {
	ID          string     `json:"id"`
	Email       string     `json:"email"`
	Role        string     `json:"role"`
	Reason      string     `json:"reason"`
	Hours       int        `json:"hours"`
	Status      string     `json:"status"`
	RequestedAt time.Time  `json:"requested_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

func (s *Store) ReplaceTenantSupport(ctx context.Context, tenantID string, gs []DirSupport) error {
	return pgx.BeginFunc(ctx, s.Pool(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM tenant_support WHERE tenant_id = $1`, tenantID); err != nil {
			return err
		}
		for _, g := range gs {
			if _, err := tx.Exec(ctx, `INSERT INTO tenant_support (id, tenant_id, email, role, reason, status, hours, requested_at, expires_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (id) DO NOTHING`,
				g.ID, tenantID, strings.ToLower(g.Email), g.Role, g.Reason, g.Status, g.Hours, g.RequestedAt, g.ExpiresAt); err != nil {
				return err
			}
		}
		return nil
	})
}

// SupportFor lists a person's support requests in a tenant, newest first.
func (s *Store) SupportFor(ctx context.Context, tenantID, email string) ([]*DirSupport, error) {
	rows, err := s.Pool().Query(ctx, `SELECT id, email, role, reason, hours, status, requested_at, expires_at FROM tenant_support
		WHERE tenant_id = $1 AND email = $2 ORDER BY requested_at DESC`, tenantID, strings.ToLower(email))
	if err != nil {
		return nil, err
	}
	return store.Collect(rows, func(r pgx.Row) (*DirSupport, error) {
		var g DirSupport
		return &g, r.Scan(&g.ID, &g.Email, &g.Role, &g.Reason, &g.Hours, &g.Status, &g.RequestedAt, &g.ExpiresAt)
	})
}

// ActiveSupportRoles: approved, unexpired support roles of a person in a tenant.
func (s *Store) ActiveSupportRoles(ctx context.Context, tenantID, email string) []string {
	rows, err := s.Pool().Query(ctx, `SELECT DISTINCT role FROM tenant_support WHERE tenant_id = $1 AND email = $2 AND status = 'approved' AND expires_at > now()`,
		tenantID, strings.ToLower(email))
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var r string
		rows.Scan(&r)
		out = append(out, r)
	}
	return out
}

func (s *Store) SetTenantAccess(ctx context.Context, tenantID, source string, requireIDP bool) error {
	_, err := s.Pool().Exec(ctx, `UPDATE tenants SET access_source = $2, require_idp = $3, directory_synced_at = now() WHERE id = $1`, tenantID, source, requireIDP)
	return err
}

// ---- tenant identity providers and domains ----

type TenantIdP struct {
	Issuer       string    `json:"issuer"`
	ClientID     string    `json:"client_id"`
	ClientSecret []byte    `json:"-"`
	SecretSet    bool      `json:"client_secret_set"`
	Label        string    `json:"label"`
	GroupClaim   string    `json:"group_claim"`
	Enabled      bool      `json:"enabled"`
	UpdatedBy    string    `json:"updated_by"`
	UpdatedAt    time.Time `json:"updated_at"`
	EgressHosts  []string  `json:"egress_hosts"`
	Protocol     string    `json:"protocol"` // oidc | saml
}

func (s *Store) TenantIdP(ctx context.Context, tenantID string) (*TenantIdP, error) {
	var p TenantIdP
	err := s.Pool().QueryRow(ctx, `SELECT issuer, client_id, client_secret, label, group_claim, enabled, updated_by, updated_at, egress_hosts, protocol FROM tenant_idps WHERE tenant_id = $1`, tenantID).
		Scan(&p.Issuer, &p.ClientID, &p.ClientSecret, &p.Label, &p.GroupClaim, &p.Enabled, &p.UpdatedBy, &p.UpdatedAt, &p.EgressHosts, &p.Protocol)
	p.SecretSet = len(p.ClientSecret) > 0
	return &p, store.NotFound(err)
}

// PutTenantIdP saves the provider; a nil secret keeps the stored one.
func (s *Store) PutTenantIdP(ctx context.Context, tenantID string, p *TenantIdP) error {
	if p.EgressHosts == nil {
		p.EgressHosts = []string{}
	}
	if p.Protocol == "" {
		p.Protocol = "oidc"
	}
	_, err := s.Pool().Exec(ctx, `INSERT INTO tenant_idps (tenant_id, issuer, client_id, client_secret, label, group_claim, enabled, updated_by, egress_hosts, protocol)
		VALUES ($1, $2, '', NULL, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (tenant_id) DO UPDATE SET issuer = $2, client_id = '', client_secret = NULL,
			label = $3, group_claim = $4, enabled = $5, updated_by = $6, egress_hosts = $7, protocol = $8, updated_at = now()`,
		tenantID, p.Issuer, p.Label, p.GroupClaim, p.Enabled, p.UpdatedBy, p.EgressHosts, p.Protocol)
	return err
}

func (s *Store) DeleteTenantIdP(ctx context.Context, tenantID string) error {
	_, err := s.Pool().Exec(ctx, `DELETE FROM tenant_idps WHERE tenant_id = $1`, tenantID)
	return err
}

type TenantDomain struct {
	Domain     string     `json:"domain"`
	Token      string     `json:"token"`
	VerifiedAt *time.Time `json:"verified_at,omitempty"`
	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
}

func (s *Store) AddTenantDomain(ctx context.Context, tenantID, domain, token, by string) (*TenantDomain, error) {
	var d TenantDomain
	err := s.Pool().QueryRow(ctx, `INSERT INTO tenant_domains (domain, tenant_id, token, created_by) VALUES ($1, $2, $3, $4)
		RETURNING domain, token, verified_at, created_by, created_at`, domain, tenantID, token, by).Scan(&d.Domain, &d.Token, &d.VerifiedAt, &d.CreatedBy, &d.CreatedAt)
	if store.IsUnique(err) {
		return nil, ErrConflict
	}
	return &d, err
}

func (s *Store) TenantDomains(ctx context.Context, tenantID string) ([]*TenantDomain, error) {
	rows, err := s.Pool().Query(ctx, `SELECT domain, token, verified_at, created_by, created_at FROM tenant_domains WHERE tenant_id = $1 ORDER BY domain`, tenantID)
	if err != nil {
		return nil, err
	}
	return store.Collect(rows, func(r pgx.Row) (*TenantDomain, error) {
		var d TenantDomain
		return &d, r.Scan(&d.Domain, &d.Token, &d.VerifiedAt, &d.CreatedBy, &d.CreatedAt)
	})
}

func (s *Store) MarkDomainVerified(ctx context.Context, tenantID, domain string) error {
	tag, err := s.Pool().Exec(ctx, `UPDATE tenant_domains SET verified_at = now() WHERE tenant_id = $1 AND domain = $2`, tenantID, domain)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (s *Store) DeleteTenantDomain(ctx context.Context, tenantID, domain string) error {
	tag, err := s.Pool().Exec(ctx, `DELETE FROM tenant_domains WHERE tenant_id = $1 AND domain = $2`, tenantID, domain)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// TenantByDomain returns the tenant that verified an email domain.
func (s *Store) TenantByDomain(ctx context.Context, domain string) (*Tenant, error) {
	return scanTenant(s.Pool().QueryRow(ctx, `SELECT `+tenantCols+` FROM tenants WHERE status <> 'removed' AND id = (
		SELECT tenant_id FROM tenant_domains WHERE domain = $1 AND verified_at IS NOT NULL)`, strings.ToLower(domain)))
}

// ---- per-tenant SCIM ----

func (s *Store) CreateTenantSCIMToken(ctx context.Context, tenantID, name, by string, hash []byte) (string, error) {
	var id string
	err := s.Pool().QueryRow(ctx, `INSERT INTO tenant_scim_tokens (tenant_id, name, token_hash, created_by) VALUES ($1, $2, $3, $4) RETURNING id`, tenantID, name, hash, by).Scan(&id)
	return id, err
}

type SCIMTokenInfo struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

func (s *Store) TenantSCIMTokens(ctx context.Context, tenantID string) ([]*SCIMTokenInfo, error) {
	rows, err := s.Pool().Query(ctx, `SELECT id, name, created_by, created_at, revoked_at FROM tenant_scim_tokens WHERE tenant_id = $1 ORDER BY created_at DESC`, tenantID)
	if err != nil {
		return nil, err
	}
	return store.Collect(rows, func(r pgx.Row) (*SCIMTokenInfo, error) {
		var t SCIMTokenInfo
		return &t, r.Scan(&t.ID, &t.Name, &t.CreatedBy, &t.CreatedAt, &t.RevokedAt)
	})
}

func (s *Store) RevokeTenantSCIMToken(ctx context.Context, tenantID, id string) error {
	tag, err := s.Pool().Exec(ctx, `UPDATE tenant_scim_tokens SET revoked_at = now() WHERE tenant_id = $1 AND id::text = $2 AND revoked_at IS NULL`, tenantID, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// TenantBySCIMToken returns the tenant a live per-tenant SCIM token belongs to.
func (s *Store) TenantBySCIMToken(ctx context.Context, slug string, hash []byte) (*Tenant, error) {
	return scanTenant(s.Pool().QueryRow(ctx, `SELECT `+tenantCols+` FROM tenants WHERE slug = $1 AND id = (
		SELECT tenant_id FROM tenant_scim_tokens WHERE token_hash = $2 AND revoked_at IS NULL)`, slug, hash))
}

type TSCIMGroup struct {
	ID         string
	Name       string
	ExternalID string
}

func (s *Store) CreateTSCIMGroup(ctx context.Context, tenantID, name, ext string) (*TSCIMGroup, error) {
	var g TSCIMGroup
	err := s.Pool().QueryRow(ctx, `INSERT INTO tenant_scim_groups (tenant_id, name, external_id) VALUES ($1, $2, $3) RETURNING id, name, external_id`, tenantID, name, ext).
		Scan(&g.ID, &g.Name, &g.ExternalID)
	if store.IsUnique(err) {
		return nil, ErrConflict
	}
	return &g, err
}

func (s *Store) TSCIMGroup(ctx context.Context, tenantID, id string) (*TSCIMGroup, error) {
	var g TSCIMGroup
	err := s.Pool().QueryRow(ctx, `SELECT id, name, external_id FROM tenant_scim_groups WHERE tenant_id = $1 AND id::text = $2`, tenantID, id).Scan(&g.ID, &g.Name, &g.ExternalID)
	return &g, store.NotFound(err)
}

func (s *Store) TSCIMGroups(ctx context.Context, tenantID, name string) ([]*TSCIMGroup, error) {
	rows, err := s.Pool().Query(ctx, `SELECT id, name, external_id FROM tenant_scim_groups WHERE tenant_id = $1 AND ($2 = '' OR name = $2) ORDER BY name`, tenantID, name)
	if err != nil {
		return nil, err
	}
	return store.Collect(rows, func(r pgx.Row) (*TSCIMGroup, error) {
		var g TSCIMGroup
		return &g, r.Scan(&g.ID, &g.Name, &g.ExternalID)
	})
}

func (s *Store) DeleteTSCIMGroup(ctx context.Context, tenantID, id string) error {
	_, err := s.Pool().Exec(ctx, `DELETE FROM tenant_scim_groups WHERE tenant_id = $1 AND id::text = $2`, tenantID, id)
	return err
}

func (s *Store) SetTSCIMMember(ctx context.Context, groupID, userID string, member bool) error {
	q := `INSERT INTO tenant_scim_members (group_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`
	if !member {
		q = `DELETE FROM tenant_scim_members WHERE group_id = $1 AND user_id = $2`
	}
	_, err := s.Pool().Exec(ctx, q, groupID, userID)
	return err
}

func (s *Store) ClearTSCIMMembers(ctx context.Context, groupID string) error {
	_, err := s.Pool().Exec(ctx, `DELETE FROM tenant_scim_members WHERE group_id = $1`, groupID)
	return err
}

func (s *Store) TSCIMMembers(ctx context.Context, groupID string) ([]*User, error) {
	rows, err := s.Pool().Query(ctx, `SELECT `+userColsU+` FROM tenant_scim_members m JOIN users u ON u.id = m.user_id WHERE m.group_id = $1 ORDER BY u.email`, groupID)
	if err != nil {
		return nil, err
	}
	return store.Collect(rows, scanUser)
}

// TSCIMGroupsOfUser lists this tenant's groups a user is in.
func (s *Store) TSCIMGroupsOfUser(ctx context.Context, tenantID, userID string) ([]*TSCIMGroup, error) {
	rows, err := s.Pool().Query(ctx, `SELECT g.id, g.name, g.external_id FROM tenant_scim_groups g JOIN tenant_scim_members m ON m.group_id = g.id
		WHERE g.tenant_id = $1 AND m.user_id = $2`, tenantID, userID)
	if err != nil {
		return nil, err
	}
	return store.Collect(rows, func(r pgx.Row) (*TSCIMGroup, error) {
		var g TSCIMGroup
		return &g, r.Scan(&g.ID, &g.Name, &g.ExternalID)
	})
}

const userColsU = `u.id, u.email, u.name, u.platform_admin, u.platform_root, u.created_at, u.disabled_at`
