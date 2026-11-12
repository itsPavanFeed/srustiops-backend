package central

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/itsPavanFeed/srustiops-backend/internal/httpx"
	"github.com/itsPavanFeed/srustiops-backend/internal/identity"
	"github.com/itsPavanFeed/srustiops-backend/internal/store"
)

// ---- teams, invitations and last active ----
//
// A team is a group of people in one tenant that holds roles: everyone in it
// has the team's roles as well as their own. Teams apply while central
// decides the tenant's access; a tenant that controls its own access uses its
// identity-provider groups instead (Access → Groups).
//
// A person added who has never signed in is invited: the invitation lapses
// after a number of days (7 by default), and with it their roles. Signing in
// accepts it. Central records when each person was last active.

const teamRoleSelect = `SELECT tr.id, u.email, t.slug, COALESCE(e.slug, ''), COALESCE(b.slug, ''), tr.role, tr.created_by, tr.created_at, u.last_seen_at, u.invite_expires_at, tm2.slug
	FROM team_roles tr JOIN teams tm2 ON tm2.id = tr.team_id JOIN team_members tm ON tm.team_id = tr.team_id
	JOIN users u ON u.id = tm.user_id JOIN tenants t ON t.id = tm2.tenant_id AND t.access_source <> 'tenant'
	LEFT JOIN entities e ON e.id = tr.entity_id LEFT JOIN business_units b ON b.id = tr.bu_id`

func scanTeamRole(r pgx.Row) (*Membership, error) {
	var m Membership
	err := r.Scan(&m.ID, &m.Email, &m.Tenant, &m.Entity, &m.BU, &m.Role, &m.CreatedBy, &m.CreatedAt, &m.LastSeenAt, &m.InviteExpiresAt, &m.Via)
	return &m, store.NotFound(err)
}

// EffectiveMembers is every role held in a tenant: people's own and the
// ones their teams give them (Via set).
func (s *Store) EffectiveMembers(ctx context.Context, tenantID string) ([]*Membership, error) {
	own, err := s.TenantMembers(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	rows, err := s.Pool().Query(ctx, teamRoleSelect+` WHERE tm2.tenant_id = $1 ORDER BY u.email, tm2.slug`, tenantID)
	if err != nil {
		return nil, err
	}
	via, err := store.Collect(rows, scanTeamRole)
	if err != nil {
		return nil, err
	}
	return append(own, via...), nil
}

type Team struct {
	ID          string       `json:"id"`
	Slug        string       `json:"slug"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Members     []TeamMember `json:"members"`
	Roles       []TeamRole   `json:"roles"`
	CreatedBy   string       `json:"created_by"`
	CreatedAt   time.Time    `json:"created_at"`
}

type TeamMember struct {
	Email           string     `json:"email"`
	LastSeenAt      *time.Time `json:"last_seen_at,omitempty"`
	InviteExpiresAt *time.Time `json:"invite_expires_at,omitempty"`
}

type TeamRole struct {
	Role   string `json:"role"`
	Entity string `json:"entity,omitempty"`
	BU     string `json:"bu,omitempty"`
}

func (s *Store) Teams(ctx context.Context, tenantID string) ([]*Team, error) {
	rows, err := s.Pool().Query(ctx, `SELECT id, slug, name, description, created_by, created_at FROM teams WHERE tenant_id = $1 ORDER BY slug`, tenantID)
	if err != nil {
		return nil, err
	}
	var out []*Team
	for rows.Next() {
		t := &Team{Members: []TeamMember{}, Roles: []TeamRole{}}
		if err := rows.Scan(&t.ID, &t.Slug, &t.Name, &t.Description, &t.CreatedBy, &t.CreatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, t)
	}
	rows.Close()
	byID := map[string]*Team{}
	for _, t := range out {
		byID[t.ID] = t
	}
	mrows, err := s.Pool().Query(ctx, `SELECT tm.team_id, u.email, u.last_seen_at, u.invite_expires_at FROM team_members tm JOIN users u ON u.id = tm.user_id
		JOIN teams t ON t.id = tm.team_id WHERE t.tenant_id = $1 ORDER BY u.email`, tenantID)
	if err != nil {
		return nil, err
	}
	for mrows.Next() {
		var id string
		var m TeamMember
		if mrows.Scan(&id, &m.Email, &m.LastSeenAt, &m.InviteExpiresAt) == nil && byID[id] != nil {
			byID[id].Members = append(byID[id].Members, m)
		}
	}
	mrows.Close()
	rrows, err := s.Pool().Query(ctx, `SELECT tr.team_id, tr.role, COALESCE(e.slug, ''), COALESCE(b.slug, '') FROM team_roles tr JOIN teams t ON t.id = tr.team_id
		LEFT JOIN entities e ON e.id = tr.entity_id LEFT JOIN business_units b ON b.id = tr.bu_id WHERE t.tenant_id = $1 ORDER BY tr.role`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rrows.Close()
	for rrows.Next() {
		var id string
		var g TeamRole
		if rrows.Scan(&id, &g.Role, &g.Entity, &g.BU) == nil && byID[id] != nil {
			byID[id].Roles = append(byID[id].Roles, g)
		}
	}
	if out == nil {
		out = []*Team{}
	}
	return out, rrows.Err()
}

func (s *Store) TeamBySlug(ctx context.Context, tenantID, slug string) (*Team, error) {
	ts, err := s.Teams(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for _, t := range ts {
		if t.Slug == slug {
			return t, nil
		}
	}
	return nil, ErrNotFound
}

// SaveTeam creates or replaces a team: its name, members and roles.
func (s *Store) SaveTeam(ctx context.Context, tenantID string, t *Team, memberIDs []string, grants []Grant, by string, create bool) (string, error) {
	tx, err := s.Pool().Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	var id string
	if create {
		err = tx.QueryRow(ctx, `INSERT INTO teams (tenant_id, slug, name, description, created_by) VALUES ($1, $2, $3, $4, $5) RETURNING id`,
			tenantID, t.Slug, t.Name, t.Description, by).Scan(&id)
		if store.IsUnique(err) {
			return "", ErrConflict
		}
	} else {
		err = tx.QueryRow(ctx, `UPDATE teams SET name = $3, description = $4 WHERE tenant_id = $1 AND slug = $2 RETURNING id`, tenantID, t.Slug, t.Name, t.Description).Scan(&id)
		if err == pgx.ErrNoRows {
			return "", ErrNotFound
		}
	}
	if err != nil {
		return "", err
	}
	if err := s.checkPeople(ctx, tx, tenantID, memberIDs); err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM team_members WHERE team_id = $1 AND NOT (user_id::text = ANY($2))`, id, memberIDs); err != nil {
		return "", err
	}
	for _, u := range memberIDs {
		if _, err := tx.Exec(ctx, `INSERT INTO team_members (team_id, user_id, added_by) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, id, u, by); err != nil {
			return "", err
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM team_roles WHERE team_id = $1`, id); err != nil {
		return "", err
	}
	for _, g := range grants {
		if _, err := tx.Exec(ctx, `INSERT INTO team_roles (team_id, entity_id, bu_id, role, created_by) VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING`,
			id, g.EntityID, g.BUID, g.Role, by); err != nil {
			return "", err
		}
	}
	return id, tx.Commit(ctx)
}

func (s *Store) DeleteTeam(ctx context.Context, tenantID, slug string) error {
	tag, err := s.Pool().Exec(ctx, `DELETE FROM teams WHERE tenant_id = $1 AND slug = $2`, tenantID, slug)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// TouchUserSeen records that a person was active and accepts their invitation.
func (s *Store) TouchUserSeen(ctx context.Context, userID string) {
	s.Pool().Exec(ctx, `UPDATE users SET last_seen_at = now(), invite_expires_at = NULL WHERE id = $1`, userID)
}

// MarkInvited makes a person who has never been active an invitee until the
// invitation lapses (days from now). People already active are left alone.
func (s *Store) MarkInvited(ctx context.Context, userID string, days int) {
	s.Pool().Exec(ctx, `UPDATE users SET invited_at = COALESCE(invited_at, now()), invite_expires_at = now() + make_interval(days => $2)
		WHERE id = $1 AND last_seen_at IS NULL AND NOT platform_admin`, userID, days)
}

// ExpireInvitations removes the roles and team places of invitees whose
// invitation lapsed, and returns who they were, by tenant.
func (s *Store) ExpireInvitations(ctx context.Context) (map[string][]string, error) {
	rows, err := s.Pool().Query(ctx, `SELECT id::text, email FROM users WHERE last_seen_at IS NULL AND invite_expires_at < now() AND NOT platform_admin`)
	if err != nil {
		return nil, err
	}
	type u struct{ id, email string }
	var us []u
	for rows.Next() {
		var x u
		if rows.Scan(&x.id, &x.email) == nil {
			us = append(us, x)
		}
	}
	rows.Close()
	out := map[string][]string{}
	for _, x := range us {
		trows, err := s.Pool().Query(ctx, `SELECT DISTINCT t.slug FROM tenants t WHERE t.id IN (SELECT tenant_id FROM memberships WHERE user_id = $1
			UNION SELECT tenant_id FROM teams WHERE id IN (SELECT team_id FROM team_members WHERE user_id = $1))`, x.id)
		if err == nil {
			for trows.Next() {
				var slug string
				if trows.Scan(&slug) == nil {
					out[slug] = append(out[slug], x.email)
				}
			}
			trows.Close()
		}
		s.Pool().Exec(ctx, `DELETE FROM memberships WHERE user_id = $1`, x.id)
		s.Pool().Exec(ctx, `DELETE FROM team_members WHERE user_id = $1`, x.id)
		s.Pool().Exec(ctx, `UPDATE users SET invite_expires_at = NULL WHERE id = $1`, x.id)
	}
	return out, nil
}

// ---- recording activity ----

// seen remembers when each person's activity was last written, so it is
// written at most every few minutes per person and replica.
var seen sync.Map

const seenEvery = 3 * time.Minute

func (s *Server) noteSeen(ctx context.Context, u *User) {
	now := time.Now()
	if v, ok := seen.Load(u.ID); ok && now.Sub(v.(time.Time)) < seenEvery {
		return
	}
	seen.Store(u.ID, now)
	go s.store.TouchUserSeen(context.WithoutCancel(ctx), u.ID)
}

// inviteLoop lapses expired invitations every ten minutes on one replica.
func (s *Server) inviteLoop(ctx context.Context) {
	every := s.cfg.InviteSweep
	if every <= 0 {
		every = 10 * time.Minute
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s.expireInvitations(ctx)
	}
}

func (s *Server) expireInvitations(ctx context.Context) {
	conn, err := s.store.Pool().Acquire(ctx)
	if err != nil {
		return
	}
	defer conn.Release()
	var got bool
	if conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(7203)`).Scan(&got); !got {
		return
	}
	defer conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock(7203)`)
	gone, err := s.store.ExpireInvitations(ctx)
	if err != nil {
		return
	}
	for tenant, emails := range gone {
		for _, e := range emails {
			s.audit(ctx, "system:invitations", "member.invite_expired", "user/"+e, tenant, nil)
		}
		if t, err := s.store.Tenant(ctx, tenant); err == nil {
			s.syncDirectory(ctx, t)
		}
	}
	if len(gone) > 0 {
		s.cache.purge()
	}
}

// ---- API ----

const defaultInviteDays = 7

// inviteDays reads ?invite_days= (1-90) on requests that add people.
func inviteDays(r *http.Request) int {
	n := defaultInviteDays
	if v := r.URL.Query().Get("invite_days"); v != "" {
		var x int
		for _, c := range v {
			if c < '0' || c > '9' {
				return n
			}
			x = x*10 + int(c-'0')
		}
		if x >= 1 && x <= 90 {
			n = x
		}
	}
	return n
}

func (s *Server) listTeams(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, false)
	if t == nil {
		return
	}
	ts, err := s.store.Teams(r.Context(), t.ID)
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	httpx.WriteJSON(w, 200, map[string]any{"teams": ts, "applies": t.AccessSource != "tenant"})
}

type teamBody struct {
	Slug        string     `json:"slug"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Members     []string   `json:"members"`
	Roles       []TeamRole `json:"roles"`
}

func (s *Server) saveTeam(create bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		t, _ := s.tenantFor(w, r, true)
		if t == nil {
			return
		}
		if t.AccessSource == "tenant" {
			httpx.WriteErr(w, http.StatusConflict, "this workspace manages its own access: use its identity-provider groups (Access → Groups) instead of teams")
			return
		}
		var b teamBody
		if !httpx.Decode(w, r, &b) {
			return
		}
		if !create {
			b.Slug = r.PathValue("team")
		}
		var probs []string
		if !identity.SlugRe.MatchString(b.Slug) {
			probs = append(probs, "slug must be lowercase letters, digits and dashes")
		}
		b.Name = strings.TrimSpace(b.Name)
		if b.Name == "" || len(b.Name) > 80 || len(b.Description) > 500 {
			probs = append(probs, "name is required (up to 80 characters); description up to 500")
		}
		if len(b.Members) > 500 || len(b.Roles) > 50 {
			probs = append(probs, "at most 500 members and 50 roles")
		}
		for _, e := range b.Members {
			if !emailRe.MatchString(e) {
				probs = append(probs, "invalid email "+e)
			}
		}
		if len(probs) > 0 {
			httpx.WriteErr(w, 422, "invalid team", probs...)
			return
		}
		var grants []Grant
		for _, g := range b.Roles {
			gr := Grant{Role: g.Role}
			switch {
			case g.Entity == "" && g.BU == "" && identity.IsTenantRole(g.Role):
				if g.Role == identity.TenantAdmin {
					httpx.WriteErr(w, 422, "tenant_admin is granted to people, not teams")
					return
				}
			case g.Entity != "" && g.BU == "" && identity.IsScopedRole(g.Role):
				e, err := s.store.Entity(r.Context(), t.ID, g.Entity)
				if err != nil {
					httpx.WriteErr(w, 422, "unknown entity "+g.Entity)
					return
				}
				gr.EntityID = &e.ID
			case g.BU != "" && g.Entity == "" && identity.IsScopedRole(g.Role):
				bu, err := s.store.BUBySlug(r.Context(), t.ID, g.BU)
				if err != nil {
					httpx.WriteErr(w, 422, "unknown business unit "+g.BU)
					return
				}
				gr.BUID = &bu.ID
			default:
				httpx.WriteErr(w, 422, "tenant-wide roles are "+strings.Join(identity.TenantRoles, ", ")+"; entity and business-unit roles are "+strings.Join(identity.ScopedRoles, ", "))
				return
			}
			grants = append(grants, gr)
		}
		me := current(r).Email
		ids := []string{}
		days := inviteDays(r)
		for _, e := range b.Members {
			u, err := s.store.EnsureUser(r.Context(), e, "", false, me)
			if err != nil {
				s.storeErr(w, err, "")
				return
			}
			s.store.MarkInvited(r.Context(), u.ID, days)
			ids = append(ids, u.ID)
		}
		var before *Team
		if !create {
			before, _ = s.store.TeamBySlug(r.Context(), t.ID, b.Slug)
		}
		if _, err := s.store.SaveTeam(r.Context(), t.ID, &Team{Slug: b.Slug, Name: b.Name, Description: b.Description}, ids, grants, me, create); err != nil {
			s.storeErr(w, err, "a team with that slug exists")
			return
		}
		action := "team.update"
		if create {
			action = "team.create"
		}
		after, _ := s.store.TeamBySlug(r.Context(), t.ID, b.Slug)
		s.audit(r.Context(), me, action, "team/"+b.Slug, t.Slug, map[string]any{"before": before, "after": after})
		s.cache.purge()
		s.syncDirectory(r.Context(), t)
		code := 200
		if create {
			code = 201
		}
		httpx.WriteJSON(w, code, after)
	}
}

func (s *Server) deleteTeam(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, true)
	if t == nil {
		return
	}
	before, err := s.store.TeamBySlug(r.Context(), t.ID, r.PathValue("team"))
	if err == nil {
		err = s.store.DeleteTeam(r.Context(), t.ID, before.Slug)
	}
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	s.audit(r.Context(), current(r).Email, "team.delete", "team/"+before.Slug, t.Slug, before)
	s.cache.purge()
	s.syncDirectory(r.Context(), t)
	w.WriteHeader(http.StatusNoContent)
}

// extendInvitation gives an invitee more time (or re-invites one whose
// invitation lapsed, once their roles are granted again).
func (s *Server) extendInvitation(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, true)
	if t == nil {
		return
	}
	email := r.PathValue("email")
	u, err := s.store.UserByEmail(r.Context(), email)
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	if u.PlatformAdmin {
		httpx.WriteErr(w, 422, "platform admins are not invited")
		return
	}
	days := inviteDays(r)
	s.store.MarkInvited(r.Context(), u.ID, days)
	s.audit(r.Context(), current(r).Email, "member.invite_extended", "user/"+email, t.Slug, map[string]int{"days": days})
	httpx.WriteJSON(w, 200, map[string]any{"email": email, "days": days})
}
