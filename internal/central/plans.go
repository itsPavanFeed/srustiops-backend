package central

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/httpx"
	"github.com/itsPavanFeed/srustiops-backend/internal/store"
	"github.com/jackc/pgx/v5"
)

// ---- plans and usage limits (Platform → Plans) ----
//
// A plan is a named set of limits. Platform admins give each workspace one;
// the limits go to the tenant plane (PUT /api/v1/plan), which refuses to
// create more stacks, environments, connections, runners or monthly runs
// than they allow. People are counted here, where memberships live. A plane
// that is offline gets its limits when it is back (planLoop retries).

type PlanLimits struct {
	Stacks       int `json:"stacks,omitempty"`
	Environments int `json:"environments,omitempty"`
	Connections  int `json:"connections,omitempty"`
	Runners      int `json:"runners,omitempty"`
	RunsPerMonth int `json:"runs_per_month,omitempty"`
	People       int `json:"people,omitempty"`
}

type Plan struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Limits      PlanLimits `json:"limits"`
	Workspaces  []string   `json:"workspaces"`
	CreatedBy   string     `json:"created_by"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

var planNameRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,39}$`)

func (s *Store) ListPlans(ctx context.Context) ([]*Plan, error) {
	rows, err := s.Pool().Query(ctx, `SELECT p.name, p.description, p.limits, p.created_by, p.updated_at,
		coalesce(array_agg(t.slug ORDER BY t.slug) FILTER (WHERE t.slug IS NOT NULL), '{}')
		FROM plans p LEFT JOIN tenants t ON t.plan = p.name GROUP BY p.name ORDER BY p.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Plan{}
	for rows.Next() {
		var p Plan
		var lim []byte
		if err := rows.Scan(&p.Name, &p.Description, &lim, &p.CreatedBy, &p.UpdatedAt, &p.Workspaces); err != nil {
			return nil, err
		}
		json.Unmarshal(lim, &p.Limits)
		out = append(out, &p)
	}
	return out, rows.Err()
}

// tenantPlan is a workspace's plan (nil when it has none).
func (s *Store) tenantPlan(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, tenantID string) (string, *PlanLimits, error) {
	var name *string
	var lim []byte
	err := q.QueryRow(ctx, `SELECT t.plan, p.limits FROM tenants t LEFT JOIN plans p ON p.name = t.plan WHERE t.id = $1`, tenantID).Scan(&name, &lim)
	if err != nil || name == nil {
		return "", nil, err
	}
	var l PlanLimits
	json.Unmarshal(lim, &l)
	return *name, &l, nil
}

const peopleSQL = `SELECT count(*) FROM (SELECT user_id FROM memberships WHERE tenant_id = $1
	UNION SELECT tm.user_id FROM team_members tm JOIN teams t ON t.id = tm.team_id WHERE t.tenant_id = $1) x`

// checkPeople refuses adding userIDs to a workspace when they would take it
// past its plan's people limit; people already in it do not count again.
func (s *Store) checkPeople(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, tenantID string, userIDs []string) error {
	plan, l, err := s.tenantPlan(ctx, q, tenantID)
	if err != nil || l == nil || l.People <= 0 {
		return err
	}
	var have, newcomers int
	if err := q.QueryRow(ctx, peopleSQL, tenantID).Scan(&have); err != nil {
		return err
	}
	if err := q.QueryRow(ctx, `SELECT count(*) FROM unnest($2::uuid[]) u WHERE u NOT IN (
		SELECT user_id FROM memberships WHERE tenant_id = $1
		UNION SELECT tm.user_id FROM team_members tm JOIN teams t ON t.id = tm.team_id WHERE t.tenant_id = $1)`, tenantID, userIDs).Scan(&newcomers); err != nil {
		return err
	}
	if newcomers > 0 && have+newcomers > l.People {
		return &store.LimitError{What: "people", Limit: l.People, Plan: plan}
	}
	return nil
}

// ---- syncing limits to planes ----

func (s *Server) planLoop(ctx context.Context) {
	every := time.Minute
	if s.cfg.InviteSweep > 0 && s.cfg.InviteSweep < every {
		every = s.cfg.InviteSweep
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		conn, err := s.store.Pool().Acquire(ctx)
		if err != nil {
			continue
		}
		var got bool
		if conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(7207)`).Scan(&got); got {
			rows, err := s.store.Pool().Query(ctx, `SELECT slug FROM tenants WHERE status = 'active' AND plan_synced_at IS NULL`)
			var slugs []string
			if err == nil {
				for rows.Next() {
					var sl string
					rows.Scan(&sl)
					slugs = append(slugs, sl)
				}
				rows.Close()
			}
			var ts []*Tenant
			for _, sl := range slugs {
				if t, err := s.store.Tenant(ctx, sl); err == nil {
					ts = append(ts, t)
				}
			}
			forEachTenant(ctx, ts, func(ctx context.Context, t *Tenant) { s.pushPlan(ctx, t) })
			conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock(7207)`)
		}
		conn.Release()
	}
}

// pushPlan sends a workspace's limits to its plane and records the outcome.
func (s *Server) pushPlan(ctx context.Context, t *Tenant) (json.RawMessage, error) {
	plan, l, err := s.store.tenantPlan(ctx, s.store.Pool(), t.ID)
	if err != nil {
		return nil, err
	}
	body := map[string]any{"plan": plan}
	if l != nil {
		b, _ := json.Marshal(l)
		json.Unmarshal(b, &body)
	}
	code, resp, err := s.callTenantAs(ctx, t, s.system(t), http.MethodPut, "/api/v1/plan", body)
	if err == nil && code != 200 {
		err = fmt.Errorf("the plane answered %d: %s", code, trim(string(resp), 300))
	}
	if err != nil {
		s.store.Pool().Exec(ctx, `UPDATE tenants SET plan_sync_error = $2 WHERE id = $1`, t.ID, trim(err.Error(), 500))
		return nil, err
	}
	s.store.Pool().Exec(ctx, `UPDATE tenants SET plan_synced_at = now(), plan_sync_error = '' WHERE id = $1`, t.ID)
	return resp, nil
}

// ---- API ----

func (s *Server) listPlans(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(w, r) {
		return
	}
	ps, err := s.store.ListPlans(r.Context())
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	type ws struct {
		Slug      string     `json:"slug"`
		Name      string     `json:"name"`
		Plan      *string    `json:"plan"`
		SyncedAt  *time.Time `json:"synced_at"`
		SyncError string     `json:"sync_error,omitempty"`
		People    int        `json:"people"`
	}
	rows, err := s.store.Pool().Query(r.Context(), `SELECT t.slug, t.name, t.plan, t.plan_synced_at, t.plan_sync_error, (`+strings.ReplaceAll(peopleSQL, "$1", "t.id")+`)
		FROM tenants t WHERE t.status <> 'removed' ORDER BY t.slug`)
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	defer rows.Close()
	out := []ws{}
	for rows.Next() {
		var x ws
		if err := rows.Scan(&x.Slug, &x.Name, &x.Plan, &x.SyncedAt, &x.SyncError, &x.People); err != nil {
			s.storeErr(w, err, "")
			return
		}
		out = append(out, x)
	}
	httpx.WriteJSON(w, 200, map[string]any{"plans": ps, "workspaces": out})
}

func (s *Server) putPlan(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(w, r) {
		return
	}
	name := r.PathValue("name")
	var b struct {
		Description string     `json:"description"`
		Limits      PlanLimits `json:"limits"`
	}
	if !httpx.Decode(w, r, &b) {
		return
	}
	l := b.Limits
	if !planNameRe.MatchString(name) {
		httpx.WriteErr(w, 422, "a plan name is lowercase letters, digits and dashes, starting with a letter")
		return
	}
	for _, n := range []int{l.Stacks, l.Environments, l.Connections, l.Runners, l.RunsPerMonth, l.People} {
		if n < 0 || n > 10_000_000 {
			httpx.WriteErr(w, 422, "each limit is 0 (no limit) or a positive number")
			return
		}
	}
	lim, _ := json.Marshal(l)
	ctx := r.Context()
	tag, err := s.store.Pool().Exec(ctx, `INSERT INTO plans (name, description, limits, created_by) VALUES ($1, $2, $3, $4)
		ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description, limits = EXCLUDED.limits, updated_at = now()
		WHERE plans.limits <> EXCLUDED.limits OR plans.description <> EXCLUDED.description`, name, trim(b.Description, 300), lim, current(r).Email)
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	if tag.RowsAffected() > 0 {
		// Every workspace on the plan takes the new limits.
		s.store.Pool().Exec(ctx, `UPDATE tenants SET plan_synced_at = NULL WHERE plan = $1`, name)
		s.audit(ctx, current(r).Email, "plan.save", "plan/"+name, "", map[string]any{"description": b.Description, "limits": l})
		go s.syncPlans(context.WithoutCancel(ctx), name)
	}
	s.listPlans(w, r)
}

// syncPlans pushes a plan's limits to its workspaces right away (the loop
// retries the ones that fail).
func (s *Server) syncPlans(ctx context.Context, plan string) {
	rows, err := s.store.Pool().Query(ctx, `SELECT slug FROM tenants WHERE plan = $1 AND status = 'active'`, plan)
	if err != nil {
		return
	}
	var slugs []string
	for rows.Next() {
		var sl string
		rows.Scan(&sl)
		slugs = append(slugs, sl)
	}
	rows.Close()
	for _, sl := range slugs {
		if t, err := s.store.Tenant(ctx, sl); err == nil {
			s.pushPlan(ctx, t)
		}
	}
}

func (s *Server) deletePlan(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(w, r) {
		return
	}
	name := r.PathValue("name")
	var users int
	s.store.Pool().QueryRow(r.Context(), `SELECT count(*) FROM tenants WHERE plan = $1`, name).Scan(&users)
	if users > 0 {
		httpx.WriteErr(w, http.StatusConflict, fmt.Sprintf("%d workspace(s) are on plan %s; move them to another plan first", users, name))
		return
	}
	tag, err := s.store.Pool().Exec(r.Context(), `DELETE FROM plans WHERE name = $1`, name)
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	if tag.RowsAffected() == 0 {
		httpx.WriteErr(w, http.StatusNotFound, "no such plan")
		return
	}
	s.audit(r.Context(), current(r).Email, "plan.delete", "plan/"+name, "", nil)
	w.WriteHeader(http.StatusNoContent)
}

// setTenantPlan gives a workspace a plan ("" for none) and pushes it.
func (s *Server) setTenantPlan(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(w, r) {
		return
	}
	ctx := r.Context()
	t, err := s.store.Tenant(ctx, r.PathValue("tenant"))
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	var b struct {
		Plan string `json:"plan"`
	}
	if !httpx.Decode(w, r, &b) {
		return
	}
	var plan *string
	if b.Plan != "" {
		plan = &b.Plan
	}
	if _, err := s.store.Pool().Exec(ctx, `UPDATE tenants SET plan = $2, plan_synced_at = NULL, plan_sync_error = '' WHERE id = $1`, t.ID, plan); err != nil {
		if strings.Contains(err.Error(), "foreign key") {
			httpx.WriteErr(w, 422, "no such plan: "+b.Plan)
			return
		}
		s.storeErr(w, err, "")
		return
	}
	s.audit(ctx, current(r).Email, "plan.assign", "tenant/"+t.Slug, t.Slug, map[string]string{"plan": b.Plan})
	out := map[string]any{"tenant": t.Slug, "plan": b.Plan, "synced": false}
	if t.Status == "active" {
		if _, err := s.pushPlan(ctx, t); err != nil {
			out["sync_error"] = err.Error() + " (it is retried until the plane takes it)"
		} else {
			out["synced"] = true
		}
	}
	httpx.WriteJSON(w, 200, out)
}

// tenantUsage shows a workspace's plan, its limits and its usage: the
// plane's counts and, from here, its people.
func (s *Server) tenantUsage(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, true)
	if t == nil {
		return
	}
	ctx := r.Context()
	plan, l, err := s.store.tenantPlan(ctx, s.store.Pool(), t.ID)
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	var people int
	s.store.Pool().QueryRow(ctx, peopleSQL, t.ID).Scan(&people)
	out := map[string]any{"plan": plan, "limits": l, "people": people}
	var plane struct {
		Usage  *store.Usage  `json:"usage"`
		Limits *store.Limits `json:"limits"`
	}
	if code, b, err := s.callTenantAs(ctx, t, s.system(t), http.MethodGet, "/api/v1/usage", nil); err == nil && code == 200 {
		json.Unmarshal(b, &plane)
		out["usage"], out["plane_limits"] = plane.Usage, plane.Limits
	} else {
		out["usage_error"] = "the workspace's plane did not answer; usage shows when it is reachable"
	}
	var synced *time.Time
	var syncErr string
	s.store.Pool().QueryRow(ctx, `SELECT plan_synced_at, plan_sync_error FROM tenants WHERE id = $1`, t.ID).Scan(&synced, &syncErr)
	out["synced_at"], out["sync_error"] = synced, syncErr
	httpx.WriteJSON(w, 200, out)
}
