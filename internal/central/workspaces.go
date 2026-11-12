package central

import (
	"context"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/httpx"
)

// Workspace is one tenant as the switcher shows it.
type Workspace struct {
	Slug         string     `json:"slug"`
	Name         string     `json:"name"`
	Connectivity string     `json:"connectivity"`
	Online       bool       `json:"online"`
	Roles        []string   `json:"roles"`  // a summary: tenant roles, then "manager @ retail"
	Access       string     `json:"access"` // member | platform (platform admin, no membership)
	Status       string     `json:"status"` // pending until its cluster is connected
	Kind         string     `json:"kind"`   // trial | production
	TrialEndsAt  *time.Time `json:"trial_ends_at,omitempty"`
	// ClockSkewMS is the largest clock offset its link agents report; the
	// switcher flags a tenant drifting past 10 seconds.
	ClockSkewMS int64      `json:"clock_skew_ms"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	// CanOpen: the person may open it (a member, a platform admin while
	// central decides access, or approved support access); otherwise a
	// platform admin can only manage its connection.
	CanOpen bool `json:"can_open"`
	// LinkSeenAt is when its link agent last reported; Stale marks a tunnel
	// workspace not heard from (or never connected) for a day.
	LinkSeenAt *time.Time `json:"link_seen_at,omitempty"`
	Stale      bool       `json:"stale,omitempty"`
}

// staleAfter is how long a tunnel workspace may go unheard before the
// console flags it.
const staleAfter = 24 * time.Hour

func stale(t *Tenant, online bool) bool {
	if online || t.Connectivity != "tunnel" {
		return false
	}
	since := t.CreatedAt
	if t.LinkSeenAt != nil {
		since = *t.LinkSeenAt
	}
	return time.Since(since) > staleAfter
}

func (s *Store) TouchTenantUsage(ctx context.Context, userID, tenantID string) error {
	_, err := s.Pool().Exec(ctx, `INSERT INTO tenant_usage (user_id, tenant_id) VALUES ($1, $2)
		ON CONFLICT (user_id, tenant_id) DO UPDATE SET last_used_at = now()`, userID, tenantID)
	return err
}

func (s *Store) TenantUsage(ctx context.Context, userID string) (map[string]time.Time, error) {
	rows, err := s.Pool().Query(ctx, `SELECT tenant_id, last_used_at FROM tenant_usage WHERE user_id = $1`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var id string
		var at time.Time
		if err := rows.Scan(&id, &at); err != nil {
			return nil, err
		}
		out[id] = at
	}
	return out, rows.Err()
}

// usageTracker records tenant use at most once a minute per person and tenant.
type usageTracker struct {
	mu   sync.Mutex
	last map[string]time.Time
}

func (s *Server) touchUsage(ctx context.Context, u *User, t *Tenant) {
	key := u.ID + "/" + t.ID
	s.usage.mu.Lock()
	if s.usage.last == nil {
		s.usage.last = map[string]time.Time{}
	}
	if time.Since(s.usage.last[key]) < time.Minute {
		s.usage.mu.Unlock()
		return
	}
	s.usage.last[key] = time.Now()
	s.usage.mu.Unlock()
	go s.store.TouchTenantUsage(context.WithoutCancel(ctx), u.ID, t.ID)
}

// workspaces lists the tenants the signed-in person may open, most recently
// used first: every tenant they are a member of and, for platform admins,
// every other tenant marked as such.
func (s *Server) workspaces(w http.ResponseWriter, r *http.Request) {
	u := current(r)
	ctx := r.Context()
	slugs, err := s.store.UserTenants(ctx, u.ID)
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	member := map[string]bool{}
	for _, sl := range slugs {
		member[sl] = true
	}
	all, err := s.store.ListTenants(ctx)
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	used, _ := s.store.TenantUsage(ctx, u.ID)
	out := []Workspace{}
	for _, t := range all {
		if !member[t.Slug] && !u.PlatformAdmin {
			continue
		}
		ws := Workspace{Slug: t.Slug, Name: t.Name, Connectivity: t.Connectivity, Online: s.online(ctx, t), Roles: []string{}, Access: "member", Status: t.Status, Kind: t.Kind, TrialEndsAt: t.TrialEndsAt,
			CanOpen: member[t.Slug], LinkSeenAt: t.LinkSeenAt}
		ws.Stale = stale(t, ws.Online)
		if at, ok := used[t.ID]; ok {
			ws.LastUsedAt = &at
		}
		if ls, err := s.store.Links(ctx, t.ID); err == nil {
			for _, l := range ls {
				if d := max(l.SkewMS, -l.SkewMS); d > max(ws.ClockSkewMS, -ws.ClockSkewMS) {
					ws.ClockSkewMS = l.SkewMS
				}
			}
		}
		if member[t.Slug] {
			if p, err := s.store.Principal(ctx, u, t.Slug); err == nil && p != nil {
				ws.Roles = append(ws.Roles, p.TenantRoles...)
				ents := make([]string, 0, len(p.EntityRoles))
				for e := range p.EntityRoles {
					ents = append(ents, e)
				}
				sort.Strings(ents)
				for _, e := range ents {
					for _, role := range p.EntityRoles[e] {
						ws.Roles = append(ws.Roles, role+" @ "+e)
					}
				}
				bus := make([]string, 0, len(p.BURoles))
				for b := range p.BURoles {
					bus = append(bus, b)
				}
				sort.Strings(bus)
				for _, b := range bus {
					for _, role := range p.BURoles[b] {
						if !hasRole(p.EntityRoles[p.BUEntity[b]], role) {
							ws.Roles = append(ws.Roles, role+" @ "+b)
						}
					}
				}
			}
		} else {
			ws.Access = "platform"
			if p, err := s.store.Principal(ctx, u, t.Slug); err == nil && p != nil {
				ws.CanOpen = true // standing platform access, or approved support access
			}
		}
		out = append(out, ws)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i].LastUsedAt, out[j].LastUsedAt
		switch {
		case a != nil && b != nil:
			return a.After(*b)
		case a != nil || b != nil:
			return a != nil
		}
		return out[i].Name < out[j].Name
	})
	httpx.WriteJSON(w, 200, out)
}

func hasRole(rs []string, r string) bool {
	for _, x := range rs {
		if x == r {
			return true
		}
	}
	return false
}
