package central

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/httpx"
	"github.com/itsPavanFeed/srustiops-backend/internal/identity"
)

// Tenant-controlled access, central side. Once a tenant takes over its
// access, central says who people are and how they signed in; the tenant
// decides roles. Central's memberships for that tenant become a directory
// copy, synced from the tenant, so the workspace list and console menus keep
// working. Changes made here are forwarded to the tenant as the person making
// them, and the tenant checks that person's rights itself.

// centralSubject must match api.CentralSubject on tenant planes.
const centralSubject = "system:central"

// platformOp: platform-level operations on a tenant record (connectivity,
// health, the link, support requests) stay open to platform admins whoever
// decides access inside the tenant.
func platformOp(r *http.Request) bool {
	p := r.URL.Path
	if strings.HasSuffix(p, "/health") || strings.Contains(p, "/link") || strings.HasSuffix(p, "/install") || strings.HasSuffix(p, "/install-tokens") || strings.Contains(p, "/provisioning") || strings.HasSuffix(p, "/support-requests") || strings.HasSuffix(p, "/access/sync") {
		return true
	}
	return strings.Count(strings.TrimPrefix(p, "/api/v1/tenants/"), "/") == 0 // the tenant record itself
}

// assertionPrincipal is what central asserts to a tenant for one request.
func (s *Server) assertionPrincipal(ctx context.Context, u *User, sess *AuthSession, t *Tenant) (*identity.Principal, error) {
	p, err := s.store.Principal(ctx, u, t.Slug)
	if err != nil {
		return nil, err
	}
	if p == nil && t.AccessSource == "tenant" {
		// No copy of a grant here (a group from the tenant's provider, say):
		// the tenant decides.
		p = &identity.Principal{Subject: u.Email, Tenant: t.Slug, BUEntity: map[string]string{}, PlatformAdmin: u.PlatformAdmin}
		bus, _ := s.store.BUs(ctx, t.ID)
		for _, b := range bus {
			p.BUEntity[b.Slug] = b.Entity
		}
	}
	if p == nil {
		return nil, nil
	}
	if t.AccessSource == "tenant" {
		// Identity only: the tenant resolves roles from its own grants.
		p.TenantRoles, p.EntityRoles, p.BURoles = []string{}, map[string][]string{}, map[string][]string{}
		p.PlatformAdmin = u.PlatformAdmin
	}
	// Who the person is: the provider's (issuer, subject); tokens and other
	// central-only sign-ins are central's own account (central URL, user ID).
	p.UserIssuer, p.UserSubject, p.EmailVerified = s.cfg.PublicURL, u.ID, true
	if sess != nil && sess.UserIssuer != "" {
		p.UserIssuer, p.UserSubject, p.EmailVerified = sess.UserIssuer, sess.UserSubject, sess.EmailVerified
	}
	if sess != nil {
		p.IDP, p.AMR = sess.IDP, sess.AMR
		if !sess.AuthTime.IsZero() {
			p.AuthTime = sess.AuthTime.Unix()
		}
		// A provider's groups mean something only to the tenant whose provider it is.
		if sess.IDP == "tenant:"+t.Slug {
			p.Groups = sess.Groups
		}
		if sess.TokenID != "" {
			p.TenantSession = s.store.TenantSessionFor(ctx, sess.TokenID, t.ID)
		}
	}
	return p, nil
}

func (s *Server) system(t *Tenant) *identity.Principal {
	return &identity.Principal{Subject: centralSubject, Tenant: t.Slug}
}

// syncDirectory refreshes central's copy of a tenant-controlled tenant's grants.
func (s *Server) syncDirectory(ctx context.Context, t *Tenant) error {
	if t.AccessSource != "tenant" {
		return nil
	}
	code, body, err := s.callTenantAs(ctx, t, s.system(t), http.MethodGet, "/api/v1/access/directory", nil)
	if err != nil {
		return err
	}
	if code != 200 {
		return fmt.Errorf("tenant answered %d: %s", code, trim(string(body), 200))
	}
	// Signed by the tenant's directory key, and newer than the last snapshot.
	body, err = s.openDirectory(ctx, t, body)
	if err != nil {
		return err
	}
	var d struct {
		Source     string       `json:"source"`
		RequireIDP bool         `json:"require_idp"`
		Grants     []DirGrant   `json:"grants"`
		Support    []DirSupport `json:"support"`
	}
	if err := json.Unmarshal(body, &d); err != nil {
		return err
	}
	added, removed, err := s.store.ReplaceTenantMemberships(ctx, t.ID, d.Grants, "directory:"+t.Slug)
	if err != nil {
		return err
	}
	if err := s.store.ReplaceTenantSupport(ctx, t.ID, d.Support); err != nil {
		return err
	}
	src := d.Source
	if src != "tenant" {
		src = "central"
	}
	if err := s.store.SetTenantAccess(ctx, t.ID, src, d.RequireIDP); err != nil {
		return err
	}
	if added+removed > 0 {
		s.log.Info("directory synced", "tenant", t.Slug, "added", added, "removed", removed)
	}
	return nil
}

func (s *Server) syncLater(t *Tenant) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := s.syncDirectory(ctx, t); err != nil {
			s.log.Warn("directory sync failed", "tenant", t.Slug, "err", err)
		}
	}()
}

// syncLoop refreshes every tenant-controlled tenant's directory copy.
func (s *Server) syncLoop(ctx context.Context) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s.onePlatformReplica(ctx, 7208, func(ctx context.Context) { // one replica syncs
			ts, err := s.store.ListTenants(ctx)
			if err != nil {
				return
			}
			forEachTenant(ctx, ts, func(ctx context.Context, x *Tenant) {
				if x.AccessSource == "tenant" && s.online(ctx, x) {
					if err := s.syncDirectory(ctx, x); err != nil {
						s.log.Warn("directory sync failed", "tenant", x.Slug, "err", err)
					}
				}
			})
		})
	}
}

// ---- takeover ----

// takeoverAccess moves access control into the tenant: central's memberships
// are imported there once, and from then on the tenant decides.
func (s *Server) takeoverAccess(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, true)
	if t == nil {
		return
	}
	if t.AccessSource == "tenant" {
		httpx.WriteErr(w, http.StatusConflict, "this tenant already controls its own access")
		return
	}
	// Team roles become each member's own grants: the tenant has no teams.
	ms, err := s.store.EffectiveMembers(r.Context(), t.ID)
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	grants := []DirGrant{}
	dup := map[DirGrant]bool{}
	for _, m := range ms {
		g := DirGrant{Email: m.Email, Role: m.Role, Entity: m.Entity, BU: m.BU}
		if !dup[g] {
			dup[g] = true
			grants = append(grants, g)
		}
	}
	by := current(r).Email
	code, body, err := s.callTenantAs(r.Context(), t, s.system(t), http.MethodPost, "/api/v1/access/import", map[string]any{"by": by, "grants": grants})
	if err != nil {
		httpx.WriteErr(w, http.StatusBadGateway, "tenant is unreachable: "+err.Error())
		return
	}
	if code != 200 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		w.Write(body)
		return
	}
	if err := s.store.SetTenantAccess(r.Context(), t.ID, "tenant", false); err != nil {
		s.storeErr(w, err, "")
		return
	}
	t.AccessSource = "tenant"
	if err := s.syncDirectory(r.Context(), t); err != nil {
		s.log.Warn("directory sync after takeover failed", "tenant", t.Slug, "err", err)
	}
	s.audit(r.Context(), by, "tenant.access_takeover", "tenant/"+t.Slug, t.Slug, map[string]int{"grants": len(grants)})
	httpx.WriteJSON(w, 200, map[string]any{"access_source": "tenant", "imported": len(grants)})
}

func (s *Server) syncAccess(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, true)
	if t == nil {
		return
	}
	if err := s.syncDirectory(r.Context(), t); err != nil {
		httpx.WriteErr(w, http.StatusBadGateway, "directory sync failed: "+err.Error())
		return
	}
	t, _ = s.store.Tenant(r.Context(), t.Slug)
	httpx.WriteJSON(w, 200, t)
}

// ---- grant changes made through central, for tenant-controlled tenants ----

// forwardGrants makes email's grants in the tenant exactly want, as the caller
// (the tenant checks the caller may), then refreshes the directory copy.
func (s *Server) forwardGrants(ctx context.Context, r *http.Request, t *Tenant, email string, want []DirGrant, onlyAdd bool) (int, string) {
	caller, err := s.assertionPrincipal(ctx, current(r), sessionOf(r), t)
	if err != nil || caller == nil {
		return http.StatusForbidden, "no access to this tenant"
	}
	call := func(method, path string, body any) (int, []byte, error) {
		return s.callTenantAs(ctx, t, caller, method, path, body)
	}
	code, body, err := call(http.MethodGet, "/api/v1/access/grants", nil)
	if err != nil {
		return http.StatusBadGateway, "tenant is unreachable: " + err.Error()
	}
	if code != 200 {
		return code, errText(body)
	}
	var have []struct{ ID, Email, Role, Entity, BU string }
	json.Unmarshal(body, &have)
	key := func(role, e, b string) string { return role + "|" + e + "|" + b }
	wantK := map[string]DirGrant{}
	for _, g := range want {
		wantK[key(g.Role, g.Entity, g.BU)] = g
	}
	haveK := map[string]string{}
	for _, g := range have {
		if strings.EqualFold(g.Email, email) {
			haveK[key(g.Role, g.Entity, g.BU)] = g.ID
		}
	}
	for k, g := range wantK {
		if _, ok := haveK[k]; ok {
			continue
		}
		code, body, err := call(http.MethodPost, "/api/v1/access/grants", map[string]string{"email": email, "role": g.Role, "entity": g.Entity, "bu": g.BU})
		if err != nil {
			return http.StatusBadGateway, err.Error()
		}
		if code != 201 {
			return code, errText(body)
		}
	}
	if !onlyAdd {
		for k, id := range haveK {
			if _, ok := wantK[k]; ok {
				continue
			}
			code, body, err := call(http.MethodDelete, "/api/v1/access/grants/"+id, nil)
			if err != nil {
				return http.StatusBadGateway, err.Error()
			}
			if code != 204 {
				return code, errText(body)
			}
		}
	}
	if err := s.syncDirectory(ctx, t); err != nil {
		s.log.Warn("directory sync failed", "tenant", t.Slug, "err", err)
	}
	return 0, ""
}

func errText(body []byte) string {
	var e struct {
		Error   string   `json:"error"`
		Details []string `json:"details"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error != "" {
		if len(e.Details) > 0 {
			return e.Error + ": " + strings.Join(e.Details, "; ")
		}
		return e.Error
	}
	return trim(string(body), 300)
}

// ---- support access ----

func (s *Server) supportRequests(w http.ResponseWriter, r *http.Request) {
	t, err := s.store.Tenant(r.Context(), r.PathValue("tenant"))
	u := current(r)
	if err != nil || !u.PlatformAdmin {
		httpx.WriteErr(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method == http.MethodGet {
		gs, err := s.store.SupportFor(r.Context(), t.ID, u.Email)
		if err != nil {
			s.storeErr(w, err, "")
			return
		}
		httpx.WriteJSON(w, 200, gs)
		return
	}
	if t.AccessSource != "tenant" {
		httpx.WriteErr(w, http.StatusConflict, "platform admins already have access to this tenant; support access applies once it controls its own access")
		return
	}
	var b struct {
		Role   string `json:"role"`
		Reason string `json:"reason"`
		Hours  int    `json:"hours"`
	}
	if !httpx.Decode(w, r, &b) {
		return
	}
	me, _ := s.assertionPrincipal(r.Context(), u, sessionOf(r), t)
	if me == nil {
		httpx.WriteErr(w, http.StatusForbidden, "cannot identify the requester")
		return
	}
	code, body, err := s.callTenantAs(r.Context(), t, s.system(t), http.MethodPost, "/api/v1/access/support-requests",
		map[string]any{"email": u.Email, "issuer": me.UserIssuer, "subject": me.UserSubject, "role": b.Role, "reason": b.Reason, "hours": b.Hours})
	if err != nil {
		httpx.WriteErr(w, http.StatusBadGateway, "tenant is unreachable: "+err.Error())
		return
	}
	if code == 201 {
		s.audit(r.Context(), u.Email, "support.request", "tenant/"+t.Slug, t.Slug, b)
		s.syncLater(t)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(body)
}

func identityStrs(v any) []string {
	xs, _ := v.([]any)
	var out []string
	for _, x := range xs {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
