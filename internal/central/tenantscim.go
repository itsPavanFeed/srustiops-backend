package central

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/itsPavanFeed/srustiops-backend/internal/httpx"
	"github.com/itsPavanFeed/srustiops-backend/internal/secure"
)

// Per-tenant SCIM 2.0 at /scim/v2/t/{tenant}/, with tokens a tenant's admins
// issue. It only says who people are and which of the tenant's groups they
// are in: users are never disabled platform-wide from here (deactivating
// removes them from this tenant's groups), and the tenant maps groups to
// roles itself (Tenant settings → Access → Group bindings).

type tscimKey struct{}

func tscimTenant(r *http.Request) *Tenant { return r.Context().Value(tscimKey{}).(*Tenant) }

func (s *Server) tenantSCIMAuth(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := httpx.ClientIP(r)
		if s.limiter.Blocked(ip) {
			scimErr(w, http.StatusTooManyRequests, "too many failed attempts")
			return
		}
		tok := httpx.Bearer(r)
		var t *Tenant
		var err error = ErrNotFound
		if strings.HasPrefix(tok, "sop_s_") {
			t, err = s.store.TenantBySCIMToken(r.Context(), r.PathValue("tenant"), secure.HashToken(tok))
		}
		if err != nil {
			s.limiter.Fail(ip)
			scimErr(w, http.StatusUnauthorized, "invalid SCIM token for this tenant")
			return
		}
		if t.AccessSource != "tenant" {
			scimErr(w, http.StatusConflict, "this tenant does not control its own access yet")
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), tscimKey{}, t)))
	})
}

// knownTo: a user belongs to this tenant's SCIM view when it created them or
// they are in one of its groups.
func (s *Server) knownTo(ctx context.Context, t *Tenant, u *User) bool {
	if gs, err := s.store.TSCIMGroupsOfUser(ctx, t.ID, u.ID); err == nil && len(gs) > 0 {
		return true
	}
	var by string
	s.store.Pool().QueryRow(ctx, `SELECT created_by FROM users WHERE id = $1`, u.ID).Scan(&by)
	return by == "scim:"+t.Slug
}

func (s *Server) tscimListUsers(w http.ResponseWriter, r *http.Request) {
	t := tscimTenant(r)
	res := []map[string]any{}
	if v, ok := filterValue(r.URL.Query().Get("filter"), "userName"); ok {
		if u, err := s.store.UserByEmail(r.Context(), strings.ToLower(v)); err == nil && s.knownTo(r.Context(), t, u) {
			res = append(res, userResource(u))
		}
	}
	scimJSON(w, 200, map[string]any{"schemas": []string{scimList}, "totalResults": len(res), "startIndex": 1, "itemsPerPage": len(res), "Resources": res})
}

func (s *Server) tscimCreateUser(w http.ResponseWriter, r *http.Request) {
	t := tscimTenant(r)
	var b scimUserBody
	if !readSCIM(w, r, &b) {
		return
	}
	email := strings.ToLower(strings.TrimSpace(b.UserName))
	if !emailRe.MatchString(email) {
		scimErr(w, 400, "userName must be an email address")
		return
	}
	u, err := s.store.EnsureUser(r.Context(), email, trim(b.displayName(), 200), false, "scim:"+t.Slug)
	if err != nil {
		scimErr(w, 500, "internal error")
		return
	}
	s.audit(r.Context(), "scim:"+t.Slug, "scim.user_create", "user/"+email, t.Slug, nil)
	scimJSON(w, 201, userResource(u))
}

func (s *Server) tscimUser(w http.ResponseWriter, r *http.Request) (*Tenant, *User, bool) {
	t := tscimTenant(r)
	u, err := s.store.UserByID(r.Context(), r.PathValue("id"))
	if err != nil || !s.knownTo(r.Context(), t, u) {
		scimErr(w, 404, "no such user")
		return nil, nil, false
	}
	return t, u, true
}

func (s *Server) tscimGetUser(w http.ResponseWriter, r *http.Request) {
	if _, u, ok := s.tscimUser(w, r); ok {
		scimJSON(w, 200, userResource(u))
	}
}

// tscimUpdateUser handles deactivation (active=false) by removing the person
// from this tenant's groups; other attributes are accepted and ignored.
func (s *Server) tscimUpdateUser(w http.ResponseWriter, r *http.Request) {
	t, u, ok := s.tscimUser(w, r)
	if !ok {
		return
	}
	var b map[string]any
	if !readSCIM(w, r, &b) {
		return
	}
	inactive := b["active"] == false
	if ops, ok := b["Operations"].([]any); ok {
		for _, o := range ops {
			op, _ := o.(map[string]any)
			if v, ok := op["value"].(map[string]any); ok && v["active"] == false {
				inactive = true
			}
			if strings.EqualFold(stringOf(op["path"]), "active") && op["value"] == false {
				inactive = true
			}
		}
	}
	if inactive {
		s.leaveTenantGroups(w, r, t, u)
		return
	}
	scimJSON(w, 200, userResource(u))
}

func stringOf(v any) string { s, _ := v.(string); return s }

func (s *Server) tscimDeleteUser(w http.ResponseWriter, r *http.Request) {
	t, u, ok := s.tscimUser(w, r)
	if !ok {
		return
	}
	s.leaveTenantGroups(w, r, t, u)
}

func (s *Server) leaveTenantGroups(w http.ResponseWriter, r *http.Request, t *Tenant, u *User) {
	gs, _ := s.store.TSCIMGroupsOfUser(r.Context(), t.ID, u.ID)
	for _, g := range gs {
		s.store.SetTSCIMMember(r.Context(), g.ID, u.ID, false)
		if err := s.pushGroup(r.Context(), t, g); err != nil {
			scimErr(w, http.StatusServiceUnavailable, "tenant unreachable; retry later")
			return
		}
	}
	s.audit(r.Context(), "scim:"+t.Slug, "scim.user_leave", "user/"+u.Email, t.Slug, map[string]int{"groups": len(gs)})
	if r.Method == http.MethodDelete {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	res := userResource(u)
	res["active"] = false
	scimJSON(w, 200, res)
}

// pushGroup sends a group's members to the tenant, which decides what the
// group grants.
func (s *Server) pushGroup(ctx context.Context, t *Tenant, g *TSCIMGroup) error {
	ms, err := s.store.TSCIMMembers(ctx, g.ID)
	if err != nil {
		return err
	}
	emails := []string{}
	for _, m := range ms {
		emails = append(emails, m.Email)
	}
	code, body, err := s.callTenantAs(ctx, t, s.system(t), http.MethodPut, "/api/v1/access/groups/"+pathEscape(g.Name)+"/members", map[string]any{"emails": emails})
	if err != nil {
		return err
	}
	if code != 204 {
		return &httpErr{code, errText(body)}
	}
	s.syncLater(t)
	return nil
}

type httpErr struct {
	code int
	msg  string
}

func (e *httpErr) Error() string { return e.msg }

func pathEscape(s string) string { return url.PathEscape(s) }

func (s *Server) tgroupResource(ctx context.Context, g *TSCIMGroup) map[string]any {
	members := []map[string]string{}
	ms, _ := s.store.TSCIMMembers(ctx, g.ID)
	for _, m := range ms {
		members = append(members, map[string]string{"value": m.ID, "display": m.Email})
	}
	return map[string]any{"schemas": []string{scimGroup}, "id": g.ID, "displayName": g.Name, "externalId": g.ExternalID, "members": members,
		"meta": map[string]any{"resourceType": "Group"}}
}

func (s *Server) tscimListGroups(w http.ResponseWriter, r *http.Request) {
	t := tscimTenant(r)
	name, _ := filterValue(r.URL.Query().Get("filter"), "displayName")
	gs, err := s.store.TSCIMGroups(r.Context(), t.ID, name)
	if err != nil {
		scimErr(w, 500, "internal error")
		return
	}
	res := []map[string]any{}
	for _, g := range gs {
		res = append(res, s.tgroupResource(r.Context(), g))
	}
	scimJSON(w, 200, map[string]any{"schemas": []string{scimList}, "totalResults": len(res), "startIndex": 1, "itemsPerPage": len(res), "Resources": res})
}

func (s *Server) setMembers(ctx context.Context, t *Tenant, g *TSCIMGroup, refs []memberRef, add bool) {
	for _, ref := range refs {
		u, err := s.store.UserByID(ctx, ref.Value)
		if err != nil {
			continue
		}
		s.store.SetTSCIMMember(ctx, g.ID, u.ID, add)
	}
}

func (s *Server) tscimCreateGroup(w http.ResponseWriter, r *http.Request) {
	t := tscimTenant(r)
	var b struct {
		DisplayName string      `json:"displayName"`
		ExternalID  string      `json:"externalId"`
		Members     []memberRef `json:"members"`
	}
	if !readSCIM(w, r, &b) {
		return
	}
	b.DisplayName = strings.TrimSpace(b.DisplayName)
	if b.DisplayName == "" || len(b.DisplayName) > 200 {
		scimErr(w, 400, "displayName is required")
		return
	}
	g, err := s.store.CreateTSCIMGroup(r.Context(), t.ID, b.DisplayName, trim(b.ExternalID, 200))
	if err != nil {
		scimErr(w, http.StatusConflict, "group exists")
		return
	}
	s.setMembers(r.Context(), t, g, b.Members, true)
	if err := s.pushGroup(r.Context(), t, g); err != nil {
		scimErr(w, http.StatusServiceUnavailable, "tenant unreachable; retry later")
		return
	}
	s.audit(r.Context(), "scim:"+t.Slug, "scim.group_create", "group/"+g.Name, t.Slug, nil)
	scimJSON(w, 201, s.tgroupResource(r.Context(), g))
}

func (s *Server) tscimGroup(w http.ResponseWriter, r *http.Request) (*Tenant, *TSCIMGroup, bool) {
	t := tscimTenant(r)
	g, err := s.store.TSCIMGroup(r.Context(), t.ID, r.PathValue("id"))
	if err != nil {
		scimErr(w, 404, "no such group")
		return nil, nil, false
	}
	return t, g, true
}

func (s *Server) tscimGetGroup(w http.ResponseWriter, r *http.Request) {
	if _, g, ok := s.tscimGroup(w, r); ok {
		scimJSON(w, 200, s.tgroupResource(r.Context(), g))
	}
}

var memberPathRe = regexp.MustCompile(`members\[value eq "([^"]+)"\]`)

func (s *Server) tscimPatchGroup(w http.ResponseWriter, r *http.Request) {
	t, g, ok := s.tscimGroup(w, r)
	if !ok {
		return
	}
	var p struct {
		Operations []struct {
			Op    string          `json:"op"`
			Path  string          `json:"path"`
			Value json.RawMessage `json:"value"`
		} `json:"Operations"`
	}
	if !readSCIM(w, r, &p) {
		return
	}
	for _, op := range p.Operations {
		var refs []memberRef
		json.Unmarshal(op.Value, &refs)
		if m := memberPathRe.FindStringSubmatch(op.Path); m != nil {
			refs = append(refs, memberRef{Value: m[1]})
		}
		switch strings.ToLower(op.Op) {
		case "add":
			s.setMembers(r.Context(), t, g, refs, true)
		case "remove":
			s.setMembers(r.Context(), t, g, refs, false)
		case "replace":
			if strings.EqualFold(op.Path, "members") || op.Path == "" {
				s.store.ClearTSCIMMembers(r.Context(), g.ID)
				s.setMembers(r.Context(), t, g, refs, true)
			}
		}
	}
	if err := s.pushGroup(r.Context(), t, g); err != nil {
		scimErr(w, http.StatusServiceUnavailable, "tenant unreachable; retry later")
		return
	}
	scimJSON(w, 200, s.tgroupResource(r.Context(), g))
}

func (s *Server) tscimPutGroup(w http.ResponseWriter, r *http.Request) {
	t, g, ok := s.tscimGroup(w, r)
	if !ok {
		return
	}
	var b struct {
		Members []memberRef `json:"members"`
	}
	if !readSCIM(w, r, &b) {
		return
	}
	s.store.ClearTSCIMMembers(r.Context(), g.ID)
	s.setMembers(r.Context(), t, g, b.Members, true)
	if err := s.pushGroup(r.Context(), t, g); err != nil {
		scimErr(w, http.StatusServiceUnavailable, "tenant unreachable; retry later")
		return
	}
	scimJSON(w, 200, s.tgroupResource(r.Context(), g))
}

func (s *Server) tscimDeleteGroup(w http.ResponseWriter, r *http.Request) {
	t, g, ok := s.tscimGroup(w, r)
	if !ok {
		return
	}
	s.store.ClearTSCIMMembers(r.Context(), g.ID)
	if err := s.pushGroup(r.Context(), t, g); err != nil {
		scimErr(w, http.StatusServiceUnavailable, "tenant unreachable; retry later")
		return
	}
	s.store.DeleteTSCIMGroup(r.Context(), t.ID, g.ID)
	s.audit(r.Context(), "scim:"+t.Slug, "scim.group_delete", "group/"+g.Name, t.Slug, nil)
	w.WriteHeader(http.StatusNoContent)
}

// ---- tokens (tenant admins) ----

func (s *Server) listTenantSCIMTokens(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, true)
	if t == nil {
		return
	}
	ts, err := s.store.TenantSCIMTokens(r.Context(), t.ID)
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	httpx.WriteJSON(w, 200, map[string]any{"tokens": ts, "url": s.cfg.PublicURL + "/scim/v2/t/" + t.Slug})
}

func (s *Server) createTenantSCIMToken(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, true)
	if t == nil {
		return
	}
	if t.AccessSource != "tenant" {
		httpx.WriteErr(w, http.StatusConflict, "move access control into the tenant first")
		return
	}
	var b struct {
		Name string `json:"name"`
	}
	if !httpx.Decode(w, r, &b) {
		return
	}
	if !tokNameRe.MatchString(b.Name) {
		httpx.WriteErr(w, 422, "name is required (letters, digits, spaces, - and _)")
		return
	}
	plain, err := secure.NewToken("s")
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	id, err := s.store.CreateTenantSCIMToken(r.Context(), t.ID, b.Name, current(r).Email, secure.HashToken(plain))
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	s.audit(r.Context(), current(r).Email, "tenant.scim_token_create", "tenant/"+t.Slug, t.Slug, map[string]string{"name": b.Name})
	httpx.WriteJSON(w, 201, map[string]any{"id": id, "secret": plain, "url": s.cfg.PublicURL + "/scim/v2/t/" + t.Slug})
}

func (s *Server) revokeTenantSCIMToken(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, true)
	if t == nil {
		return
	}
	if err := s.store.RevokeTenantSCIMToken(r.Context(), t.ID, r.PathValue("id")); err != nil {
		s.storeErr(w, err, "")
		return
	}
	s.audit(r.Context(), current(r).Email, "tenant.scim_token_revoke", "tenant/"+t.Slug, t.Slug, map[string]string{"id": r.PathValue("id")})
	w.WriteHeader(http.StatusNoContent)
}
