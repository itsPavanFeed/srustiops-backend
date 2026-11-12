package central

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/httpx"
	"github.com/jackc/pgx/v5"
)

// ---- workspace creation policy ----
//
// Platform admins create any workspace. Anyone else signed in with a verified
// address in an allowed domain may create a trial workspace at once, within
// the quotas, and may request a production workspace, which waits for a
// platform admin. Trials end after TrialDays: the workspace stays readable,
// and changes are refused until a platform admin makes it production.

type WorkspacePolicy struct {
	AllowedDomains []string `json:"allowed_domains"`
	TrialDays      int      `json:"trial_days"`
	TrialPerPerson int      `json:"trial_per_person"`
	TrialPerDomain int      `json:"trial_per_domain"`
	// ProductionApproval: production workspaces need a platform admin's
	// approval (always true today; kept explicit for the console).
	ProductionApproval bool `json:"production_requires_approval"`
}

func defaultPolicy() WorkspacePolicy {
	return WorkspacePolicy{AllowedDomains: []string{}, TrialDays: 30, TrialPerPerson: 1, TrialPerDomain: 3, ProductionApproval: true}
}

func (s *Store) WorkspacePolicy(ctx context.Context) WorkspacePolicy {
	p := defaultPolicy()
	var raw []byte
	if s.Pool().QueryRow(ctx, `SELECT value FROM platform_settings WHERE key = 'workspace_policy'`).Scan(&raw) == nil {
		json.Unmarshal(raw, &p)
	}
	if p.AllowedDomains == nil {
		p.AllowedDomains = []string{}
	}
	return p
}

func (s *Store) PutWorkspacePolicy(ctx context.Context, p WorkspacePolicy, by string) error {
	raw, _ := json.Marshal(p)
	_, err := s.Pool().Exec(ctx, `INSERT INTO platform_settings (key, value, updated_by) VALUES ('workspace_policy', $1, $2)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_by = EXCLUDED.updated_by, updated_at = now()`, raw, by)
	return err
}

// trialCounts is how many live trial workspaces a person and a domain hold.
func (s *Store) trialCounts(ctx context.Context, email, domain string) (person, dom int) {
	s.Pool().QueryRow(ctx, `SELECT count(*) FILTER (WHERE lower(created_by) = lower($1)), count(*) FILTER (WHERE lower(split_part(created_by, '@', 2)) = $2)
		FROM tenants WHERE kind = 'trial' AND status <> 'removed'`, email, domain).Scan(&person, &dom)
	return
}

func emailDomain(email string) string {
	if i := strings.LastIndex(email, "@"); i >= 0 {
		return strings.ToLower(email[i+1:])
	}
	return ""
}

// creatorKind says what the caller may create: "any" (platform admin),
// "allowed" (an allowed, verified domain) or "" with the reason.
func (s *Server) creatorKind(r *http.Request) (string, string) {
	u := current(r)
	if u.PlatformAdmin {
		return "any", ""
	}
	if sess := sessionOf(r); sess != nil && sess.UserIssuer != "" && !sess.EmailVerified {
		return "", "your sign-in did not verify your email address"
	}
	if !slices.Contains(s.store.WorkspacePolicy(r.Context()).AllowedDomains, emailDomain(u.Email)) {
		return "", "workspaces can be created only by addresses in the platform's allowed domains; ask a platform admin"
	}
	return "allowed", ""
}

func (s *Server) getWorkspacePolicy(w http.ResponseWriter, r *http.Request) {
	p := s.store.WorkspacePolicy(r.Context())
	kind, why := s.creatorKind(r)
	res := map[string]any{"policy": p, "can_create": kind != "", "reason": why, "platform_admin": kind == "any"}
	if kind == "allowed" {
		u := current(r)
		person, dom := s.store.trialCounts(r.Context(), u.Email, emailDomain(u.Email))
		res["trials"] = map[string]int{"yours": person, "your_limit": p.TrialPerPerson, "domain": dom, "domain_limit": p.TrialPerDomain}
	}
	httpx.WriteJSON(w, 200, res)
}

func (s *Server) putWorkspacePolicy(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(w, r) {
		return
	}
	var p WorkspacePolicy
	if !httpx.Decode(w, r, &p) {
		return
	}
	var probs []string
	doms := []string{}
	for _, d := range p.AllowedDomains {
		d = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(d, "@")))
		if d == "" {
			continue
		}
		if !domainRe.MatchString(d) {
			probs = append(probs, d+" is not a domain")
		} else if !slices.Contains(doms, d) {
			doms = append(doms, d)
		}
	}
	if p.TrialDays < 1 || p.TrialDays > 365 {
		probs = append(probs, "trial_days must be 1 to 365")
	}
	if p.TrialPerPerson < 0 || p.TrialPerPerson > 20 || p.TrialPerDomain < 0 || p.TrialPerDomain > 500 {
		probs = append(probs, "trial quotas must be 0 to 20 per person and 0 to 500 per domain")
	}
	if len(probs) > 0 {
		httpx.WriteErr(w, 422, "invalid workspace policy", probs...)
		return
	}
	p.AllowedDomains, p.ProductionApproval = doms, true
	if err := s.store.PutWorkspacePolicy(r.Context(), p, current(r).Email); err != nil {
		s.storeErr(w, err, "")
		return
	}
	s.audit(r.Context(), current(r).Email, "platform.workspace_policy", "platform/workspace-policy", "", p)
	httpx.WriteJSON(w, 200, p)
}

// ---- requests ----

type WorkspaceRequest struct {
	ID          string     `json:"id"`
	Slug        string     `json:"slug"`
	Name        string     `json:"name"`
	Target      string     `json:"target"`
	Reason      string     `json:"reason"`
	RequestedBy string     `json:"requested_by"`
	Status      string     `json:"status"`
	DecidedBy   string     `json:"decided_by,omitempty"`
	Decision    string     `json:"decision,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	DecidedAt   *time.Time `json:"decided_at,omitempty"`
}

const wsReqCols = `id, slug, name, target, reason, requested_by, status, decided_by, decision, created_at, decided_at`

func scanWSReq(r pgx.Row) (*WorkspaceRequest, error) {
	var q WorkspaceRequest
	err := r.Scan(&q.ID, &q.Slug, &q.Name, &q.Target, &q.Reason, &q.RequestedBy, &q.Status, &q.DecidedBy, &q.Decision, &q.CreatedAt, &q.DecidedAt)
	return &q, err
}

// createWorkspaceRequest is the one way to ask for a workspace: a platform
// admin's is created at once, a trial within quota is created at once, and a
// production request waits for approval.
func (s *Server) createWorkspaceRequest(w http.ResponseWriter, r *http.Request) {
	var b struct {
		tenantBody
		Kind   string `json:"kind"` // trial | production
		Reason string `json:"reason"`
	}
	if !httpx.Decode(w, r, &b) {
		return
	}
	u := current(r)
	who, why := s.creatorKind(r)
	if who == "" {
		httpx.WriteErr(w, http.StatusForbidden, why)
		return
	}
	if b.Kind != "trial" && b.Kind != "production" {
		httpx.WriteErr(w, 422, `kind must be "trial" or "production"`)
		return
	}
	// Self-service workspaces connect first, through the link; the requester
	// becomes their first tenant admin.
	if b.AdminEmail == "" || who != "any" {
		b.AdminEmail = u.Email
	}
	if who != "any" {
		b.Connectivity, b.BackendURL, b.ServerCAPEM = "tunnel", "", ""
	}
	if probs := b.validate(true); len(probs) > 0 {
		httpx.WriteErr(w, 422, "invalid workspace", probs...)
		return
	}
	if _, err := s.store.Tenant(r.Context(), b.Slug); err == nil || s.store.slugTaken(r.Context(), b.Slug) {
		httpx.WriteErr(w, http.StatusConflict, "a workspace with that slug exists or was used before")
		return
	}
	pol := s.store.WorkspacePolicy(r.Context())
	if b.Kind == "trial" {
		ends := time.Now().AddDate(0, 0, pol.TrialDays)
		if who != "any" {
			person, dom := s.store.trialCounts(r.Context(), u.Email, emailDomain(u.Email))
			if person >= pol.TrialPerPerson || dom >= pol.TrialPerDomain {
				httpx.WriteErr(w, http.StatusConflict, "trial quota reached: "+strconv.Itoa(pol.TrialPerPerson)+" per person and "+strconv.Itoa(pol.TrialPerDomain)+" per domain; remove a trial or request a production workspace")
				return
			}
		}
		s.createWorkspace(w, r, b.tenantBody, &Tenant{Kind: "trial", TrialEndsAt: &ends}, u.Email)
		return
	}
	if who == "any" {
		s.createWorkspace(w, r, b.tenantBody, &Tenant{Kind: "production"}, u.Email)
		return
	}
	if l := len(strings.TrimSpace(b.Reason)); l < 10 || l > 500 {
		httpx.WriteErr(w, 422, "say what the production workspace is for (10 to 500 characters)")
		return
	}
	q, err := scanWSReq(s.store.Pool().QueryRow(r.Context(), `INSERT INTO workspace_requests (slug, name, target, reason, requested_by)
		VALUES ($1, $2, $3, $4, $5) RETURNING `+wsReqCols, b.Slug, b.Name, b.Target, strings.TrimSpace(b.Reason), u.Email))
	if err != nil {
		s.storeErr(w, err, "a request for that slug is already waiting")
		return
	}
	s.audit(r.Context(), u.Email, "workspace.request", "workspace-request/"+q.ID, "", q)
	httpx.WriteJSON(w, 202, map[string]any{"request": q, "message": "a platform admin will review the request"})
}

func (s *Store) slugTaken(ctx context.Context, slug string) bool {
	var n int
	s.Pool().QueryRow(ctx, `SELECT count(*) FROM tenants WHERE slug = $1`, slug).Scan(&n)
	return n > 0
}

func (s *Server) listWorkspaceRequests(w http.ResponseWriter, r *http.Request) {
	u := current(r)
	q, args := `SELECT `+wsReqCols+` FROM workspace_requests WHERE lower(requested_by) = lower($1) ORDER BY created_at DESC LIMIT 100`, []any{u.Email}
	if u.PlatformAdmin {
		q, args = `SELECT `+wsReqCols+` FROM workspace_requests ORDER BY status <> 'pending', created_at DESC LIMIT 200`, nil
	}
	rows, err := s.store.Pool().Query(r.Context(), q, args...)
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	out := []*WorkspaceRequest{}
	for rows.Next() {
		x, err := scanWSReq(rows)
		if err != nil {
			rows.Close()
			s.storeErr(w, err, "")
			return
		}
		out = append(out, x)
	}
	rows.Close()
	httpx.WriteJSON(w, 200, out)
}

func (s *Server) decideWorkspaceRequest(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(w, r) {
		return
	}
	decision := r.PathValue("decision")
	if decision != "approve" && decision != "reject" {
		httpx.WriteErr(w, http.StatusNotFound, "not found")
		return
	}
	var b struct {
		Reason string `json:"reason"`
	}
	httpx.Decode(w, r, &b)
	by := current(r).Email
	q, err := scanWSReq(s.store.Pool().QueryRow(r.Context(), `SELECT `+wsReqCols+` FROM workspace_requests WHERE id::text = $1 AND status = 'pending'`, r.PathValue("id")))
	if err != nil {
		httpx.WriteErr(w, http.StatusNotFound, "no pending request with that id")
		return
	}
	status := map[string]string{"approve": "approved", "reject": "rejected"}[decision]
	if decision == "approve" && s.store.slugTaken(r.Context(), q.Slug) {
		httpx.WriteErr(w, http.StatusConflict, "the slug was taken since; reject and ask for another")
		return
	}
	if _, err := s.store.Pool().Exec(r.Context(), `UPDATE workspace_requests SET status = $2, decided_by = $3, decision = $4, decided_at = now() WHERE id = $1 AND status = 'pending'`,
		q.ID, status, by, strings.TrimSpace(b.Reason)); err != nil {
		s.storeErr(w, err, "")
		return
	}
	s.audit(r.Context(), by, "workspace.request_"+status, "workspace-request/"+q.ID, q.Slug, map[string]string{"requested_by": q.RequestedBy, "reason": b.Reason})
	if decision == "reject" {
		q.Status, q.DecidedBy, q.Decision = status, by, b.Reason
		httpx.WriteJSON(w, 200, map[string]any{"request": q})
		return
	}
	// The requester is the first tenant admin; the install command goes to
	// them from the workspace's install page.
	s.createWorkspace(w, r, tenantBody{Slug: q.Slug, Name: q.Name, AdminEmail: q.RequestedBy, Connectivity: "tunnel", Target: q.Target},
		&Tenant{Kind: "production"}, q.RequestedBy)
}

// promoteWorkspace makes a trial a production workspace.
func (s *Server) promoteWorkspace(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(w, r) {
		return
	}
	tag, err := s.store.Pool().Exec(r.Context(), `UPDATE tenants SET kind = 'production', trial_ends_at = NULL, updated_at = now() WHERE slug = $1 AND kind = 'trial' AND status <> 'removed'`, r.PathValue("tenant"))
	if err != nil || tag.RowsAffected() == 0 {
		httpx.WriteErr(w, http.StatusNotFound, "no trial workspace with that slug")
		return
	}
	s.audit(r.Context(), current(r).Email, "workspace.promote", "tenant/"+r.PathValue("tenant"), r.PathValue("tenant"), nil)
	t, _ := s.store.Tenant(r.Context(), r.PathValue("tenant"))
	httpx.WriteJSON(w, 200, t)
}

// trialRefusal answers a change to a workspace whose trial has ended.
// Reading stays open, so nothing is lost while it is promoted or removed.
func trialRefusal(w http.ResponseWriter, r *http.Request, t *Tenant) bool {
	if t.Kind != "trial" || t.TrialEndsAt == nil || time.Now().Before(*t.TrialEndsAt) || r.Method == http.MethodGet || r.Method == http.MethodHead {
		return false
	}
	httpx.WriteErr(w, http.StatusForbidden, "trial_expired: the trial of "+t.Slug+" ended on "+t.TrialEndsAt.Format("2 Jan 2006")+"; a platform admin can make it a production workspace")
	return true
}

// ---- removal ----

// removeWorkspace deregisters a workspace: the tenant plane is told to stop
// (it refuses work from then on, its data untouched), its link certificates,
// enrolments, install and SCIM tokens are revoked and its tunnels closed,
// memberships and verified domains are released, and it disappears from
// every list. Infrastructure the provisioner built has its SrustiOps services
// and the provisioner's access removed; the tenant's data stays.
func (s *Server) removeWorkspace(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, true)
	if t == nil {
		return
	}
	var b struct {
		Confirm string `json:"confirm"`
	}
	if !httpx.Decode(w, r, &b) {
		return
	}
	if b.Confirm != t.Slug {
		httpx.WriteErr(w, 422, "type the workspace's slug ("+t.Slug+") to confirm")
		return
	}
	ctx, by := r.Context(), current(r).Email
	// While the link is still up: the tenant plane stops its services.
	told := false
	if t.Status == "active" && s.online(ctx, t) {
		code, _, err := s.callTenantAs(ctx, t, s.system(t), http.MethodPost, "/api/v1/decommission", map[string]string{"by": by})
		told = err == nil && code < 300
	}
	prov := s.decommissionProvisioned(ctx, t, by)
	if err := s.store.RemoveTenant(ctx, t.ID, by); err != nil {
		s.storeErr(w, err, "")
		return
	}
	if s.link != nil {
		s.link.hub.Drop(t.Slug, "")
	}
	s.mu.Lock()
	for k := range s.transports {
		if k == t.Slug || strings.HasPrefix(k, t.Slug+"\x00") {
			delete(s.transports, k)
		}
	}
	s.mu.Unlock()
	s.audit(ctx, by, "tenant.remove", "tenant/"+t.Slug, t.Slug, map[string]any{"tenant_told": told, "provisioned": prov != nil})
	res := map[string]any{"removed": t.Slug, "tenant_stopped": told,
		"uninstall": map[string]string{
			"kubernetes": "helm -n srustiops uninstall srustiops   # the database, its volumes and secrets are kept",
			"docker":     "docker compose down   # without -v: the database volume is kept",
		},
		"data": "The tenant's database, state, bucket and keys are not touched."}
	if prov != nil {
		res["provisioner"] = prov
	}
	httpx.WriteJSON(w, 200, res)
}

// RemoveTenant revokes everything that lets anyone reach the tenant through
// central, and marks it removed. The row stays for audit; the slug is not reused.
func (s *Store) RemoveTenant(ctx context.Context, tenantID, by string) error {
	return pgx.BeginFunc(ctx, s.Pool(), func(tx pgx.Tx) error {
		for _, q := range []string{
			`UPDATE link_certs SET revoked_at = now(), revoked_by = $2 WHERE tenant_id = $1 AND revoked_at IS NULL`,
			`UPDATE link_enrollments SET used_at = now() WHERE tenant_id = $1 AND used_at IS NULL AND $2 <> ''`,
			`UPDATE install_tokens SET used_at = now() WHERE tenant_id = $1 AND used_at IS NULL AND $2 <> ''`,
			`UPDATE tenant_scim_tokens SET revoked_at = now() WHERE tenant_id = $1 AND revoked_at IS NULL AND $2 <> ''`,
			// Tokens of people who belonged to this tenant only.
			`UPDATE api_tokens SET revoked_at = now() WHERE revoked_at IS NULL AND $2 <> '' AND user_id IN (
				SELECT m.user_id FROM memberships m JOIN users u ON u.id = m.user_id WHERE m.tenant_id = $1 AND NOT u.platform_admin
				AND NOT EXISTS (SELECT 1 FROM memberships o WHERE o.user_id = m.user_id AND o.tenant_id <> $1))`,
			`DELETE FROM token_tenant_sessions WHERE tenant_id = $1 AND $2 <> ''`,
			`DELETE FROM memberships WHERE tenant_id = $1 AND $2 <> ''`,
			`DELETE FROM tenant_domains WHERE tenant_id = $1 AND $2 <> ''`,
			`DELETE FROM tenant_links WHERE tenant_id = $1 AND $2 <> ''`,
			`DELETE FROM link_webhook_queue WHERE tenant_id = $1 AND $2 <> ''`,
			`UPDATE tenants SET status = 'removed', removed_at = now(), removed_by = $2, updated_at = now() WHERE id = $1`,
		} {
			if _, err := tx.Exec(ctx, q, tenantID, by); err != nil {
				return err
			}
		}
		return nil
	})
}
