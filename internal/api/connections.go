package api

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/itsPavanFeed/srustiops-backend/internal/identity"
	"github.com/itsPavanFeed/srustiops-backend/internal/spec"
	"github.com/itsPavanFeed/srustiops-backend/internal/store"
)

var connNameRe = regexp.MustCompile(`^[a-z][a-z0-9-]{1,47}$`)

type connBody struct {
	Name     string          `json:"name"`
	Cloud    json.RawMessage `json:"cloud"`
	Entities []string        `json:"entities"` // [] = every entity
	// SharedAccount registers an account that another connection already
	// covers, on purpose: the provisioner keeps one connection per
	// workspace it builds, each with its own role, and several workspaces
	// may live in one account.
	SharedAccount bool `json:"shared_account"`
}

// Everyone in the tenant may read connections: they hold identifiers only.
func (s *Server) listConnections(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Has("limit") { // a page: {items, total, counts}
		provider := q.Get("provider")
		switch provider {
		case "", "aws", "gcp", "azure":
		default:
			writeErr(w, 422, "provider must be aws, gcp or azure")
			return
		}
		offset, _ := strconv.Atoi(q.Get("offset"))
		if offset < 0 {
			offset = 0
		}
		cs, total, counts, err := s.store.ConnectionPage(r.Context(), provider, limit(r, 10, 100), offset)
		if err != nil {
			s.writeStoreErr(w, err, "")
			return
		}
		writeJSON(w, 200, map[string]any{"items": cs, "total": total, "counts": counts})
		return
	}
	cs, err := s.store.ListConnections(r.Context())
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	writeJSON(w, 200, cs)
}

func (s *Server) getConnection(w http.ResponseWriter, r *http.Request) {
	c, err := s.store.GetConnection(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	resp := map[string]any{"connection": c}
	if cl, err := spec.DecodeCloud(c.Cloud); err == nil && cl.NeedsOIDCToken() {
		resp["oidc"] = map[string]string{
			"issuer":          s.issuer.URL,
			"audience":        cl.Audience(),
			"subject_pattern": "srustiops:entity:*:env:*:stack:*",
		}
	}
	writeJSON(w, 200, resp)
}

func (s *Server) validConnection(w http.ResponseWriter, b *connBody, create bool) (json.RawMessage, bool) {
	var probs []string
	if create && !connNameRe.MatchString(b.Name) {
		probs = append(probs, "name must be lowercase letters, digits and dashes (2-48)")
	}
	if b.Entities == nil {
		b.Entities = []string{}
	}
	for _, e := range b.Entities {
		if !identity.SlugRe.MatchString(e) {
			probs = append(probs, "entities must be entity slugs")
		}
	}
	c, err := spec.DecodeCloud(b.Cloud)
	if err != nil {
		probs = append(probs, errLines(err)...)
	} else if c.Provider == "none" {
		probs = append(probs, `a connection needs a cloud provider; environments without a cloud simply have no connection`)
	}
	if len(probs) > 0 {
		writeErr(w, 422, "invalid cloud connection", probs...)
		return nil, false
	}
	cloud, _ := json.Marshal(c)
	return cloud, true
}

func (s *Server) createConnection(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	var b connBody
	if !decode(w, r, &b) {
		return
	}
	cloud, ok := s.validConnection(w, &b, true)
	if !ok {
		return
	}
	if dup := s.duplicateConnection(r.Context(), cloud, ""); dup != "" && !b.SharedAccount {
		writeErr(w, http.StatusConflict, "connection "+dup+" already points at this account, project or subscription; register each one once")
		return
	}
	c, err := s.store.CreateConnection(r.Context(), &store.Connection{Name: b.Name, Cloud: cloud, Entities: b.Entities, CreatedBy: user(r).Subject})
	if err != nil {
		s.writeStoreErr(w, err, "a connection with that name exists")
		return
	}
	s.audit(r.Context(), user(r).Actor(), "connection.create", "connection/"+c.Name, "", c)
	writeJSON(w, 201, c)
}

// updateConnection changes identifiers or scope. Every environment using it
// gets a new config hash, so plans made against the old values go stale.
func (s *Server) updateConnection(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	cur, err := s.store.GetConnection(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	var b connBody
	if !decode(w, r, &b) {
		return
	}
	cloud, ok := s.validConnection(w, &b, false)
	if !ok {
		return
	}
	if dup := s.duplicateConnection(r.Context(), cloud, cur.ID); dup != "" {
		writeErr(w, http.StatusConflict, "connection "+dup+" already points at this account, project or subscription")
		return
	}
	if s.dryRun(w, r) {
		return
	}
	c, err := s.store.UpdateConnection(r.Context(), &store.Connection{ID: cur.ID, Cloud: cloud, Entities: b.Entities})
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.audit(r.Context(), user(r).Actor(), "connection.update", "connection/"+c.Name, "", map[string]any{"before": cur, "after": c})
	writeJSON(w, 200, c)
}

// deleteConnection removes a connection no environment uses.
func (s *Server) deleteConnection(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	cur, err := s.store.GetConnection(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	if cur.EnvironmentID != nil {
		writeErr(w, http.StatusConflict, "environment "+cur.Environment+" uses this connection; remove it from the environment first")
		return
	}
	if s.dryRun(w, r) {
		return
	}
	if err := s.store.DeleteConnection(r.Context(), cur.ID); err != nil {
		s.writeStoreErr(w, err, "environments or stacks still use this connection; remove them first")
		return
	}
	s.audit(r.Context(), user(r).Actor(), "connection.delete", "connection/"+cur.Name, "", cur)
	w.WriteHeader(http.StatusNoContent)
}

// cloudScope is what identifies the account a connection points at: the AWS
// account of its role, the GCP project, or the Azure subscription.
func cloudScope(c *spec.Cloud) string {
	switch c.Provider {
	case "aws":
		return "aws:" + accountOf(c.AWS.RoleARN)
	case "gcp":
		return "gcp:" + c.GCP.ProjectID
	case "azure":
		return "azure:" + strings.ToLower(c.Azure.SubscriptionID)
	}
	return ""
}

// duplicateConnection names another connection for the same account,
// project or subscription (one account is registered once).
func (s *Server) duplicateConnection(ctx context.Context, cloud json.RawMessage, except string) string {
	c, err := spec.DecodeCloud(cloud)
	if err != nil {
		return ""
	}
	want := cloudScope(c)
	if want == "" || strings.HasSuffix(want, ":") {
		return ""
	}
	all, err := s.store.ListConnections(ctx)
	if err != nil {
		return ""
	}
	for _, o := range all {
		if o.ID == except {
			continue
		}
		if oc, err := spec.DecodeCloud(o.Cloud); err == nil && cloudScope(oc) == want {
			return o.Name
		}
	}
	return ""
}

type connCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"` // ok | fail | skip
	Detail string `json:"detail"`
}

// testCloud tries the sign-in a scan or plan would do, with the read-only
// identity (or the deploy identity when there is no separate one).
func (s *Server) testCloud(ctx context.Context, name string, c *spec.Cloud) []connCheck {
	checks := []connCheck{{Name: "Configuration", Status: "ok", Detail: "identifiers are valid"}}
	if c.Auth == "ambient" {
		return append(checks, connCheck{Name: "Sign-in", Status: "skip", Detail: "ambient credentials are checked on the runner at plan time"})
	}
	cl, err := s.discoveryClient(ctx, name, c)
	if err != nil {
		return append(checks, connCheck{Name: "Credentials", Status: "fail", Detail: err.Error()})
	}
	if c.Auth == "vault" {
		checks = append(checks, connCheck{Name: "Credentials", Status: "ok", Detail: "read from the secret store"})
	}
	pick := func(apply, plan string) string {
		if plan != "" {
			return plan
		}
		return apply
	}
	var who string
	switch c.Provider {
	case "aws":
		who = pick(c.AWS.RoleARN, c.AWS.PlanRoleARN)
		err = cl.SignInAWS(ctx, who)
	case "gcp":
		who = pick(c.GCP.ServiceAccountEmail, c.GCP.PlanServiceAccountEmail)
		err = cl.SignInGCP(ctx, c.GCP.WorkloadIdentityProvider, who)
	case "azure":
		who = pick(c.Azure.ClientID, c.Azure.PlanClientID)
		err = cl.SignInAzure(ctx, c.Azure.TenantID, who)
	}
	if err != nil {
		hint := " — check that " + who + " trusts issuer " + s.issuer.URL + " for subject " + discoverySubject(name)
		if c.Auth == "vault" {
			hint = " — check the stored credentials" + map[bool]string{true: " and that they may assume " + who, false: ""}[who != ""]
		}
		return append(checks, connCheck{Name: "Sign-in", Status: "fail", Detail: err.Error() + hint})
	}
	if who == "" {
		who = "the stored credentials"
	}
	return append(checks, connCheck{Name: "Sign-in", Status: "ok", Detail: "signed in with " + who})
}

// testConnection checks a saved connection.
func (s *Server) testConnection(w http.ResponseWriter, r *http.Request) {
	if !user(r).ManagesTenant() {
		writeErr(w, http.StatusForbidden, "testing connections needs the tenant admin or devops role")
		return
	}
	c, err := s.store.GetConnection(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	cl, err := spec.DecodeCloud(c.Cloud)
	if err != nil {
		writeErr(w, 422, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"checks": s.testCloud(r.Context(), c.Name, cl)})
}

// testNewConnection checks a connection before it is registered.
func (s *Server) testNewConnection(w http.ResponseWriter, r *http.Request) {
	if !user(r).ManagesTenant() {
		writeErr(w, http.StatusForbidden, "testing connections needs the tenant admin or devops role")
		return
	}
	var b connBody
	if !decode(w, r, &b) {
		return
	}
	cloud, ok := s.validConnection(w, &b, true)
	if !ok {
		return
	}
	cl, _ := spec.DecodeCloud(cloud)
	checks := s.testCloud(r.Context(), b.Name, cl)
	if dup := s.duplicateConnection(r.Context(), cloud, ""); dup != "" {
		checks = append(checks, connCheck{Name: "Duplicate", Status: "fail", Detail: "connection " + dup + " already points at this account"})
	}
	writeJSON(w, 200, map[string]any{"checks": checks})
}
