package central

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/httpx"
	"github.com/itsPavanFeed/srustiops-backend/internal/oidc"
	"github.com/itsPavanFeed/srustiops-backend/internal/secure"
)

// A tenant's own identity provider.
//
//	GET /api/v1/auth/discover?email=   which sign-in to offer an address (email first)
//	/auth/tenant/{tenant}/login        OIDC code flow with PKCE against the tenant's provider
//	/auth/tenant/{tenant}/callback     verifies the ID token, then has the tenant verify it
//	                                   too and issue its own session (tenant-bound session)
//
// The provider may only sign in addresses in the tenant's DNS-verified
// domains, so one tenant's provider cannot vouch for anybody else.

var tenantDomainRe = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

const challengePrefix = "_srustiops-challenge."

func (s *Server) tenantRedirect(slug string) string {
	return s.cfg.PublicURL + "/auth/tenant/" + slug + "/callback"
}

type tenantIdPView struct {
	IdP         *TenantIdP      `json:"idp"`
	Domains     []*TenantDomain `json:"domains"`
	RedirectURI string          `json:"redirect_uri"`
	SCIMURL     string          `json:"scim_url"`
	AccessSrc   string          `json:"access_source"`
	// For a SAML provider: register these at the IdP.
	ACSURL     string `json:"acs_url"`
	SPEntityID string `json:"sp_entity_id"`
}

func (s *Server) getTenantIdP(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, true)
	if t == nil {
		return
	}
	v := tenantIdPView{RedirectURI: s.tenantRedirect(t.Slug), SCIMURL: s.cfg.PublicURL + "/scim/v2/t/" + t.Slug, AccessSrc: t.AccessSource, Domains: []*TenantDomain{},
		ACSURL: s.cfg.PublicURL + "/auth/tenant/" + t.Slug + "/acs", SPEntityID: s.cfg.PublicURL + "/auth/tenant/" + t.Slug + "/saml/metadata"}
	if p, err := s.store.TenantIdP(r.Context(), t.ID); err == nil {
		v.IdP = p
	}
	if ds, err := s.store.TenantDomains(r.Context(), t.ID); err == nil {
		v.Domains = ds
	}
	httpx.WriteJSON(w, 200, v)
}

func (s *Server) putTenantIdP(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, true)
	if t == nil {
		return
	}
	if t.AccessSource != "tenant" {
		httpx.WriteErr(w, http.StatusConflict, "move access control into the tenant first: its own provider is part of tenant-controlled access")
		return
	}
	var b struct {
		Issuer       string `json:"issuer"`
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		Label        string `json:"label"`
		GroupClaim   string `json:"group_claim"`
		Enabled      bool   `json:"enabled"`
		RequireIDP   bool   `json:"require_idp"`
		// SAML instead of OIDC: the IdP's metadata (pasted or by URL) or its fields.
		Protocol       string `json:"protocol"`
		Metadata       string `json:"metadata"`
		MetadataURL    string `json:"metadata_url"`
		EntityID       string `json:"entity_id"`
		SSOURL         string `json:"sso_url"`
		CertificatePEM string `json:"certificate_pem"`
		EmailAttr      string `json:"email_attribute"`
	}
	if !httpx.Decode(w, r, &b) {
		return
	}
	if b.Protocol == "saml" {
		s.putTenantSAML(w, r, t, b.Label, b.GroupClaim, b.Enabled, b.RequireIDP,
			signInBody{Metadata: b.Metadata, MetadataURL: b.MetadataURL, EntityID: b.EntityID, SSOURL: b.SSOURL, CertificatePEM: b.CertificatePEM, EmailAttr: b.EmailAttr})
		return
	}
	if b.Protocol != "" && b.Protocol != "oidc" {
		httpx.WriteErr(w, 422, `protocol must be "oidc" or "saml"`)
		return
	}
	b.Issuer = strings.TrimRight(strings.TrimSpace(b.Issuer), "/")
	var probs []string
	devHTTP := func(u *url.URL) bool { // a local stand-in provider, in development and tests
		h := u.Hostname()
		return u.Scheme == "http" && (h == "127.0.0.1" || h == "localhost") && (s.cfg.InsecureHTTP || s.cfg.DevTrustDomains)
	}
	if u, err := url.Parse(b.Issuer); err != nil || u.Host == "" || (u.Scheme != "https" && !devHTTP(u)) {
		probs = append(probs, "issuer must be the provider's https URL")
	}
	if b.ClientID == "" {
		probs = append(probs, "client_id is required")
	}
	if b.Label = strings.TrimSpace(b.Label); b.Label == "" {
		b.Label = "Sign in with " + t.Name + " SSO"
	}
	if b.GroupClaim == "" {
		b.GroupClaim = "groups"
	}
	if len(probs) > 0 {
		httpx.WriteErr(w, 422, "invalid identity provider", probs...)
		return
	}
	entry, err := s.discoverIdP(r.Context(), b.Issuer)
	if err != nil {
		httpx.WriteErr(w, 422, "cannot use that provider: "+err.Error())
		return
	}
	// The tenant keeps its own copy of issuer and client ID and verifies every
	// ID token against them; set them there first, as the caller.
	caller, err := s.assertionPrincipal(r.Context(), current(r), sessionOf(r), t)
	if err != nil || caller == nil {
		httpx.WriteErr(w, http.StatusForbidden, "no access to this tenant")
		return
	}
	code, body, err := s.callTenantAs(r.Context(), t, caller, http.MethodGet, "/api/v1/access", nil)
	if err != nil || code != 200 {
		httpx.WriteErr(w, http.StatusBadGateway, "reading the tenant's access settings failed: "+errText(body))
		return
	}
	var cur map[string]any
	json.Unmarshal(body, &cur)
	// The client ID and secret go to the tenant, which runs the sign-in
	// itself; central keeps only what discovery and the relay need.
	settings := map[string]any{"support_access": cur["support_access"], "require_mfa": cur["require_mfa"], "max_session_hours": cur["max_session_hours"],
		"accepted_providers": cur["accepted_providers"], "idp_issuer": b.Issuer, "idp_client_id": b.ClientID, "require_idp": b.RequireIDP && b.Enabled,
		"group_claim": b.GroupClaim}
	if b.ClientSecret != "" {
		settings["idp_client_secret"] = b.ClientSecret
	}
	if code, body, err = s.callTenantAs(r.Context(), t, caller, http.MethodPut, "/api/v1/access/settings", settings); err != nil || code != 200 {
		httpx.WriteErr(w, max(code, http.StatusBadGateway), "the tenant refused the settings: "+errText(body))
		return
	}
	p := &TenantIdP{Issuer: b.Issuer, Label: b.Label, GroupClaim: b.GroupClaim, Enabled: b.Enabled, UpdatedBy: current(r).Email, EgressHosts: egressHosts(entry)}
	if err := s.store.PutTenantIdP(r.Context(), t.ID, p); err != nil {
		s.storeErr(w, err, "")
		return
	}
	s.idps.forget(t.ID)
	s.audit(r.Context(), current(r).Email, "tenant.idp_set", "tenant/"+t.Slug, t.Slug, map[string]any{"issuer": b.Issuer, "client_id": b.ClientID, "enabled": b.Enabled, "require_idp": b.RequireIDP})
	s.syncLater(t)
	s.getTenantIdP(w, r)
}

func (s *Server) deleteTenantIdP(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, true)
	if t == nil {
		return
	}
	if t.RequireIDP {
		httpx.WriteErr(w, http.StatusConflict, "the tenant requires its provider for sign-in; turn that off first")
		return
	}
	if err := s.store.DeleteTenantIdP(r.Context(), t.ID); err != nil {
		s.storeErr(w, err, "")
		return
	}
	s.idps.forget(t.ID)
	s.audit(r.Context(), current(r).Email, "tenant.idp_removed", "tenant/"+t.Slug, t.Slug, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) addTenantDomain(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, true)
	if t == nil {
		return
	}
	var b struct {
		Domain string `json:"domain"`
	}
	if !httpx.Decode(w, r, &b) {
		return
	}
	d := strings.ToLower(strings.TrimSpace(b.Domain))
	if !tenantDomainRe.MatchString(d) {
		httpx.WriteErr(w, 422, "domain must be a DNS name such as acme.com")
		return
	}
	td, err := s.store.AddTenantDomain(r.Context(), t.ID, d, "srustiops-verification="+randToken(18), current(r).Email)
	if err != nil {
		s.storeErr(w, err, "that domain is already claimed by a tenant")
		return
	}
	s.audit(r.Context(), current(r).Email, "tenant.domain_add", "domain/"+d, t.Slug, nil)
	httpx.WriteJSON(w, 201, map[string]any{"domain": td, "txt_name": challengePrefix + d, "txt_value": td.Token})
}

func (s *Server) verifyTenantDomain(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, true)
	if t == nil {
		return
	}
	d := strings.ToLower(r.PathValue("domain"))
	ds, err := s.store.TenantDomains(r.Context(), t.ID)
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	var td *TenantDomain
	for _, x := range ds {
		if x.Domain == d {
			td = x
		}
	}
	if td == nil {
		httpx.WriteErr(w, 404, "not found")
		return
	}
	ok := s.cfg.DevTrustDomains
	if !ok {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		txts, err := net.DefaultResolver.LookupTXT(ctx, challengePrefix+d)
		cancel()
		for _, v := range txts {
			ok = ok || strings.TrimSpace(v) == td.Token
		}
		if !ok {
			msg := "no TXT record " + challengePrefix + d + " with the expected value yet (DNS changes can take a while)"
			if err != nil {
				msg += ": " + err.Error()
			}
			httpx.WriteErr(w, 422, msg)
			return
		}
	}
	if err := s.store.MarkDomainVerified(r.Context(), t.ID, d); err != nil {
		s.storeErr(w, err, "")
		return
	}
	s.audit(r.Context(), current(r).Email, "tenant.domain_verified", "domain/"+d, t.Slug, map[string]bool{"dev_trusted": s.cfg.DevTrustDomains})
	s.getTenantIdP(w, r)
}

func (s *Server) deleteTenantDomain(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, true)
	if t == nil {
		return
	}
	if err := s.store.DeleteTenantDomain(r.Context(), t.ID, strings.ToLower(r.PathValue("domain"))); err != nil {
		s.storeErr(w, err, "")
		return
	}
	s.audit(r.Context(), current(r).Email, "tenant.domain_remove", "domain/"+r.PathValue("domain"), t.Slug, nil)
	w.WriteHeader(http.StatusNoContent)
}

// discover tells the login page which sign-in fits an address: the tenant's
// own provider when its domain is verified by a tenant with one, otherwise
// the platform's options.
func (s *Server) discover(w http.ResponseWriter, r *http.Request) {
	email := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("email")))
	at := strings.LastIndexByte(email, '@')
	res := map[string]any{"mode": "platform"}
	if at > 0 {
		if t, err := s.store.TenantByDomain(r.Context(), email[at+1:]); err == nil {
			if p, err := s.store.TenantIdP(r.Context(), t.ID); err == nil && p.Enabled {
				res = map[string]any{"mode": "tenant", "tenant": map[string]string{"slug": t.Slug, "name": t.Name}, "label": p.Label,
					"login": "/auth/tenant/" + t.Slug + "/login?login_hint=" + url.QueryEscape(email)}
			}
		}
		// An enterprise provider (Platform → Sign-in) that owns the domain.
		if res["mode"] == "platform" {
			if ps, err := s.store.SignInProviders(r.Context()); err == nil {
				for _, p := range ps {
					if p.Enabled && contains(p.AllowedDomains, email[at+1:]) {
						res = map[string]any{"mode": "provider", "label": p.Label, "login": "/auth/" + p.Kind + "/" + p.ID + "/login?login_hint=" + url.QueryEscape(email)}
						break
					}
				}
			}
		}
	}
	httpx.WriteJSON(w, 200, res)
}

// ---- the sign-in flow ----

type idpCache struct {
	mu sync.Mutex
	m  map[string]*idpEntry
}

type idpEntry struct {
	issuer, authURL, tokenURL, jwksURL string
	verifier                           *oidc.Verifier
	fetched                            time.Time
}

func (c *idpCache) forget(tenantID string) {
	c.mu.Lock()
	delete(c.m, tenantID)
	c.mu.Unlock()
}

func (s *Server) discoverIdP(ctx context.Context, issuer string) (*idpEntry, error) {
	hc := &http.Client{Timeout: 10 * time.Second}
	get := func(u string, v any) error {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		resp, err := hc.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return fmt.Errorf("%s returned %s", u, resp.Status)
		}
		return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(v)
	}
	var doc struct {
		Issuer   string `json:"issuer"`
		AuthURL  string `json:"authorization_endpoint"`
		TokenURL string `json:"token_endpoint"`
		JWKSURI  string `json:"jwks_uri"`
	}
	if err := get(issuer+"/.well-known/openid-configuration", &doc); err != nil {
		return nil, err
	}
	if strings.TrimRight(doc.Issuer, "/") != issuer {
		return nil, errors.New("discovery document names another issuer")
	}
	var jwks json.RawMessage
	if err := get(doc.JWKSURI, &jwks); err != nil {
		return nil, err
	}
	v, err := oidc.NewVerifier(issuer, jwks)
	if err != nil {
		return nil, err
	}
	return &idpEntry{issuer: issuer, authURL: doc.AuthURL, tokenURL: doc.TokenURL, jwksURL: doc.JWKSURI, verifier: v, fetched: time.Now()}, nil
}

// egressHosts: the host:port pairs the tenant's sign-in calls (discovery,
// token, keys), which the link's egress relay may reach for it.
func egressHosts(e *idpEntry) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, raw := range []string{e.issuer, e.tokenURL, e.jwksURL} {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			continue
		}
		port := u.Port()
		if port == "" {
			port = map[string]string{"https": "443", "http": "80"}[u.Scheme]
		}
		h := u.Hostname() + ":" + port
		if !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	return out
}

// tenantLogin starts a sign-in with a tenant's own provider. The tenant
// creates the state, nonce and PKCE verifier and keeps them; central only
// redirects the browser.
func (s *Server) tenantLogin(w http.ResponseWriter, r *http.Request) {
	t, err := s.store.Tenant(r.Context(), r.PathValue("tenant"))
	if err != nil {
		s.ssoFail(w, r, "no_access")
		return
	}
	if p, err := s.store.TenantIdP(r.Context(), t.ID); err != nil || !p.Enabled {
		s.ssoFail(w, r, "tenant_idp_off")
		return
	}
	p, _ := s.store.TenantIdP(r.Context(), t.ID)
	start, site := "/api/v1/access/oidc/start", http.SameSiteLaxMode
	if p.Protocol == "saml" {
		start, site = "/api/v1/access/saml/start", http.SameSiteNoneMode // the IdP posts back cross-site
	}
	code, body, err := s.callTenantAs(r.Context(), t, s.system(t), http.MethodPost, start,
		map[string]string{"redirect_uri": s.tenantRedirect(t.Slug), "login_hint": r.URL.Query().Get("login_hint")})
	if err != nil {
		s.ssoFail(w, r, "tenant_offline")
		return
	}
	var st struct {
		AuthorizeURL string `json:"authorize_url"`
		State        string `json:"state"`
	}
	if code != 200 || json.Unmarshal(body, &st) != nil || st.State == "" {
		s.log.Warn("tenant could not start a sign-in", "tenant", t.Slug, "code", code, "body", trim(string(body), 200))
		s.ssoFail(w, r, "provider_unavailable")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: stateCookie, Value: st.State, Path: "/auth", MaxAge: int(flowTTL.Seconds()),
		HttpOnly: true, Secure: !s.cfg.InsecureHTTP, SameSite: site})
	http.Redirect(w, r, st.AuthorizeURL, http.StatusFound)
}

// tenantCallback passes the code to the tenant without redeeming it: the
// tenant redeems it with its own credentials and verifier, verifies the ID
// token, and tells central who signed in.
func (s *Server) tenantCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t, err := s.store.Tenant(ctx, r.PathValue("tenant"))
	if err != nil {
		s.ssoFail(w, r, "no_access")
		return
	}
	state := r.URL.Query().Get("state")
	c, err := r.Cookie(stateCookie)
	http.SetCookie(w, &http.Cookie{Name: stateCookie, Value: "", Path: "/auth", MaxAge: -1, HttpOnly: true, Secure: !s.cfg.InsecureHTTP, SameSite: http.SameSiteLaxMode})
	if err != nil || state == "" || c.Value != state {
		s.ssoFail(w, r, "state_mismatch")
		return
	}
	if e := r.URL.Query().Get("error"); e != "" {
		s.ssoFail(w, r, "idp_"+e)
		return
	}
	code, body, err := s.callTenantAs(ctx, t, s.system(t), http.MethodPost, "/api/v1/access/oidc/finish",
		map[string]string{"state": state, "code": r.URL.Query().Get("code")})
	if err != nil {
		s.ssoFail(w, r, "tenant_offline")
		return
	}
	s.finishTenantSignIn(w, r, t, code, body)
}

// tenantACS receives a SAML response for a tenant's own provider and has the
// tenant verify it (central does not): the tenant then issues its session.
func (s *Server) tenantACS(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t, err := s.store.Tenant(ctx, r.PathValue("tenant"))
	if err != nil {
		s.ssoFail(w, r, "no_access")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	if err := r.ParseForm(); err != nil || r.PostForm.Get("SAMLResponse") == "" || r.Form.Get("SAMLart") != "" {
		s.ssoFail(w, r, "invalid_token")
		return
	}
	state := r.PostForm.Get("RelayState")
	if c, err := r.Cookie(stateCookie); err == nil && c.Value != state {
		s.ssoFail(w, r, "state_mismatch")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: stateCookie, Value: "", Path: "/auth", MaxAge: -1, HttpOnly: true, Secure: !s.cfg.InsecureHTTP, SameSite: http.SameSiteNoneMode})
	if state == "" {
		s.ssoFail(w, r, "expired")
		return
	}
	code, body, err := s.callTenantAs(ctx, t, s.system(t), http.MethodPost, "/api/v1/access/saml/finish",
		map[string]string{"state": state, "saml_response": r.PostForm.Get("SAMLResponse")})
	if err != nil {
		s.ssoFail(w, r, "tenant_offline")
		return
	}
	s.finishTenantSignIn(w, r, t, code, body)
}

// tenantSAMLMetadata serves a tenant's service-provider metadata (made by the tenant).
func (s *Server) tenantSAMLMetadata(w http.ResponseWriter, r *http.Request) {
	t, err := s.store.Tenant(r.Context(), r.PathValue("tenant"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	code, body, err := s.callTenantAs(r.Context(), t, s.system(t), http.MethodGet, "/api/v1/access/saml/metadata", nil)
	if err != nil || code != 200 {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Write(body)
}

// finishTenantSignIn turns the tenant's verdict into a central session code.
func (s *Server) finishTenantSignIn(w http.ResponseWriter, r *http.Request, t *Tenant, code int, body []byte) {
	ctx := r.Context()
	var who struct {
		Session  string   `json:"session"`
		Email    string   `json:"email"`
		Verified bool     `json:"email_verified"`
		Issuer   string   `json:"issuer"`
		Subject  string   `json:"subject"`
		AMR      []string `json:"amr"`
	}
	if code != 200 || json.Unmarshal(body, &who) != nil || who.Session == "" || who.Subject == "" || !who.Verified {
		s.log.Warn("tenant refused the sign-in", "tenant", t.Slug, "code", code, "body", trim(string(body), 200))
		s.ssoFail(w, r, "tenant_refused")
		return
	}
	email := strings.ToLower(strings.TrimSpace(who.Email))
	// The tenant's provider vouches only for the tenant's own domains.
	at := strings.LastIndexByte(email, '@')
	owner, err := s.store.TenantByDomain(ctx, email[at+1:])
	if at < 0 || err != nil || owner.ID != t.ID {
		s.audit(ctx, "sso:"+email, "auth.sso_denied", "user/"+email, t.Slug, map[string]string{"provider": "tenant:" + t.Slug, "reason": "domain not verified by this tenant"})
		s.ssoFail(w, r, "domain_not_allowed")
		return
	}
	u, err := s.store.EnsureUser(ctx, email, "", false, "sso:tenant:"+t.Slug)
	if err != nil || u.DisabledAt != nil {
		s.ssoFail(w, r, "no_access")
		return
	}
	if u.PlatformRoot {
		s.ssoFail(w, r, "root_uses_recovery_token")
		return
	}
	sess := &AuthSession{IDP: "tenant:" + t.Slug, UserIssuer: who.Issuer, UserSubject: who.Subject, EmailVerified: true, AMR: who.AMR, TenantID: t.ID, TenantSession: who.Session}
	codeStr := randToken(32)
	if err := s.store.CreateAuthCodeWith(ctx, secure.HashToken(codeStr), u.ID, codeTTL, sess); err != nil {
		s.ssoFail(w, r, "internal")
		return
	}
	s.audit(ctx, u.Email, "auth.sso_login", "user/"+u.Email, t.Slug, map[string]any{"provider": "tenant:" + t.Slug, "issuer": who.Issuer, "subject": who.Subject})
	http.Redirect(w, r, "/#/sso/"+codeStr, http.StatusFound)
}

// putTenantSAML saves a SAML provider for a tenant: the tenant keeps the
// metadata and verifies every assertion with it; central keeps the label and
// the entity ID for discovery.
func (s *Server) putTenantSAML(w http.ResponseWriter, r *http.Request, t *Tenant, label, groupClaim string, enabled, requireIDP bool, b signInBody) {
	c, prob := s.samlConfigFrom(r.Context(), b)
	if prob != "" {
		httpx.WriteErr(w, 422, "invalid identity provider", prob)
		return
	}
	if label = strings.TrimSpace(label); label == "" {
		label = "Sign in with " + t.Name + " SSO"
	}
	if groupClaim == "" {
		groupClaim = "groups"
	}
	caller, err := s.assertionPrincipal(r.Context(), current(r), sessionOf(r), t)
	if err != nil || caller == nil {
		httpx.WriteErr(w, http.StatusForbidden, "no access to this tenant")
		return
	}
	code, body, err := s.callTenantAs(r.Context(), t, caller, http.MethodGet, "/api/v1/access", nil)
	if err != nil || code != 200 {
		httpx.WriteErr(w, http.StatusBadGateway, "reading the tenant's access settings failed: "+errText(body))
		return
	}
	var cur map[string]any
	json.Unmarshal(body, &cur)
	settings := map[string]any{"support_access": cur["support_access"], "require_mfa": cur["require_mfa"], "max_session_hours": cur["max_session_hours"],
		"accepted_providers": cur["accepted_providers"], "require_idp": requireIDP && enabled, "group_claim": groupClaim,
		"idp_protocol": "saml", "idp_saml_metadata": c.Metadata, "idp_saml_email_attribute": c.EmailAttr}
	if code, body, err = s.callTenantAs(r.Context(), t, caller, http.MethodPut, "/api/v1/access/settings", settings); err != nil || code != 200 {
		httpx.WriteErr(w, max(code, http.StatusBadGateway), "the tenant refused the settings: "+errText(body))
		return
	}
	p := &TenantIdP{Issuer: c.EntityID, Label: label, GroupClaim: groupClaim, Enabled: enabled, UpdatedBy: current(r).Email, Protocol: "saml"}
	if err := s.store.PutTenantIdP(r.Context(), t.ID, p); err != nil {
		s.storeErr(w, err, "")
		return
	}
	s.idps.forget(t.ID)
	s.audit(r.Context(), current(r).Email, "tenant.idp_set", "tenant/"+t.Slug, t.Slug, map[string]any{"protocol": "saml", "entity_id": c.EntityID, "sso_url": c.SSOURL, "enabled": enabled, "require_idp": requireIDP})
	s.syncLater(t)
	s.getTenantIdP(w, r)
}
