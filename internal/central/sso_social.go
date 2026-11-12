package central

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/cloudapi"
	"github.com/itsPavanFeed/srustiops-backend/internal/httpx"
	"github.com/itsPavanFeed/srustiops-backend/internal/oidc"
	"github.com/itsPavanFeed/srustiops-backend/internal/secure"
)

// Google and GitHub sign-in, configured by a platform admin.
//
//	Google  OpenID Connect, authorization code with PKCE; the ID token's
//	        signature, issuer, audience, expiry and nonce are verified and the
//	        email must be verified. Allowed domains match the email's domain.
//	GitHub  OAuth with PKCE (GitHub issues no ID token); the primary verified
//	        email comes from the API. Allowed organisations need active membership.
//
// Both end in the same place as the generic OIDC flow: an existing, enabled
// user with that email gets a one-time code for a session. Access still comes
// from roles granted in SrustiOps.

const googleIssuer = "https://accounts.google.com"

var (
	googleClientRe = regexp.MustCompile(`^[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com$`)
	githubClientRe = regexp.MustCompile(`^[A-Za-z0-9._-]{8,64}$`)
	domainRe       = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
	ghOrgRe        = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,37}[A-Za-z0-9])?$`)
)

var providerLabels = map[string]string{"google": "Sign in with Google", "github": "Sign in with GitHub"}

func ssoAAD(id string) []byte { return []byte("sso-provider:" + id) }

func (s *Server) ssoClient() *http.Client {
	return cloudapi.Redirected(&http.Client{Timeout: 15 * time.Second}, s.cfg.SSOTestURL)
}

func (s *Server) redirectURI(id string) string {
	return strings.TrimRight(s.cfg.PublicURL, "/") + "/auth/callback/" + id
}

// enabledProvider loads a configured, enabled provider with its secret.
func (s *Server) enabledProvider(ctx context.Context, id string) (string, string, []string, []string, error) {
	p, err := s.store.SSOProvider(ctx, id)
	if err != nil || !p.Enabled {
		return "", "", nil, nil, errors.New("not configured")
	}
	sealer, err := s.sealer()
	if err != nil {
		return "", "", nil, nil, err
	}
	secret, err := sealer.Open(p.ClientSecret, ssoAAD(id))
	if err != nil {
		return "", "", nil, nil, errors.New("the client secret cannot be decrypted")
	}
	return p.ClientID, string(secret), p.AllowedDomains, p.AllowedOrgs, nil
}

// googleDiscovery loads (and caches) Google's endpoints and keys.
func (s *Server) googleDiscovery(ctx context.Context, refresh bool) (*oidcProvider, error) {
	p := &s.google
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.verifier != nil && !refresh && time.Since(p.fetched) < discoveryCache {
		return p, nil
	}
	hc := s.ssoClient()
	get := func(u string, v any) error {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		resp, err := hc.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
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
	if err := get(googleIssuer+"/.well-known/openid-configuration", &doc); err != nil {
		return nil, err
	}
	if doc.Issuer != googleIssuer {
		return nil, errors.New("unexpected issuer in Google's discovery document")
	}
	var jwks json.RawMessage
	if err := get(doc.JWKSURI, &jwks); err != nil {
		return nil, err
	}
	v, err := oidc.NewVerifier(googleIssuer, jwks)
	if err != nil {
		return nil, err
	}
	// Google also issues tokens with the bare host as issuer.
	alt, err := oidc.NewVerifier("accounts.google.com", jwks)
	if err != nil {
		return nil, err
	}
	p.authURL, p.tokenURL, p.verifier, p.alt, p.fetched = doc.AuthURL, doc.TokenURL, v, alt, time.Now()
	return p, nil
}

// socialLogin starts a Google or GitHub sign-in.
func (s *Server) socialLogin(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("provider")
	clientID, _, _, orgs, err := s.enabledProvider(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	state, verifier, nonce := randToken(24), randToken(32), randToken(24)
	if err := s.store.CreateAuthFlow(r.Context(), id, state, verifier, nonce); err != nil {
		s.storeErr(w, err, "")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: stateCookie, Value: state, Path: "/auth", MaxAge: int(flowTTL.Seconds()),
		HttpOnly: true, Secure: !s.cfg.InsecureHTTP, SameSite: http.SameSiteLaxMode})
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"client_id": {clientID}, "redirect_uri": {s.redirectURI(id)}, "state": {state},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
	}
	var auth string
	switch id {
	case "google":
		p, err := s.googleDiscovery(r.Context(), false)
		if err != nil {
			s.log.Error("Google sign-in unavailable", "err", err)
			s.ssoFail(w, r, "provider_unavailable")
			return
		}
		q.Set("response_type", "code")
		q.Set("scope", "openid email profile")
		q.Set("nonce", nonce)
		q.Set("prompt", "select_account")
		auth = p.authURL
	case "github":
		scope := "read:user user:email"
		if len(orgs) > 0 {
			scope += " read:org"
		}
		q.Set("scope", scope)
		q.Set("allow_signup", "false")
		auth = "https://github.com/login/oauth/authorize"
	}
	sep := "?"
	if strings.Contains(auth, "?") {
		sep = "&"
	}
	http.Redirect(w, r, auth+sep+q.Encode(), http.StatusFound)
}

// socialCallback finishes a Google or GitHub sign-in.
func (s *Server) socialCallback(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("provider")
	ctx := r.Context()
	clientID, secret, domains, orgs, err := s.enabledProvider(ctx, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	state := r.URL.Query().Get("state")
	c, cerr := r.Cookie(stateCookie)
	http.SetCookie(w, &http.Cookie{Name: stateCookie, Value: "", Path: "/auth", MaxAge: -1, HttpOnly: true, Secure: !s.cfg.InsecureHTTP, SameSite: http.SameSiteLaxMode})
	if cerr != nil || state == "" || c.Value != state {
		s.ssoFail(w, r, "state_mismatch")
		return
	}
	if e := r.URL.Query().Get("error"); e != "" {
		s.ssoFail(w, r, "idp_"+e)
		return
	}
	verifier, nonce, err := s.store.TakeAuthFlow(ctx, id, state, flowTTL)
	if err != nil {
		s.ssoFail(w, r, "expired")
		return
	}
	code := r.URL.Query().Get("code")
	var email, issuer, subject string
	switch id {
	case "google":
		email, subject, err = s.googleEmail(ctx, clientID, secret, code, verifier, nonce)
		issuer = googleIssuer
	case "github":
		email, subject, err = s.githubEmail(ctx, clientID, secret, code, verifier, orgs)
		issuer = "https://github.com"
	}
	if err != nil {
		var f ssoFailure
		if errors.As(err, &f) {
			s.audit(ctx, "sso:"+id, "auth.sso_denied", "user/"+email, "", map[string]string{"provider": id, "reason": string(f)})
			s.ssoFail(w, r, string(f))
			return
		}
		s.log.Warn("sign-in failed", "provider", id, "err", err)
		s.ssoFail(w, r, "token_exchange")
		return
	}
	s.finishSSO(w, r, id, email, domains, issuer, subject, true)
}

// ssoFailure is a reason shown to the person (and audited).
type ssoFailure string

func (f ssoFailure) Error() string { return string(f) }

func (s *Server) googleEmail(ctx context.Context, clientID, secret, code, verifier, nonce string) (email, subject string, err error) {
	p, err := s.googleDiscovery(ctx, false)
	if err != nil {
		return "", "", err
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {s.redirectURI("google")},
		"client_id": {clientID}, "client_secret": {secret}, "code_verifier": {verifier}}
	var tok struct {
		IDToken string `json:"id_token"`
	}
	if err := s.postForm(ctx, p.tokenURL, form, &tok); err != nil || tok.IDToken == "" {
		return "", "", fmt.Errorf("token exchange: %v", err)
	}
	verify := func(p *oidcProvider) (map[string]any, error) {
		claims, err := p.verifier.Verify(tok.IDToken, clientID, time.Now())
		if err != nil && p.alt != nil {
			if c2, err2 := p.alt.Verify(tok.IDToken, clientID, time.Now()); err2 == nil {
				return c2, nil
			}
		}
		return claims, err
	}
	claims, err := verify(p)
	if err != nil && err.Error() == "unknown signing key" { // Google rotated its keys
		if p, err2 := s.googleDiscovery(ctx, true); err2 == nil {
			claims, err = verify(p)
		}
	}
	if err != nil || claims["nonce"] != nonce {
		return "", "", ssoFailure("invalid_token")
	}
	email, _ = claims["email"].(string)
	email = strings.ToLower(strings.TrimSpace(email))
	subject, _ = claims["sub"].(string)
	if verified, _ := claims["email_verified"].(bool); email == "" || !verified {
		return email, subject, ssoFailure("email_not_verified")
	}
	return email, subject, nil
}

func (s *Server) githubEmail(ctx context.Context, clientID, secret, code, verifier string, orgs []string) (string, string, error) {
	form := url.Values{"client_id": {clientID}, "client_secret": {secret}, "code": {code}, "redirect_uri": {s.redirectURI("github")}, "code_verifier": {verifier}}
	var tok struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := s.postForm(ctx, "https://github.com/login/oauth/access_token", form, &tok); err != nil || tok.AccessToken == "" {
		return "", "", fmt.Errorf("token exchange: %v %s", err, tok.Error)
	}
	api := func(path string, v any) (int, error) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com"+path, nil)
		req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		resp, err := s.ssoClient().Do(req)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return resp.StatusCode, nil
		}
		return 200, json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(v)
	}
	var who struct {
		Login string `json:"login"`
		ID    int64  `json:"id"`
	}
	if code, err := api("/user", &who); err != nil || code != 200 {
		return "", "", fmt.Errorf("reading the GitHub user: %v (HTTP %d)", err, code)
	}
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if code, err := api("/user/emails", &emails); err != nil || code != 200 {
		return "", who.Login, fmt.Errorf("reading the GitHub user's emails: %v (HTTP %d)", err, code)
	}
	email := ""
	for _, e := range emails {
		if e.Primary && e.Verified {
			email = strings.ToLower(strings.TrimSpace(e.Email))
		}
	}
	if email == "" {
		return "", who.Login, ssoFailure("email_not_verified")
	}
	for _, org := range orgs {
		var m struct {
			State string `json:"state"`
		}
		if code, err := api("/user/memberships/orgs/"+url.PathEscape(org), &m); err == nil && code == 200 && m.State == "active" {
			return email, strconv.FormatInt(who.ID, 10), nil
		}
	}
	if len(orgs) > 0 {
		return email, strconv.FormatInt(who.ID, 10), ssoFailure("org_not_allowed")
	}
	return email, strconv.FormatInt(who.ID, 10), nil
}

func (s *Server) postForm(ctx context.Context, u string, form url.Values, out any) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := s.ssoClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned %s", u, resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// finishSSO maps an authenticated email to an existing, enabled user and
// hands the browser a one-time code for a session (every provider ends here).
func (s *Server) finishSSO(w http.ResponseWriter, r *http.Request, provider, email string, domains []string, issuer, subject string, verified bool, amr ...[]string) {
	ctx := r.Context()
	at := strings.LastIndexByte(email, '@')
	if len(domains) > 0 && (at < 0 || !contains(domains, email[at+1:])) || !s.domainAllowed(email) {
		s.audit(ctx, "sso:"+email, "auth.sso_denied", "user/"+email, "", map[string]string{"provider": provider, "reason": "domain not allowed"})
		s.ssoFail(w, r, "domain_not_allowed")
		return
	}
	u, err := s.store.UserByEmail(ctx, email)
	if err != nil || u.DisabledAt != nil {
		s.audit(ctx, "sso:"+email, "auth.sso_denied", "user/"+email, "", map[string]string{"provider": provider, "reason": "no such user or disabled"})
		s.ssoFail(w, r, "no_access")
		return
	}
	if u.PlatformRoot {
		// The recovery account has exactly one credential, its root token.
		s.audit(ctx, "sso:"+email, "auth.sso_denied", "user/"+email, "", map[string]string{"provider": provider, "reason": "platform root"})
		s.ssoFail(w, r, "root_uses_recovery_token")
		return
	}
	code := randToken(32)
	if subject == "" {
		s.ssoFail(w, r, "invalid_token")
		return
	}
	sess := &AuthSession{IDP: provider, UserIssuer: issuer, UserSubject: subject, EmailVerified: verified}
	if len(amr) > 0 {
		sess.AMR = amr[0]
	}
	if err := s.store.CreateAuthCodeWith(ctx, secure.HashToken(code), u.ID, codeTTL, sess); err != nil {
		s.ssoFail(w, r, "internal")
		return
	}
	s.audit(ctx, u.Email, "auth.sso_login", "user/"+u.Email, "", map[string]string{"provider": provider, "issuer": issuer, "subject": subject})
	http.Redirect(w, r, "/#/sso/"+code, http.StatusFound)
}

// ---- configuration (platform admins) ----

type ssoProviderView struct {
	ID             string     `json:"id"`
	Label          string     `json:"label"`
	Configured     bool       `json:"configured"`
	Enabled        bool       `json:"enabled"`
	ClientID       string     `json:"client_id,omitempty"`
	SecretSet      bool       `json:"client_secret_set"`
	AllowedDomains []string   `json:"allowed_domains"`
	AllowedOrgs    []string   `json:"allowed_orgs"`
	RedirectURI    string     `json:"redirect_uri"`
	UpdatedBy      string     `json:"updated_by,omitempty"`
	UpdatedAt      *time.Time `json:"updated_at,omitempty"`
}

func (s *Server) listSSOProviders(w http.ResponseWriter, r *http.Request) {
	if !current(r).PlatformAdmin {
		httpx.WriteErr(w, http.StatusForbidden, "only platform admins configure sign-in")
		return
	}
	ps, err := s.store.ListSSOProviders(r.Context())
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	by := map[string]*ssoProviderView{}
	for _, p := range ps {
		t := p.UpdatedAt
		by[p.ID] = &ssoProviderView{ID: p.ID, Configured: true, Enabled: p.Enabled, ClientID: p.ClientID, SecretSet: len(p.ClientSecret) > 0,
			AllowedDomains: p.AllowedDomains, AllowedOrgs: p.AllowedOrgs, UpdatedBy: p.UpdatedBy, UpdatedAt: &t}
	}
	out := []*ssoProviderView{}
	for _, id := range []string{"google", "github"} {
		v := by[id]
		if v == nil {
			v = &ssoProviderView{ID: id, AllowedDomains: []string{}, AllowedOrgs: []string{}}
		}
		v.Label, v.RedirectURI = providerLabels[id], s.redirectURI(id)
		out = append(out, v)
	}
	httpx.WriteJSON(w, 200, map[string]any{"providers": out, "generic_oidc": s.cfg.OIDCIssuer != ""})
}

func (s *Server) putSSOProvider(w http.ResponseWriter, r *http.Request) {
	if !current(r).PlatformAdmin {
		httpx.WriteErr(w, http.StatusForbidden, "only platform admins configure sign-in")
		return
	}
	id := r.PathValue("provider")
	if providerLabels[id] == "" {
		httpx.WriteErr(w, http.StatusNotFound, "unknown provider "+id)
		return
	}
	var b struct {
		ClientID       string   `json:"client_id"`
		ClientSecret   string   `json:"client_secret"` // empty keeps the stored secret
		AllowedDomains []string `json:"allowed_domains"`
		AllowedOrgs    []string `json:"allowed_orgs"`
		Enabled        *bool    `json:"enabled"`
	}
	if !httpx.Decode(w, r, &b) {
		return
	}
	var probs []string
	b.ClientID = strings.TrimSpace(b.ClientID)
	if id == "google" && !googleClientRe.MatchString(b.ClientID) {
		probs = append(probs, "client_id must be a Google OAuth client ID (…apps.googleusercontent.com)")
	}
	if id == "github" && !githubClientRe.MatchString(b.ClientID) {
		probs = append(probs, "client_id must be the GitHub OAuth app's client ID")
	}
	cur, curErr := s.store.SSOProvider(r.Context(), id)
	if b.ClientSecret == "" && (curErr != nil || len(cur.ClientSecret) == 0) {
		probs = append(probs, "client_secret is required")
	} else if b.ClientSecret != "" && (len(b.ClientSecret) < 10 || len(b.ClientSecret) > 256 || strings.ContainsAny(b.ClientSecret, " \n\t")) {
		probs = append(probs, "client_secret must be 10-256 characters without spaces")
	}
	domains := []string{}
	for _, d := range b.AllowedDomains {
		if d = strings.ToLower(strings.TrimSpace(d)); d == "" {
			continue
		} else if !domainRe.MatchString(d) {
			probs = append(probs, "not a domain: "+d)
		} else {
			domains = append(domains, d)
		}
	}
	orgs := []string{}
	for _, o := range b.AllowedOrgs {
		if o = strings.TrimSpace(o); o == "" {
			continue
		} else if id != "github" {
			probs = append(probs, "allowed organisations apply to GitHub only")
			break
		} else if !ghOrgRe.MatchString(o) {
			probs = append(probs, "not a GitHub organisation name: "+o)
		} else {
			orgs = append(orgs, o)
		}
	}
	if len(probs) > 0 {
		httpx.WriteErr(w, 422, "invalid sign-in settings", probs...)
		return
	}
	var sealed []byte
	if b.ClientSecret != "" {
		sealer, err := s.sealer()
		if err == nil {
			sealed, err = sealer.Seal([]byte(b.ClientSecret), ssoAAD(id))
		}
		if err != nil {
			s.storeErr(w, err, "")
			return
		}
	}
	enabled := true
	if b.Enabled != nil {
		enabled = *b.Enabled
	}
	if err := s.store.PutSSOProvider(r.Context(), &SSOProvider{ID: id, ClientID: b.ClientID, ClientSecret: sealed, AllowedDomains: domains, AllowedOrgs: orgs, Enabled: enabled, UpdatedBy: current(r).Email}); err != nil {
		s.storeErr(w, err, "")
		return
	}
	s.audit(r.Context(), current(r).Email, "auth.provider.configure", "sso/"+id, "", map[string]any{"client_id": b.ClientID, "secret_changed": b.ClientSecret != "", "allowed_domains": domains, "allowed_orgs": orgs, "enabled": enabled})
	s.listSSOProviders(w, r)
}

func (s *Server) deleteSSOProvider(w http.ResponseWriter, r *http.Request) {
	if !current(r).PlatformAdmin {
		httpx.WriteErr(w, http.StatusForbidden, "only platform admins configure sign-in")
		return
	}
	id := r.PathValue("provider")
	if err := s.store.DeleteSSOProvider(r.Context(), id); err != nil {
		s.storeErr(w, err, "")
		return
	}
	s.audit(r.Context(), current(r).Email, "auth.provider.remove", "sso/"+id, "", nil)
	w.WriteHeader(http.StatusNoContent)
}

// enabledProviders lists the sign-in buttons for the login page.
func (s *Server) enabledProviders(ctx context.Context) []map[string]string {
	out := []map[string]string{}
	ps, err := s.store.ListSSOProviders(ctx)
	if err != nil {
		return out
	}
	for _, p := range ps {
		if p.Enabled && len(p.ClientSecret) > 0 {
			out = append(out, map[string]string{"id": p.ID, "label": providerLabels[p.ID], "login": "/auth/login/" + p.ID})
		}
	}
	return out
}
