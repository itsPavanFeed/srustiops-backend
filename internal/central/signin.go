package central

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/crewjam/saml"
	"github.com/jackc/pgx/v5"

	"github.com/itsPavanFeed/srustiops-backend/internal/httpx"
	"github.com/itsPavanFeed/srustiops-backend/internal/store"
)

// ---- enterprise sign-in: OpenID Connect and SAML providers ----
//
// Platform admins add any number of OIDC providers (Okta, Entra ID, Ping,
// Keycloak, Auth0) and SAML 2.0 identity providers under Platform → Sign-in.
// Each becomes a button on the sign-in page, and ends where every provider
// ends (finishSSO): an existing, enabled person with that email gets a
// session. Access still comes from roles granted in SrustiOps.
//
//	OIDC  /auth/oidc/{id}/login → /auth/oidc/{id}/callback: code flow with
//	      PKCE and nonce; the ID token's signature, issuer, audience and expiry
//	      are verified and its email must be verified.
//	SAML  /auth/saml/{id}/login → (IdP) → POST /auth/saml/{id}/acs: an
//	      SP-initiated AuthnRequest (HTTP-Redirect); the Response must be signed
//	      by the IdP's certificate, answer that very request (InResponseTo, so it
//	      cannot be replayed or sent unasked), be addressed to us and be current.
//	      /auth/saml/{id}/metadata is our service-provider metadata.

var providerIDRe = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)

type SignInProvider struct {
	ID             string          `json:"id"`
	Kind           string          `json:"kind"` // oidc | saml
	Label          string          `json:"label"`
	Config         json.RawMessage `json:"config"`
	Secret         []byte          `json:"-"`
	AllowedDomains []string        `json:"allowed_domains"`
	Enabled        bool            `json:"enabled"`
	UpdatedBy      string          `json:"updated_by"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

type oidcConfig struct {
	Issuer   string `json:"issuer"`
	ClientID string `json:"client_id"`
	Scopes   string `json:"scopes,omitempty"`
}

type samlConfig struct {
	Metadata    string `json:"metadata"` // the IdP's metadata XML (pasted, fetched, or built from the fields)
	EntityID    string `json:"entity_id"`
	SSOURL      string `json:"sso_url"`
	EmailAttr   string `json:"email_attribute,omitempty"` // "" = NameID, then the usual email attributes
	MetadataURL string `json:"metadata_url,omitempty"`
}

const signInCols = `id, kind, label, config, secret, allowed_domains, enabled, updated_by, updated_at`

func scanSignIn(r pgx.Row) (*SignInProvider, error) {
	var p SignInProvider
	err := r.Scan(&p.ID, &p.Kind, &p.Label, &p.Config, &p.Secret, &p.AllowedDomains, &p.Enabled, &p.UpdatedBy, &p.UpdatedAt)
	return &p, store.NotFound(err)
}

func (s *Store) SignInProviders(ctx context.Context) ([]*SignInProvider, error) {
	rows, err := s.Pool().Query(ctx, `SELECT `+signInCols+` FROM sign_in_providers ORDER BY label`)
	if err != nil {
		return nil, err
	}
	return store.Collect(rows, scanSignIn)
}

func (s *Store) SignInProvider(ctx context.Context, kind, id string) (*SignInProvider, error) {
	return scanSignIn(s.Pool().QueryRow(ctx, `SELECT `+signInCols+` FROM sign_in_providers WHERE id = $1 AND kind = $2`, id, kind))
}

func (s *Store) PutSignInProvider(ctx context.Context, p *SignInProvider) error {
	_, err := s.Pool().Exec(ctx, `INSERT INTO sign_in_providers (id, kind, label, config, secret, allowed_domains, enabled, updated_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (id) DO UPDATE SET label = EXCLUDED.label, config = EXCLUDED.config, secret = COALESCE(EXCLUDED.secret, sign_in_providers.secret),
		allowed_domains = EXCLUDED.allowed_domains, enabled = EXCLUDED.enabled, updated_by = EXCLUDED.updated_by, updated_at = now()
		WHERE sign_in_providers.kind = EXCLUDED.kind`, p.ID, p.Kind, p.Label, p.Config, p.Secret, p.AllowedDomains, p.Enabled, p.UpdatedBy)
	return err
}

func (s *Store) DeleteSignInProvider(ctx context.Context, id string) error {
	tag, err := s.Pool().Exec(ctx, `DELETE FROM sign_in_providers WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func signInAAD(id string) []byte { return []byte("sign-in-provider:" + id) }

// allowedURL: https, or http to this machine (development and tests).
func allowedURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	h := u.Hostname()
	ip := net.ParseIP(h)
	return u.Scheme == "http" && (h == "localhost" || (ip != nil && ip.IsLoopback()))
}

// ---- OIDC ----

var oidcCache = struct {
	sync.Mutex
	m map[string]*idpEntry
}{m: map[string]*idpEntry{}}

func (s *Server) oidcEndpoints(ctx context.Context, id, issuer string, refresh bool) (*idpEntry, error) {
	oidcCache.Lock()
	e := oidcCache.m[id]
	oidcCache.Unlock()
	if e != nil && e.issuer == issuer && !refresh && time.Since(e.fetched) < discoveryCache {
		return e, nil
	}
	e, err := s.discoverIdP(ctx, issuer)
	if err != nil {
		return nil, err
	}
	oidcCache.Lock()
	oidcCache.m[id] = e
	oidcCache.Unlock()
	return e, nil
}

func (s *Server) oidcRedirect(id string) string {
	return strings.TrimRight(s.cfg.PublicURL, "/") + "/auth/oidc/" + id + "/callback"
}

func (s *Server) enterpriseProvider(r *http.Request, kind string) (*SignInProvider, bool) {
	p, err := s.store.SignInProvider(r.Context(), kind, r.PathValue("id"))
	return p, err == nil && p.Enabled
}

func (s *Server) oidcLogin(w http.ResponseWriter, r *http.Request) {
	p, ok := s.enterpriseProvider(r, "oidc")
	if !ok {
		http.NotFound(w, r)
		return
	}
	var c oidcConfig
	json.Unmarshal(p.Config, &c)
	e, err := s.oidcEndpoints(r.Context(), p.ID, c.Issuer, false)
	if err != nil {
		s.log.Error("sign-in provider unavailable", "provider", p.ID, "err", err)
		s.ssoFail(w, r, "provider_unavailable")
		return
	}
	state, verifier, nonce := randToken(24), randToken(32), randToken(24)
	if err := s.store.CreateAuthFlow(r.Context(), "oidc:"+p.ID, state, verifier, nonce); err != nil {
		s.storeErr(w, err, "")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: stateCookie, Value: state, Path: "/auth", MaxAge: int(flowTTL.Seconds()),
		HttpOnly: true, Secure: !s.cfg.InsecureHTTP, SameSite: http.SameSiteLaxMode})
	sum := sha256.Sum256([]byte(verifier))
	scopes := "openid email profile"
	if c.Scopes != "" {
		scopes = c.Scopes
	}
	q := url.Values{"response_type": {"code"}, "client_id": {c.ClientID}, "redirect_uri": {s.oidcRedirect(p.ID)}, "scope": {scopes},
		"state": {state}, "nonce": {nonce}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
	if h := r.URL.Query().Get("login_hint"); h != "" && len(h) < 256 {
		q.Set("login_hint", h)
	}
	sep := "?"
	if strings.Contains(e.authURL, "?") {
		sep = "&"
	}
	http.Redirect(w, r, e.authURL+sep+q.Encode(), http.StatusFound)
}

func (s *Server) oidcCallback(w http.ResponseWriter, r *http.Request) {
	p, ok := s.enterpriseProvider(r, "oidc")
	if !ok {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	state := r.URL.Query().Get("state")
	ck, cerr := r.Cookie(stateCookie)
	http.SetCookie(w, &http.Cookie{Name: stateCookie, Value: "", Path: "/auth", MaxAge: -1, HttpOnly: true, Secure: !s.cfg.InsecureHTTP, SameSite: http.SameSiteLaxMode})
	if cerr != nil || state == "" || ck.Value != state {
		s.ssoFail(w, r, "state_mismatch")
		return
	}
	if e := r.URL.Query().Get("error"); e != "" {
		s.ssoFail(w, r, "idp_"+e)
		return
	}
	verifier, nonce, err := s.store.TakeAuthFlow(ctx, "oidc:"+p.ID, state, flowTTL)
	if err != nil {
		s.ssoFail(w, r, "expired")
		return
	}
	var c oidcConfig
	json.Unmarshal(p.Config, &c)
	e, err := s.oidcEndpoints(ctx, p.ID, c.Issuer, false)
	if err != nil {
		s.ssoFail(w, r, "provider_unavailable")
		return
	}
	secret := ""
	if len(p.Secret) > 0 {
		sealer, err := s.sealer()
		if err == nil {
			var b []byte
			if b, err = sealer.Open(p.Secret, signInAAD(p.ID)); err == nil {
				secret = string(b)
			}
		}
		if err != nil {
			s.ssoFail(w, r, "internal")
			return
		}
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {r.URL.Query().Get("code")}, "redirect_uri": {s.oidcRedirect(p.ID)},
		"client_id": {c.ClientID}, "code_verifier": {verifier}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, e.tokenURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if secret != "" {
		req.SetBasicAuth(url.QueryEscape(c.ClientID), url.QueryEscape(secret))
	}
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		s.ssoFail(w, r, "token_exchange")
		return
	}
	defer resp.Body.Close()
	var tok struct {
		IDToken string `json:"id_token"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tok) != nil || tok.IDToken == "" {
		s.ssoFail(w, r, "token_exchange")
		return
	}
	claims, err := e.verifier.Verify(tok.IDToken, c.ClientID, time.Now())
	if err != nil && err.Error() == "unknown signing key" {
		if e2, err2 := s.oidcEndpoints(ctx, p.ID, c.Issuer, true); err2 == nil {
			claims, err = e2.verifier.Verify(tok.IDToken, c.ClientID, time.Now())
		}
	}
	if err != nil || claims["nonce"] != nonce {
		s.log.Warn("ID token rejected", "provider", p.ID, "err", err)
		s.ssoFail(w, r, "invalid_token")
		return
	}
	email, _ := claims["email"].(string)
	email = strings.ToLower(strings.TrimSpace(email))
	verified, _ := claims["email_verified"].(bool)
	if email == "" || !verified {
		s.audit(ctx, "sso:"+p.ID, "auth.sso_denied", "user/"+email, "", map[string]string{"provider": "oidc:" + p.ID, "reason": "email missing or not verified"})
		s.ssoFail(w, r, "email_not_verified")
		return
	}
	sub, _ := claims["sub"].(string)
	s.finishSSO(w, r, "oidc:"+p.ID, email, p.AllowedDomains, c.Issuer, sub, true, identityStrs(claims["amr"]))
}

// ---- SAML ----

// spKey is this central's SAML service-provider key and certificate, made
// on first use and kept sealed (it signs nothing the IdP must trust; it lets
// IdPs that require one encrypt assertions to us).
func (s *Server) spKey(ctx context.Context) (*rsa.PrivateKey, *x509.Certificate, error) {
	s.spMu.Lock()
	defer s.spMu.Unlock()
	if s.spRSA != nil {
		return s.spRSA, s.spCert, nil
	}
	sealer, err := s.sealer()
	if err != nil {
		return nil, nil, err
	}
	k0, c0, seen, ok := s.loadSPKey(ctx, sealer)
	if ok {
		s.spRSA, s.spCert = k0, c0
		return k0, c0, nil
	}
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "SrustiOps SAML service provider"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(10, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		return nil, nil, err
	}
	pt, _ := json.Marshal(struct{ Key, Cert []byte }{x509.MarshalPKCS1PrivateKey(k), der})
	sealed, err := sealer.Seal(pt, []byte("saml-sp-key"))
	if err != nil {
		return nil, nil, err
	}
	v, _ := json.Marshal(map[string]string{"sealed": base64.StdEncoding.EncodeToString(sealed)})
	// A stored key that cannot be opened (the master key changed) is replaced;
	// IdPs then need the new SP metadata.
	// A stored key that cannot be opened (the master key changed) is replaced
	// (IdPs then need the new SP metadata); one another replica just stored is kept.
	if _, err := s.store.Pool().Exec(ctx, `INSERT INTO platform_settings (key, value, updated_by) VALUES ('saml_sp_key', $1, 'system:saml')
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now() WHERE platform_settings.value::text = $2`, v, string(seen)); err != nil {
		return nil, nil, err
	}
	k2, c2, _, ok := s.loadSPKey(ctx, sealer)
	if !ok {
		return nil, nil, errors.New("the SAML service-provider key could not be stored")
	}
	s.spRSA, s.spCert = k2, c2
	return k2, c2, nil
}

func (s *Server) loadSPKey(ctx context.Context, sealer interface {
	Open(ct, aad []byte) ([]byte, error)
}) (*rsa.PrivateKey, *x509.Certificate, []byte, bool) {
	var raw []byte
	var stored struct {
		Sealed string `json:"sealed"`
	}
	if s.store.Pool().QueryRow(ctx, `SELECT value::text FROM platform_settings WHERE key = 'saml_sp_key'`).Scan(&raw) != nil || json.Unmarshal(raw, &stored) != nil {
		return nil, nil, raw, false
	}
	b, _ := base64.StdEncoding.DecodeString(stored.Sealed)
	pt, err := sealer.Open(b, []byte("saml-sp-key"))
	if err != nil {
		return nil, nil, raw, false
	}
	var kv struct{ Key, Cert []byte }
	if json.Unmarshal(pt, &kv) != nil {
		return nil, nil, raw, false
	}
	k, err1 := x509.ParsePKCS1PrivateKey(kv.Key)
	c, err2 := x509.ParseCertificate(kv.Cert)
	return k, c, raw, err1 == nil && err2 == nil
}

func (s *Server) samlSP(ctx context.Context, p *SignInProvider) (*saml.ServiceProvider, *samlConfig, error) {
	var c samlConfig
	if err := json.Unmarshal(p.Config, &c); err != nil {
		return nil, nil, err
	}
	md, err := parseSAMLMetadata([]byte(c.Metadata))
	if err != nil {
		return nil, nil, err
	}
	k, cert, err := s.spKey(ctx)
	if err != nil {
		return nil, nil, err
	}
	base := strings.TrimRight(s.cfg.PublicURL, "/") + "/auth/saml/" + p.ID
	mdURL, _ := url.Parse(base + "/metadata")
	acsURL, _ := url.Parse(base + "/acs")
	sp := &saml.ServiceProvider{
		EntityID: mdURL.String(), Key: k, Certificate: cert, MetadataURL: *mdURL, AcsURL: *acsURL, IDPMetadata: md,
		AuthnNameIDFormat: saml.EmailAddressNameIDFormat, HTTPClient: &http.Client{Timeout: 10 * time.Second},
	}
	return sp, &c, nil
}

func (s *Server) samlMetadata(w http.ResponseWriter, r *http.Request) {
	p, err := s.store.SignInProvider(r.Context(), "saml", r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	sp, _, err := s.samlSP(r.Context(), p)
	if err != nil {
		httpx.WriteErr(w, 500, "the provider's settings are invalid")
		return
	}
	b, _ := xml.MarshalIndent(sp.Metadata(), "", "  ")
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Write(b)
}

func (s *Server) samlLogin(w http.ResponseWriter, r *http.Request) {
	p, ok := s.enterpriseProvider(r, "saml")
	if !ok {
		http.NotFound(w, r)
		return
	}
	sp, _, err := s.samlSP(r.Context(), p)
	if err != nil {
		s.log.Error("SAML provider unusable", "provider", p.ID, "err", err)
		s.ssoFail(w, r, "provider_unavailable")
		return
	}
	req, err := sp.MakeAuthenticationRequest(sp.GetSSOBindingLocation(saml.HTTPRedirectBinding), saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		s.ssoFail(w, r, "provider_unavailable")
		return
	}
	// RelayState is the flow's state; the flow remembers the request ID the
	// Response must answer.
	state := randToken(24)
	if err := s.store.CreateAuthFlow(r.Context(), "saml:"+p.ID, state, req.ID, ""); err != nil {
		s.storeErr(w, err, "")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: stateCookie, Value: state, Path: "/auth", MaxAge: int(flowTTL.Seconds()),
		HttpOnly: true, Secure: !s.cfg.InsecureHTTP, SameSite: http.SameSiteNoneMode})
	u, err := req.Redirect(state, sp)
	if err != nil {
		s.ssoFail(w, r, "provider_unavailable")
		return
	}
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// parseSAMLMetadata reads an IdP's EntityDescriptor, or the first one of an
// EntitiesDescriptor that has an IdP role.
func parseSAMLMetadata(b []byte) (*saml.EntityDescriptor, error) {
	var ed saml.EntityDescriptor
	if err := xml.Unmarshal(b, &ed); err == nil && len(ed.IDPSSODescriptors) > 0 {
		return &ed, nil
	}
	var all saml.EntitiesDescriptor
	if err := xml.Unmarshal(b, &all); err != nil {
		return nil, err
	}
	for i := range all.EntityDescriptors {
		if len(all.EntityDescriptors[i].IDPSSODescriptors) > 0 {
			return &all.EntityDescriptors[i], nil
		}
	}
	return nil, errors.New("no identity-provider entity in the metadata")
}

// samlEmailAttrs are the attributes IdPs commonly put the email in.
var samlEmailAttrs = []string{"email", "mail", "emailAddress", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "urn:oid:0.9.2342.19200300.100.1.3"}

func (s *Server) samlACS(w http.ResponseWriter, r *http.Request) {
	p, ok := s.enterpriseProvider(r, "saml")
	if !ok {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	if err := r.ParseForm(); err != nil || r.PostForm.Get("SAMLResponse") == "" || r.Form.Get("SAMLart") != "" {
		s.ssoFail(w, r, "invalid_token") // only the HTTP-POST binding, never artifacts
		return
	}
	state := r.PostForm.Get("RelayState")
	// The state cookie is SameSite=None (the IdP posts cross-site); when a
	// browser drops it anyway the single-use flow is still the check.
	if ck, err := r.Cookie(stateCookie); err == nil && ck.Value != state {
		s.ssoFail(w, r, "state_mismatch")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: stateCookie, Value: "", Path: "/auth", MaxAge: -1, HttpOnly: true, Secure: !s.cfg.InsecureHTTP, SameSite: http.SameSiteNoneMode})
	reqID, _, err := s.store.TakeAuthFlow(ctx, "saml:"+p.ID, state, flowTTL)
	if err != nil || state == "" {
		s.ssoFail(w, r, "expired")
		return
	}
	sp, c, err := s.samlSP(ctx, p)
	if err != nil {
		s.ssoFail(w, r, "provider_unavailable")
		return
	}
	a, err := sp.ParseResponse(r, []string{reqID})
	if err != nil {
		var ie *saml.InvalidResponseError
		detail := err.Error()
		if errors.As(err, &ie) && ie.PrivateErr != nil {
			detail = ie.PrivateErr.Error()
		}
		s.log.Warn("SAML response rejected", "provider", p.ID, "err", detail)
		s.audit(ctx, "sso:"+p.ID, "auth.sso_denied", "provider/"+p.ID, "", map[string]string{"provider": "saml:" + p.ID, "reason": trim(detail, 200)})
		s.ssoFail(w, r, "invalid_token")
		return
	}
	email, subject := samlIdentity(a, c.EmailAttr)
	if email == "" || subject == "" {
		s.ssoFail(w, r, "email_not_verified")
		return
	}
	issuer := c.EntityID
	if a.Issuer.Value != "" {
		issuer = a.Issuer.Value
	}
	s.finishSSO(w, r, "saml:"+p.ID, email, p.AllowedDomains, issuer, subject, true)
}

// samlIdentity reads the email (the chosen attribute, an email NameID, or a
// usual email attribute) and the stable subject (the NameID).
func samlIdentity(a *saml.Assertion, attr string) (email, subject string) {
	if a.Subject != nil && a.Subject.NameID != nil {
		subject = strings.TrimSpace(a.Subject.NameID.Value)
	}
	vals := map[string]string{}
	for _, st := range a.AttributeStatements {
		for _, at := range st.Attributes {
			if len(at.Values) > 0 {
				vals[at.Name] = at.Values[0].Value
				if at.FriendlyName != "" {
					vals[at.FriendlyName] = at.Values[0].Value
				}
			}
		}
	}
	switch {
	case attr != "":
		email = vals[attr]
	case strings.Contains(subject, "@"):
		email = subject
	default:
		for _, k := range samlEmailAttrs {
			if v := vals[k]; v != "" {
				email = v
				break
			}
		}
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if !emailRe.MatchString(email) {
		email = ""
	}
	return email, subject
}

// ---- configuration (platform admins) ----

type signInView struct {
	ID             string         `json:"id"`
	Kind           string         `json:"kind"`
	Label          string         `json:"label"`
	Enabled        bool           `json:"enabled"`
	AllowedDomains []string       `json:"allowed_domains"`
	Config         map[string]any `json:"config"`
	SecretSet      bool           `json:"client_secret_set,omitempty"`
	RedirectURI    string         `json:"redirect_uri,omitempty"` // OIDC: register this at the provider
	ACSURL         string         `json:"acs_url,omitempty"`      // SAML: the assertion consumer service
	SPEntityID     string         `json:"sp_entity_id,omitempty"` // SAML: our entity ID (= metadata URL)
	UpdatedBy      string         `json:"updated_by"`
	UpdatedAt      time.Time      `json:"updated_at"`
}

func (s *Server) signInView(p *SignInProvider) signInView {
	v := signInView{ID: p.ID, Kind: p.Kind, Label: p.Label, Enabled: p.Enabled, AllowedDomains: p.AllowedDomains, UpdatedBy: p.UpdatedBy, UpdatedAt: p.UpdatedAt, Config: map[string]any{}}
	base := strings.TrimRight(s.cfg.PublicURL, "/")
	if p.Kind == "oidc" {
		var c oidcConfig
		json.Unmarshal(p.Config, &c)
		v.Config = map[string]any{"issuer": c.Issuer, "client_id": c.ClientID, "scopes": c.Scopes}
		v.SecretSet, v.RedirectURI = len(p.Secret) > 0, s.oidcRedirect(p.ID)
	} else {
		var c samlConfig
		json.Unmarshal(p.Config, &c)
		v.Config = map[string]any{"entity_id": c.EntityID, "sso_url": c.SSOURL, "email_attribute": c.EmailAttr, "metadata_url": c.MetadataURL}
		v.ACSURL, v.SPEntityID = base+"/auth/saml/"+p.ID+"/acs", base+"/auth/saml/"+p.ID+"/metadata"
	}
	return v
}

func (s *Server) listSignInProviders(w http.ResponseWriter, r *http.Request) {
	if !current(r).PlatformAdmin {
		httpx.WriteErr(w, http.StatusForbidden, "only platform admins configure sign-in")
		return
	}
	ps, err := s.store.SignInProviders(r.Context())
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	out := []signInView{}
	for _, p := range ps {
		out = append(out, s.signInView(p))
	}
	httpx.WriteJSON(w, 200, out)
}

type signInBody struct {
	Kind           string   `json:"kind"`
	Label          string   `json:"label"`
	AllowedDomains []string `json:"allowed_domains"`
	Enabled        *bool    `json:"enabled"`
	// OIDC
	Issuer       string `json:"issuer"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"` // empty keeps the stored one
	Scopes       string `json:"scopes"`
	// SAML: metadata XML, a metadata URL to fetch it from, or the fields.
	Metadata       string `json:"metadata"`
	MetadataURL    string `json:"metadata_url"`
	EntityID       string `json:"entity_id"`
	SSOURL         string `json:"sso_url"`
	CertificatePEM string `json:"certificate_pem"`
	EmailAttr      string `json:"email_attribute"`
}

func (s *Server) putSignInProvider(w http.ResponseWriter, r *http.Request) {
	if !current(r).PlatformAdmin {
		httpx.WriteErr(w, http.StatusForbidden, "only platform admins configure sign-in")
		return
	}
	id := r.PathValue("id")
	var b signInBody
	if !httpx.Decode(w, r, &b) {
		return
	}
	var probs []string
	if !providerIDRe.MatchString(id) || id == "google" || id == "github" {
		probs = append(probs, "the id must be lowercase letters, digits and dashes (not google or github)")
	}
	b.Label = strings.TrimSpace(b.Label)
	if b.Label == "" || len(b.Label) > 60 {
		probs = append(probs, "label is required (up to 60 characters), e.g. \"Sign in with Okta\"")
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
	if len(domains) == 0 {
		// Unlike Google or GitHub, an enterprise provider vouches for whatever
		// addresses it likes: it may sign in only its organisation's domains.
		probs = append(probs, "name the email domains this provider may sign in (allowed_domains)")
	}
	cur, curErr := s.store.SignInProvider(r.Context(), b.Kind, id)
	if curErr == nil && cur.Kind != b.Kind {
		probs = append(probs, "a provider with that id is of another kind")
	}
	p := &SignInProvider{ID: id, Kind: b.Kind, Label: b.Label, AllowedDomains: domains, Enabled: b.Enabled == nil || *b.Enabled, UpdatedBy: current(r).Email}
	audit := map[string]any{"kind": b.Kind, "label": b.Label, "allowed_domains": domains, "enabled": p.Enabled}
	switch b.Kind {
	case "oidc":
		b.Issuer = strings.TrimRight(strings.TrimSpace(b.Issuer), "/")
		if !allowedURL(b.Issuer) {
			probs = append(probs, "issuer must be the provider's https URL")
		}
		if b.ClientID = strings.TrimSpace(b.ClientID); b.ClientID == "" || len(b.ClientID) > 256 {
			probs = append(probs, "client_id is required")
		}
		if b.ClientSecret != "" && (len(b.ClientSecret) > 512 || strings.ContainsAny(b.ClientSecret, " \n\t")) {
			probs = append(probs, "client_secret must be up to 512 characters without spaces")
		}
		if b.Scopes != "" && (!strings.Contains(" "+b.Scopes+" ", " openid ") || len(b.Scopes) > 200) {
			probs = append(probs, "scopes must include openid")
		}
		if len(probs) == 0 {
			// The issuer must answer discovery now, so a typo fails here, not at sign-in.
			if _, err := s.discoverIdP(r.Context(), b.Issuer); err != nil {
				probs = append(probs, "the issuer's discovery document could not be read: "+trim(err.Error(), 200))
			}
		}
		p.Config, _ = json.Marshal(oidcConfig{Issuer: b.Issuer, ClientID: b.ClientID, Scopes: b.Scopes})
		if b.ClientSecret != "" {
			sealer, err := s.sealer()
			if err == nil {
				p.Secret, err = sealer.Seal([]byte(b.ClientSecret), signInAAD(id))
			}
			if err != nil {
				s.storeErr(w, err, "")
				return
			}
		}
		audit["issuer"], audit["client_id"], audit["secret_changed"] = b.Issuer, b.ClientID, b.ClientSecret != ""
	case "saml":
		var c samlConfig
		var prob string
		if strings.TrimSpace(b.Metadata) == "" && strings.TrimSpace(b.MetadataURL) == "" && b.CertificatePEM == "" && curErr == nil {
			// Nothing new about the IdP: keep its stored metadata.
			json.Unmarshal(cur.Config, &c)
			c.EmailAttr = strings.TrimSpace(b.EmailAttr)
		} else {
			c, prob = s.samlConfigFrom(r.Context(), b)
		}
		if prob != "" {
			probs = append(probs, prob)
		}
		p.Config, _ = json.Marshal(c)
		audit["entity_id"], audit["sso_url"], audit["metadata_url"] = c.EntityID, c.SSOURL, c.MetadataURL
	default:
		probs = append(probs, `kind must be "oidc" or "saml"`)
	}
	if len(probs) > 0 {
		httpx.WriteErr(w, 422, "invalid sign-in provider", probs...)
		return
	}
	if err := s.store.PutSignInProvider(r.Context(), p); err != nil {
		s.storeErr(w, err, "")
		return
	}
	oidcCache.Lock()
	delete(oidcCache.m, id)
	oidcCache.Unlock()
	action := "auth.provider.configure"
	if curErr != nil {
		action = "auth.provider.add"
	}
	s.audit(r.Context(), current(r).Email, action, "sso/"+id, "", audit)
	saved, _ := s.store.SignInProvider(r.Context(), b.Kind, id)
	httpx.WriteJSON(w, 200, s.signInView(saved))
}

// samlConfigFrom turns what the admin gave into IdP metadata we can verify with.
func (s *Server) samlConfigFrom(ctx context.Context, b signInBody) (samlConfig, string) {
	c := samlConfig{EmailAttr: strings.TrimSpace(b.EmailAttr), MetadataURL: strings.TrimSpace(b.MetadataURL)}
	raw := strings.TrimSpace(b.Metadata)
	switch {
	case raw == "" && c.MetadataURL != "":
		if !allowedURL(c.MetadataURL) {
			return c, "metadata_url must be an https URL"
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.MetadataURL, nil)
		resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
		if err != nil {
			return c, "the metadata could not be fetched: " + trim(err.Error(), 200)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512<<10))
		if resp.StatusCode != 200 {
			return c, fmt.Sprintf("the metadata URL answered %d", resp.StatusCode)
		}
		raw = string(body)
	case raw == "":
		// Built from the fields.
		blk, _ := pem.Decode([]byte(b.CertificatePEM))
		if blk == nil {
			return c, "give the IdP's metadata, its metadata URL, or its entity ID, SSO URL and signing certificate (PEM)"
		}
		if _, err := x509.ParseCertificate(blk.Bytes); err != nil {
			return c, "the signing certificate is not a valid X.509 certificate"
		}
		if strings.TrimSpace(b.EntityID) == "" || !allowedURL(b.SSOURL) {
			return c, "the entity ID and an https SSO URL are required"
		}
		ed := saml.EntityDescriptor{EntityID: strings.TrimSpace(b.EntityID), IDPSSODescriptors: []saml.IDPSSODescriptor{{
			SSODescriptor: saml.SSODescriptor{RoleDescriptor: saml.RoleDescriptor{ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
				KeyDescriptors: []saml.KeyDescriptor{{Use: "signing", KeyInfo: saml.KeyInfo{X509Data: saml.X509Data{
					X509Certificates: []saml.X509Certificate{{Data: base64.StdEncoding.EncodeToString(blk.Bytes)}}}}}}}},
			SingleSignOnServices: []saml.Endpoint{{Binding: saml.HTTPRedirectBinding, Location: b.SSOURL}},
		}}}
		x, _ := xml.Marshal(ed)
		raw = string(x)
	}
	if len(raw) > 512<<10 {
		return c, "the metadata is too large"
	}
	md, err := parseSAMLMetadata([]byte(raw))
	if err != nil {
		return c, "the metadata is not valid SAML metadata: " + trim(err.Error(), 200)
	}
	c.Metadata, c.EntityID = raw, md.EntityID
	var signing bool
	for _, d := range md.IDPSSODescriptors {
		for _, e := range d.SingleSignOnServices {
			if e.Binding == saml.HTTPRedirectBinding {
				c.SSOURL = e.Location
			}
		}
		for _, k := range d.KeyDescriptors {
			if (k.Use == "" || k.Use == "signing") && len(k.KeyInfo.X509Data.X509Certificates) > 0 {
				signing = true
			}
		}
	}
	switch {
	case c.EntityID == "":
		return c, "the metadata names no IdP entity ID"
	case c.SSOURL == "" || !allowedURL(c.SSOURL):
		return c, "the metadata has no https single sign-on URL with the HTTP-Redirect binding"
	case !signing:
		return c, "the metadata has no signing certificate: assertions could not be verified"
	}
	return c, ""
}

func (s *Server) deleteSignInProvider(w http.ResponseWriter, r *http.Request) {
	if !current(r).PlatformAdmin {
		httpx.WriteErr(w, http.StatusForbidden, "only platform admins configure sign-in")
		return
	}
	id := r.PathValue("id")
	if err := s.store.DeleteSignInProvider(r.Context(), id); err != nil {
		s.storeErr(w, err, "")
		return
	}
	s.audit(r.Context(), current(r).Email, "auth.provider.remove", "sso/"+id, "", nil)
	w.WriteHeader(http.StatusNoContent)
}

// enterpriseButtons are the sign-in buttons of enabled OIDC and SAML providers.
func (s *Server) enterpriseButtons(ctx context.Context) []map[string]string {
	out := []map[string]string{}
	ps, err := s.store.SignInProviders(ctx)
	if err != nil {
		return out
	}
	for _, p := range ps {
		if p.Enabled {
			out = append(out, map[string]string{"id": p.ID, "label": p.Label, "kind": p.Kind, "login": "/auth/" + p.Kind + "/" + p.ID + "/login"})
		}
	}
	return out
}
