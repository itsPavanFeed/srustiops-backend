package api

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/xml"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/crewjam/saml"

	"github.com/itsPavanFeed/srustiops-backend/internal/store"
)

// A tenant's own SAML identity provider.
//
// Like the tenant's own OIDC provider, this plane runs the sign-in and
// verifies it; central only passes the browser along:
//
//	central /auth/tenant/{t}/login → POST /access/saml/start here: an
//	    AuthnRequest whose ID this plane remembers, and the IdP URL to send
//	    the browser to
//	IdP → POST central /auth/tenant/{t}/acs → POST /access/saml/finish here:
//	    the Response must be signed by the IdP's certificate (from the
//	    metadata saved here), answer that request, be addressed to this
//	    tenant's ACS and audience, and be current. Then this plane issues
//	    its own session, as for OIDC.
//
// The service provider's entity ID and ACS are central's per-tenant URLs;
// its key (for IdPs that encrypt assertions) is made here and kept sealed.

const samlKeySetting = "saml_sp_key"

var tenantSP struct {
	sync.Mutex
	key  *rsa.PrivateKey
	cert *x509.Certificate
}

func (s *Server) samlSPKey(ctx context.Context) (*rsa.PrivateKey, *x509.Certificate, error) {
	tenantSP.Lock()
	defer tenantSP.Unlock()
	if tenantSP.key != nil {
		return tenantSP.key, tenantSP.cert, nil
	}
	load := func() bool {
		b, ok := s.openSetting(ctx, samlKeySetting, samlKeySetting)
		if !ok {
			return false
		}
		var kv struct{ Key, Cert []byte }
		if json.Unmarshal(b, &kv) != nil {
			return false
		}
		k, err1 := x509.ParsePKCS1PrivateKey(kv.Key)
		c, err2 := x509.ParseCertificate(kv.Cert)
		if err1 != nil || err2 != nil {
			return false
		}
		tenantSP.key, tenantSP.cert = k, c
		return true
	}
	if load() {
		return tenantSP.key, tenantSP.cert, nil
	}
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "SrustiOps " + s.cfg.Tenant + " SAML service provider"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(10, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		return nil, nil, err
	}
	pt, _ := json.Marshal(struct{ Key, Cert []byte }{x509.MarshalPKCS1PrivateKey(k), der})
	if err := s.sealSetting(ctx, samlKeySetting, samlKeySetting, pt, "system:saml"); err != nil {
		return nil, nil, err
	}
	if !load() {
		return nil, nil, errors.New("the SAML service-provider key could not be stored")
	}
	return tenantSP.key, tenantSP.cert, nil
}

func (s *Server) samlServiceProvider(ctx context.Context) (*saml.ServiceProvider, error) {
	a := s.access()
	if a.IDPProtocol != "saml" || a.IDPSAMLMetadata == "" {
		return nil, errors.New("this tenant has no SAML identity provider")
	}
	md, err := parseIdPMetadata([]byte(a.IDPSAMLMetadata))
	if err != nil {
		return nil, err
	}
	k, cert, err := s.samlSPKey(ctx)
	if err != nil {
		return nil, err
	}
	base := strings.TrimRight(s.cfg.CentralURL, "/") + "/auth/tenant/" + s.cfg.Tenant
	mdURL, _ := url.Parse(base + "/saml/metadata")
	acs, _ := url.Parse(base + "/acs")
	return &saml.ServiceProvider{EntityID: mdURL.String(), Key: k, Certificate: cert, MetadataURL: *mdURL, AcsURL: *acs, IDPMetadata: md,
		AuthnNameIDFormat: saml.EmailAddressNameIDFormat}, nil
}

// parseIdPMetadata reads an IdP's EntityDescriptor (or the first IdP of an
// EntitiesDescriptor) and checks it can be used: an HTTP-Redirect SSO URL
// and a signing certificate.
func parseIdPMetadata(b []byte) (*saml.EntityDescriptor, error) {
	var ed saml.EntityDescriptor
	if err := xml.Unmarshal(b, &ed); err != nil || len(ed.IDPSSODescriptors) == 0 {
		var all saml.EntitiesDescriptor
		if err := xml.Unmarshal(b, &all); err != nil {
			return nil, errors.New("not SAML metadata")
		}
		found := false
		for i := range all.EntityDescriptors {
			if len(all.EntityDescriptors[i].IDPSSODescriptors) > 0 {
				ed, found = all.EntityDescriptors[i], true
				break
			}
		}
		if !found {
			return nil, errors.New("no identity-provider entity in the metadata")
		}
	}
	var sso, signing bool
	for _, d := range ed.IDPSSODescriptors {
		for _, e := range d.SingleSignOnServices {
			sso = sso || e.Binding == saml.HTTPRedirectBinding
		}
		for _, k := range d.KeyDescriptors {
			signing = signing || ((k.Use == "" || k.Use == "signing") && len(k.KeyInfo.X509Data.X509Certificates) > 0)
		}
	}
	switch {
	case ed.EntityID == "":
		return nil, errors.New("the metadata names no entity ID")
	case !sso:
		return nil, errors.New("the metadata has no single sign-on URL with the HTTP-Redirect binding")
	case !signing:
		return nil, errors.New("the metadata has no signing certificate")
	}
	return &ed, nil
}

func (s *Server) samlStart(w http.ResponseWriter, r *http.Request) {
	if !central(w, r) {
		return
	}
	sp, err := s.samlServiceProvider(r.Context())
	if err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	req, err := sp.MakeAuthenticationRequest(sp.GetSSOBindingLocation(saml.HTTPRedirectBinding), saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		writeErr(w, 500, "the sign-in request could not be made")
		return
	}
	state := randURL(24)
	if err := s.store.CreateTenantAuthFlow(r.Context(), state, req.ID, "", sp.AcsURL.String()); err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	u, err := req.Redirect(state, sp)
	if err != nil {
		writeErr(w, 500, "the sign-in request could not be made")
		return
	}
	writeJSON(w, 200, map[string]string{"authorize_url": u.String(), "state": state})
}

func (s *Server) samlFinish(w http.ResponseWriter, r *http.Request) {
	if !central(w, r) {
		return
	}
	var b struct {
		State        string `json:"state"`
		SAMLResponse string `json:"saml_response"`
	}
	if !decode(w, r, &b) {
		return
	}
	reqID, _, _, err := s.store.TakeTenantAuthFlow(r.Context(), b.State)
	if err != nil || b.SAMLResponse == "" {
		writeErr(w, http.StatusUnauthorized, "unknown or expired sign-in")
		return
	}
	sp, err := s.samlServiceProvider(r.Context())
	if err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	// The library reads the response from a form post, as the IdP sent it.
	form := url.Values{"SAMLResponse": {b.SAMLResponse}, "RelayState": {b.State}}
	hr, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, sp.AcsURL.String(), strings.NewReader(form.Encode()))
	hr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := hr.ParseForm(); err != nil {
		writeErr(w, 400, "invalid response")
		return
	}
	asr, err := sp.ParseResponse(hr, []string{reqID})
	if err != nil {
		detail := err.Error()
		var ie *saml.InvalidResponseError
		if errors.As(err, &ie) && ie.PrivateErr != nil {
			detail = ie.PrivateErr.Error()
		}
		s.log.Warn("SAML response rejected", "err", detail)
		writeErr(w, http.StatusUnauthorized, "the SAML response was rejected")
		return
	}
	a := s.access()
	email, subject, groups := samlPerson(asr, a.IDPSAMLEmailAttr, a.GroupClaim)
	if email == "" || subject == "" {
		writeErr(w, http.StatusUnauthorized, "the identity provider sent no email address")
		return
	}
	// Grants bind to (issuer, subject): always the configured entity ID.
	if asr.Issuer.Value != "" && asr.Issuer.Value != a.IDPIssuer {
		writeErr(w, http.StatusUnauthorized, "the assertion names another issuer")
		return
	}
	issuer := a.IDPIssuer
	ts := &store.TenantSession{Email: email, Issuer: issuer, Subject: subject, AMR: samlAMR(asr), Groups: groups, AuthTime: time.Now()}
	for _, st := range asr.AuthnStatements {
		if !st.AuthnInstant.IsZero() {
			ts.AuthTime = st.AuthnInstant
		}
	}
	id := "tsid_" + randURL(24)
	exp := time.Now().Add(12 * time.Hour)
	if err := s.store.CreateIdentitySession(r.Context(), id, ts, exp); err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.audit(r.Context(), email, "access.session", "user/"+email, "", map[string]any{"issuer": issuer, "subject": subject, "protocol": "saml", "groups": len(groups)})
	writeJSON(w, 200, map[string]any{"session": id, "email": email, "email_verified": true, "issuer": issuer, "subject": subject,
		"amr": ts.AMR, "auth_time": ts.AuthTime.Unix(), "expires_at": exp})
}

// samlPerson reads the email (the chosen attribute, an email NameID, or a
// usual email attribute), the subject (NameID) and the groups attribute.
func samlPerson(a *saml.Assertion, emailAttr, groupAttr string) (email, subject string, groups []string) {
	if a.Subject != nil && a.Subject.NameID != nil {
		subject = strings.TrimSpace(a.Subject.NameID.Value)
	}
	if groupAttr == "" {
		groupAttr = "groups"
	}
	vals := map[string][]string{}
	for _, st := range a.AttributeStatements {
		for _, at := range st.Attributes {
			for _, v := range at.Values {
				vals[at.Name] = append(vals[at.Name], v.Value)
				if at.FriendlyName != "" {
					vals[at.FriendlyName] = append(vals[at.FriendlyName], v.Value)
				}
			}
		}
	}
	first := func(k string) string {
		if v := vals[k]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	switch {
	case emailAttr != "":
		email = first(emailAttr)
	case strings.Contains(subject, "@"):
		email = subject
	default:
		for _, k := range []string{"email", "mail", "emailAddress", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "urn:oid:0.9.2342.19200300.100.1.3"} {
			if email = first(k); email != "" {
				break
			}
		}
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if !strings.Contains(email, "@") || len(email) > 254 {
		email = ""
	}
	groups = vals[groupAttr]
	if groups == nil {
		groups = []string{}
	}
	if len(groups) > 200 {
		groups = groups[:200]
	}
	return email, subject, groups
}

// samlAMR maps the authentication context to amr values: MFA contexts count as "mfa".
func samlAMR(a *saml.Assertion) []string {
	out := []string{}
	for _, st := range a.AuthnStatements {
		ref := strings.ToLower(st.AuthnContext.AuthnContextClassRef.Value)
		switch {
		case strings.Contains(ref, "multifactor") || strings.Contains(ref, "mfa") || strings.Contains(ref, "timesynctoken") || strings.Contains(ref, "x509"):
			out = append(out, "mfa")
		case strings.Contains(ref, "password"):
			out = append(out, "pwd")
		}
	}
	return out
}

// samlSPMetadata is this tenant's service-provider metadata, which central serves.
func (s *Server) samlSPMetadata(w http.ResponseWriter, r *http.Request) {
	if !central(w, r) {
		return
	}
	sp, err := s.samlServiceProvider(r.Context())
	if err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	b, _ := xml.MarshalIndent(sp.Metadata(), "", "  ")
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Write(b)
}
