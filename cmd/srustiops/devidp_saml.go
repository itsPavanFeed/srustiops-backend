package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/crewjam/saml"
)

// devSAMLIdP is the dev identity provider's SAML side: a fresh signing key
// per start, service providers looked up by their metadata URL (loopback
// only), and a session for whoever is named (?email=…&confirm=1 or a form).
func devSAMLIdP(base string, groups map[string][]string) (*saml.IdentityProvider, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "SrustiOps dev identity provider"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, _ := x509.ParseCertificate(der)
	md, _ := url.Parse(base + "/saml/metadata")
	sso, _ := url.Parse(base + "/saml/sso")
	return &saml.IdentityProvider{Key: key, Signer: key, Certificate: cert, MetadataURL: *md, SSOURL: *sso,
		ServiceProviderProvider: devSPs{}, SessionProvider: devSessions{groups: groups}}, nil
}

type devSPs struct{}

// GetServiceProvider fetches a service provider's metadata from its entity
// ID, which SrustiOps makes its metadata URL. Loopback addresses only.
func (devSPs) GetServiceProvider(r *http.Request, id string) (*saml.EntityDescriptor, error) {
	u, err := url.Parse(id)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, errors.New("unknown service provider")
	}
	if ip := net.ParseIP(u.Hostname()); u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return nil, errors.New("the dev identity provider serves loopback service providers only")
	}
	// Loopback only (checked above), and a development tool: local central
	// planes use development certificates, so they are not verified here.
	hc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec
	resp, err := hc.Get(id)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	var ed saml.EntityDescriptor
	if err := xml.Unmarshal(b, &ed); err != nil {
		return nil, err
	}
	return &ed, nil
}

type devSessions struct{ groups map[string][]string }

func (d devSessions) GetSession(w http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest) *saml.Session {
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	if email == "" || r.FormValue("confirm") == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html><meta name="viewport" content="width=device-width"><title>Dev identity provider (SAML)</title>
<body style="font:15px system-ui;display:grid;place-items:center;min-height:90vh;background:#f4f6f8"><form method="get" style="background:#fff;padding:28px;border-radius:12px;box-shadow:0 2px 12px #0001;min-width:320px">
<h2 style="margin:0 0 6px">Dev identity provider</h2><p style="color:#667;margin:0 0 16px">SAML, local development only. Signs in whoever you name.</p>`)
		for k, vs := range r.Form {
			if k != "email" && k != "confirm" {
				fmt.Fprintf(w, `<input type="hidden" name="%s" value="%s">`, html.EscapeString(k), html.EscapeString(vs[0]))
			}
		}
		fmt.Fprintf(w, `<label>Email<br><input name="email" value="%s" style="width:100%%;padding:8px;margin:6px 0 14px;font:inherit"></label>
<button name="confirm" value="1" style="padding:8px 16px;font:inherit;border-radius:8px;border:0;background:#0f766e;color:#fff">Sign in</button></form>`, html.EscapeString(email))
		return nil
	}
	now := time.Now()
	return &saml.Session{ID: randB64(16), CreateTime: now, ExpireTime: now.Add(10 * time.Minute), Index: randB64(8),
		NameID: email, NameIDFormat: string(saml.EmailAddressNameIDFormat), UserEmail: email, UserName: email, Groups: d.groups[email]}
}
