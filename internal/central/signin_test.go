package central

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"
)

// testSAMLIdP is a real SAML identity provider (the library's), signing
// assertions for whoever the test names.
type testSAMLIdP struct {
	idp   *saml.IdentityProvider
	srv   *httptest.Server
	email string
	sp    *saml.EntityDescriptor
}

func (f *testSAMLIdP) GetServiceProvider(r *http.Request, id string) (*saml.EntityDescriptor, error) {
	return f.sp, nil
}

func (f *testSAMLIdP) GetSession(w http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest) *saml.Session {
	now := time.Now()
	return &saml.Session{ID: fmt.Sprint(now.UnixNano()), CreateTime: now, ExpireTime: now.Add(5 * time.Minute), Index: "1",
		NameID: f.email, NameIDFormat: string(saml.EmailAddressNameIDFormat), UserEmail: f.email}
}

func newSAMLIdP(t *testing.T) *testSAMLIdP {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "idp"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	f := &testSAMLIdP{}
	mux := http.NewServeMux()
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	md, _ := url.Parse(f.srv.URL + "/metadata")
	sso, _ := url.Parse(f.srv.URL + "/sso")
	f.idp = &saml.IdentityProvider{Key: key, Signer: key, Certificate: cert, MetadataURL: *md, SSOURL: *sso, ServiceProviderProvider: f, SessionProvider: f}
	mux.HandleFunc("/metadata", f.idp.ServeMetadata)
	mux.HandleFunc("/sso", f.idp.ServeSSO)
	return f
}

var formField = regexp.MustCompile(`name="(SAMLResponse|RelayState)" value="([^"]*)"`)

// samlRound runs central's login, the IdP, and returns the ACS form values.
func samlRound(t *testing.T, b *http.Client, front string, f *testSAMLIdP, id, email string) url.Values {
	resp, err := b.Get(front + "/auth/saml/" + id + "/login")
	if err != nil || resp.StatusCode != http.StatusFound {
		t.Fatalf("saml login: %v %v", err, resp)
	}
	f.email = email
	resp, err = b.Get(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	form := url.Values{}
	for _, m := range formField.FindAllStringSubmatch(string(body), -1) {
		form.Set(m[1], htmlUnescape(m[2]))
	}
	if form.Get("SAMLResponse") == "" {
		t.Fatalf("IdP gave no response: %s", body)
	}
	return form
}

func htmlUnescape(s string) string {
	return strings.NewReplacer("&#43;", "+", "&#61;", "=", "&#34;", `"`, "&amp;", "&", "&lt;", "<", "&gt;", ">", "&#39;", "'").Replace(s)
}

func postACS(t *testing.T, b *http.Client, front, id string, form url.Values) string {
	resp, err := b.PostForm(front+"/auth/saml/"+id+"/acs", form)
	if err != nil || resp.StatusCode != http.StatusFound {
		t.Fatalf("acs: %v %v", err, resp)
	}
	return resp.Header.Get("Location")
}

func TestEnterpriseSAML(t *testing.T) {
	srv, st, front := testServer(t, "")
	key := make([]byte, 32)
	rand.Read(key)
	srv.cfg.MasterKey = base64.StdEncoding.EncodeToString(key)
	ctx := context.Background()
	suffix := fmt.Sprint(time.Now().UnixNano())
	id := "saml" + suffix[len(suffix)-8:]
	alice, bob := "alice"+suffix+"@corp.test", "bob"+suffix+"@other.test"
	st.EnsureUser(ctx, alice, "", false, "test")
	st.EnsureUser(ctx, bob, "", false, "test")
	f := newSAMLIdP(t)
	mdXML, _ := xml.Marshal(f.idp.Metadata())
	// What a platform admin saves (the handler's checks are exercised here too).
	c, prob := srv.samlConfigFrom(ctx, signInBody{Metadata: string(mdXML)})
	if prob != "" {
		t.Fatalf("metadata refused: %s", prob)
	}
	if _, prob := srv.samlConfigFrom(ctx, signInBody{Metadata: strings.ReplaceAll(string(mdXML), "KeyDescriptor", "Ignored")}); prob == "" {
		t.Fatal("metadata without a signing certificate was accepted")
	}
	cfg, _ := xmlJSON(c)
	t.Cleanup(func() { st.DeleteSignInProvider(context.Background(), id) })
	if err := st.PutSignInProvider(ctx, &SignInProvider{ID: id, Kind: "saml", Label: "Corp", Config: cfg, AllowedDomains: []string{"corp.test"}, Enabled: true, UpdatedBy: "test"}); err != nil {
		t.Fatal(err)
	}
	// The IdP learns our SP metadata the way an admin would upload it.
	resp, err := http.Get(front.URL + "/auth/saml/" + id + "/metadata")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("sp metadata: %v %v", err, resp)
	}
	var spMD saml.EntityDescriptor
	xml.NewDecoder(resp.Body).Decode(&spMD)
	resp.Body.Close()
	// Without our encryption key the IdP sends a plaintext (signed)
	// assertion, so tampering below changes signed bytes.
	for i := range spMD.SPSSODescriptors {
		var ks []saml.KeyDescriptor
		for _, k := range spMD.SPSSODescriptors[i].KeyDescriptors {
			if k.Use != "encryption" {
				ks = append(ks, k)
			}
		}
		spMD.SPSSODescriptors[i].KeyDescriptors = ks
	}
	f.sp = &spMD
	if len(spMD.SPSSODescriptors) == 0 || spMD.SPSSODescriptors[0].AssertionConsumerServices[0].Location != front.URL+"/auth/saml/"+id+"/acs" {
		t.Fatalf("SP metadata lacks our ACS: %+v", spMD)
	}

	// A good sign-in ends with a one-time code.
	b := browser()
	form := samlRound(t, b, front.URL, f, id, alice)
	if loc := postACS(t, b, front.URL, id, form); !strings.Contains(loc, "/#/sso/") {
		t.Fatalf("good response: sent to %s", loc)
	}
	// The same response again is refused: its request was answered.
	if loc := postACS(t, b, front.URL, id, form); !strings.Contains(loc, "sso_error=expired") {
		t.Fatalf("replay: sent to %s", loc)
	}
	// A response for one request cannot finish another flow.
	b2 := browser()
	form2 := samlRound(t, b2, front.URL, f, id, alice)
	b3 := browser()
	form3 := samlRound(t, b3, front.URL, f, id, alice)
	form2.Set("RelayState", form3.Get("RelayState"))
	if loc := postACS(t, b3, front.URL, id, form2); !strings.Contains(loc, "sso_error=invalid_token") {
		t.Fatalf("crossed response: sent to %s", loc)
	}
	// A tampered assertion fails its signature.
	b4 := browser()
	form4 := samlRound(t, b4, front.URL, f, id, alice)
	raw, _ := base64.StdEncoding.DecodeString(form4.Get("SAMLResponse"))
	other := "mallory" + suffix + "@corp.test"
	st.EnsureUser(ctx, other, "", false, "test")
	if !strings.Contains(string(raw), alice) {
		t.Fatal("the assertion is not in plaintext; the tamper check would test nothing")
	}
	form4.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(strings.ReplaceAll(string(raw), alice, other))))
	if loc := postACS(t, b4, front.URL, id, form4); !strings.Contains(loc, "sso_error=invalid_token") {
		t.Fatalf("tampered: sent to %s", loc)
	}
	// An address outside the provider's domains is refused.
	b5 := browser()
	if loc := postACS(t, b5, front.URL, id, samlRound(t, b5, front.URL, f, id, bob)); !strings.Contains(loc, "domain_not_allowed") {
		t.Fatalf("foreign domain: sent to %s", loc)
	}
	// IdP-initiated responses (no request of ours) are refused.
	if loc := postACS(t, browser(), front.URL, id, url.Values{"SAMLResponse": {form.Get("SAMLResponse")}}); !strings.Contains(loc, "sso_error=") {
		t.Fatalf("unsolicited: sent to %s", loc)
	}
}

func TestEnterpriseOIDC(t *testing.T) {
	idp := newIdP(t)
	srv, st, front := testServer(t, "")
	key := make([]byte, 32)
	rand.Read(key)
	srv.cfg.MasterKey = base64.StdEncoding.EncodeToString(key)
	ctx := context.Background()
	suffix := fmt.Sprint(time.Now().UnixNano())
	id := "oidc" + suffix[len(suffix)-8:]
	alice := "alice" + suffix + "@corp.test"
	st.EnsureUser(ctx, alice, "", false, "test")
	cfg := []byte(fmt.Sprintf(`{"issuer":%q,"client_id":"srustiops"}`, idp.srv.URL))
	t.Cleanup(func() { st.DeleteSignInProvider(context.Background(), id) })
	if err := st.PutSignInProvider(ctx, &SignInProvider{ID: id, Kind: "oidc", Label: "Corp", Config: cfg, AllowedDomains: []string{"corp.test"}, Enabled: true, UpdatedBy: "test"}); err != nil {
		t.Fatal(err)
	}
	run := func(email string, verified bool) string {
		b := browser()
		resp, err := b.Get(front.URL + "/auth/oidc/" + id + "/login")
		if err != nil || resp.StatusCode != http.StatusFound {
			t.Fatalf("login: %v %v", err, resp)
		}
		resp, err = b.Get(idp.authorize(resp.Header.Get("Location"), email, verified))
		if err != nil || resp.StatusCode != http.StatusFound {
			t.Fatalf("callback: %v %v", err, resp)
		}
		return resp.Header.Get("Location")
	}
	if loc := run(alice, true); !strings.Contains(loc, "/#/sso/") {
		t.Fatalf("good sign-in: %s", loc)
	}
	if loc := run(alice, false); !strings.Contains(loc, "email_not_verified") {
		t.Fatalf("unverified email: %s", loc)
	}
	if loc := run("eve"+suffix+"@else.test", true); !strings.Contains(loc, "domain_not_allowed") {
		t.Fatalf("foreign domain: %s", loc)
	}
}

func xmlJSON(c samlConfig) ([]byte, error) { return json.Marshal(c) }
