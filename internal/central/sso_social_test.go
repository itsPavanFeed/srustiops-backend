package central

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSocial plays Google (OIDC: discovery, JWKS, token with PKCE) and GitHub
// (OAuth token with PKCE, /user, /user/emails, org membership) behind the
// test redirection: the original host is the first path segment.
type fakeSocial struct {
	idp   *fakeIdP // reused for its RSA key and token signing
	srv   *httptest.Server
	mu    sync.Mutex
	codes map[string]map[string]string
}

func newSocial(t *testing.T) *fakeSocial {
	f := &fakeSocial{idp: newIdP(t), codes: map[string]map[string]string{}}
	mux := http.NewServeMux()
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	mux.HandleFunc("/accounts.google.com/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"issuer": googleIssuer, "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
			"token_endpoint": "https://oauth2.googleapis.com/token", "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs"})
	})
	mux.HandleFunc("/www.googleapis.com/oauth2/v3/certs", func(w http.ResponseWriter, r *http.Request) {
		resp, err := http.Get(f.idp.srv.URL + "/jwks")
		if err != nil {
			w.WriteHeader(502)
			return
		}
		defer resp.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		var v any
		json.NewDecoder(resp.Body).Decode(&v)
		json.NewEncoder(w).Encode(v)
	})
	take := func(r *http.Request) map[string]string {
		r.ParseForm()
		f.mu.Lock()
		defer f.mu.Unlock()
		c := f.codes[r.Form.Get("code")]
		delete(f.codes, r.Form.Get("code"))
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if c == nil || base64.RawURLEncoding.EncodeToString(sum[:]) != c["challenge"] || r.Form.Get("client_secret") != "test-secret-123" {
			return nil
		}
		return c
	}
	mux.HandleFunc("/oauth2.googleapis.com/token", func(w http.ResponseWriter, r *http.Request) {
		c := take(r)
		if c == nil || r.Form.Get("client_id") != "123-abc.apps.googleusercontent.com" {
			w.WriteHeader(400)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"id_token": f.googleToken(c["nonce"], c["email"], c["verified"] == "true")})
	})
	mux.HandleFunc("/github.com/login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		c := take(r)
		if c == nil || r.Header.Get("Accept") != "application/json" {
			json.NewEncoder(w).Encode(map[string]string{"error": "bad_verification_code"})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"access_token": "gho_" + c["email"] + "|" + c["org"]})
	})
	user := func(r *http.Request) (string, string) {
		v := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer gho_")
		email, org, _ := strings.Cut(v, "|")
		return email, org
	}
	mux.HandleFunc("/api.github.com/user", func(w http.ResponseWriter, r *http.Request) {
		email, _ := user(r)
		json.NewEncoder(w).Encode(map[string]string{"login": strings.Split(email, "@")[0]})
	})
	mux.HandleFunc("/api.github.com/user/emails", func(w http.ResponseWriter, r *http.Request) {
		email, _ := user(r)
		json.NewEncoder(w).Encode([]map[string]any{{"email": "other@else.test", "primary": false, "verified": true}, {"email": email, "primary": true, "verified": !strings.HasPrefix(email, "unverified")}})
	})
	mux.HandleFunc("/api.github.com/user/memberships/orgs/", func(w http.ResponseWriter, r *http.Request) {
		_, org := user(r)
		if !strings.HasSuffix(r.URL.Path, "/"+org) {
			w.WriteHeader(404)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"state": "active"})
	})
	return f
}

func (f *fakeSocial) googleToken(nonce, email string, verified bool) string {
	tok := f.idp.idToken(nonce, email, verified)
	// Re-sign with Google's issuer and the Google client as audience.
	parts := strings.Split(tok, ".")
	var claims map[string]any
	b, _ := base64.RawURLEncoding.DecodeString(parts[1])
	json.Unmarshal(b, &claims)
	claims["iss"], claims["aud"] = googleIssuer, "123-abc.apps.googleusercontent.com"
	return f.idp.sign(claims)
}

// authorize plays the person approving at Google or GitHub.
func (f *fakeSocial) authorize(authURL, email, org string, verified bool) string {
	u, _ := url.Parse(authURL)
	q := u.Query()
	code := fmt.Sprintf("code-%d", time.Now().UnixNano())
	f.mu.Lock()
	f.codes[code] = map[string]string{"challenge": q.Get("code_challenge"), "nonce": q.Get("nonce"), "email": email, "org": org, "verified": fmt.Sprint(verified)}
	f.mu.Unlock()
	return q.Get("redirect_uri") + "?code=" + code + "&state=" + url.QueryEscape(q.Get("state"))
}

func socialLoginFlow(t *testing.T, front, provider string, f *fakeSocial, email, org string, verified bool) string {
	b := browser()
	resp, err := b.Get(front + "/auth/login/" + provider)
	if err != nil || resp.StatusCode != http.StatusFound {
		t.Fatalf("login %s: %v %v", provider, err, resp)
	}
	loc := resp.Header.Get("Location")
	if provider == "google" && !strings.HasPrefix(loc, "https://accounts.google.com/o/oauth2/v2/auth?") ||
		provider == "github" && !strings.HasPrefix(loc, "https://github.com/login/oauth/authorize?") {
		t.Fatalf("%s authorize URL: %s", provider, loc)
	}
	if !strings.Contains(loc, "code_challenge_method=S256") {
		t.Fatalf("%s sign-in does not use PKCE: %s", provider, loc)
	}
	resp, err = b.Get(f.authorize(loc, email, org, verified))
	if err != nil || resp.StatusCode != http.StatusFound {
		t.Fatalf("callback %s: %v %v", provider, err, resp)
	}
	return resp.Header.Get("Location")
}

func TestGoogleAndGitHubSignIn(t *testing.T) {
	f := newSocial(t)
	srv, st, front := testServer(t, "")
	key := make([]byte, 32)
	rand.Read(key)
	srv.cfg.MasterKey = base64.StdEncoding.EncodeToString(key)
	srv.cfg.SSOTestURL = f.srv.URL
	ctx := context.Background()
	suffix := fmt.Sprint(time.Now().UnixNano())
	alice := "alice" + suffix + "@acme.test"
	st.EnsureUser(ctx, alice, "", false, "test")

	// Not configured: no sign-in route.
	if resp, _ := browser().Get(front.URL + "/auth/login/google"); resp.StatusCode != 404 {
		t.Fatalf("unconfigured provider: %d", resp.StatusCode)
	}
	sealer, _ := srv.sealer()
	for _, p := range []*SSOProvider{
		{ID: "google", ClientID: "123-abc.apps.googleusercontent.com", AllowedDomains: []string{"acme.test"}, AllowedOrgs: []string{}},
		{ID: "github", ClientID: "Ov23liTest0001", AllowedDomains: []string{}, AllowedOrgs: []string{"acme"}},
	} {
		p.ClientSecret, _ = sealer.Seal([]byte("test-secret-123"), ssoAAD(p.ID))
		p.Enabled, p.UpdatedBy = true, "test"
		if err := st.PutSSOProvider(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	var cfg struct {
		Providers []map[string]string `json:"providers"`
	}
	resp, _ := http.Get(front.URL + "/api/v1/auth/config")
	json.NewDecoder(resp.Body).Decode(&cfg)
	if len(cfg.Providers) != 2 {
		t.Fatalf("login page providers: %+v", cfg.Providers)
	}

	// Google: a verified email of an allowed domain signs in.
	loc := socialLoginFlow(t, front.URL, "google", f, alice, "", true)
	if !strings.HasPrefix(loc, "/#/sso/") {
		t.Fatalf("google sign-in: %s", loc)
	}
	if status(t, front.URL+"/api/v1/me", exchange(t, front.URL, strings.TrimPrefix(loc, "/#/sso/"), 200)) != 200 {
		t.Fatal("google session does not work")
	}
	if loc := socialLoginFlow(t, front.URL, "google", f, alice, "", false); !strings.Contains(loc, "email_not_verified") {
		t.Fatalf("google unverified: %s", loc)
	}
	other := "bob" + suffix + "@other.test"
	st.EnsureUser(ctx, other, "", false, "test")
	if loc := socialLoginFlow(t, front.URL, "google", f, other, "", true); !strings.Contains(loc, "domain_not_allowed") {
		t.Fatalf("google domain: %s", loc)
	}

	// GitHub: the primary verified email of a member of an allowed org.
	loc = socialLoginFlow(t, front.URL, "github", f, alice, "acme", true)
	if !strings.HasPrefix(loc, "/#/sso/") {
		t.Fatalf("github sign-in: %s", loc)
	}
	if loc := socialLoginFlow(t, front.URL, "github", f, alice, "elsewhere", true); !strings.Contains(loc, "org_not_allowed") {
		t.Fatalf("github org: %s", loc)
	}
	if loc := socialLoginFlow(t, front.URL, "github", f, "nobody"+suffix+"@acme.test", "acme", true); !strings.Contains(loc, "no_access") {
		t.Fatalf("github unknown user: %s", loc)
	}

	// A Google flow cannot be finished at GitHub's callback.
	b := browser()
	resp, _ = b.Get(front.URL + "/auth/login/google")
	cb := f.authorize(resp.Header.Get("Location"), alice, "", true)
	resp, _ = b.Get(strings.Replace(cb, "/auth/callback/google", "/auth/callback/github", 1))
	if !strings.Contains(resp.Header.Get("Location"), "sso_error=expired") {
		t.Fatalf("cross-provider callback: %s", resp.Header.Get("Location"))
	}
}
