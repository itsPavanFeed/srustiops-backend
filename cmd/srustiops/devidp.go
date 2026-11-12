package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/oidc"
)

// runDevIdP is a stand-in OpenID Connect provider for local development and
// tests: it signs in whoever is named (login_hint or a form), with PKCE, and
// puts their groups in the ID token. It is a SAML 2.0 identity provider too
// (/saml/metadata, /saml/sso), signing assertions for whoever is named.
// Loopback only; never for real use.
func runDevIdP(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("dev-idp", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:18996", "loopback address to listen on")
	client := fs.String("client", "srustiops-dev", "the only client_id accepted")
	groupsFlag := fs.String("groups", "", "groups by email: a@x.com=g1,g2;b@x.com=g3 (others get none)")
	fs.Parse(args)
	host, _, err := net.SplitHostPort(*listen)
	if err != nil || (host != "127.0.0.1" && host != "localhost" && host != "::1") {
		return errors.New("dev-idp listens on loopback only")
	}
	groups := map[string][]string{}
	for _, part := range strings.Split(*groupsFlag, ";") {
		if email, gs, ok := strings.Cut(strings.TrimSpace(part), "="); ok {
			groups[strings.ToLower(email)] = strings.Split(gs, ",")
		}
	}
	issuerURL := "http://" + *listen
	key, err := oidc.GenerateKey()
	if err != nil {
		return err
	}
	iss, err := oidc.New(issuerURL, key)
	if err != nil {
		return err
	}
	type grant struct {
		email, nonce, redirect, challenge string
		at                                time.Time
	}
	var mu sync.Mutex
	codes := map[string]grant{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"jwks_uri":%q,"response_types_supported":["code"],"id_token_signing_alg_values_supported":["ES256"],"code_challenge_methods_supported":["S256"]}`,
			issuerURL, issuerURL+"/authorize", issuerURL+"/token", issuerURL+"/jwks")
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(iss.JWKS())
	})
	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("client_id") != *client || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
			http.Error(w, "unknown client or no PKCE", 400)
			return
		}
		email := strings.ToLower(strings.TrimSpace(q.Get("email")))
		if email == "" {
			email = strings.ToLower(strings.TrimSpace(q.Get("login_hint")))
		}
		if email == "" || q.Get("confirm") == "" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, `<!doctype html><meta name="viewport" content="width=device-width"><title>Dev identity provider</title>
<body style="font:15px system-ui;display:grid;place-items:center;min-height:90vh;background:#f4f6f8"><form style="background:#fff;padding:28px;border-radius:12px;box-shadow:0 2px 12px #0001;min-width:320px">
<h2 style="margin:0 0 6px">Dev identity provider</h2><p style="color:#667;margin:0 0 16px">Local development only. Signs in whoever you name.</p>`)
			for k, vs := range q {
				if k != "email" && k != "confirm" {
					fmt.Fprintf(w, `<input type="hidden" name="%s" value="%s">`, html.EscapeString(k), html.EscapeString(vs[0]))
				}
			}
			fmt.Fprintf(w, `<label>Email<br><input name="email" value="%s" style="width:100%%;padding:8px;margin:6px 0 14px;font:inherit"></label>
<button name="confirm" value="1" style="padding:8px 16px;font:inherit;border-radius:8px;border:0;background:#0f766e;color:#fff">Sign in</button></form>`, html.EscapeString(email))
			return
		}
		code := randB64(24)
		mu.Lock()
		codes[code] = grant{email: email, nonce: q.Get("nonce"), redirect: q.Get("redirect_uri"), challenge: q.Get("code_challenge"), at: time.Now()}
		mu.Unlock()
		u, err := url.Parse(q.Get("redirect_uri"))
		if err != nil {
			http.Error(w, "bad redirect_uri", 400)
			return
		}
		v := u.Query()
		v.Set("code", code)
		v.Set("state", q.Get("state"))
		u.RawQuery = v.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		mu.Lock()
		g, ok := codes[r.PostForm.Get("code")]
		delete(codes, r.PostForm.Get("code"))
		mu.Unlock()
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !ok || time.Since(g.at) > time.Minute || g.redirect != r.PostForm.Get("redirect_uri") || base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(400)
			w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		now := time.Now()
		gs := groups[g.email]
		if gs == nil {
			gs = []string{}
		}
		tok, err := iss.SignJWT(map[string]any{"aud": *client, "sub": g.email, "email": g.email, "email_verified": true, "nonce": g.nonce,
			"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "auth_time": now.Unix(), "amr": []string{"pwd", "mfa"}, "groups": gs})
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":%q,"token_type":"Bearer","expires_in":300,"id_token":%q}`, randB64(16), tok)
	})
	sidp, err := devSAMLIdP(issuerURL, groups)
	if err != nil {
		return err
	}
	mux.HandleFunc("/saml/metadata", sidp.ServeMetadata)
	mux.HandleFunc("/saml/sso", sidp.ServeSSO)
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { <-ctx.Done(); srv.Close() }()
	fmt.Printf("dev identity provider at %s (client_id %s)\n", issuerURL, *client)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func randB64(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
