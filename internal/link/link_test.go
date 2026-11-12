package link

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// gatewayForTest is a minimal gateway: enrolment with token "good", renewal
// with a valid certificate, and tunnels into a Hub.
func gatewayForTest(t *testing.T, ca *CA, hub *Hub, ctx context.Context) *httptest.Server {
	mux := http.NewServeMux()
	issue := func(w http.ResponseWriter, r *http.Request, tenant string) {
		var b struct{ Tenant, Token, CSR string }
		decodeJSON(r, &b)
		csr, err := ParseCSR([]byte(b.CSR))
		if err != nil {
			http.Error(w, err.Error(), 422)
			return
		}
		_, p, err := ca.Sign(csr, TenantID(tenant), CertTTL)
		if err != nil {
			http.Error(w, err.Error(), 422)
			return
		}
		fmt.Fprintf(w, `{"certificate":%q}`, p)
	}
	mux.HandleFunc("POST /v1/link/enroll", func(w http.ResponseWriter, r *http.Request) {
		var b struct{ Tenant, Token string }
		body, _ := io.ReadAll(r.Body)
		decodeBytes(body, &b)
		if b.Token != "good" {
			http.Error(w, `{"error":"bad token"}`, 401)
			return
		}
		var c struct{ CSR string }
		decodeBytes(body, &c)
		if csr, err := ParseCSR([]byte(c.CSR)); err == nil {
			boundFP.Store(keyFingerprint(csr))
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		issue(w, r, b.Tenant)
	})
	mux.HandleFunc("POST /v1/link/reenroll", func(w http.ResponseWriter, r *http.Request) {
		var b struct{ Tenant, CSR string }
		body, _ := io.ReadAll(r.Body)
		decodeBytes(body, &b)
		csr, err := ParseCSR([]byte(b.CSR))
		if err != nil {
			http.Error(w, err.Error(), 422)
			return
		}
		// The test gateway accepts only the key it saw at enrolment.
		if fp := keyFingerprint(csr); fp != boundFP.Load() {
			http.Error(w, `{"error":"not the bound key"}`, 401)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		issue(w, r, b.Tenant)
	})
	mux.HandleFunc("POST /v1/link/renew", func(w http.ResponseWriter, r *http.Request) {
		c := peer(r)
		slug, ok := "", false
		if c != nil {
			slug, ok = TenantOf(c)
		}
		if !ok {
			http.Error(w, `{"error":"no cert"}`, 401)
			return
		}
		issue(w, r, slug)
	})
	mux.HandleFunc("GET /v1/link/connect", func(w http.ResponseWriter, r *http.Request) {
		c := peer(r)
		slug, ok := "", false
		if c != nil {
			slug, ok = TenantOf(c)
		}
		if !ok || r.Header.Get("Upgrade") != Proto {
			http.Error(w, "no", 401)
			return
		}
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: %s\r\n\r\n", Proto)
		go hub.Serve(ctx, &BufConn{Conn: conn, R: brw.Reader}, slug, Serial(c), r.RemoteAddr)
	})
	srv := httptest.NewUnstartedServer(mux)
	srv.EnableHTTP2 = false
	srv.TLS = &tls.Config{ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: ca.Pool(), NextProtos: []string{"http/1.1"}}
	srv.StartTLS()
	return srv
}

func peer(r *http.Request) *x509.Certificate {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
		return nil
	}
	return r.TLS.VerifiedChains[0][0]
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestTunnelEndToEnd(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ca, _, err := NewCA()
	if err != nil {
		t.Fatal(err)
	}
	hub := NewHub()
	gw := gatewayForTest(t, ca, hub, ctx)
	defer gw.Close()

	// The tenant API: TLS, reached by the agent at a fixed address.
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			h := sha256.New()
			n, _ := io.Copy(h, r.Body)
			fmt.Fprintf(w, "%d %x", n, h.Sum(nil))
			return
		}
		fmt.Fprintf(w, "hello from %s", r.URL.Path)
	}))
	defer api.Close()

	gwURL, _ := url.Parse(gw.URL)
	gwCAs := x509.NewCertPool()
	gwCAs.AddCert(gw.Certificate())
	cfg := AgentConfig{Tenant: "acme", URL: gwURL, Target: api.Listener.Addr().String(), ServerCAs: gwCAs, StateDir: t.TempDir(), Connections: 2}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// A wrong token is refused and nothing is written.
	bad := cfg
	bad.EnrollToken = "nope"
	if err := NewAgent(bad, log).Run(ctx); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("bad token: %v", err)
	}

	cfg.EnrollToken = "good"
	agent := NewAgent(cfg, log)
	go agent.Run(ctx)
	waitFor(t, "two tunnels", func() bool { return len(hub.Tunnels("acme")) == 2 })
	if hub.Online("globex") {
		t.Fatal("another tenant must be offline")
	}
	if _, err := hub.Dial(ctx, "globex"); err != ErrOffline {
		t.Fatalf("dial offline tenant: %v", err)
	}

	// Central's view: the usual TLS to the tenant API, inside a stream.
	apiCAs := x509.NewCertPool()
	apiCAs.AddCert(api.Certificate())
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: apiCAs},
		DialContext:     func(ctx context.Context, _, _ string) (net.Conn, error) { return hub.Dial(ctx, "acme") },
	}}
	target := "https://" + api.Listener.Addr().String()
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := client.Get(fmt.Sprintf("%s/runs/%d", target, i))
			if err != nil {
				t.Error(err)
				return
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if want := fmt.Sprintf("hello from /runs/%d", i); string(b) != want {
				t.Errorf("got %q want %q", b, want)
			}
		}()
	}
	wg.Wait()

	// A large body streams both ways intact.
	big := bytes.Repeat([]byte("srustiops-"), 512<<10) // 4 MiB
	resp, err := client.Post(target+"/upload", "application/octet-stream", bytes.NewReader(big))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if want := fmt.Sprintf("%d %x", len(big), sha256.Sum256(big)); string(b) != want {
		t.Fatalf("upload: got %q", b)
	}

	// Dropped tunnels come back on their own.
	if n := hub.Drop("acme", ""); n != 2 {
		t.Fatalf("dropped %d", n)
	}
	waitFor(t, "reconnect", func() bool { return hub.Online("acme") })

	// The certificate names the tenant and renews for the same tenant.
	if err := agent.obtain(ctx, "/v1/link/renew", ""); err != nil {
		t.Fatalf("renew: %v", err)
	}
	if slug, _ := TenantOf(agent.leafCert()); slug != "acme" {
		t.Fatalf("renewed cert names %q", slug)
	}

	// A restarted agent reuses its stored certificate: no token needed.
	cfg2 := cfg
	cfg2.EnrollToken = ""
	a2 := NewAgent(cfg2, log)
	if err := a2.load(); err != nil {
		t.Fatalf("stored certificate: %v", err)
	}
	// ...but not for another tenant's slug.
	cfg3 := cfg2
	cfg3.Tenant = "globex"
	if err := NewAgent(cfg3, log).load(); err == nil {
		t.Fatal("a certificate for acme must not load as globex")
	}
}

func TestIdentities(t *testing.T) {
	ca, bundle, err := NewCA()
	if err != nil {
		t.Fatal(err)
	}
	again, err := LoadCA(bundle)
	if err != nil || !again.Cert.Equal(ca.Cert) {
		t.Fatalf("reload CA: %v", err)
	}
	_, csrPEM, _ := NewKeyAndCSR("x")
	csr, _ := ParseCSR(csrPEM)
	c, _, err := ca.Sign(csr, TenantID("acme"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if s, ok := TenantOf(c); !ok || s != "acme" || IsReplica(c) {
		t.Fatalf("tenant cert: %q %v", s, ok)
	}
	if err := ca.Verify(c); err != nil {
		t.Fatal(err)
	}
	r, _, _ := ca.Sign(csr, ReplicaID, time.Hour)
	if _, ok := TenantOf(r); ok || !IsReplica(r) {
		t.Fatal("replica cert")
	}
	other, _, _ := NewCA()
	if other.Verify(c) == nil {
		t.Fatal("a certificate from another CA must not verify")
	}
	if _, err := ParseCSR([]byte("junk")); err == nil {
		t.Fatal("junk CSR accepted")
	}
}

func decodeJSON(r *http.Request, v any) { b, _ := io.ReadAll(r.Body); decodeBytes(b, v) }
func decodeBytes(b []byte, v any)       { json.Unmarshal(b, v) }

var boundFP atomic.Value

func keyFingerprint(csr *x509.CertificateRequest) string {
	der, _ := x509.MarshalPKIXPublicKey(csr.PublicKey)
	sum := sha256.Sum256(der)
	return fmt.Sprintf("%x", sum)
}

func newTestSetup(t *testing.T, ctx context.Context) (*Hub, AgentConfig, *httptest.Server, *slog.Logger) {
	ca, _, _ := NewCA()
	hub := NewHub()
	gw := gatewayForTest(t, ca, hub, ctx)
	t.Cleanup(gw.Close)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if d := r.URL.Query().Get("sleep"); d != "" {
			dur, _ := time.ParseDuration(d)
			time.Sleep(dur)
		}
		fmt.Fprintf(w, "ok %s", r.URL.Path)
	}))
	t.Cleanup(api.Close)
	gwURL, _ := url.Parse(gw.URL)
	pool := x509.NewCertPool()
	pool.AddCert(gw.Certificate())
	cfg := AgentConfig{Tenant: "acme", URL: gwURL, Target: api.Listener.Addr().String(), ServerCAs: pool, StateDir: t.TempDir(), Connections: 1, EnrollToken: "good", Version: "test-1"}
	return hub, cfg, api, slog.New(slog.NewTextHandler(io.Discard, nil))
}

func plainClient(hub *Hub) *http.Client {
	return &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return hub.Dial(ctx, "acme") }}}
}

// Draining a replica lets open streams finish and moves the agent to a new tunnel.
func TestDrainKeepsOpenStreams(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hub, cfg, api, log := newTestSetup(t, ctx)
	go NewAgent(cfg, log).Run(ctx)
	waitFor(t, "tunnel", func() bool { return hub.Online("acme") })
	waitFor(t, "hello", func() bool { ts := hub.Tunnels("acme"); return len(ts) == 1 && ts[0].Version == "test-1" })
	done := make(chan string, 1)
	go func() {
		resp, err := plainClient(hub).Get("http://" + api.Listener.Addr().String() + "/logs?sleep=1500ms")
		if err != nil {
			done <- "error: " + err.Error()
			return
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		done <- string(b)
	}()
	time.Sleep(300 * time.Millisecond)
	hub.Drain(10 * time.Second) // returns when the open stream ended
	if got := <-done; got != "ok /logs" {
		t.Fatalf("the open stream was cut by the drain: %q", got)
	}
	waitFor(t, "replacement tunnel", func() bool { return hub.Online("acme") })
}

// A control-only agent (direct tenant) reports health but never carries API streams.
func TestControlOnlyMode(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hub, cfg, _, log := newTestSetup(t, ctx)
	cfg.Mode = ModeControl
	go NewAgent(cfg, log).Run(ctx)
	waitFor(t, "control tunnel", func() bool { ts := hub.Tunnels("acme"); return len(ts) == 1 && ts[0].Mode == ModeControl })
	if hub.Online("acme") || !hub.Connected("acme") {
		t.Fatal("a control-only tunnel is connected but carries no API streams")
	}
	if _, err := hub.Dial(ctx, "acme"); err != ErrOffline {
		t.Fatalf("dial through a control-only tunnel: %v", err)
	}
	if s := hub.Tunnels("acme")[0].SkewMS; s > 5000 || s < -5000 {
		t.Fatalf("clock skew reported as %d ms", s)
	}
}

// The egress relay reaches only what the gateway allows.
func TestEgressRelay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hub, cfg, _, log := newTestSetup(t, ctx)
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "token endpoint") }))
	defer idp.Close()
	allowed := idp.Listener.Addr().String()
	hub.Egress = func(ctx context.Context, tenant, target string) (net.Conn, error) {
		if tenant != "acme" || target != allowed {
			return nil, fmt.Errorf("%s is not allowed", target)
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", target)
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	cfg.EgressListen = l.Addr().String()
	l.Close()
	go NewAgent(cfg, log).Run(ctx)
	waitFor(t, "tunnel", func() bool { return hub.Online("acme") })
	conn, err := net.Dial("tcp", cfg.EgressListen)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", allowed, allowed)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("allowed CONNECT: %v %v", err, resp)
	}
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", allowed)
	r2, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r2.Body)
	if string(b) != "token endpoint" {
		t.Fatalf("relayed body %q", b)
	}
	conn.Close()
	c2, _ := net.Dial("tcp", cfg.EgressListen)
	fmt.Fprintf(c2, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	r3, err := http.ReadResponse(bufio.NewReader(c2), &http.Request{Method: http.MethodConnect})
	if err != nil || r3.StatusCode != 403 {
		t.Fatalf("a host the gateway does not allow must be refused: %v %v", err, r3)
	}
	c2.Close()
}

// After an offline expiry the agent re-enrols with its bound key, without a token.
func TestReenrollWithBoundKey(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, cfg, _, log := newTestSetup(t, ctx)
	a := NewAgent(cfg, log)
	if err := a.ensureCert(ctx); err != nil {
		t.Fatal(err)
	}
	fp := Fingerprint(a.leafCert())
	cfg.EnrollToken = ""
	b := NewAgent(cfg, log)
	if err := b.obtain(ctx, "/v1/link/reenroll", ""); err != nil {
		t.Fatalf("re-enrol with the bound key: %v", err)
	}
	if Fingerprint(b.leafCert()) != fp {
		t.Fatal("re-enrolment must keep the bound key")
	}
	// Another key is refused.
	os.WriteFile(filepath.Join(cfg.StateDir, "link-key.pem"), mustKey(), 0o600)
	if err := NewAgent(cfg, log).obtain(ctx, "/v1/link/reenroll", ""); err == nil {
		t.Fatal("a different key must not re-enrol")
	}
}

func mustKey() []byte { k, _, _ := NewKeyAndCSR("x"); return k }

func TestSealToTenant(t *testing.T) {
	k, _ := ecdh.X25519().GenerateKey(rand.Reader)
	env, err := SealTo(k.PublicKey(), []byte("acme|/api/v1/webhooks/github"), []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenWith(k, []byte("acme|/api/v1/webhooks/github"), env)
	if err != nil || string(got) != "payload" {
		t.Fatalf("open: %q %v", got, err)
	}
	if _, err := OpenWith(k, []byte("globex|/api/v1/webhooks/github"), env); err == nil {
		t.Fatal("an envelope for one tenant must not open as another's")
	}
	other, _ := ecdh.X25519().GenerateKey(rand.Reader)
	if _, err := OpenWith(other, []byte("acme|/api/v1/webhooks/github"), env); err == nil {
		t.Fatal("only the tenant's key opens it")
	}
}
