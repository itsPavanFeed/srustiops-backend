package link

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
)

// AgentConfig configures `srustiops link`, the agent that runs beside a tenant plane.
type AgentConfig struct {
	Tenant      string         // this tenant's slug; the issued certificate must name it
	URL         *url.URL       // the gateway, https://host:port
	Target      string         // host:port of the tenant API; the only place streams go
	ServerCAs   *x509.CertPool // pinned CA of the gateway's certificate (nil = system roots)
	StateDir    string         // holds link-key.pem and link.pem
	EnrollToken string         // one-time token, needed only until the first certificate
	Connections int            // tunnels kept open at once
	// Mode is "tunnel" (API streams and control) or "control" (control only,
	// for a tenant central reaches directly).
	Mode    string
	Version string
	// EgressListen, when set, serves an HTTP CONNECT proxy here that relays
	// over the link to hosts central allows for this tenant (its identity
	// provider), for tenants with no other way out.
	EgressListen string
}

type Agent struct {
	cfg  AgentConfig
	log  *slog.Logger
	mu   sync.RWMutex
	cert *tls.Certificate
	leaf *x509.Certificate
	// The newest open tunnel, used for egress streams.
	sessMu sync.Mutex
	sess   *yamux.Session
	// renewed is closed (and replaced) after each certificate renewal, so
	// every tunnel moves to the new certificate before the old one expires.
	renewedMu sync.Mutex
	renewed   chan struct{}
}

func (a *Agent) renewedC() <-chan struct{} {
	a.renewedMu.Lock()
	defer a.renewedMu.Unlock()
	return a.renewed
}

func (a *Agent) announceRenewal() {
	a.renewedMu.Lock()
	close(a.renewed)
	a.renewed = make(chan struct{})
	a.renewedMu.Unlock()
}

func NewAgent(cfg AgentConfig, log *slog.Logger) *Agent {
	if cfg.Connections < 1 {
		cfg.Connections = 2
	}
	if cfg.Mode == "" {
		cfg.Mode = ModeTunnel
	}
	if cfg.Mode == ModeControl {
		cfg.Connections = 1
	}
	return &Agent{cfg: cfg, log: log, renewed: make(chan struct{})}
}

func (a *Agent) keyFile() string  { return filepath.Join(a.cfg.StateDir, "link-key.pem") }
func (a *Agent) certFile() string { return filepath.Join(a.cfg.StateDir, "link.pem") }

// Run enrols or recovers if needed, then keeps the tunnels open and the
// certificate fresh.
func (a *Agent) Run(ctx context.Context) error {
	if err := os.MkdirAll(a.cfg.StateDir, 0o700); err != nil {
		return err
	}
	if err := a.ensureCert(ctx); err != nil {
		return err
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); a.renewLoop(ctx) }()
	if a.cfg.EgressListen != "" {
		wg.Add(1)
		go func() { defer wg.Done(); a.serveEgress(ctx) }()
	}
	for i := range a.cfg.Connections {
		wg.Add(1)
		go func() { defer wg.Done(); a.connectLoop(ctx, i) }()
	}
	wg.Wait()
	return nil
}

// ensureCert makes sure a valid certificate is loaded: the stored one, a
// re-enrolment with the bound key after an offline expiry, or a first
// enrolment with the one-time token.
func (a *Agent) ensureCert(ctx context.Context) error {
	err := a.load()
	if err == nil && time.Now().Before(a.leafCert().NotAfter) {
		return nil
	}
	if err == nil { // expired while offline: the bound key proves who we are
		if rerr := a.obtain(ctx, "/v1/link/reenroll", ""); rerr == nil {
			a.log.Info("re-enrolled with the bound key after the certificate expired", "serial", Serial(a.leafCert()))
			return nil
		} else if a.cfg.EnrollToken == "" {
			return fmt.Errorf("the link certificate expired and re-enrolment was refused (%v): issue a new enrolment token", rerr)
		}
	}
	if a.cfg.EnrollToken == "" {
		return errors.New("no valid link certificate in the state directory: set SRUSTIOPS_LINK_ENROLL_TOKEN to a one-time enrolment token from central")
	}
	if err := a.obtain(ctx, "/v1/link/enroll", a.cfg.EnrollToken); err != nil {
		return fmt.Errorf("enrolment: %w", err)
	}
	a.log.Info("enrolled with the central gateway", "tenant", a.cfg.Tenant, "serial", Serial(a.leafCert()), "fingerprint", Fingerprint(a.leafCert()))
	return nil
}

func (a *Agent) leafCert() *x509.Certificate {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.leaf
}

func (a *Agent) load() error {
	c, err := tls.LoadX509KeyPair(a.certFile(), a.keyFile())
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return err
	}
	if slug, ok := TenantOf(leaf); !ok || slug != a.cfg.Tenant {
		return fmt.Errorf("the stored link certificate is not for tenant %s", a.cfg.Tenant)
	}
	a.mu.Lock()
	a.cert, a.leaf = &c, leaf
	a.mu.Unlock()
	return nil
}

func (a *Agent) tlsConfig(withCert bool) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: a.cfg.ServerCAs, ServerName: a.cfg.URL.Hostname(),
		NextProtos: []string{"http/1.1"},
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			a.mu.RLock()
			defer a.mu.RUnlock()
			if a.cert == nil || !withCert {
				return &tls.Certificate{}, nil
			}
			return a.cert, nil
		},
	}
}

// boundKey reads the link's private key; it stays the same across renewals
// and re-enrolment, so its fingerprint identifies the link.
func (a *Agent) boundKey() (*ecdsa.PrivateKey, []byte, error) {
	b, err := os.ReadFile(a.keyFile())
	if err != nil {
		return nil, nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, nil, errors.New("link key is not PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, nil, err
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New("link key is not ECDSA")
	}
	return ek, b, nil
}

// obtain gets a certificate. Enrolment makes a new key; renewal (with the
// current certificate) and re-enrolment (after an offline expiry) keep the
// bound key and send a CSR signed by it.
func (a *Agent) obtain(ctx context.Context, path, token string) error {
	var keyPEM, csrPEM []byte
	var err error
	if path == "/v1/link/enroll" {
		keyPEM, csrPEM, err = NewKeyAndCSR(TenantID(a.cfg.Tenant))
	} else {
		var k *ecdsa.PrivateKey
		if k, keyPEM, err = a.boundKey(); err == nil {
			var der []byte
			der, err = x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: TenantID(a.cfg.Tenant)}}, k)
			csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
		}
	}
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]string{"tenant": a.cfg.Tenant, "token": token, "csr": string(csrPEM)})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.URL.String()+path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	hc := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: a.tlsConfig(path == "/v1/link/renew"), ForceAttemptHTTP2: false}}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var out struct {
		Certificate string `json:"certificate"`
		Error       string `json:"error"`
	}
	json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out)
	if resp.StatusCode != 200 {
		return fmt.Errorf("gateway answered %d: %s", resp.StatusCode, out.Error)
	}
	b, _ := pem.Decode([]byte(out.Certificate))
	if b == nil {
		return errors.New("gateway returned no certificate")
	}
	leaf, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return err
	}
	if slug, ok := TenantOf(leaf); !ok || slug != a.cfg.Tenant {
		return errors.New("gateway issued a certificate for another tenant")
	}
	// Key first, certificate second: a crash in between leaves a pair that
	// fails to load, and the next start re-enrols or asks for a token.
	if err := writeAtomic(a.keyFile(), keyPEM, 0o600); err != nil {
		return err
	}
	if err := writeAtomic(a.certFile(), []byte(out.Certificate), 0o644); err != nil {
		return err
	}
	return a.load()
}

func writeAtomic(path string, b []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (a *Agent) renewLoop(ctx context.Context) {
	for {
		leaf := a.leafCert()
		// Renew two thirds into what is left. Not from NotBefore: it is
		// backdated for clock skew, which would make short lifetimes renew at once.
		wait := max(time.Until(leaf.NotAfter)*2/3, 0)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		path := "/v1/link/renew"
		if time.Now().After(leaf.NotAfter) {
			path = "/v1/link/reenroll" // expired while the gateway was unreachable
		}
		if err := a.obtain(ctx, path, ""); err != nil {
			a.log.Warn("link certificate renewal failed; retrying", "err", err, "expires", leaf.NotAfter)
			select {
			case <-ctx.Done():
				return
			case <-time.After(30 * time.Second):
			}
			continue
		}
		a.log.Info("link certificate renewed", "serial", Serial(a.leafCert()), "expires", a.leafCert().NotAfter)
		a.announceRenewal()
	}
}

func (a *Agent) connectLoop(ctx context.Context, n int) {
	backoff := time.Second
	for ctx.Err() == nil {
		start := time.Now()
		drained := make(chan struct{})
		done := make(chan error, 1)
		renewed := a.renewedC()
		go func() { done <- a.serveOnce(ctx, a.lane(n), drained) }()
		select {
		case <-ctx.Done():
			return
		case <-renewed:
			// A new certificate: open a tunnel with it now; the old one keeps
			// its open streams until the gateway closes it at the old
			// certificate's expiry, so nothing waits on a reconnect.
			a.log.Info("certificate renewed; opening a tunnel with it", "tunnel", n)
			backoff = time.Second
			continue
		case <-drained:
			// The replica is draining: open a replacement now; the old tunnel
			// keeps serving its open streams until the gateway closes it.
			a.log.Info("gateway replica draining; opening a replacement tunnel", "tunnel", n)
			backoff = time.Second
			continue
		case err := <-done:
			if ctx.Err() != nil {
				return
			}
			if time.Since(start) > time.Minute {
				backoff = time.Second
			}
			a.log.Warn("tunnel closed; reconnecting", "tunnel", n, "err", err, "in", backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff + time.Duration(mrand.Int64N(int64(backoff/2)+1))):
			}
			backoff = min(backoff*2, 30*time.Second)
		}
	}
}

// serveOnce opens one tunnel and serves it until it breaks. drained is
// closed when the gateway asks this tunnel to move.
// lane is the traffic tunnel n carries: with two or more tunnels the first
// is interactive and the rest bulk (see LaneInteractive).
func (a *Agent) lane(n int) string {
	if a.cfg.Connections < 2 || a.cfg.Mode == ModeControl {
		return ""
	}
	if n == 0 {
		return LaneInteractive
	}
	return LaneBulk
}

func (a *Agent) serveOnce(ctx context.Context, lane string, drained chan struct{}) error {
	if time.Now().After(a.leafCert().NotAfter) {
		if err := a.ensureCert(ctx); err != nil {
			return err
		}
	}
	raw, err := a.dial(ctx)
	if err != nil {
		return err
	}
	conn := tls.Client(raw, a.tlsConfig(true))
	hctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	err = conn.HandshakeContext(hctx)
	cancel()
	if err != nil {
		raw.Close()
		return err
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	host := a.cfg.URL.Host
	fmt.Fprintf(conn, "GET /v1/link/connect HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: %s\r\nX-SrustiOps-Tenant: %s\r\nX-SrustiOps-Link-Mode: %s\r\n\r\n", host, Proto, a.cfg.Tenant, a.cfg.Mode)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		conn.Close()
		return err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		conn.Close()
		return fmt.Errorf("gateway refused the tunnel (%d): %s", resp.StatusCode, bytes.TrimSpace(msg))
	}
	sess, err := yamux.Server(&BufConn{Conn: conn, R: br}, yamuxConfig())
	if err != nil {
		conn.Close()
		return err
	}
	defer sess.Close()
	a.sessMu.Lock()
	a.sess = sess
	a.sessMu.Unlock()
	go a.controlStream(ctx, sess, lane, drained)
	a.log.Info("tunnel open", "gateway", host, "target", a.cfg.Target, "mode", a.cfg.Mode)
	for {
		s, err := sess.Accept()
		if err != nil {
			return fmt.Errorf("tunnel ended: %w", err)
		}
		if a.cfg.Mode != ModeTunnel {
			s.Close() // control-only: central reaches the API directly
			continue
		}
		go a.stream(ctx, s)
	}
}

// controlStream says hello, reports health and clock every 15 seconds, and
// listens for drain.
func (a *Agent) controlStream(ctx context.Context, sess *yamux.Session, lane string, drained chan struct{}) {
	s, err := sess.Open()
	if err != nil {
		return
	}
	defer s.Close()
	enc := json.NewEncoder(s)
	if enc.Encode(Message{Type: "control"}) != nil || enc.Encode(Message{Type: "hello", Version: a.cfg.Version, Mode: a.cfg.Mode, Lane: lane, Time: time.Now().UnixNano()}) != nil {
		return
	}
	go func() {
		dec := json.NewDecoder(s)
		for {
			var m Message
			if dec.Decode(&m) != nil {
				return
			}
			if m.Type == "drain" {
				select {
				case <-drained:
				default:
					close(drained)
				}
			}
		}
	}()
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-sess.CloseChan():
			return
		case <-t.C:
			if enc.Encode(Message{Type: "health", Time: time.Now().UnixNano()}) != nil {
				return
			}
		}
	}
}

// stream pipes one API stream to the tenant API. The target is fixed in the
// agent's configuration; the gateway cannot choose another.
func (a *Agent) stream(ctx context.Context, s net.Conn) {
	d := net.Dialer{Timeout: 10 * time.Second}
	t, err := d.DialContext(ctx, "tcp", a.cfg.Target)
	if err != nil {
		a.log.Warn("tenant API unreachable from the link agent", "target", a.cfg.Target, "err", err)
		s.Close()
		return
	}
	Pipe(s, t)
}

// serveEgress is a local HTTP CONNECT proxy for the tenant plane: each
// connection becomes an egress stream on the link, which central relays only
// to hosts allowed for this tenant (its identity provider).
func (a *Agent) serveEgress(ctx context.Context) {
	ln, err := net.Listen("tcp", a.cfg.EgressListen)
	if err != nil {
		a.log.Error("egress relay could not listen", "addr", a.cfg.EgressListen, "err", err)
		return
	}
	context.AfterFunc(ctx, func() { ln.Close() })
	a.log.Info("egress relay listening", "addr", a.cfg.EgressListen)
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go a.egress(c)
	}
}

func (a *Agent) egress(c net.Conn) {
	br := bufio.NewReader(c)
	c.SetReadDeadline(time.Now().Add(15 * time.Second))
	req, err := http.ReadRequest(br)
	if err != nil || req.Method != http.MethodConnect {
		io.WriteString(c, "HTTP/1.1 405 Method Not Allowed\r\n\r\n")
		c.Close()
		return
	}
	c.SetReadDeadline(time.Time{})
	a.sessMu.Lock()
	sess := a.sess
	a.sessMu.Unlock()
	if sess == nil || sess.IsClosed() {
		io.WriteString(c, "HTTP/1.1 503 Service Unavailable\r\n\r\nlink down\n")
		c.Close()
		return
	}
	s, err := sess.Open()
	if err != nil {
		io.WriteString(c, "HTTP/1.1 503 Service Unavailable\r\n\r\n")
		c.Close()
		return
	}
	json.NewEncoder(s).Encode(Message{Type: "egress", Target: req.Host})
	sr := bufio.NewReader(s)
	line, _ := sr.ReadString('\n')
	if strings.TrimSpace(line) != "ok" {
		io.WriteString(c, "HTTP/1.1 403 Forbidden\r\n\r\n"+line)
		c.Close()
		s.Close()
		return
	}
	io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
	Pipe(&BufConn{Conn: c, R: br}, &BufConn{Conn: s, R: sr})
}

// dial reaches the gateway directly, or through HTTPS_PROXY with CONNECT.
func (a *Agent) dial(ctx context.Context) (net.Conn, error) {
	d := net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	host := a.cfg.URL.Host
	if a.cfg.URL.Port() == "" {
		host = net.JoinHostPort(a.cfg.URL.Hostname(), "443")
	}
	proxy, err := http.ProxyFromEnvironment(&http.Request{URL: a.cfg.URL})
	if err != nil || proxy == nil {
		return d.DialContext(ctx, "tcp", host)
	}
	pc, err := d.DialContext(ctx, "tcp", proxy.Host)
	if err != nil {
		return nil, fmt.Errorf("proxy %s: %w", proxy.Host, err)
	}
	req := "CONNECT " + host + " HTTP/1.1\r\nHost: " + host + "\r\n"
	if u := proxy.User; u != nil {
		pw, _ := u.Password()
		req += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(u.Username()+":"+pw)) + "\r\n"
	}
	if _, err := io.WriteString(pc, req+"\r\n"); err != nil {
		pc.Close()
		return nil, err
	}
	br := bufio.NewReader(pc)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil || resp.StatusCode != 200 {
		pc.Close()
		if err == nil {
			err = fmt.Errorf("proxy answered %s", resp.Status)
		}
		return nil, err
	}
	return &BufConn{Conn: pc, R: br}, nil
}
