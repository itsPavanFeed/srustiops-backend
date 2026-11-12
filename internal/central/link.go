package central

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/certs"
	"github.com/itsPavanFeed/srustiops-backend/internal/httpx"
	"github.com/itsPavanFeed/srustiops-backend/internal/link"
	"github.com/itsPavanFeed/srustiops-backend/internal/secure"
)

// gateway is the central side of the tenant link: the tunnels this replica
// holds, the link CA, and how to reach tunnels held by other replicas.
type gateway struct {
	ca         *link.CA
	serverCA   *link.CA // issues bootstrapped tenants' API certificates
	hub        *link.Hub
	replica    string
	replicaURL string
	peerCert   *tls.Certificate // this replica's identity towards other replicas
	serverCAs  *x509.CertPool   // trusted for other replicas' gateway certificates

	mu  sync.Mutex
	ids map[*link.Tunnel]string // tunnel → tenant_links row

	flushMu sync.Mutex
	flushes map[string]*sync.Mutex // one webhook flush at a time per tenant
}

// EnableLink turns on the tenant link with the platform's link CA. Without
// it, tunnel tenants are always offline.
func (s *Server) EnableLink(ca, serverCA *link.CA) error {
	g := &gateway{ca: ca, serverCA: serverCA, hub: link.NewHub(), replicaURL: s.cfg.LinkAdvertiseURL, ids: map[*link.Tunnel]string{}, flushes: map[string]*sync.Mutex{}}
	host, _ := os.Hostname()
	g.replica = host + "-" + randHex(4)
	keyPEM, csrPEM, err := link.NewKeyAndCSR(link.ReplicaID)
	if err != nil {
		return err
	}
	csr, _ := link.ParseCSR(csrPEM)
	_, certPEM, err := ca.Sign(csr, link.ReplicaID, 30*24*time.Hour)
	if err != nil {
		return err
	}
	pc, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	g.peerCert = &pc
	if s.cfg.LinkServerCA != "" {
		b, err := os.ReadFile(s.cfg.LinkServerCA)
		if err != nil {
			return fmt.Errorf("SRUSTIOPS_LINK_SERVER_CA: %w", err)
		}
		g.serverCAs = x509.NewCertPool()
		if !g.serverCAs.AppendCertsFromPEM(b) {
			return errors.New("SRUSTIOPS_LINK_SERVER_CA contains no certificates")
		}
	}
	g.hub.OnChange = s.linkChanged
	g.hub.Egress = s.egressFor
	s.link = g
	return nil
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// runLink serves the gateway listener until ctx ends.
func (s *Server) runLink(ctx context.Context) error {
	g := s.link
	s.store.DeleteReplicaLinks(context.WithoutCancel(ctx), g.replica)
	kp, err := certs.NewKeyPair(s.cfg.LinkTLSCert, s.cfg.LinkTLSKey)
	if err != nil {
		return fmt.Errorf("link TLS certificate: %w", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteJSON(w, 200, map[string]string{"status": "ok", "replica": g.replica})
	})
	mux.HandleFunc("POST /v1/link/enroll", s.linkEnroll)
	mux.HandleFunc("POST /v1/link/renew", s.linkRenew)
	mux.HandleFunc("POST /v1/link/reenroll", s.linkReenroll)
	mux.HandleFunc("GET /v1/link/connect", func(w http.ResponseWriter, r *http.Request) { s.linkConnect(ctx, w, r) })
	mux.HandleFunc("GET /v1/link/relay/{tenant}", s.linkRelay)
	mux.HandleFunc("POST /v1/install/bootstrap", s.installBootstrap)
	// Tenants behind the link fetch central's assertion keys here: the
	// gateway is the one address they reach.
	mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.Write(s.issuer.JWKS())
	})
	srv := &http.Server{
		Addr: s.cfg.LinkListen, Handler: s.admitGateway(mux),
		ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 16 << 10,
		ErrorLog: slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
		// HTTP/1.1 only: tunnels start with an HTTP/1.1 upgrade.
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12, GetCertificate: kp.GetCertificate, NextProtos: []string{"http/1.1"},
			ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: g.ca.Pool(),
		},
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServeTLS("", "") }()
	s.log.Info("tenant link gateway serving", "listen", s.cfg.LinkListen, "public_url", s.cfg.LinkPublicURL, "replica", g.replica)
	select {
	case <-ctx.Done():
		// Move every agent to another replica first; open streams (run
		// logs, events) get DrainGrace to finish.
		s.log.Info("draining tenant links", "replica", g.replica, "grace", link.DrainGrace)
		g.hub.Drain(link.DrainGrace)
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
		s.store.DeleteReplicaLinks(sctx, g.replica)
		return nil
	case err := <-errc:
		return err
	}
}

// peer returns the verified link certificate of the caller, if any.
func peer(r *http.Request) *x509.Certificate {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
		return nil
	}
	return r.TLS.VerifiedChains[0][0]
}

type certBody struct {
	Tenant string `json:"tenant"`
	Token  string `json:"token"`
	CSR    string `json:"csr"`
}

func (s *Server) issueLinkCert(w http.ResponseWriter, r *http.Request, t *Tenant, csrPEM, via string) {
	csr, err := link.ParseCSR([]byte(csrPEM))
	if err != nil {
		httpx.WriteErr(w, 422, err.Error())
		return
	}
	c, certPEM, err := s.link.ca.Sign(csr, link.TenantID(t.Slug), s.cfg.LinkCertTTL)
	if err != nil {
		httpx.WriteErr(w, 422, err.Error())
		return
	}
	lc := &LinkCert{Serial: link.Serial(c), Fingerprint: link.Fingerprint(c), IssuedVia: via, NotAfter: c.NotAfter}
	if err := s.store.AddLinkCert(r.Context(), t.ID, lc); err != nil {
		s.storeErr(w, err, "")
		return
	}
	s.audit(r.Context(), "link:"+t.Slug, "link."+via, "tenant/"+t.Slug, t.Slug, map[string]any{"serial": lc.Serial, "fingerprint": lc.Fingerprint, "ip": httpx.ClientIP(r), "expires_at": c.NotAfter})
	httpx.WriteJSON(w, 200, map[string]any{"certificate": string(certPEM), "ca": string(s.link.ca.PEM), "expires_at": c.NotAfter})
}

// linkEnroll trades a one-time enrolment token for the first link certificate.
func (s *Server) linkEnroll(w http.ResponseWriter, r *http.Request) {
	ip := httpx.ClientIP(r)
	if s.limiter.Blocked(ip) {
		httpx.WriteErr(w, http.StatusTooManyRequests, "too many failed enrolment attempts")
		return
	}
	var b certBody
	if !httpx.Decode(w, r, &b) {
		return
	}
	t, err := s.store.TakeEnrollment(r.Context(), b.Tenant, secure.HashToken(b.Token))
	if err != nil {
		s.limiter.Fail(ip)
		httpx.WriteErr(w, http.StatusUnauthorized, "enrolment token is invalid, used or expired")
		return
	}
	if t.Connectivity != "tunnel" {
		httpx.WriteErr(w, http.StatusConflict, "tenant "+t.Slug+" is not set to connect through the tenant link")
		return
	}
	s.issueLinkCert(w, r, t, b.CSR, "enroll")
}

// linkRenew issues the next certificate to an agent presenting a valid one.
func (s *Server) linkRenew(w http.ResponseWriter, r *http.Request) {
	c := peer(r)
	slug, ok := "", false
	if c != nil {
		slug, ok = link.TenantOf(c)
	}
	if !ok || !s.store.LinkCertValid(r.Context(), slug, link.Serial(c)) {
		httpx.WriteErr(w, http.StatusUnauthorized, "a valid, unrevoked link certificate is required")
		return
	}
	var b certBody
	if !httpx.Decode(w, r, &b) {
		return
	}
	t, err := s.store.Tenant(r.Context(), slug)
	if err != nil {
		httpx.WriteErr(w, http.StatusForbidden, "unknown tenant")
		return
	}
	csr, err := link.ParseCSR([]byte(b.CSR))
	if err != nil || keyFingerprint(csr) != link.Fingerprint(c) {
		httpx.WriteErr(w, 422, "renewal keeps the link's bound key")
		return
	}
	s.issueLinkCert(w, r, t, b.CSR, "renew")
}

// linkReenroll lets an agent whose certificate expired while it was offline
// come back with its bound key, within 30 days and only if never revoked.
func (s *Server) linkReenroll(w http.ResponseWriter, r *http.Request) {
	ip := httpx.ClientIP(r)
	if s.limiter.Blocked(ip) {
		httpx.WriteErr(w, http.StatusTooManyRequests, "too many failed attempts")
		return
	}
	var b certBody
	if !httpx.Decode(w, r, &b) {
		return
	}
	csr, err := link.ParseCSR([]byte(b.CSR))
	if err != nil || csr.CheckSignature() != nil {
		httpx.WriteErr(w, 422, "a CSR signed by the link's bound key is required")
		return
	}
	if !s.store.LinkReenrollable(r.Context(), b.Tenant, keyFingerprint(csr)) {
		s.limiter.Fail(ip)
		httpx.WriteErr(w, http.StatusUnauthorized, "re-enrolment refused: unknown or revoked key, or the last certificate expired more than 30 days ago; issue a new enrolment token")
		return
	}
	t, err := s.store.Tenant(r.Context(), b.Tenant)
	if err != nil {
		httpx.WriteErr(w, http.StatusUnauthorized, "unknown tenant")
		return
	}
	s.issueLinkCert(w, r, t, b.CSR, "reenroll")
}

func keyFingerprint(csr *x509.CertificateRequest) string {
	return link.KeyFingerprint(csr.RawSubjectPublicKeyInfo)
}

func upgrade(w http.ResponseWriter, proto string) (net.Conn, *bufio.Reader, error) {
	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return nil, nil, err
	}
	conn.SetDeadline(time.Time{})
	if _, err := fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: %s\r\n\r\n", proto); err != nil {
		conn.Close()
		return nil, nil, err
	}
	return conn, brw.Reader, nil
}

// linkConnect accepts a tenant's tunnel. The tenant is taken from the
// certificate, never from the request.
func (s *Server) linkConnect(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), link.Proto) {
		httpx.WriteErr(w, http.StatusUpgradeRequired, "upgrade to "+link.Proto)
		return
	}
	c := peer(r)
	slug, ok := "", false
	if c != nil {
		slug, ok = link.TenantOf(c)
	}
	if !ok {
		httpx.WriteErr(w, http.StatusUnauthorized, "a link certificate is required")
		return
	}
	if claimed := r.Header.Get("X-SrustiOps-Tenant"); claimed != "" && claimed != slug {
		httpx.WriteErr(w, http.StatusForbidden, "certificate was issued to another tenant")
		return
	}
	serial := link.Serial(c)
	if !s.store.LinkCertValid(r.Context(), slug, serial) {
		httpx.WriteErr(w, http.StatusUnauthorized, "link certificate is revoked or unknown")
		return
	}
	// Every tenant runs the agent: tunnel tenants for API streams and
	// control, direct tenants for control only.
	if _, err := s.store.Tenant(r.Context(), slug); err != nil {
		httpx.WriteErr(w, http.StatusForbidden, "unknown tenant")
		return
	}
	if s.tunnelsFull(slug) {
		// The agent backs off and tries again; old tunnels close on their own.
		httpx.WriteLimited(w, http.StatusTooManyRequests, "rate_limited", "tunnels", "workspace "+slug+" holds as many tunnels as it may on this gateway", 10*time.Second)
		return
	}
	conn, br, err := upgrade(w, link.Proto)
	if err != nil {
		return
	}
	remote := httpx.ClientIP(r)
	go func() {
		// Not bound to ctx: at shutdown the hub drains tunnels first.
		err := s.link.hub.Serve(context.WithoutCancel(ctx), &link.BufConn{Conn: conn, R: br}, slug, serial, remote)
		s.log.Info("tenant link closed", "tenant", slug, "remote", remote, "reason", err)
	}()
}

// linkRelay lets another replica open a stream on a tunnel this one holds.
func (s *Server) linkRelay(w http.ResponseWriter, r *http.Request) {
	c := peer(r)
	if c == nil || !link.IsReplica(c) || !strings.EqualFold(r.Header.Get("Upgrade"), link.RelayProto) {
		httpx.WriteErr(w, http.StatusUnauthorized, "replicas only")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	stream, err := s.link.hub.DialLane(ctx, r.PathValue("tenant"), r.URL.Query().Get("lane"))
	cancel()
	if err != nil {
		httpx.WriteErr(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	conn, br, err := upgrade(w, link.RelayProto)
	if err != nil {
		stream.Close()
		return
	}
	go link.Pipe(&link.BufConn{Conn: conn, R: br}, stream)
}

// linkChanged keeps tenant_links in step with the hub, drops tunnels whose
// certificate was revoked meanwhile, and flushes webhooks queued while the
// tenant was offline.
func (s *Server) linkChanged(t *link.Tunnel, up bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	g := s.link
	g.mu.Lock()
	id, known := g.ids[t]
	if up && !known {
		id = newUUID()
		g.ids[t] = id
	}
	if !up {
		delete(g.ids, t)
	}
	g.mu.Unlock()
	if !up {
		s.store.DeleteLink(ctx, id)
		if ten, err := s.store.Tenant(ctx, t.Tenant); err == nil {
			s.store.TouchLinkSeen(ctx, ten.ID, time.Now())
		}
		s.audit(ctx, "link:"+t.Tenant, "link.disconnect", "tenant/"+t.Tenant, t.Tenant, map[string]string{"serial": t.Serial, "remote": t.Remote})
		return
	}
	ten, err := s.store.Tenant(ctx, t.Tenant)
	if err != nil {
		return
	}
	if !known {
		s.cache.purge() // a new tunnel may make a pending workspace active
	}
	if !s.store.LinkCertValid(ctx, t.Tenant, t.Serial) {
		s.log.Warn("dropping tenant link: certificate revoked", "tenant", t.Tenant, "serial", t.Serial)
		g.hub.Drop(t.Tenant, t.Serial)
		return
	}
	if err := s.store.UpsertLink(ctx, ten.ID, id, &LinkRow{Replica: g.replica, ReplicaURL: g.replicaURL, Serial: t.Serial, Remote: t.Remote,
		ConnectedAt: t.Connected, LastSeen: t.LastSeen(), Version: t.Version(), Mode: t.Mode(), Lane: t.Lane(), SkewMS: t.ClockSkew().Milliseconds()}); err != nil {
		s.log.Warn("recording tenant link failed", "tenant", t.Tenant, "err", err)
	}
	if !known {
		s.log.Info("tenant link open", "tenant", t.Tenant, "remote", t.Remote, "serial", t.Serial)
		s.audit(ctx, "link:"+t.Tenant, "link.connect", "tenant/"+t.Tenant, t.Tenant, map[string]string{"serial": t.Serial, "remote": t.Remote})
		go func() {
			kctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			if err := s.fetchTenantKeys(kctx, ten); err != nil {
				s.log.Warn("reading the tenant's directory keys failed", "tenant", ten.Slug, "err", err)
			}
			s.flushWebhooks(ten)
		}()
		s.syncLater(ten)
		if ten.Status == "pending" {
			s.store.AddInstallEvent(ctx, ten.ID, "tunnel_online", "from "+t.Remote)
			go s.checkActivation(ten)
		}
	}
}

func newUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// dialTenant opens a stream to a tunnel tenant's API: through a tunnel on
// this replica, else through a replica that holds one.
func (s *Server) dialTenant(ctx context.Context, t *Tenant, lane string) (net.Conn, error) {
	if s.link == nil {
		return nil, link.ErrOffline
	}
	c, err := s.link.hub.DialLane(ctx, t.Slug, lane)
	if !errors.Is(err, link.ErrOffline) {
		return c, err
	}
	links, err := s.store.Links(ctx, t.ID)
	if err != nil {
		return nil, err
	}
	for _, l := range links {
		if l.Replica == s.link.replica {
			continue
		}
		if c, err := s.relay(ctx, l.ReplicaURL, t.Slug, lane); err == nil {
			return c, nil
		} else {
			s.log.Warn("relay to replica failed", "replica", l.Replica, "tenant", t.Slug, "err", err)
		}
	}
	return nil, link.ErrOffline
}

func (s *Server) relay(ctx context.Context, replicaURL, slug, lane string) (net.Conn, error) {
	u, err := url.Parse(replicaURL)
	if err != nil {
		return nil, err
	}
	// Replicas are addressed by pod address; every one serves the gateway's
	// public certificate, so that is the name to verify.
	name := u.Hostname()
	if pu, err := url.Parse(s.cfg.LinkPublicURL); err == nil && pu.Hostname() != "" {
		name = pu.Hostname()
	}
	d := tls.Dialer{Config: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: s.link.serverCAs, ServerName: name,
		Certificates: []tls.Certificate{*s.link.peerCert}, NextProtos: []string{"http/1.1"}}}
	conn, err := d.DialContext(ctx, "tcp", u.Host)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(conn, "GET /v1/link/relay/%s?lane=%s HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: %s\r\n\r\n", slug, url.QueryEscape(lane), u.Host, link.RelayProto)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		conn.Close()
		return nil, errors.New("replica answered " + resp.Status)
	}
	return &link.BufConn{Conn: conn, R: br}, nil
}

// online reports whether central can reach the tenant plane now.
func (s *Server) online(ctx context.Context, t *Tenant) bool {
	if t.Connectivity != "tunnel" {
		return true
	}
	if s.link == nil {
		return false
	}
	if s.link.hub.Online(t.Slug) {
		return true
	}
	// This replica knows its own tunnels; others report theirs in tenant_links.
	ls, err := s.store.Links(ctx, t.ID)
	if err != nil {
		return false
	}
	for _, l := range ls {
		if l.Replica != s.link.replica {
			return true
		}
	}
	return false
}

// ---- admin API: link status, enrolment, revocation ----

func (s *Server) tenantLink(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, true)
	if t == nil {
		return
	}
	tunnels, err := s.store.Links(r.Context(), t.ID)
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	certs, err := s.store.LinkCerts(r.Context(), t.ID, 20)
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	if tunnels == nil {
		tunnels = []*LinkRow{}
	}
	if certs == nil {
		certs = []*LinkCert{}
	}
	httpx.WriteJSON(w, 200, map[string]any{
		"connectivity":    t.Connectivity,
		"gateway_enabled": s.link != nil,
		"gateway_url":     s.cfg.LinkPublicURL,
		"online":          s.online(r.Context(), t),
		"tunnels":         tunnels,
		"certificates":    certs,
		"queued_webhooks": s.store.QueuedWebhookCount(r.Context(), t.ID),
	})
}

func (s *Server) createEnrollment(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, true)
	if t == nil {
		return
	}
	if s.link == nil {
		httpx.WriteErr(w, http.StatusConflict, "the tenant link gateway is not enabled on this central plane (SRUSTIOPS_LINK_LISTEN)")
		return
	}
	s.enrollmentResponse(w, r, t, 200)
}

// enrollmentResponse issues a one-time enrolment token and the agent's settings.
func (s *Server) enrollmentResponse(w http.ResponseWriter, r *http.Request, t *Tenant, code int, extra ...map[string]any) {
	tok, err := secure.NewToken("l")
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	exp := time.Now().Add(link.EnrollTTL)
	if err := s.store.CreateEnrollment(r.Context(), t.ID, secure.HashToken(tok), current(r).Email, exp); err != nil {
		s.storeErr(w, err, "")
		return
	}
	s.audit(r.Context(), current(r).Email, "link.enrollment.create", "tenant/"+t.Slug, t.Slug, map[string]any{"expires_at": exp})
	res := map[string]any{
		"token":      tok,
		"expires_at": exp,
		"agent_settings": map[string]string{
			"SRUSTIOPS_TENANT":            t.Slug,
			"SRUSTIOPS_LINK_URL":          s.cfg.LinkPublicURL,
			"SRUSTIOPS_LINK_ENROLL_TOKEN": tok,
			"SRUSTIOPS_LINK_TARGET":       "host:port of the tenant API, as the agent reaches it",
			"SRUSTIOPS_LINK_STATE_DIR":    "a persistent directory for the link key and certificate",
			"SRUSTIOPS_LINK_MODE":         map[bool]string{true: link.ModeTunnel, false: link.ModeControl}[t.Connectivity == "tunnel"],
		},
	}
	for _, e := range extra {
		for k, v := range e {
			res[k] = v
		}
	}
	httpx.WriteJSON(w, code, res)
}

func (s *Server) revokeLinkCert(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, true)
	if t == nil {
		return
	}
	serial := r.PathValue("serial")
	revoked, err := s.store.RevokeLinkCerts(r.Context(), t.ID, serial, current(r).Email)
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	if len(revoked) == 0 {
		httpx.WriteErr(w, 404, "no live certificate with that serial")
		return
	}
	dropped := 0
	if s.link != nil {
		for _, sn := range revoked {
			dropped += s.link.hub.Drop(t.Slug, sn)
		}
	}
	s.audit(r.Context(), current(r).Email, "link.revoke", "tenant/"+t.Slug, t.Slug, map[string]any{"serial": serial, "revoked": revoked})
	httpx.WriteJSON(w, 200, map[string]any{"revoked": len(revoked), "tunnels_closed": dropped})
}

// ---- webhooks for offline tenants ----

// flushWebhooks delivers webhooks queued while the tenant was offline, oldest
// first, and stops at the first failure so order is kept.
func (s *Server) flushWebhooks(t *Tenant) {
	// Every tunnel that opens triggers a flush; they take turns so a delivery
	// is never sent twice.
	s.link.flushMu.Lock()
	m := s.link.flushes[t.ID]
	if m == nil {
		m = &sync.Mutex{}
		s.link.flushes[t.ID] = m
	}
	s.link.flushMu.Unlock()
	m.Lock()
	defer m.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	sent := 0
	for {
		qs, err := s.store.QueuedWebhooks(ctx, t.ID, 50)
		if err != nil || len(qs) == 0 {
			break
		}
		for _, q := range qs {
			resp, err := s.relayToTenant(ctx, t, "/api/v1/webhooks/queued", map[string]string{"Content-Type": "application/json"},
				mustJSON(map[string]any{"path": q.Path, "envelope": q.Sealed}))
			if err != nil {
				s.log.Warn("queued webhook delivery failed; will retry on the next connect", "tenant", t.Slug, "err", err)
				return
			}
			io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			resp.Body.Close()
			if resp.StatusCode >= 500 {
				return
			}
			s.store.DeleteQueuedWebhook(ctx, q.ID)
			sent++
		}
	}
	// Tell the tenant what a full or expired queue dropped, so it can resync.
	if n := s.store.TakeWebhooksDropped(ctx, t.ID); n > 0 {
		code, _, err := s.callTenantAs(ctx, t, s.system(t), http.MethodPost, "/api/v1/link/events",
			map[string]any{"type": "webhooks_dropped", "count": n, "detail": fmt.Sprintf("%d webhook deliveries were dropped while the tenant was offline (queue full or older than 72 hours).", n)})
		if err != nil || code >= 300 {
			s.log.Warn("could not report dropped webhooks to the tenant; will retry", "tenant", t.Slug, "code", code, "err", err)
			s.store.Pool().Exec(ctx, `UPDATE tenants SET webhooks_dropped = webhooks_dropped + $2 WHERE id = $1`, t.ID, n)
		}
		s.audit(ctx, "system:link", "link.webhooks_dropped", "tenant/"+t.Slug, t.Slug, map[string]int{"count": n})
	}
	if sent > 0 {
		s.log.Info("delivered queued webhooks", "tenant", t.Slug, "count", sent)
	}
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

// egressFor relays a tenant's egress stream to a host its identity
// provider uses (issuer, token and key endpoints), and nothing else.
func (s *Server) egressFor(ctx context.Context, tenant, target string) (net.Conn, error) {
	t, err := s.store.Tenant(ctx, tenant)
	if err != nil {
		return nil, err
	}
	p, err := s.store.TenantIdP(ctx, t.ID)
	if err != nil {
		return nil, errors.New("no identity provider is configured for this tenant")
	}
	for _, h := range p.EgressHosts {
		if h == target {
			d := net.Dialer{Timeout: 10 * time.Second}
			s.audit(ctx, "link:"+tenant, "link.egress", "host/"+target, tenant, nil)
			return d.DialContext(ctx, "tcp", target)
		}
	}
	return nil, fmt.Errorf("%s is not an allowed identity provider host for this tenant", target)
}
