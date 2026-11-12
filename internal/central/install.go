package central

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/httpx"
	"github.com/itsPavanFeed/srustiops-backend/internal/link"
	"github.com/itsPavanFeed/srustiops-backend/internal/secure"
)

// Connection-first onboarding.
//
// A workspace created for a client without peering starts "pending". The
// console issues a one-time install token; `srustiops bootstrap` in the
// client's cluster redeems it at the gateway (the one address the cluster
// needs to reach) and gets back the tenant API's certificate for an internal
// name, the CAs it must trust and a link enrolment token. Every key is made
// in the cluster; central only ever sees certificate requests. When the
// tunnel is up and the tenant plane answers, the workspace turns "active" and
// onboarding and integrations open up.

var localNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

const (
	installTTL    = time.Hour
	serverCertTTL = 365 * 24 * time.Hour
)

// issueInstallToken makes a one-time install token for a pending or tunnel tenant.
func (s *Server) issueInstallToken(ctx context.Context, t *Tenant, by string) (string, time.Time, error) {
	tok, err := secure.NewToken("i")
	if err != nil {
		return "", time.Time{}, err
	}
	exp := time.Now().Add(installTTL)
	if err := s.store.CreateInstallToken(ctx, t.ID, secure.HashToken(tok), by, exp); err != nil {
		return "", time.Time{}, err
	}
	s.store.AddInstallEvent(ctx, t.ID, "token_issued", "by "+by)
	s.audit(ctx, by, "tenant.install_token", "tenant/"+t.Slug, t.Slug, map[string]any{"expires_at": exp})
	return tok, exp, nil
}

// installView is what the console's install page shows.
type installView struct {
	Status       string          `json:"status"`
	Connectivity string          `json:"connectivity"`
	Target       string          `json:"target"`
	Online       bool            `json:"online"`
	InternalName string          `json:"internal_name"`
	GatewayURL   string          `json:"gateway_url"`
	CentralURL   string          `json:"central_url"`
	GatewayCA    string          `json:"gateway_ca,omitempty"` // to pin when the gateway's certificate is private
	ImageRepo    string          `json:"image_repo"`
	ImageTag     string          `json:"image_tag"`
	Events       []*InstallEvent `json:"events"`
	Token        string          `json:"token,omitempty"` // only when just issued
	ExpiresAt    *time.Time      `json:"expires_at,omitempty"`
}

func (s *Server) installView(ctx context.Context, t *Tenant) *installView {
	v := &installView{Status: t.Status, Connectivity: t.Connectivity, Target: t.Target, Online: s.online(ctx, t),
		InternalName: link.InternalName(t.Slug), GatewayURL: s.cfg.LinkPublicURL, CentralURL: s.cfg.PublicURL, ImageRepo: s.cfg.ImageRepo, ImageTag: s.cfg.ImageTag, Events: []*InstallEvent{}}
	if es, err := s.store.InstallEvents(ctx, t.ID); err == nil {
		v.Events = es
	}
	if s.cfg.LinkServerCA != "" {
		if b, err := os.ReadFile(s.cfg.LinkServerCA); err == nil {
			v.GatewayCA = string(b)
		}
	}
	return v
}

func (s *Server) getInstall(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, true)
	if t == nil {
		return
	}
	if t.Status == "pending" && s.online(r.Context(), t) {
		s.checkActivation(t)
		t, _ = s.store.Tenant(r.Context(), t.Slug)
	}
	httpx.WriteJSON(w, 200, s.installView(r.Context(), t))
}

func (s *Server) createInstallToken(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, true)
	if t == nil {
		return
	}
	if s.link == nil || t.Connectivity != "tunnel" {
		httpx.WriteErr(w, http.StatusConflict, "install tokens are for tenants connected through the tenant link")
		return
	}
	tok, exp, err := s.issueInstallToken(r.Context(), t, current(r).Email)
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	v := s.installView(r.Context(), t)
	v.Token, v.ExpiresAt = tok, &exp
	httpx.WriteJSON(w, 200, v)
}

// installBootstrap redeems an install token: the tenant API's certificate
// (for its internal name), the CAs it must trust and a link enrolment token.
func (s *Server) installBootstrap(w http.ResponseWriter, r *http.Request) {
	ip := httpx.ClientIP(r)
	if s.limiter.Blocked(ip) {
		httpx.WriteErr(w, http.StatusTooManyRequests, "too many failed attempts")
		return
	}
	var b struct {
		Tenant    string `json:"tenant"`
		Token     string `json:"token"`
		ServerCSR string `json:"server_csr"`
		// In-cluster names runners use for the API (service names, localhost).
		ServerNames []string `json:"server_names"`
	}
	if !httpx.Decode(w, r, &b) {
		return
	}
	t, err := s.store.TakeInstallToken(r.Context(), b.Tenant, secure.HashToken(b.Token))
	if err != nil {
		s.limiter.Fail(ip)
		httpx.WriteErr(w, http.StatusUnauthorized, "install token is invalid, used or expired: issue a new one in the console")
		return
	}
	s.store.AddInstallEvent(r.Context(), t.ID, "token_redeemed", "from "+ip)
	if s.cfg.ClientCA == "" {
		httpx.WriteErr(w, http.StatusServiceUnavailable, "this central plane has no SRUSTIOPS_CLIENT_CA configured; a platform admin must set it")
		return
	}
	clientCA, err := os.ReadFile(s.cfg.ClientCA)
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	csr, err := link.ParseCSR([]byte(b.ServerCSR))
	if err != nil {
		httpx.WriteErr(w, 422, err.Error())
		return
	}
	name := link.InternalName(t.Slug)
	var also []string
	for _, n := range b.ServerNames {
		n = strings.ToLower(strings.TrimSpace(n))
		// Never another tenant's internal name: central dials tenants by it.
		if len(also) < 8 && localNameRe.MatchString(n) && !strings.HasSuffix(n, ".tenant.srustiops.internal") {
			also = append(also, n)
		}
	}
	_, certPEM, err := s.link.serverCA.SignServer(csr, name, serverCertTTL, also...)
	if err != nil {
		httpx.WriteErr(w, 422, err.Error())
		return
	}
	// The tenant API is now identified by the internal name under central's
	// own CA: central needs no customer PKI to trust it.
	t.BackendURL, t.ServerCAPEM = "https://"+name, string(s.link.serverCA.PEM)
	if _, err := s.store.UpdateTenant(r.Context(), t); err != nil {
		s.storeErr(w, err, "")
		return
	}
	// The cluster made this key; pin it so the CA alone cannot stand in.
	if err := s.store.PinServerKey(r.Context(), t.ID, keyFingerprint(csr)); err != nil {
		s.storeErr(w, err, "")
		return
	}
	s.cache.purge() // the gateway listener is not the main one: clear cached tenant records here
	enroll, err := secure.NewToken("l")
	if err == nil {
		err = s.store.CreateEnrollment(r.Context(), t.ID, secure.HashToken(enroll), "install:"+t.Slug, time.Now().Add(installTTL))
	}
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	s.store.AddInstallEvent(r.Context(), t.ID, "certificates_issued", name)
	s.audit(r.Context(), "install:"+t.Slug, "tenant.bootstrap", "tenant/"+t.Slug, t.Slug, map[string]string{"ip": ip, "name": name})
	httpx.WriteJSON(w, 200, map[string]string{
		"tenant":             t.Slug,
		"internal_name":      name,
		"server_certificate": string(certPEM),
		"server_ca":          string(s.link.serverCA.PEM),
		"central_client_ca":  string(clientCA),
		"central_issuer":     s.cfg.PublicURL,
		"link_url":           s.cfg.LinkPublicURL,
		"link_enroll_token":  enroll,
	})
}

// checkActivation turns a pending tenant active once its plane answers
// through the link as itself.
func (s *Server) checkActivation(t *Tenant) {
	if t.Status != "pending" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rt, err := s.transport(t)
	if err != nil {
		return
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, t.BackendURL+"/healthz", nil)
	resp, err := (&http.Client{Transport: rt}).Do(req)
	if err != nil {
		s.store.AddInstallEvent(ctx, t.ID, "health_failed", trim(err.Error(), 200))
		return
	}
	defer resp.Body.Close()
	var h struct{ Tenant string }
	json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&h)
	if resp.StatusCode != 200 || h.Tenant != t.Slug {
		s.store.AddInstallEvent(ctx, t.ID, "health_failed", "the tenant plane did not identify as "+t.Slug)
		return
	}
	if s.store.ActivateTenant(ctx, t.ID) {
		s.store.AddInstallEvent(ctx, t.ID, "tenant_healthy", "workspace active")
		s.audit(ctx, "system:install", "tenant.activated", "tenant/"+t.Slug, t.Slug, nil)
		s.log.Info("tenant connected and active", "tenant", t.Slug)
	}
}

// pendingRefusal: a workspace whose cluster is not connected yet opens
// nothing but its install page.
func pendingRefusal(w http.ResponseWriter, t *Tenant) bool {
	if t.Status != "pending" {
		return false
	}
	httpx.WriteJSON(w, http.StatusConflict, map[string]string{"code": "tenant_pending",
		"error": "tenant_pending: " + t.Name + " is not connected yet; finish connecting its cluster first (Platform → " + t.Slug + " → Connect)"})
	return true
}
