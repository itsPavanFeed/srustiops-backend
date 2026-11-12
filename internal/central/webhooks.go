package central

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/httpx"
	"github.com/itsPavanFeed/srustiops-backend/internal/identity"
	"github.com/itsPavanFeed/srustiops-backend/internal/link"
)

// relaySubject must match api.RelaySubject on the tenant plane.
const relaySubject = "system:webhook-relay"

// githubWebhook is the public endpoint a tenant's GitHub App posts to:
// POST /webhooks/github/{tenant}. Central keeps no webhook secret; it relays the
// delivery unchanged to the tenant plane over mTLS with a relay assertion, and
// the tenant plane verifies GitHub's signature with its own secret.
func (s *Server) githubWebhook(w http.ResponseWriter, r *http.Request) {
	ip := httpx.ClientIP(r)
	if s.hookLimiter.Blocked(ip) {
		httpx.WriteErr(w, http.StatusTooManyRequests, "too many requests")
		return
	}
	if r.Header.Get("X-GitHub-Event") == "" || r.Header.Get("X-Hub-Signature-256") == "" {
		s.hookLimiter.Fail(ip)
		httpx.WriteErr(w, http.StatusBadRequest, "not a signed GitHub webhook delivery")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 25<<20+1)) // GitHub caps payloads at 25 MB
	if err != nil || len(body) > 25<<20 {
		httpx.WriteErr(w, http.StatusRequestEntityTooLarge, "payload too large")
		return
	}
	t, err := s.store.Tenant(r.Context(), r.PathValue("tenant"))
	if err != nil {
		s.hookLimiter.Fail(ip)
		httpx.WriteErr(w, http.StatusNotFound, "not found")
		return
	}
	const path = "/api/v1/webhooks/github"
	headers := map[string]string{}
	for _, h := range []string{"Content-Type", "User-Agent", "X-GitHub-Event", "X-GitHub-Delivery", "X-Hub-Signature-256",
		"X-GitHub-Hook-ID", "X-GitHub-Hook-Installation-Target-ID", "X-GitHub-Hook-Installation-Target-Type"} {
		if v := r.Header.Get(h); v != "" {
			headers[h] = v
		}
	}
	s.deliverWebhook(w, r, t, path, headers, body, ip)
}

// deliverWebhook relays a delivery to the tenant plane, or queues it while a
// tunnel tenant is offline (answering 202) for delivery when its link returns.
func (s *Server) deliverWebhook(w http.ResponseWriter, r *http.Request, t *Tenant, path string, headers map[string]string, body []byte, ip string) {
	var resp *http.Response
	var err error
	if s.online(r.Context(), t) {
		resp, err = s.relayToTenant(r.Context(), t, path, headers, body)
	} else {
		err = link.ErrOffline
	}
	if errors.Is(err, link.ErrOffline) {
		// Kept for the tenant, sealed to its key: central cannot read it.
		sealed, serr := s.sealForTenant(t, path, headers, body)
		if serr != nil {
			httpx.WriteErr(w, http.StatusServiceUnavailable, "tenant is offline and cannot take queued deliveries yet: "+serr.Error())
			return
		}
		if err := s.store.QueueWebhook(r.Context(), t.ID, path, sealed); err != nil {
			s.storeErr(w, err, "")
			return
		}
		httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"queued": true, "reason": "tenant link is offline; delivery follows when it reconnects"})
		return
	}
	if err != nil {
		s.log.Warn("webhook relay failed", "tenant", t.Slug, "path", path, "err", err)
		httpx.WriteErr(w, http.StatusBadGateway, "tenant is unreachable")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		s.hookLimiter.Fail(ip)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, io.LimitReader(resp.Body, 64<<10))
}

type queuedDelivery struct {
	Headers map[string]string `json:"headers"`
	Body    []byte            `json:"body"`
}

// sealForTenant seals a delivery to the tenant's pinned encryption key,
// bound to the tenant and the webhook path.
func (s *Server) sealForTenant(t *Tenant, path string, headers map[string]string, body []byte) ([]byte, error) {
	pub, err := s.tenantEncKey(t)
	if err != nil {
		return nil, err
	}
	b, _ := json.Marshal(queuedDelivery{headers, body})
	return link.SealTo(pub, []byte(t.Slug+"|"+path), b)
}

// relayToTenant posts a webhook body to the tenant plane with a relay
// assertion; the tenant verifies the sender's own signature or token.
func (s *Server) relayToTenant(ctx context.Context, t *Tenant, path string, headers map[string]string, body []byte) (*http.Response, error) {
	assertion, err := identity.SignAssertion(s.issuer, &identity.Principal{Subject: relaySubject, Tenant: t.Slug}, http.MethodPost, path, time.Now())
	if err != nil {
		return nil, err
	}
	rt, err := s.transportLane(t, link.LaneBulk)
	if err != nil {
		return nil, err
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, t.BackendURL+path, bytes.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set(assertionHeader, assertion)
	return (&http.Client{Transport: rt, Timeout: 30 * time.Second}).Do(req)
}

// cloudEvent is the public endpoint cloud event routers post to:
// POST /webhooks/cloud/{tenant}/{source}. EventBridge API destinations,
// Pub/Sub push subscriptions and Event Grid webhooks send the event source's
// token (header X-SrustiOps-Event-Token, or ?token= where headers cannot be
// set). Central keeps no token; it relays to the tenant plane, which checks
// it, so a forged or replayed event without the token is refused there.
func (s *Server) cloudEvent(w http.ResponseWriter, r *http.Request) {
	ip := httpx.ClientIP(r)
	if s.hookLimiter.Blocked(ip) {
		httpx.WriteErr(w, http.StatusTooManyRequests, "too many requests")
		return
	}
	token := r.Header.Get("X-SrustiOps-Event-Token")
	if token == "" {
		token = r.URL.Query().Get("token")
	}
	source := r.PathValue("source")
	if token == "" || !eventSourceRe.MatchString(source) {
		s.hookLimiter.Fail(ip)
		httpx.WriteErr(w, http.StatusUnauthorized, "missing event token")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20+1))
	if err != nil || len(body) > 1<<20 {
		httpx.WriteErr(w, http.StatusRequestEntityTooLarge, "payload too large")
		return
	}
	t, err := s.store.Tenant(r.Context(), r.PathValue("tenant"))
	if err != nil {
		s.hookLimiter.Fail(ip)
		httpx.WriteErr(w, http.StatusNotFound, "not found")
		return
	}
	path := "/api/v1/webhooks/cloud/" + source
	headers := map[string]string{"X-SrustiOps-Event-Token": token}
	for _, h := range []string{"Content-Type", "User-Agent", "Aeg-Event-Type"} {
		if v := r.Header.Get(h); v != "" {
			headers[h] = v
		}
	}
	s.deliverWebhook(w, r, t, path, headers, body, ip)
}

var eventSourceRe = regexp.MustCompile(`^[0-9a-f-]{36}$`)
