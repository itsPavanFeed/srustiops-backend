// Package central is the central plane: it serves the frontend, authenticates
// users, keeps the tenant directory (tenants, entities, memberships) and routes
// each request to the right tenant plane.
//
// Routing ("the wrapper"): /api/v1/t/{tenant}/<path> is forwarded to that
// tenant's backend as /api/v1/<path> over mTLS. The user's token never leaves
// central; instead central attaches a 60-second ES256 assertion naming the user,
// their roles in that tenant, and the exact method and path.
package central

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/certs"
	"github.com/itsPavanFeed/srustiops-backend/internal/config"
	"github.com/itsPavanFeed/srustiops-backend/internal/envfile"
	"github.com/itsPavanFeed/srustiops-backend/internal/httpx"
	"github.com/itsPavanFeed/srustiops-backend/internal/identity"
	"github.com/itsPavanFeed/srustiops-backend/internal/link"
	"github.com/itsPavanFeed/srustiops-backend/internal/metrics"
	"github.com/itsPavanFeed/srustiops-backend/internal/oidc"
	"github.com/itsPavanFeed/srustiops-backend/internal/secure"
	"github.com/itsPavanFeed/srustiops-backend/internal/store"
)

const assertionHeader = "X-SrustiOps-Assertion"

var (
	emailRe   = regexp.MustCompile(`^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$|^[A-Za-z0-9._%+-]{1,64}@[a-z0-9-]{1,63}$`)
	nameRe    = regexp.MustCompile(`^[A-Za-z0-9 ._'&()-]{1,80}$`)
	tokNameRe = regexp.MustCompile(`^[A-Za-z0-9 ._-]{1,64}$`)
	maxTTL    = 90 * 24 * time.Hour
)

type Server struct {
	cfg      *config.Central
	store    *Store
	issuer   *oidc.Issuer
	cert     *certs.KeyPair // mTLS client identity, reloaded when rotated
	log      *slog.Logger
	limiter  *httpx.Limiter
	hookBase atomic.Value // string: public webhook base URL from SRUSTIOPS_ENV_FILE
	// hookLimiter blocks addresses that send unsigned or rejected webhooks.
	hookLimiter *httpx.Limiter

	mu         sync.Mutex
	transports map[string]*tenantTransport
	sso        oidcProvider
	google     oidcProvider
	// The SAML service-provider key and certificate (made on first use).
	spMu   sync.Mutex
	spRSA  *rsa.PrivateKey
	spCert *x509.Certificate

	link  *gateway // the tenant link gateway; nil when it is off
	usage usageTracker
	idps  idpCache  // tenants' own identity providers (discovery and keys)
	shape *shaper   // rate limits and in-flight caps
	cache *reqCache // sessions, tenants and principals on the request path
}

type tenantTransport struct {
	key string // backend URL + CA, to rebuild when the tenant record changes
	rt  http.RoundTripper
}

func New(cfg *config.Central, st *Store, iss *oidc.Issuer, log *slog.Logger) (*Server, error) {
	WebhookQueueMax = cfg.WebhookQueueMax
	cert, err := certs.NewKeyPair(cfg.ClientCert, cfg.ClientKey)
	if err != nil {
		return nil, fmt.Errorf("loading mTLS client certificate: %w", err)
	}
	return &Server{cfg: cfg, store: st, issuer: iss, cert: cert, log: log,
		limiter: httpx.NewLimiter(10, time.Minute, 5*time.Minute), hookLimiter: httpx.NewLimiter(30, time.Minute, 10*time.Minute), transports: map[string]*tenantTransport{}, shape: newShaper(), cache: newReqCache()}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteJSON(w, 200, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.Write(s.issuer.JWKS())
	})

	// SSO (OIDC) and SCIM provisioning.
	mux.HandleFunc("GET /api/v1/auth/config", s.authConfig)
	mux.HandleFunc("GET /api/v1/openapi.json", s.openAPI)
	mux.HandleFunc("GET /auth/login", s.ssoLogin)
	mux.HandleFunc("GET /auth/callback", s.ssoCallback)
	mux.HandleFunc("GET /auth/login/{provider}", s.socialLogin)
	mux.HandleFunc("GET /auth/callback/{provider}", s.socialCallback)
	mux.HandleFunc("POST /api/v1/auth/exchange", s.authExchange)
	mux.HandleFunc("GET /api/v1/auth/discover", s.discover)
	mux.HandleFunc("GET /auth/oidc/{id}/login", s.oidcLogin)
	mux.HandleFunc("GET /auth/oidc/{id}/callback", s.oidcCallback)
	mux.HandleFunc("GET /auth/saml/{id}/login", s.samlLogin)
	mux.HandleFunc("POST /auth/saml/{id}/acs", s.samlACS)
	mux.HandleFunc("GET /auth/saml/{id}/metadata", s.samlMetadata)
	mux.HandleFunc("GET /auth/tenant/{tenant}/login", s.tenantLogin)
	mux.HandleFunc("GET /auth/tenant/{tenant}/callback", s.tenantCallback)
	mux.HandleFunc("POST /auth/tenant/{tenant}/acs", s.tenantACS)
	mux.HandleFunc("GET /auth/tenant/{tenant}/saml/metadata", s.tenantSAMLMetadata)
	tsc := s.tenantSCIMAuth
	mux.Handle("GET /scim/v2/t/{tenant}/ServiceProviderConfig", tsc(s.scimConfig))
	mux.Handle("GET /scim/v2/t/{tenant}/Users", tsc(s.tscimListUsers))
	mux.Handle("POST /scim/v2/t/{tenant}/Users", tsc(s.tscimCreateUser))
	mux.Handle("GET /scim/v2/t/{tenant}/Users/{id}", tsc(s.tscimGetUser))
	mux.Handle("PUT /scim/v2/t/{tenant}/Users/{id}", tsc(s.tscimUpdateUser))
	mux.Handle("PATCH /scim/v2/t/{tenant}/Users/{id}", tsc(s.tscimUpdateUser))
	mux.Handle("DELETE /scim/v2/t/{tenant}/Users/{id}", tsc(s.tscimDeleteUser))
	mux.Handle("GET /scim/v2/t/{tenant}/Groups", tsc(s.tscimListGroups))
	mux.Handle("POST /scim/v2/t/{tenant}/Groups", tsc(s.tscimCreateGroup))
	mux.Handle("GET /scim/v2/t/{tenant}/Groups/{id}", tsc(s.tscimGetGroup))
	mux.Handle("PATCH /scim/v2/t/{tenant}/Groups/{id}", tsc(s.tscimPatchGroup))
	mux.Handle("PUT /scim/v2/t/{tenant}/Groups/{id}", tsc(s.tscimPutGroup))
	mux.Handle("DELETE /scim/v2/t/{tenant}/Groups/{id}", tsc(s.tscimDeleteGroup))
	mux.HandleFunc("POST /webhooks/github/{tenant}", s.githubWebhook)
	mux.HandleFunc("POST /webhooks/slack/{tenant}", s.slackInteraction)
	mux.HandleFunc("POST /webhooks/cloud/{tenant}/{source}", s.cloudEvent)
	sc := s.scimAuth
	mux.Handle("GET /scim/v2/ServiceProviderConfig", sc(s.scimConfig))
	mux.Handle("GET /scim/v2/Users", sc(s.scimListUsers))
	mux.Handle("POST /scim/v2/Users", sc(s.scimCreateUser))
	mux.Handle("GET /scim/v2/Users/{id}", sc(s.scimGetUser))
	mux.Handle("PUT /scim/v2/Users/{id}", sc(s.scimUpdateUser))
	mux.Handle("PATCH /scim/v2/Users/{id}", sc(s.scimUpdateUser))
	mux.Handle("DELETE /scim/v2/Users/{id}", sc(s.scimDeleteUser))
	mux.Handle("GET /scim/v2/Groups", sc(s.scimListGroups))
	mux.Handle("POST /scim/v2/Groups", sc(s.scimCreateGroup))
	mux.Handle("GET /scim/v2/Groups/{id}", sc(s.scimGetGroup))
	mux.Handle("PATCH /scim/v2/Groups/{id}", sc(s.scimPatchGroup))
	mux.Handle("DELETE /scim/v2/Groups/{id}", sc(s.scimDeleteGroup))

	a := s.auth
	mux.Handle("POST /api/v1/auth/logout", a(s.logout))
	mux.Handle("GET /api/v1/auth/providers", a(s.listSSOProviders))
	mux.Handle("PUT /api/v1/auth/providers/{provider}", a(s.putSSOProvider))
	mux.Handle("DELETE /api/v1/auth/providers/{provider}", a(s.deleteSSOProvider))
	mux.Handle("GET /api/v1/auth/enterprise-providers", a(s.listSignInProviders))
	mux.Handle("PUT /api/v1/auth/enterprise-providers/{id}", a(s.putSignInProvider))
	mux.Handle("DELETE /api/v1/auth/enterprise-providers/{id}", a(s.deleteSignInProvider))
	mux.Handle("GET /api/v1/me", a(s.me))
	mux.Handle("GET /api/v1/me/workspaces", a(s.workspaces))
	mux.Handle("GET /api/v1/me/tokens", a(s.listOwnTokens))
	mux.Handle("POST /api/v1/me/tokens", a(s.createOwnToken))
	mux.Handle("DELETE /api/v1/me/tokens/{id}", a(s.revokeOwnToken))

	mux.Handle("GET /api/v1/platform/admins", a(s.listPlatformAdmins))
	mux.Handle("PUT /api/v1/platform/admins/{email}", a(s.setPlatformAdmin))
	mux.Handle("DELETE /api/v1/platform/admins/{email}", a(s.setPlatformAdmin))

	mux.Handle("GET /api/v1/tenants", a(s.listTenants))
	mux.Handle("POST /api/v1/tenants", a(s.onboardTenant))
	mux.Handle("GET /api/v1/tenants/{tenant}", a(s.getTenant))
	mux.Handle("PUT /api/v1/tenants/{tenant}", a(s.updateTenant))
	mux.Handle("DELETE /api/v1/tenants/{tenant}", a(s.removeWorkspace))
	mux.Handle("POST /api/v1/tenants/{tenant}/promote", a(s.promoteWorkspace))
	mux.Handle("GET /api/v1/provisioner/blueprints", a(s.provisionerBlueprints))
	mux.Handle("GET /api/v1/tenants/{tenant}/provisioning", a(s.getProvisioning))
	mux.Handle("GET /api/v1/tenants/{tenant}/provisioning/{id}/logs", a(s.provisioningLogs))
	mux.Handle("POST /api/v1/tenants/{tenant}/provisioning", a(s.startProvisioning))
	mux.Handle("POST /api/v1/tenants/{tenant}/provisioning/{id}/connect", a(s.connectProvisioning))
	mux.Handle("POST /api/v1/tenants/{tenant}/provisioning/{id}/trust/check", a(s.checkTrust))
	mux.Handle("POST /api/v1/tenants/{tenant}/provisioning/{id}/approve", a(s.approveProvisioning))
	mux.Handle("POST /api/v1/tenants/{tenant}/provisioning/{id}/retry", a(s.retryProvisioning))
	mux.Handle("POST /api/v1/tenants/{tenant}/provisioning/{id}/handover", a(s.handOverProvisioning))
	mux.Handle("GET /api/v1/platform/attention", a(s.platformAttention))
	mux.Handle("GET /api/v1/platform/audit", a(s.platformAuditLog))
	mux.Handle("GET /api/v1/platform/alerts", a(s.getAlertSettings))
	mux.Handle("PUT /api/v1/platform/alerts", a(s.putAlertSettings))
	mux.Handle("POST /api/v1/platform/alerts/test", a(s.testAlert))
	mux.Handle("GET /api/v1/platform/audit/verify", a(s.verifyPlatformAudit))
	mux.Handle("GET /api/v1/platform/fleet", a(s.getFleet))
	mux.Handle("GET /api/v1/platform/plans", a(s.listPlans))
	mux.Handle("PUT /api/v1/platform/plans/{name}", a(s.putPlan))
	mux.Handle("DELETE /api/v1/platform/plans/{name}", a(s.deletePlan))
	mux.Handle("PUT /api/v1/tenants/{tenant}/plan", a(s.setTenantPlan))
	mux.Handle("GET /api/v1/tenants/{tenant}/usage", a(s.tenantUsage))
	mux.Handle("POST /api/v1/platform/fleet/rollouts", a(s.startRollout))
	mux.Handle("POST /api/v1/platform/fleet/rollout/{action}", a(s.controlRollout))
	mux.Handle("GET /api/v1/platform/audit-export", a(s.getPlatformExport))
	mux.Handle("PUT /api/v1/platform/audit-export", a(s.putPlatformExport))
	mux.Handle("DELETE /api/v1/platform/audit-export", a(s.deletePlatformExport))
	mux.Handle("GET /api/v1/rate-limits", a(s.getRateLimits))
	mux.Handle("PUT /api/v1/rate-limits", a(s.putRateLimits))
	mux.Handle("GET /api/v1/workspace-policy", a(s.getWorkspacePolicy))
	mux.Handle("PUT /api/v1/workspace-policy", a(s.putWorkspacePolicy))
	mux.Handle("GET /api/v1/workspace-requests", a(s.listWorkspaceRequests))
	mux.Handle("POST /api/v1/workspace-requests", a(s.createWorkspaceRequest))
	mux.Handle("POST /api/v1/workspace-requests/{id}/{decision}", a(s.decideWorkspaceRequest))
	mux.Handle("GET /api/v1/tenants/{tenant}/health", a(s.tenantHealth))
	mux.Handle("GET /api/v1/tenants/{tenant}/link", a(s.tenantLink))
	mux.Handle("GET /api/v1/tenants/{tenant}/install", a(s.getInstall))
	mux.Handle("POST /api/v1/tenants/{tenant}/install-tokens", a(s.createInstallToken))
	mux.Handle("POST /api/v1/tenants/{tenant}/link/enrollments", a(s.createEnrollment))
	mux.Handle("DELETE /api/v1/tenants/{tenant}/link/certificates", a(s.revokeLinkCert))
	mux.Handle("DELETE /api/v1/tenants/{tenant}/link/certificates/{serial}", a(s.revokeLinkCert))
	mux.Handle("GET /api/v1/tenants/{tenant}/entities", a(s.listEntities))
	mux.Handle("POST /api/v1/tenants/{tenant}/entities", a(s.createEntity))
	mux.Handle("GET /api/v1/tenants/{tenant}/bus", a(s.listBUs))
	mux.Handle("POST /api/v1/tenants/{tenant}/bus", a(s.createBU))
	mux.Handle("GET /api/v1/tenants/{tenant}/members", a(s.listMembers))
	mux.Handle("GET /api/v1/tenants/{tenant}/approvers", a(s.listApprovers))
	mux.Handle("POST /api/v1/tenants/{tenant}/members", a(s.addMember))
	mux.Handle("DELETE /api/v1/tenants/{tenant}/members/{id}", a(s.removeMember))
	mux.Handle("PUT /api/v1/tenants/{tenant}/users/{email}/roles", a(s.setUserRoles))
	mux.Handle("POST /api/v1/tenants/{tenant}/users/{email}/invitation", a(s.extendInvitation))
	mux.Handle("GET /api/v1/tenants/{tenant}/teams", a(s.listTeams))
	mux.Handle("POST /api/v1/tenants/{tenant}/teams", a(s.saveTeam(true)))
	mux.Handle("PUT /api/v1/tenants/{tenant}/teams/{team}", a(s.saveTeam(false)))
	mux.Handle("DELETE /api/v1/tenants/{tenant}/teams/{team}", a(s.deleteTeam))
	mux.Handle("POST /api/v1/tenants/{tenant}/access/takeover", a(s.takeoverAccess))
	mux.Handle("GET /api/v1/tenants/{tenant}/idp", a(s.getTenantIdP))
	mux.Handle("PUT /api/v1/tenants/{tenant}/idp", a(s.putTenantIdP))
	mux.Handle("DELETE /api/v1/tenants/{tenant}/idp", a(s.deleteTenantIdP))
	mux.Handle("POST /api/v1/tenants/{tenant}/domains", a(s.addTenantDomain))
	mux.Handle("POST /api/v1/tenants/{tenant}/domains/{domain}/verify", a(s.verifyTenantDomain))
	mux.Handle("DELETE /api/v1/tenants/{tenant}/domains/{domain}", a(s.deleteTenantDomain))
	mux.Handle("GET /api/v1/tenants/{tenant}/scim-tokens", a(s.listTenantSCIMTokens))
	mux.Handle("POST /api/v1/tenants/{tenant}/scim-tokens", a(s.createTenantSCIMToken))
	mux.Handle("DELETE /api/v1/tenants/{tenant}/scim-tokens/{id}", a(s.revokeTenantSCIMToken))
	mux.Handle("POST /api/v1/tenants/{tenant}/access/sync", a(s.syncAccess))
	mux.Handle("GET /api/v1/tenants/{tenant}/support-requests", a(s.supportRequests))
	mux.Handle("POST /api/v1/tenants/{tenant}/support-requests", a(s.supportRequests))
	mux.Handle("POST /api/v1/tenants/{tenant}/tokens", a(s.issueMemberToken))
	mux.Handle("GET /api/v1/tenants/{tenant}/slack", a(s.getSlackApp))
	mux.Handle("PUT /api/v1/tenants/{tenant}/slack", a(s.putSlackApp))
	mux.Handle("DELETE /api/v1/tenants/{tenant}/slack", a(s.deleteSlackApp))

	// The wrapper: everything under /api/v1/t/{tenant}/ goes to that tenant plane.
	mux.Handle("/api/v1/t/{tenant}/{rest...}", a(s.proxy))

	if s.cfg.WebDir != "" {
		mux.Handle("/", httpx.SPA(s.cfg.WebDir))
	}
	return httpx.Trace(s.log, "central", 2*time.Second, metrics.Default.Requests("central", httpx.SecurityHeaders(!s.cfg.InsecureHTTP, s.limitIP(s.purgeOnChange(mux)))))
}

func (s *Server) Run(ctx context.Context) error {
	var tlsCfg *tls.Config
	if !s.cfg.InsecureHTTP {
		kp, err := certs.NewKeyPair(s.cfg.TLSCert, s.cfg.TLSKey)
		if err != nil {
			return fmt.Errorf("TLS certificate: %w", err)
		}
		tlsCfg = certs.ServerConfig(kp, nil)
	} else {
		s.log.Warn("central serving plain HTTP on loopback for local development only", "listen", s.cfg.Listen)
	}
	if s.cfg.EnvFile != "" {
		s.loadEnvFile()
		go envfile.Watch(ctx, 2*time.Second, s.loadEnvFile, func() []string { return []string{s.cfg.EnvFile} })
	}
	linkDone := make(chan struct{})
	if s.link != nil && s.cfg.LinkListen != "" {
		go func() {
			defer close(linkDone)
			if err := s.runLink(ctx); err != nil {
				s.log.Error("tenant link gateway stopped", "err", err)
			}
		}()
	} else {
		close(linkDone)
	}
	// On shutdown the gateway drains its tunnels (agents move to another
	// replica, open streams finish) before the process exits.
	defer func() { <-linkDone }()
	go s.syncLoop(ctx)
	go s.provisionLoop(ctx)
	go s.rateLimitLoop(ctx)
	go s.alertLoop(ctx)
	go s.inviteLoop(ctx)
	go s.platformExporter(ctx)
	go s.fleetLoop(ctx)
	go s.planLoop(ctx)
	s.registerMetrics(metrics.Default)
	s.log.Info("central plane serving", "listen", s.cfg.Listen, "public_url", s.cfg.PublicURL)
	return httpx.Serve(ctx, s.log, s.cfg.Listen, s.Handler(), tlsCfg, "", "")
}

// loadEnvFile picks up SRUSTIOPS_WEBHOOK_BASE_URL from the env file, so a new
// tunnel or ingress address takes effect without a restart.
func (s *Server) loadEnvFile() {
	m, err := envfile.Read(s.cfg.EnvFile)
	if err != nil {
		s.log.Warn("reading env file failed", "file", s.cfg.EnvFile, "err", err)
		return
	}
	v := strings.TrimRight(m["SRUSTIOPS_WEBHOOK_BASE_URL"], "/")
	if u, err := url.Parse(v); v != "" && (err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "") {
		s.log.Warn("ignoring SRUSTIOPS_WEBHOOK_BASE_URL in env file: must be an https origin", "value", v)
		return
	}
	if old, _ := s.hookBase.Load().(string); old != v {
		s.hookBase.Store(v)
		s.log.Info("webhook base URL", "url", v, "from", s.cfg.EnvFile)
	}
}

// webhookBase is where Git hosts send webhooks: the env file, then the
// environment, then the public URL.
func (s *Server) webhookBase() string {
	if v, _ := s.hookBase.Load().(string); v != "" {
		return v
	}
	if s.cfg.WebhookBaseURL != "" {
		return s.cfg.WebhookBaseURL
	}
	return s.cfg.PublicURL
}

// ---- auth ----

type ctxKey struct{}

func current(r *http.Request) *User { return r.Context().Value(ctxKey{}).(*User) }

type sessKey struct{}

// sessionOf is how the caller's session signed in.
func sessionOf(r *http.Request) *AuthSession {
	if a, ok := r.Context().Value(sessKey{}).(*AuthSession); ok {
		return a
	}
	return &AuthSession{IDP: "token"}
}

func (s *Server) auth(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := httpx.ClientIP(r)
		if s.limiter.Blocked(ip) {
			w.Header().Set("Retry-After", "300")
			httpx.WriteErr(w, http.StatusTooManyRequests, "too many failed authentication attempts")
			return
		}
		tok := httpx.Bearer(r)
		var u *User
		var sess *AuthSession
		var err error
		if strings.HasPrefix(tok, "sop_u_") {
			u, sess, err = s.session(r.Context(), secure.HashToken(tok))
		}
		if u == nil || err != nil {
			if s.limiter.Fail(ip) {
				s.audit(r.Context(), "anonymous", "auth.lockout", "ip/"+ip, "", map[string]string{"path": r.URL.Path})
			}
			httpx.WriteErr(w, http.StatusUnauthorized, "missing, invalid or expired token")
			return
		}
		if !s.limitUser(w, r, u) {
			return
		}
		s.noteSeen(r.Context(), u)
		ctx := context.WithValue(r.Context(), ctxKey{}, u)
		h(w, r.WithContext(context.WithValue(ctx, sessKey{}, sess)))
	})
}

func (s *Server) audit(ctx context.Context, actor, action, target, tenant string, payload any) {
	if payload == nil {
		payload = map[string]any{}
	}
	if err := s.store.AppendAudit(context.WithoutCancel(ctx), actor, action, target, tenant, payload); err != nil {
		s.log.Error("audit write failed", "action", action, "err", err)
	}
}

func (s *Server) storeErr(w http.ResponseWriter, err error, conflict string) {
	switch {
	case errors.Is(err, ErrNotFound):
		httpx.WriteErr(w, http.StatusNotFound, "not found")
	case errors.Is(err, ErrConflict):
		httpx.WriteErr(w, http.StatusConflict, conflict)
	case errors.As(err, new(*store.LimitError)):
		httpx.WriteErr(w, http.StatusForbidden, err.Error())
	default:
		s.log.Error("store error", "err", err)
		httpx.WriteErr(w, http.StatusInternalServerError, "internal error")
	}
}

// tenantFor loads {tenant} and the caller's roles in it. Platform admins act as
// tenant admins (and more) in every tenant.
func (s *Server) tenantFor(w http.ResponseWriter, r *http.Request, needAdmin bool) (*Tenant, *identity.Principal) {
	u := current(r)
	t, err := s.store.Tenant(r.Context(), r.PathValue("tenant"))
	if err != nil {
		s.storeErr(w, err, "")
		return nil, nil
	}
	p, err := s.store.Principal(r.Context(), u, t.Slug)
	if err != nil {
		s.storeErr(w, err, "")
		return nil, nil
	}
	// Connection first: until its cluster is connected, a workspace opens
	// only its connection and install pages.
	if !platformOp(r) && pendingRefusal(w, t) {
		return nil, nil
	}
	platform := u.PlatformAdmin && (t.AccessSource != "tenant" || platformOp(r))
	if p == nil && !platform {
		httpx.WriteErr(w, http.StatusNotFound, "not found")
		return nil, nil
	}
	if needAdmin && !platform && !p.HasTenantRole(identity.TenantAdmin) {
		httpx.WriteErr(w, http.StatusForbidden, "this needs the tenant_admin role")
		return nil, nil
	}
	if p == nil {
		p = &identity.Principal{Subject: u.Email, Tenant: t.Slug, EntityRoles: map[string][]string{}}
	}
	return t, p
}

// ---- me ----

type meTenant struct {
	Slug          string     `json:"slug"`
	Name          string     `json:"name"`
	TenantRoles   []string   `json:"tenant_roles"`
	PlatformAdmin bool       `json:"platform_admin,omitempty"`
	Entities      []meEntity `json:"entities"`
}

type meEntity struct {
	Slug  string   `json:"slug"`
	Name  string   `json:"name"`
	Roles []string `json:"roles"` // granted on the entity (inherited by its BUs)
	BUs   []meBU   `json:"bus"`
}

type meBU struct {
	Slug  string   `json:"slug"`
	Name  string   `json:"name"`
	Roles []string `json:"roles"` // effective in this BU
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	u := current(r)
	slugs, err := s.store.UserTenants(r.Context(), u.ID)
	if u.PlatformAdmin && err == nil {
		var all []*Tenant
		if all, err = s.store.ListTenants(r.Context()); err == nil {
			slugs = slugs[:0]
			for _, t := range all {
				slugs = append(slugs, t.Slug)
			}
		}
	}
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	tenants := []meTenant{}
	for _, slug := range slugs {
		t, err := s.store.Tenant(r.Context(), slug)
		if err != nil {
			continue
		}
		p, _ := s.store.Principal(r.Context(), u, slug)
		if p == nil {
			continue
		}
		ents, _ := s.store.Entities(r.Context(), t.ID)
		bus, _ := s.store.BUs(r.Context(), t.ID)
		mt := meTenant{Slug: t.Slug, Name: t.Name, TenantRoles: p.TenantRoles, PlatformAdmin: p.PlatformAdmin, Entities: []meEntity{}}
		for _, e := range ents {
			me := meEntity{Slug: e.Slug, Name: e.Name, Roles: orEmpty(p.EntityRoles[e.Slug]), BUs: []meBU{}}
			for _, b := range bus {
				if b.Entity != e.Slug {
					continue
				}
				if roles := p.BURoles[b.Slug]; len(roles) > 0 || p.SeesAllBUs() {
					me.BUs = append(me.BUs, meBU{Slug: b.Slug, Name: b.Name, Roles: orEmpty(roles)})
				}
			}
			if len(me.BUs) > 0 || len(me.Roles) > 0 || p.SeesAllBUs() {
				mt.Entities = append(mt.Entities, me)
			}
		}
		tenants = append(tenants, mt)
	}
	httpx.WriteJSON(w, 200, map[string]any{"user": u, "tenants": tenants})
}

func orEmpty(xs []string) []string {
	if xs == nil {
		return []string{}
	}
	return xs
}

func (s *Server) listOwnTokens(w http.ResponseWriter, r *http.Request) {
	ts, err := s.store.ListTokens(r.Context(), current(r).ID)
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	httpx.WriteJSON(w, 200, ts)
}

type tokenBody struct {
	Email   string `json:"email,omitempty"`
	Name    string `json:"name"`
	TTLDays int    `json:"ttl_days"`
}

func (b *tokenBody) check(w http.ResponseWriter) (time.Duration, bool) {
	ttl := time.Duration(b.TTLDays) * 24 * time.Hour
	if !tokNameRe.MatchString(b.Name) || ttl <= 0 || ttl > maxTTL {
		httpx.WriteErr(w, 422, "token name is required and ttl_days must be between 1 and 90")
		return 0, false
	}
	return ttl, true
}

func (s *Server) createOwnToken(w http.ResponseWriter, r *http.Request) {
	var b tokenBody
	if !httpx.Decode(w, r, &b) {
		return
	}
	ttl, ok := b.check(w)
	if !ok {
		return
	}
	u := current(r)
	if u.PlatformAdmin {
		httpx.WriteErr(w, http.StatusForbidden, "platform admins sign in with SSO and the platform root has a single recovery token (rotate it with srustiops central bootstrap); personal tokens are not issued to them")
		return
	}
	s.issueToken(w, r, u, b.Name, ttl, "")
}

func (s *Server) issueToken(w http.ResponseWriter, r *http.Request, u *User, name string, ttl time.Duration, tenant string) {
	plain, err := secure.NewToken("u")
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	t, err := s.store.CreateToken(r.Context(), u.ID, name, current(r).Email, secure.HashToken(plain), time.Now().Add(ttl))
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	s.audit(r.Context(), current(r).Email, "token.create", "user/"+u.Email, tenant, map[string]any{"token": t.ID, "expires_at": t.ExpiresAt})
	httpx.WriteJSON(w, 201, map[string]any{"token": t, "user": u.Email, "secret": plain})
}

func (s *Server) revokeOwnToken(w http.ResponseWriter, r *http.Request) {
	u := current(r)
	if err := s.store.RevokeToken(r.Context(), u.ID, r.PathValue("id")); err != nil {
		s.storeErr(w, err, "")
		return
	}
	s.audit(r.Context(), u.Email, "token.revoke", "user/"+u.Email, "", map[string]string{"token": r.PathValue("id")})
	w.WriteHeader(http.StatusNoContent)
}

// ---- tenants (platform admins) ----

func platformAdmin(w http.ResponseWriter, r *http.Request) bool {
	if !current(r).PlatformAdmin {
		httpx.WriteErr(w, http.StatusForbidden, "this needs a platform admin")
		return false
	}
	return true
}

func (s *Server) listTenants(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(w, r) {
		return
	}
	ts, err := s.store.ListTenants(r.Context())
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	out := make([]tenantView, 0, len(ts))
	for _, t := range ts {
		out = append(out, tenantView{Tenant: t, Online: s.online(r.Context(), t)})
	}
	httpx.WriteJSON(w, 200, out)
}

// tenantView is a tenant with whether central can reach it right now.
type tenantView struct {
	*Tenant
	Online bool `json:"online"`
}

type tenantBody struct {
	Slug         string `json:"slug"`
	Name         string `json:"name"`
	BackendURL   string `json:"backend_url"`
	ServerCAPEM  string `json:"server_ca_pem"`
	AdminEmail   string `json:"admin_email"`
	Connectivity string `json:"connectivity"` // direct (default) or tunnel
	Target       string `json:"target"`       // eks, gke, aks, kubernetes, compose
}

// reservedSlugs are console routes (#/workspaces/new, #/platform, …) and
// names a workspace must not take.
var reservedSlugs = map[string]bool{"new": true, "platform": true, "account": true, "workspaces": true, "login": true, "sso": true,
	"api": true, "admin": true, "settings": true, "connect": true, "central": true, "srustiops": true}

func (b *tenantBody) validate(create bool) []string {
	var probs []string
	if create && !identity.SlugRe.MatchString(b.Slug) {
		probs = append(probs, "slug must be lowercase letters, digits and dashes (2-32)")
	}
	if create && reservedSlugs[b.Slug] {
		probs = append(probs, "slug \""+b.Slug+"\" is reserved; choose another")
	}
	if !nameRe.MatchString(b.Name) {
		probs = append(probs, "name is required")
	}
	// Tenants on the link may leave the URL out: bootstrap gives their API an
	// internal name under central's own CA.
	if b.BackendURL == "" && b.Connectivity == "tunnel" {
	} else if u, err := url.Parse(b.BackendURL); err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" && u.Path != "/" || u.RawQuery != "" {
		probs = append(probs, "backend_url must be the tenant plane's https:// base URL")
	}
	switch b.Target {
	case "", "eks", "gke", "aks", "kubernetes", "compose":
	default:
		probs = append(probs, "target must be eks, gke, aks, kubernetes or compose")
	}
	if b.Connectivity == "" {
		b.Connectivity = "direct"
	}
	if b.Connectivity != "direct" && b.Connectivity != "tunnel" {
		probs = append(probs, "connectivity must be direct or tunnel")
	}
	if b.ServerCAPEM != "" && !x509.NewCertPool().AppendCertsFromPEM([]byte(b.ServerCAPEM)) {
		probs = append(probs, "server_ca_pem must contain PEM certificates")
	}
	if create && !emailRe.MatchString(b.AdminEmail) {
		probs = append(probs, "admin_email must be the first tenant admin's email")
	}
	return probs
}

// onboardTenant registers a tenant plane and its first tenant admin, and
// returns the settings that plane must be started with.
func (s *Server) onboardTenant(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(w, r) {
		return
	}
	var b tenantBody
	if !httpx.Decode(w, r, &b) {
		return
	}
	if probs := b.validate(true); len(probs) > 0 {
		httpx.WriteErr(w, 422, "invalid tenant", probs...)
		return
	}
	s.createWorkspace(w, r, b, &Tenant{Kind: "production"}, current(r).Email)
}

// createWorkspace creates a tenant and its first tenant admin, and answers
// with its install command (connection first) or its plane settings. proto
// carries the kind and trial end; by is who it is recorded as created by.
func (s *Server) createWorkspace(w http.ResponseWriter, r *http.Request, b tenantBody, proto *Tenant, by string) {
	nt := &Tenant{Slug: b.Slug, Name: b.Name, BackendURL: strings.TrimRight(b.BackendURL, "/"), ServerCAPEM: b.ServerCAPEM, Connectivity: b.Connectivity, Target: b.Target, CreatedBy: by,
		Kind: proto.Kind, TrialEndsAt: proto.TrialEndsAt}
	bootstrap := b.Connectivity == "tunnel" && b.BackendURL == ""
	if bootstrap {
		if s.link == nil {
			httpx.WriteErr(w, http.StatusConflict, "the tenant link gateway is not enabled on this central plane (SRUSTIOPS_LINK_LISTEN)")
			return
		}
		// Connection first: pending until its cluster runs bootstrap and the
		// tenant plane answers through the link.
		nt.BackendURL, nt.ServerCAPEM, nt.Status = "https://"+link.InternalName(b.Slug), string(s.link.serverCA.PEM), "pending"
	}
	t, err := s.store.CreateTenant(r.Context(), nt)
	if err != nil {
		s.storeErr(w, err, "a tenant with that slug exists")
		return
	}
	admin, err := s.store.EnsureUser(r.Context(), b.AdminEmail, "", false, by)
	if err == nil {
		_, err = s.store.AddMembership(r.Context(), admin.ID, t.ID, nil, nil, identity.TenantAdmin, by)
	}
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	s.audit(r.Context(), by, "tenant.onboard", "tenant/"+t.Slug, t.Slug, map[string]string{"backend_url": t.BackendURL, "admin": b.AdminEmail, "connectivity": t.Connectivity, "kind": t.Kind})
	settings := map[string]any{
		"tenant": t,
		"tenant_plane_settings": map[string]string{
			"SRUSTIOPS_TENANT":      t.Slug,
			"SRUSTIOPS_CENTRAL_URL": s.cfg.PublicURL,
			"SRUSTIOPS_PUBLIC_URL":  t.BackendURL,
			"note":                  "Also set SRUSTIOPS_CENTRAL_CLIENT_CA to the CA that issued central's client certificate.",
		},
	}
	if bootstrap {
		tok, exp, err := s.issueInstallToken(r.Context(), t, by)
		if err != nil {
			s.storeErr(w, err, "")
			return
		}
		v := s.installView(r.Context(), t)
		v.Token, v.ExpiresAt = tok, &exp
		httpx.WriteJSON(w, 201, map[string]any{"tenant": t, "install": v})
		return
	}
	if t.Connectivity == "tunnel" && s.link != nil {
		// The tenant runs the link agent next to its plane; it enrols with
		// this one-time token and then dials out. Nothing dials in.
		s.enrollmentResponse(w, r, t, 201, settings)
		return
	}
	httpx.WriteJSON(w, 201, settings)
}

func (s *Server) getTenant(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, false)
	if t != nil {
		httpx.WriteJSON(w, 200, t)
	}
}

func (s *Server) updateTenant(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(w, r) {
		return
	}
	var b tenantBody
	if !httpx.Decode(w, r, &b) {
		return
	}
	if probs := b.validate(false); len(probs) > 0 {
		httpx.WriteErr(w, 422, "invalid tenant", probs...)
		return
	}
	t, err := s.store.UpdateTenant(r.Context(), &Tenant{Slug: r.PathValue("tenant"), Name: b.Name, BackendURL: strings.TrimRight(b.BackendURL, "/"), ServerCAPEM: b.ServerCAPEM, Connectivity: b.Connectivity})
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	if t.Connectivity != "tunnel" && s.link != nil {
		s.link.hub.Drop(t.Slug, "")
	}
	s.audit(r.Context(), current(r).Email, "tenant.update", "tenant/"+t.Slug, t.Slug, map[string]string{"backend_url": t.BackendURL, "connectivity": t.Connectivity})
	httpx.WriteJSON(w, 200, t)
}

// tenantHealth checks central can reach the tenant plane over mTLS and that
// it identifies as the same tenant.
func (s *Server) tenantHealth(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, true)
	if t == nil {
		return
	}
	rt, err := s.transport(t)
	if err != nil {
		httpx.WriteJSON(w, 200, map[string]any{"reachable": false, "error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, t.BackendURL+"/healthz", nil)
	resp, err := (&http.Client{Transport: rt}).Do(req)
	if err != nil {
		httpx.WriteJSON(w, 200, map[string]any{"reachable": false, "error": err.Error()})
		return
	}
	defer resp.Body.Close()
	var h struct{ Status, Tenant string }
	json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&h)
	ok := resp.StatusCode == 200 && h.Tenant == t.Slug
	res := map[string]any{"reachable": ok, "status": resp.StatusCode, "reported_tenant": h.Tenant}
	if !ok && h.Tenant != t.Slug {
		res["error"] = "the backend at this URL is not configured as tenant " + t.Slug
	}
	httpx.WriteJSON(w, 200, res)
}

// ---- entities & members (tenant admins, or platform admins) ----

func (s *Server) listEntities(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, false)
	if t == nil {
		return
	}
	es, err := s.store.Entities(r.Context(), t.ID)
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	httpx.WriteJSON(w, 200, es)
}

func (s *Server) createEntity(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, true)
	if t == nil {
		return
	}
	var b struct{ Slug, Name string }
	if !httpx.Decode(w, r, &b) {
		return
	}
	if !identity.SlugRe.MatchString(b.Slug) || !nameRe.MatchString(b.Name) {
		httpx.WriteErr(w, 422, "slug must be lowercase letters, digits and dashes (2-32) and name is required")
		return
	}
	e, err := s.store.CreateEntity(r.Context(), t.ID, b.Slug, b.Name, current(r).Email)
	if err != nil {
		s.storeErr(w, err, "that slug is already used by an entity or a business unit in this tenant")
		return
	}
	s.audit(r.Context(), current(r).Email, "entity.create", "entity/"+e.Slug, t.Slug, e)
	httpx.WriteJSON(w, 201, e)
}

func (s *Server) listBUs(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, false)
	if t == nil {
		return
	}
	bs, err := s.store.BUs(r.Context(), t.ID)
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	httpx.WriteJSON(w, 200, bs)
}

// createBU adds a business unit (a product) under an entity.
func (s *Server) createBU(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, true)
	if t == nil {
		return
	}
	var b struct{ Slug, Name, Entity string }
	if !httpx.Decode(w, r, &b) {
		return
	}
	if !identity.SlugRe.MatchString(b.Slug) || !nameRe.MatchString(b.Name) {
		httpx.WriteErr(w, 422, "slug must be lowercase letters, digits and dashes (2-32) and name is required")
		return
	}
	e, err := s.store.Entity(r.Context(), t.ID, b.Entity)
	if err != nil {
		httpx.WriteErr(w, 422, "unknown entity "+b.Entity)
		return
	}
	bu, err := s.store.CreateBU(r.Context(), t.ID, e.ID, b.Slug, b.Name, current(r).Email)
	if err != nil {
		s.storeErr(w, err, "that slug is already used by a business unit or an entity in this tenant")
		return
	}
	s.audit(r.Context(), current(r).Email, "bu.create", "bu/"+bu.Slug, t.Slug, bu)
	httpx.WriteJSON(w, 201, bu)
}

func (s *Server) listMembers(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, true)
	if t == nil {
		return
	}
	ms, err := s.store.EffectiveMembers(r.Context(), t.ID)
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	httpx.WriteJSON(w, 200, ms)
}

// listApprovers tells any member of a tenant who can sign which approval:
// finops, security and devops (tenant-wide), and the managers of each entity
// and business unit. It lists only the roles that approve, never other
// memberships.
func (s *Server) listApprovers(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, false)
	if t == nil {
		return
	}
	ms, err := s.store.EffectiveMembers(r.Context(), t.ID)
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	out := map[string]any{}
	tenant := map[string][]string{}
	entity := map[string][]string{}
	bu := map[string][]string{}
	for _, m := range ms {
		switch {
		case m.Role == identity.FinOps || m.Role == identity.Security || m.Role == identity.DevOps:
			tenant[m.Role] = append(tenant[m.Role], m.Email)
		case m.Role == identity.Manager && m.BU != "":
			bu[m.BU] = append(bu[m.BU], m.Email)
		case m.Role == identity.Manager && m.Entity != "":
			entity[m.Entity] = append(entity[m.Entity], m.Email)
		}
	}
	out["tenant"], out["entity_managers"], out["bu_managers"] = tenant, entity, bu
	httpx.WriteJSON(w, 200, out)
}

func (s *Server) addMember(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, true)
	if t == nil {
		return
	}
	var b struct{ Email, Name, Entity, BU, Role string }
	if !httpx.Decode(w, r, &b) {
		return
	}
	if !emailRe.MatchString(b.Email) {
		httpx.WriteErr(w, 422, "email is invalid")
		return
	}
	var entityID, buID *string
	scopeErr := "tenant-wide roles are " + strings.Join(identity.TenantRoles, ", ") + "; entity and business-unit roles are " + strings.Join(identity.ScopedRoles, ", ") + "; give at most one of entity or bu"
	switch {
	case b.Entity == "" && b.BU == "" && identity.IsTenantRole(b.Role):
	case b.Entity != "" && b.BU == "" && identity.IsScopedRole(b.Role):
		e, err := s.store.Entity(r.Context(), t.ID, b.Entity)
		if err != nil {
			httpx.WriteErr(w, 422, "unknown entity "+b.Entity)
			return
		}
		entityID = &e.ID
	case b.BU != "" && b.Entity == "" && identity.IsScopedRole(b.Role):
		bu, err := s.store.BUBySlug(r.Context(), t.ID, b.BU)
		if err != nil {
			httpx.WriteErr(w, 422, "unknown business unit "+b.BU)
			return
		}
		buID = &bu.ID
	default:
		httpx.WriteErr(w, 422, scopeErr)
		return
	}
	if t.AccessSource == "tenant" {
		if code, msg := s.forwardGrants(r.Context(), r, t, b.Email, []DirGrant{{Email: b.Email, Role: b.Role, Entity: b.Entity, BU: b.BU}}, true); code != 0 {
			httpx.WriteErr(w, code, msg)
			return
		}
		s.audit(r.Context(), current(r).Email, "member.add", "user/"+b.Email, t.Slug, b)
		httpx.WriteJSON(w, 201, map[string]string{"email": b.Email, "role": b.Role, "entity": b.Entity, "bu": b.BU, "tenant": t.Slug})
		return
	}
	u, err := s.store.EnsureUser(r.Context(), b.Email, b.Name, false, current(r).Email)
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	m, err := s.store.AddMembership(r.Context(), u.ID, t.ID, entityID, buID, b.Role, current(r).Email)
	if err != nil {
		s.storeErr(w, err, "that membership exists")
		return
	}
	s.store.MarkInvited(r.Context(), u.ID, inviteDays(r))
	s.audit(r.Context(), current(r).Email, "member.add", "user/"+b.Email, t.Slug, m)
	httpx.WriteJSON(w, 201, m)
}

// setUserRoles replaces a person's roles in a tenant with the given set (an
// empty set removes the person from the tenant). Every role is validated like
// a single grant, and a tenant admin cannot remove their own tenant_admin role.
func (s *Server) setUserRoles(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, true)
	if t == nil {
		return
	}
	email := r.PathValue("email") // as stored; people are matched by their exact address
	if !emailRe.MatchString(email) {
		httpx.WriteErr(w, 422, "email is invalid")
		return
	}
	var b struct {
		Roles []struct{ Role, Entity, BU string } `json:"roles"`
	}
	if !httpx.Decode(w, r, &b) {
		return
	}
	if len(b.Roles) > 50 {
		httpx.WriteErr(w, 422, "at most 50 roles per person")
		return
	}
	var grants []Grant
	selfAdmin := false
	for _, g := range b.Roles {
		gr := Grant{Role: g.Role}
		switch {
		case g.Entity == "" && g.BU == "" && identity.IsTenantRole(g.Role):
			selfAdmin = selfAdmin || g.Role == identity.TenantAdmin
		case g.Entity != "" && g.BU == "" && identity.IsScopedRole(g.Role):
			e, err := s.store.Entity(r.Context(), t.ID, g.Entity)
			if err != nil {
				httpx.WriteErr(w, 422, "unknown entity "+g.Entity)
				return
			}
			gr.EntityID = &e.ID
		case g.BU != "" && g.Entity == "" && identity.IsScopedRole(g.Role):
			bu, err := s.store.BUBySlug(r.Context(), t.ID, g.BU)
			if err != nil {
				httpx.WriteErr(w, 422, "unknown business unit "+g.BU)
				return
			}
			gr.BUID = &bu.ID
		default:
			httpx.WriteErr(w, 422, "tenant-wide roles are "+strings.Join(identity.TenantRoles, ", ")+"; entity and business-unit roles are "+strings.Join(identity.ScopedRoles, ", "))
			return
		}
		grants = append(grants, gr)
	}
	me := current(r)
	if strings.EqualFold(me.Email, email) && !me.PlatformAdmin && !selfAdmin {
		httpx.WriteErr(w, 422, "you cannot remove your own tenant_admin role; ask another tenant admin")
		return
	}
	var added, removed []string
	if t.AccessSource == "tenant" {
		want := []DirGrant{}
		for _, g := range b.Roles {
			want = append(want, DirGrant{Email: email, Role: g.Role, Entity: g.Entity, BU: g.BU})
		}
		if code, msg := s.forwardGrants(r.Context(), r, t, email, want, false); code != 0 {
			httpx.WriteErr(w, code, msg)
			return
		}
		added = []string{"forwarded to tenant"}
	} else {
		u, err := s.store.EnsureUser(r.Context(), email, "", false, me.Email)
		if err != nil {
			s.storeErr(w, err, "")
			return
		}
		if added, removed, err = s.store.SetUserRoles(r.Context(), t.ID, u.ID, grants, me.Email); err != nil {
			s.storeErr(w, err, "")
			return
		}
		if len(grants) > 0 {
			s.store.MarkInvited(r.Context(), u.ID, inviteDays(r))
		}
	}
	if len(added)+len(removed) > 0 {
		s.audit(r.Context(), me.Email, "member.roles", "user/"+email, t.Slug, map[string]any{"added": added, "removed": removed, "roles": b.Roles})
	}
	ms, err := s.store.TenantMembers(r.Context(), t.ID)
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	out := []*Membership{}
	for _, m := range ms {
		if strings.EqualFold(m.Email, email) {
			out = append(out, m)
		}
	}
	httpx.WriteJSON(w, 200, out)
}

func (s *Server) removeMember(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, true)
	if t == nil {
		return
	}
	if t.AccessSource == "tenant" {
		ms, err := s.store.TenantMembers(r.Context(), t.ID)
		if err != nil {
			s.storeErr(w, err, "")
			return
		}
		var gone *Membership
		for _, m := range ms {
			if m.ID == r.PathValue("id") {
				gone = m
			}
		}
		if gone == nil {
			httpx.WriteErr(w, 404, "not found")
			return
		}
		want := []DirGrant{}
		for _, m := range ms {
			if m.ID != gone.ID && strings.EqualFold(m.Email, gone.Email) {
				want = append(want, DirGrant{Email: m.Email, Role: m.Role, Entity: m.Entity, BU: m.BU})
			}
		}
		if code, msg := s.forwardGrants(r.Context(), r, t, gone.Email, want, false); code != 0 {
			httpx.WriteErr(w, code, msg)
			return
		}
		s.audit(r.Context(), current(r).Email, "member.remove", "user/"+gone.Email, t.Slug, gone)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	m, err := s.store.RemoveMembership(r.Context(), t.ID, r.PathValue("id"))
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	s.audit(r.Context(), current(r).Email, "member.remove", "user/"+m.Email, t.Slug, m)
	w.WriteHeader(http.StatusNoContent)
}

// issueMemberToken lets a tenant admin hand a first token to a member. It is
// refused for anyone who also belongs to another tenant or is a platform admin,
// so a tenant admin can never impersonate people outside their tenant.
func (s *Server) issueMemberToken(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, true)
	if t == nil {
		return
	}
	var b tokenBody
	if !httpx.Decode(w, r, &b) {
		return
	}
	ttl, ok := b.check(w)
	if !ok {
		return
	}
	u, err := s.store.UserByEmail(r.Context(), b.Email)
	if err != nil {
		httpx.WriteErr(w, 422, "add the user as a member first")
		return
	}
	p, err := s.store.Principal(r.Context(), u, t.Slug)
	if err != nil || p == nil {
		httpx.WriteErr(w, 422, "add the user as a member first")
		return
	}
	only, err := s.store.OnlyInTenant(r.Context(), u.ID, t.ID)
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	if u.PlatformAdmin {
		httpx.WriteErr(w, http.StatusForbidden, "platform admins sign in with SSO; the platform root has a single recovery token")
		return
	}
	if !current(r).PlatformAdmin && !only {
		httpx.WriteErr(w, http.StatusForbidden, "this user belongs to other tenants or is a platform admin; they must create their own tokens")
		return
	}
	s.issueToken(w, r, u, b.Name, ttl, t.Slug)
}

// ---- the wrapper ----

func (s *Server) transport(t *Tenant) (http.RoundTripper, error) {
	return s.transportLane(t, link.LaneInteractive)
}

// bulkPath reports whether a tenant API path moves bulk data (log streams,
// state history, assistant streams, exports), which rides the link's bulk lane.
func bulkPath(p string) bool {
	return streamPath(p) || strings.HasSuffix(p, "/logs") || strings.Contains(p, "/state-versions") || strings.Contains(p, "/export") || p == "/api/v1/assistant/ask"
}

// streamPath reports whether a tenant API path is a server-sent-event
// stream (live logs, change events): long-lived, so it has its own cap.
func streamPath(p string) bool {
	return strings.HasSuffix(p, "/stream")
}

// transportLane is the HTTP transport to a tenant's API. Tunnel tenants get
// one per link lane, so bulk transfers never share a TCP connection with
// interactive requests.
func (s *Server) transportLane(t *Tenant, lane string) (http.RoundTripper, error) {
	key := t.BackendURL + "\x00" + t.ServerCAPEM + "\x00" + t.Connectivity + "\x00" + t.ServerKeyPin
	slot := t.Slug
	if t.Connectivity == "tunnel" {
		slot += "\x00" + lane
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if tt := s.transports[slot]; tt != nil && tt.key == key {
		return tt.rt, nil
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12, GetClientCertificate: s.cert.GetClientCertificate}
	if t.ServerCAPEM != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(t.ServerCAPEM)) {
			return nil, errors.New("tenant server CA is invalid")
		}
		tc.RootCAs = pool
	}
	if pin := t.ServerKeyPin; pin != "" {
		// The key the tenant's cluster made at bootstrap: a certificate from
		// the tenant server CA alone (a leaked CA key) cannot impersonate it.
		tc.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 || link.KeyFingerprint(cs.PeerCertificates[0].RawSubjectPublicKeyInfo) != pin {
				return errors.New("tenant API key does not match the key pinned at bootstrap")
			}
			return nil
		}
	}
	rt := &http.Transport{TLSClientConfig: tc, ResponseHeaderTimeout: 60 * time.Second, IdleConnTimeout: 90 * time.Second, MaxIdleConnsPerHost: 16}
	if t.Connectivity == "tunnel" {
		// Same mTLS session to the tenant API, carried inside a stream on the
		// tenant's outbound link instead of a TCP connection to BackendURL.
		ten := *t
		rt.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) { return s.dialTenant(ctx, &ten, lane) }
		rt.Proxy = nil
	}
	s.transports[slot] = &tenantTransport{key: key, rt: rt}
	return rt, nil
}

const assistantTimeout = 5 * time.Minute

// proxy forwards /api/v1/t/{tenant}/<rest> to the tenant plane as /api/v1/<rest>.
func (s *Server) proxy(w http.ResponseWriter, r *http.Request) {
	u := current(r)
	slug := r.PathValue("tenant")
	t, err := s.tenant(r.Context(), slug)
	if err != nil {
		httpx.WriteErr(w, http.StatusNotFound, "not found")
		return
	}
	p, err := s.principal(r.Context(), u, sessionOf(r), t)
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	if p == nil {
		// Same answer as an unknown tenant: membership is not discoverable.
		httpx.WriteErr(w, http.StatusNotFound, "not found")
		return
	}
	s.touchUsage(r.Context(), u, t)
	if pendingRefusal(w, t) || trialRefusal(w, r, t) {
		return
	}
	if !s.online(r.Context(), t) {
		httpx.WriteErr(w, http.StatusServiceUnavailable, "tenant_offline: tenant "+slug+" is offline (its link to central is down)")
		return
	}
	prefix := "/api/v1/t/" + slug
	escaped := r.URL.EscapedPath()
	if !strings.HasPrefix(escaped, prefix+"/") {
		httpx.WriteErr(w, http.StatusBadRequest, "bad path")
		return
	}
	path := "/api/v1" + strings.TrimPrefix(escaped, prefix)
	target, err := url.Parse(t.BackendURL + path)
	if err != nil {
		httpx.WriteErr(w, http.StatusBadRequest, "bad path")
		return
	}
	target.RawQuery = r.URL.RawQuery
	assertion, err := identity.SignAssertion(s.issuer, p, r.Method, target.EscapedPath(), time.Now())
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	lane := link.LaneInteractive
	if bulkPath(path) {
		lane = link.LaneBulk
	}
	release := s.admitWorkspace(w, r, u, slug, lane == link.LaneBulk, streamPath(path))
	if release == nil {
		return
	}
	defer release()
	rt, err := s.transportLane(t, lane)
	if err != nil {
		httpx.WriteErr(w, http.StatusBadGateway, "tenant "+slug+" is misconfigured")
		return
	}
	if streamPath(path) {
		// Streams last up to 30 minutes, then the console reconnects.
		http.NewResponseController(w).SetWriteDeadline(time.Now().Add(31 * time.Minute))
	} else if path == "/api/v1/assistant/ask" {
		// The tenant streams progress while the assistant works, which can
		// outlast the server's normal write timeout.
		http.NewResponseController(w).SetWriteDeadline(time.Now().Add(assistantTimeout + 30*time.Second))
	}
	rp := &httputil.ReverseProxy{
		Transport:     rt,
		FlushInterval: -1, // pass streamed responses through as they arrive
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL = target
			pr.Out.Host = target.Host
			pr.Out.Header.Del("Authorization")
			pr.Out.Header.Del("Cookie")
			pr.Out.Header.Set(assertionHeader, assertion)
			httpx.SetTrace(pr.In.Context(), pr.Out) // the workspace continues central's trace
			pr.SetXForwarded()
		},
		ModifyResponse: func(resp *http.Response) error {
			// The workspace continued central's trace; central's own headers
			// already name it, once.
			resp.Header.Del("traceparent")
			resp.Header.Del("X-Request-Id")
			// Access changed inside a tenant-controlled tenant (a grant, a
			// support decision): refresh central's directory copy.
			if t.AccessSource == "tenant" && r.Method != http.MethodGet && resp.StatusCode < 300 && strings.HasPrefix(path, "/api/v1/access/") {
				s.syncLater(t)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			s.log.Warn("tenant plane unreachable", "tenant", slug, "err", err)
			if errors.Is(err, link.ErrOffline) {
				httpx.WriteErr(w, http.StatusServiceUnavailable, "tenant_offline: tenant "+slug+" is offline (its link to central is down)")
				return
			}
			httpx.WriteErr(w, http.StatusBadGateway, "tenant "+slug+" is unreachable")
		},
	}
	rp.ServeHTTP(w, r)
}

// ---- platform admins ----

// Platform admins manage tenants and sign-in; they sign in with SSO. The
// platform root is listed first and can be neither added nor removed here.
func (s *Server) listPlatformAdmins(w http.ResponseWriter, r *http.Request) {
	if !current(r).PlatformAdmin {
		httpx.WriteErr(w, http.StatusForbidden, "only platform admins see platform admins")
		return
	}
	us, err := s.store.PlatformAdmins(r.Context())
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	httpx.WriteJSON(w, 200, map[string]any{"items": us, "sso": len(s.enabledProviders(r.Context())) > 0 || s.cfg.OIDCIssuer != ""})
}

func (s *Server) setPlatformAdmin(w http.ResponseWriter, r *http.Request) {
	me := current(r)
	if !me.PlatformAdmin {
		httpx.WriteErr(w, http.StatusForbidden, "only platform admins add or remove platform admins")
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.PathValue("email")))
	if !emailRe.MatchString(email) {
		httpx.WriteErr(w, 422, "email is invalid")
		return
	}
	grant := r.Method == http.MethodPut
	if !grant && strings.EqualFold(email, me.Email) {
		httpx.WriteErr(w, 422, "you cannot remove yourself; ask another platform admin")
		return
	}
	u, err := s.store.SetPlatformAdmin(r.Context(), email, grant, me.Email)
	if errors.Is(err, ErrNotFound) {
		httpx.WriteErr(w, 404, "not a platform admin, or the platform root (which cannot be removed)")
		return
	}
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	action := "platform_admin.add"
	if !grant {
		action = "platform_admin.remove"
	}
	s.audit(r.Context(), me.Email, action, "user/"+email, "", nil)
	httpx.WriteJSON(w, 200, u)
}
