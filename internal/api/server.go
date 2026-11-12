// Package api is a tenant plane's HTTP surface: the REST API the central plane
// forwards user requests to, the runner (agent) API, the OpenTofu HTTP state
// backend and the OIDC issuer clouds trust for this tenant's runs.
//
// User requests are accepted only from the central plane: the TLS connection
// must present central's client certificate (mTLS), and each request must carry
// a short-lived assertion signed by central, bound to the method and path and
// naming this tenant. This plane never sees users' API tokens.
package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/assistant"
	"github.com/itsPavanFeed/srustiops-backend/internal/blob"
	"github.com/itsPavanFeed/srustiops-backend/internal/bundlecache"
	"github.com/itsPavanFeed/srustiops-backend/internal/catalog"
	"github.com/itsPavanFeed/srustiops-backend/internal/certs"
	"github.com/itsPavanFeed/srustiops-backend/internal/config"
	"github.com/itsPavanFeed/srustiops-backend/internal/httpx"
	"github.com/itsPavanFeed/srustiops-backend/internal/identity"
	"github.com/itsPavanFeed/srustiops-backend/internal/metrics"
	"github.com/itsPavanFeed/srustiops-backend/internal/oidc"
	"github.com/itsPavanFeed/srustiops-backend/internal/orchestrator"
	"github.com/itsPavanFeed/srustiops-backend/internal/release"
	"github.com/itsPavanFeed/srustiops-backend/internal/secure"
	"github.com/itsPavanFeed/srustiops-backend/internal/store"
)

// AssertionHeader carries central's signed assertion on forwarded requests.
const AssertionHeader = "X-SrustiOps-Assertion"

type Server struct {
	auditQ     auditBacklog                   // audit events whose write failed, retried in order
	backupCopy blob.Store                     // second destination for backups (nil: none)
	gates      map[string]*gate               // integration routes whose edits and deletes need approval
	decom      atomic.Pointer[decommissioned] // set once the workspace is removed from the platform
	// outputsChanged marks stacks whose last apply changed their exported outputs.
	outputsChanged sync.Map
	cfg            *config.Server
	store          *store.Store
	sealer         *secure.Sealer
	issuer         *oidc.Issuer
	log            *slog.Logger
	limiter        *httpx.Limiter
	central        *centralKeys
	objects        blob.Store // tenant bucket for state, plans and backups; nil = keep them in PostgreSQL
	changes        *changeHub // change events for the console's live streams
	engine         orchestrator.Engine
	wakeMu         sync.Mutex
	wake           chan struct{} // closed to nudge long-polling runners when work is queued

	assistant      atomic.Pointer[assistantState]  // nil = disabled
	assistantDocs  atomic.Pointer[[]assistant.Doc] // catalog, guide and runbooks
	assistantExtra []assistant.Doc                 // runbooks from SRUSTIOPS_ASSISTANT_DOCS_DIR
	askLimiter     *httpx.Limiter
	gh             ghCache                           // GitHub App with its token cache
	ghSnap         atomic.Pointer[ghSettings]        // GitHub App settings, reloaded on change
	dirSnap        atomic.Pointer[map[string]string] // business unit → entity, learned from central
	accessSnap     atomic.Pointer[accessSettings]    // who decides access: central or this tenant
	idp            idpCache                          // this tenant's own identity provider keys
	fetcher        release.Fetcher                   // registry, or the offline module mirror
	keys           *linkKeys                         // directory signing and queue encryption keys
	slackSnap      atomic.Pointer[slackSettings]     // Slack incoming webhook, reloaded on change
	emailSnap      atomic.Pointer[emailSettings]     // the mail server (SMTP), reloaded on change
	mailKick       chan struct{}                     // wakes the mailer when emails are queued
	platSnap       atomic.Pointer[platform]          // catalog, tenant defaults and deployed module release
	bundles        *bundlecache.Cache                // release bundles: memory, then disk, then the database or bucket
}

func New(cfg *config.Server, st *store.Store, cat *catalog.Catalog, sealer *secure.Sealer, iss *oidc.Issuer, log *slog.Logger) (*Server, error) {
	ck, err := newCentralKeys(cfg)
	if err != nil {
		return nil, err
	}
	srv := &Server{cfg: cfg, store: st, sealer: sealer, issuer: iss, log: log, central: ck, changes: newChangeHub(), mailKick: make(chan struct{}, 1), auditQ: auditBacklog{wake: make(chan struct{}, 1)},
		limiter: httpx.NewLimiter(10, time.Minute, 5*time.Minute), wake: make(chan struct{}), engine: orchestrator.Builtin{},
		askLimiter: httpx.NewLimiter(60, time.Hour, 15*time.Minute)}
	bundled, err := bundledPlatform(cat, cfg.CatalogDir, cfg.Tenant)
	if err != nil {
		return nil, err
	}
	srv.platSnap.Store(bundled)
	ck.seen = func(jti string, exp time.Time) (bool, error) { return st.SeenAssertion(context.Background(), jti, exp) }
	if ck.av != nil {
		ck.av.Seen = ck.seen
	}
	srv.fetcher = &release.Registry{Base: cfg.RegistryURL}
	if cfg.ModuleMirror != "" {
		key, err := release.ParseMirrorKey(cfg.ModuleMirrorKey)
		if err != nil {
			return nil, err
		}
		srv.fetcher = &release.Mirror{Dir: cfg.ModuleMirror, Key: key}
		log.Info("module releases vendor packages from the offline module mirror", "dir", cfg.ModuleMirror)
	}
	if srv.bundles, err = bundlecache.New(srv.loadBundle, cfg.BundleCacheDir, cfg.BundleCacheMem, cfg.BundleCacheDisk); err != nil {
		log.Warn("the bundle disk cache is unavailable; caching in memory only", "dir", cfg.BundleCacheDir, "err", err)
		srv.bundles, _ = bundlecache.New(srv.loadBundle, "", cfg.BundleCacheMem, 0)
	}
	srv.loadActiveRelease(context.Background())
	if err := srv.enableAssistant(); err != nil {
		return nil, err
	}
	srv.loadDirectory(context.Background())
	srv.loadAccess(context.Background())
	if err := srv.loadLinkKeys(context.Background()); err != nil {
		return nil, fmt.Errorf("directory keys: %w", err)
	}
	var dc decommissioned
	srv.contractsConfig(context.Background()) // scopes pull requests to the contracts repository
	if cfg.BackupCopyURL != "" {
		bs, err := blob.Open(cfg.BackupCopyURL, cfg.BucketAccessKey, cfg.BucketSecretKey, nil)
		if err != nil {
			return nil, fmt.Errorf("SRUSTIOPS_BACKUP_COPY_URL: %w", err)
		}
		srv.backupCopy = bs
	}
	if ok, _ := srv.store.Setting(context.Background(), decommissionSetting, &dc); ok {
		srv.decom.Store(&dc)
		log.Warn("this workspace was removed from the platform: refusing all work; the data is kept", "on", dc.At)
	}
	if err := srv.registerBootstrapRunner(context.Background()); err != nil {
		return nil, err
	}
	srv.loadSlack(context.Background())
	if err := st.FailStaleScans(context.Background()); err != nil {
		log.Warn("closing interrupted inventory scans", "err", err)
	}
	if err := srv.ghReload(context.Background()); err != nil {
		return nil, fmt.Errorf("loading GitHub App settings: %w", err)
	}
	if cfg.BucketURL != "" {
		bs, err := blob.Open(cfg.BucketURL, cfg.BucketAccessKey, cfg.BucketSecretKey, nil)
		if err != nil {
			return nil, fmt.Errorf("SRUSTIOPS_BUCKET_URL: %w", err)
		}
		srv.objects = bs
		if cfg.BucketCreate {
			if err := srv.objects.EnsureBucket(context.Background()); err != nil {
				return nil, fmt.Errorf("creating bucket: %w", err)
			}
		}
		log.Info("state and plans are stored in the tenant bucket", "bucket", bs.String())
	}
	return srv, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		h := map[string]any{"status": "ok", "tenant": s.cfg.Tenant, "version": s.cfg.Version}
		if n := s.auditQ.len(); n > 0 {
			h["status"], h["audit_backlog"] = "degraded", n // audit events not written yet
		}
		if held := store.HeldLocks(); len(held) > 0 {
			jobs := map[string]string{}
			for k, since := range held {
				jobs[jobName(k)] = since.UTC().Format(time.RFC3339)
			}
			h["running_jobs"] = jobs // single-replica jobs this replica runs now
		}
		writeJSON(w, 200, h)
	})
	mux.HandleFunc("GET /.well-known/openid-configuration", s.raw(s.issuer.Discovery))
	mux.HandleFunc("GET /.well-known/jwks.json", s.raw(s.issuer.JWKS))

	// Users, via the central plane. Fine-grained checks happen in each handler,
	// because they depend on the entity of the resource being touched.
	u := func(h http.HandlerFunc) http.Handler { return s.authUser(h) }
	mux.Handle("GET /api/v1/me", u(s.me))
	mux.Handle("GET /api/v1/openapi.json", u(s.openAPI))
	// Tenant-controlled access: tenant admins manage it here; central syncs
	// its directory copy and relays support requests and sign-ins.
	mux.Handle("GET /api/v1/access", u(s.getAccess))
	mux.Handle("PUT /api/v1/access/settings", u(s.putAccessSettings))
	mux.Handle("GET /api/v1/access/grants", u(s.listAccessGrants))
	mux.Handle("POST /api/v1/access/grants", u(s.addAccessGrant))
	mux.Handle("DELETE /api/v1/access/grants/{id}", u(s.deleteAccessGrant))
	mux.Handle("GET /api/v1/access/bindings", u(s.listGroupBindings))
	mux.Handle("POST /api/v1/access/bindings", u(s.addGroupBinding))
	mux.Handle("DELETE /api/v1/access/bindings/{id}", u(s.deleteGroupBinding))
	mux.Handle("GET /api/v1/access/support", u(s.listSupportGrants))
	mux.Handle("POST /api/v1/access/support/{id}/{decision}", u(s.decideSupportGrant))
	mux.Handle("POST /api/v1/access/import", u(s.importAccess))
	mux.Handle("GET /api/v1/access/directory", u(s.accessDirectory))
	mux.Handle("POST /api/v1/access/support-requests", u(s.requestSupport))
	mux.Handle("PUT /api/v1/access/groups/{group}/members", u(s.setGroupMembers))
	mux.Handle("POST /api/v1/access/oidc/start", u(s.oidcStart))
	mux.Handle("POST /api/v1/access/oidc/finish", u(s.oidcFinish))
	mux.Handle("POST /api/v1/access/saml/start", u(s.samlStart))
	mux.Handle("POST /api/v1/access/saml/finish", u(s.samlFinish))
	mux.Handle("GET /api/v1/access/saml/metadata", u(s.samlSPMetadata))
	mux.Handle("GET /api/v1/link/keys", u(s.linkKeysView))
	mux.Handle("POST /api/v1/link/events", u(s.linkEvent))
	mux.Handle("GET /api/v1/catalog", u(s.getCatalog))
	mux.Handle("GET /api/v1/connections", u(s.listConnections))
	mux.Handle("POST /api/v1/connections", u(s.createConnection))
	mux.Handle("POST /api/v1/connections/test", u(s.testNewConnection))
	mux.Handle("GET /api/v1/connections/{id}", u(s.getConnection))
	mux.Handle("PUT /api/v1/connections/{id}", u(s.gated("connection.update", "Cloud connection", s.updateConnection, "id")))
	mux.Handle("DELETE /api/v1/connections/{id}", u(s.gated("connection.delete", "Cloud connection", s.deleteConnection, "id")))
	mux.Handle("POST /api/v1/connections/{id}/scan", u(s.scanConnection))
	mux.Handle("POST /api/v1/connections/{id}/test", u(s.testConnection))
	mux.Handle("GET /api/v1/orgs", u(s.listOrgs))
	mux.Handle("POST /api/v1/orgs", u(s.createOrg))
	mux.Handle("GET /api/v1/orgs/{id}", u(s.getOrg))
	mux.Handle("PUT /api/v1/orgs/{id}", u(s.gated("org.update", "Organisation", s.updateOrg, "id")))
	mux.Handle("DELETE /api/v1/orgs/{id}", u(s.gated("org.delete", "Organisation", s.deleteOrg, "id")))
	mux.Handle("POST /api/v1/orgs/{id}/sync", u(s.syncOrg))
	mux.Handle("PUT /api/v1/orgs/{id}/mapping", u(s.mapUnit))
	mux.Handle("POST /api/v1/orgs/{id}/onboard", u(s.onboardOrg))
	mux.Handle("GET /api/v1/event-sources", u(s.listEventSources))
	mux.Handle("POST /api/v1/event-sources", u(s.createEventSource))
	mux.Handle("DELETE /api/v1/event-sources/{id}", u(s.gated("events.delete", "Event source", s.deleteEventSource, "id")))
	mux.Handle("GET /api/v1/cloud-events", u(s.listCloudEvents))
	mux.Handle("GET /api/v1/stacks/{id}/live-changes", u(s.stackLiveChanges))
	mux.Handle("GET /api/v1/stacks/{id}/contract", u(s.getStackContract))
	mux.Handle("PUT /api/v1/stacks/{id}/contract", u(s.putStackContract))
	mux.Handle("GET /api/v1/inventory", u(s.listInventory))
	mux.Handle("GET /api/v1/inventory/scans", u(s.listScans))
	mux.Handle("GET /api/v1/inventory/summary", u(s.inventorySummary))
	mux.Handle("GET /api/v1/inventory/services", u(s.inventoryServices))
	mux.Handle("GET /api/v1/inventory/resource", u(s.inventoryResource))
	mux.Handle("POST /api/v1/inventory/adopt", u(s.adoptResources))
	mux.Handle("POST /api/v1/inventory/bulk-import", u(s.bulkImport))
	mux.Handle("GET /api/v1/environments", u(s.listEnvironments))
	mux.Handle("POST /api/v1/environments", u(s.createEnvironment))
	mux.Handle("GET /api/v1/environments/{id}", u(s.getEnvironment))
	mux.Handle("PUT /api/v1/environments/{id}", u(s.updateEnvironment))
	mux.Handle("DELETE /api/v1/environments/{id}", u(s.deleteEnvironment))
	mux.Handle("GET /api/v1/stacks", u(s.listStacks))
	mux.Handle("POST /api/v1/stacks", u(s.createStack))
	mux.Handle("POST /api/v1/stacks/preview", u(s.previewStack))
	mux.Handle("POST /api/v1/stacks/propose", u(s.proposeStack))
	mux.Handle("GET /api/v1/stacks/{id}", u(s.getStack))
	mux.Handle("PUT /api/v1/stacks/{id}", u(s.updateStack))
	mux.Handle("GET /api/v1/stacks/{id}/runs", u(s.listStackRuns))
	mux.Handle("GET /api/v1/stacks/{id}/dependencies", u(s.stackDependencies))
	mux.Handle("GET /api/v1/stack-graph", u(s.stackGraph))
	mux.Handle("POST /api/v1/stacks/{id}/runs", u(s.createRun))
	mux.Handle("GET /api/v1/stacks/{id}/state-versions", u(s.listStateVersions))
	mux.Handle("GET /api/v1/stacks/{id}/resources", u(s.stackResourceView))
	mux.Handle("GET /api/v1/stacks/{id}/outputs", u(s.stackOutputs))
	mux.Handle("GET /api/v1/stacks/{id}/lifecycle", u(s.stackLifecycle))
	mux.Handle("POST /api/v1/stacks/{id}/lock", u(s.lockStack))
	mux.Handle("DELETE /api/v1/stacks/{id}/lock", u(s.unlockStack))
	mux.Handle("DELETE /api/v1/stacks/{id}", u(s.deleteStack))
	mux.Handle("POST /api/v1/stacks/{id}/clone", u(s.cloneStack))
	mux.Handle("GET /api/v1/stacks/{id}/promote", u(s.promotePreview))
	mux.Handle("POST /api/v1/stacks/{id}/promote", u(s.promoteStack))
	mux.Handle("GET /api/v1/stack-templates", u(s.listTemplates))
	mux.Handle("POST /api/v1/stack-templates", u(s.createTemplate))
	mux.Handle("GET /api/v1/stack-templates/{id}", u(s.getTemplate))
	mux.Handle("PUT /api/v1/stack-templates/{id}", u(s.updateTemplate))
	mux.Handle("DELETE /api/v1/stack-templates/{id}", u(s.deleteTemplate))
	mux.Handle("GET /api/v1/environments/{id}/schedule", u(s.getSchedule))
	mux.Handle("PUT /api/v1/environments/{id}/schedule", u(s.putSchedule))
	mux.Handle("POST /api/v1/environments/{id}/check-now", u(s.checkNow))
	mux.Handle("POST /api/v1/runs/{id}/cancel", u(s.cancelRun))
	mux.Handle("GET /api/v1/notifications/preferences", u(s.getNotificationPrefs))
	mux.Handle("PUT /api/v1/notifications/preferences", u(s.putNotificationPrefs))
	mux.Handle("GET /api/v1/integrations/email", u(s.getEmailIntegration))
	mux.Handle("PUT /api/v1/integrations/email", u(s.gatedIfConfigured("email", "Email (SMTP)", s.putEmailIntegration)))
	mux.Handle("DELETE /api/v1/integrations/email", u(s.gated("email.delete", "Email (SMTP)", s.deleteEmailIntegration)))
	mux.Handle("POST /api/v1/integrations/email/test", u(s.testEmailIntegration))
	mux.Handle("POST /api/v1/fleet/target", u(s.putFleetTarget))
	mux.Handle("PUT /api/v1/plan", u(s.putPlanLimits))
	mux.Handle("GET /api/v1/usage", u(s.getUsage))
	mux.Handle("GET /api/v1/retention", u(s.getRetention))
	mux.Handle("PUT /api/v1/retention", u(s.putRetention))
	mux.Handle("POST /api/v1/retention/prune", u(s.pruneNow))
	mux.Handle("GET /api/v1/git-identities", u(s.listGitIdentities))
	mux.Handle("POST /api/v1/git-identities", u(s.addGitIdentity))
	mux.Handle("DELETE /api/v1/git-identities/{provider}/{login}", u(s.deleteGitIdentity))
	mux.Handle("GET /api/v1/costs", u(s.getCosts))
	mux.Handle("PUT /api/v1/costs/settings", u(s.putCostSettings))
	mux.Handle("POST /api/v1/costs/refresh", u(s.refreshCosts))
	mux.Handle("PUT /api/v1/budgets/{bu}", u(s.putBudget))
	mux.Handle("DELETE /api/v1/budgets/{bu}", u(s.deleteBudget))
	mux.Handle("GET /api/v1/fleet", u(s.getFleet))
	mux.Handle("GET /api/v1/backups", u(s.listBackups))
	mux.Handle("POST /api/v1/backups", u(s.createBackup))
	mux.Handle("PUT /api/v1/backups/schedule", u(s.putBackupSchedule))
	mux.Handle("POST /api/v1/backups/{id}/drill", u(s.drillBackupHandler))
	mux.Handle("GET /api/v1/backups/{id}/download", u(s.downloadBackup))
	mux.Handle("GET /api/v1/integrations/audit-export", u(s.getAuditExport))
	mux.Handle("PUT /api/v1/integrations/audit-export", u(s.gatedIfConfigured("audit-export", "Audit export", s.putAuditExport)))
	mux.Handle("DELETE /api/v1/integrations/audit-export", u(s.gated("audit-export.delete", "Audit export", s.deleteAuditExport)))
	mux.Handle("POST /api/v1/integrations/audit-export/test", u(s.testAuditExport))
	mux.Handle("GET /api/v1/policies/library", u(s.policyLibrary))
	mux.Handle("POST /api/v1/policies/backtest", u(s.backtestPolicy))
	mux.Handle("GET /api/v1/runs", u(s.listRuns))
	mux.Handle("GET /api/v1/runs/{id}", u(s.getRun))
	mux.Handle("GET /api/v1/runs/{id}/logs", u(s.getRunLogs))
	mux.Handle("GET /api/v1/runs/{id}/logs/stream", u(s.streamRunLogs))
	mux.Handle("GET /api/v1/events/stream", u(s.streamChanges))
	mux.Handle("POST /api/v1/runs/{id}/approve", u(s.approveRun))
	mux.Handle("POST /api/v1/runs/{id}/override", u(s.overrideRun))
	mux.Handle("GET /api/v1/runs/{id}/live-to-code", u(s.getLiveToCode))
	mux.Handle("POST /api/v1/runs/{id}/live-to-code", u(s.applyLiveToCode))
	mux.Handle("POST /api/v1/runs/{id}/discard", u(s.discardRun))
	mux.Handle("GET /api/v1/audit", u(s.listAudit))
	mux.Handle("GET /api/v1/audit/verify", u(s.verifyAudit))
	mux.Handle("GET /api/v1/contracts", u(s.getContracts))
	mux.Handle("PUT /api/v1/contracts", u(s.gatedIfConfigured("contracts", "Contracts repository", s.putContracts)))
	mux.Handle("PUT /api/v1/contracts/token", u(s.gatedIfConfigured("contracts-token", "Contracts repository token", s.putContractsToken)))
	mux.Handle("POST /api/v1/contracts/sync", u(s.syncContractsNow))
	mux.Handle("GET /api/v1/policies", u(s.listPolicies))
	mux.Handle("POST /api/v1/policies", u(s.createPolicy))
	mux.Handle("PUT /api/v1/policies/{id}", u(s.updatePolicy))
	mux.Handle("DELETE /api/v1/policies/{id}", u(s.deletePolicy))
	mux.Handle("POST /api/v1/policies/test", u(s.testPolicy))
	mux.Handle("GET /api/v1/settings/risk", u(s.getRiskSettings))
	mux.Handle("PUT /api/v1/settings/risk", u(s.putRiskSettings))
	mux.Handle("GET /api/v1/assistant", u(s.assistantInfo))
	mux.Handle("POST /api/v1/assistant/ask", u(s.askAssistant))
	mux.Handle("GET /api/v1/integrations/channels", u(s.getChannels))
	mux.Handle("PUT /api/v1/integrations/channels", u(s.gatedIfConfigured("channels", "Notification channels", s.putChannels)))
	mux.Handle("POST /api/v1/integrations/channels/test", u(s.testChannels))
	mux.Handle("GET /api/v1/integrations/assistant", u(s.getAssistantIntegration))
	mux.Handle("PUT /api/v1/integrations/assistant", u(s.gatedIfConfigured("assistant", "Assistant", s.putAssistantIntegration)))
	mux.Handle("DELETE /api/v1/integrations/assistant", u(s.gated("assistant.delete", "Assistant", s.deleteAssistantIntegration)))
	mux.Handle("GET /api/v1/integrations/github", u(s.getGitHubIntegration))
	mux.Handle("PUT /api/v1/integrations/github", u(s.gatedIfConfigured("github", "GitHub App", s.putGitHubIntegration)))
	mux.Handle("DELETE /api/v1/integrations/github", u(s.gated("github.delete", "GitHub App", s.deleteGitHubIntegration)))
	mux.Handle("POST /api/v1/integrations/github/test", u(s.testGitHubIntegration))
	mux.Handle("GET /api/v1/integrations/github/deliveries", u(s.listGitHubDeliveries))
	mux.Handle("POST /api/v1/webhooks/github", s.authRelay(s.githubWebhook))
	mux.Handle("POST /api/v1/webhooks/queued", s.authRelay(s.queuedWebhook))
	mux.Handle("POST /api/v1/webhooks/cloud/{source}", s.authRelay(s.cloudEventHook))
	mux.Handle("GET /api/v1/pull-requests", u(s.listPullRequests))
	mux.Handle("GET /api/v1/notifications", u(s.listNotifications))
	mux.Handle("GET /api/v1/notifications/unread", u(s.unreadNotifications))
	mux.Handle("POST /api/v1/notifications/read", u(s.readNotifications))
	mux.Handle("GET /api/v1/integrations/slack", u(s.getSlackIntegration))
	mux.Handle("PUT /api/v1/integrations/slack", u(s.gatedIfConfigured("slack", "Slack notifications", s.putSlackIntegration)))
	mux.Handle("DELETE /api/v1/integrations/slack", u(s.gated("slack.delete", "Slack notifications", s.deleteSlackIntegration)))
	mux.Handle("POST /api/v1/integrations/slack/test", u(s.testSlackIntegration))
	mux.Handle("GET /api/v1/releases/cache", u(s.bundleCacheStats))
	mux.Handle("GET /api/v1/releases/{kind}", u(s.listReleases))
	mux.Handle("GET /api/v1/releases/{kind}/source", u(s.getReleaseSource))
	mux.Handle("PUT /api/v1/releases/{kind}/source", u(s.putReleaseSource))
	mux.Handle("PUT /api/v1/releases/{kind}/source/token", u(s.putReleaseToken))
	mux.Handle("POST /api/v1/releases/{kind}/builds", u(s.buildReleaseNow))
	mux.Handle("GET /api/v1/releases/{kind}/{id}", u(s.getRelease))
	mux.Handle("GET /api/v1/releases/{kind}/files", u(s.getReleaseFile))
	mux.Handle("POST /api/v1/releases/{kind}/changes", u(s.proposeReleaseChange))
	mux.Handle("POST /api/v1/releases/{kind}/{id}/request", u(s.requestActivation))
	mux.Handle("POST /api/v1/releases/{kind}/{id}/approve", u(s.approveRelease))
	mux.Handle("POST /api/v1/releases/{kind}/{id}/reject", u(s.rejectRelease))
	mux.Handle("POST /api/v1/releases/{kind}/{id}/merge", u(s.retryMerge))
	mux.Handle("POST /api/v1/releases/{kind}/{id}/override", u(s.overrideRelease))
	mux.Handle("GET /api/v1/integrations/secret-store", u(s.getSecretStore))
	mux.Handle("PUT /api/v1/integrations/secret-store", u(s.gatedIfConfigured("secret-store", "Secret store", s.putSecretStore)))
	mux.Handle("DELETE /api/v1/integrations/secret-store", u(s.gated("secret-store.delete", "Secret store", s.deleteSecretStore)))
	mux.Handle("GET /api/v1/integration-changes", u(s.listChanges))
	mux.Handle("POST /api/v1/integration-changes/{id}/approve", u(s.decideChange("approve")))
	mux.Handle("POST /api/v1/integration-changes/{id}/override", u(s.decideChange("override")))
	mux.Handle("POST /api/v1/integration-changes/{id}/reject", u(s.decideChange("reject")))
	mux.Handle("POST /api/v1/integration-changes/{id}/cancel", u(s.decideChange("cancel")))
	mux.Handle("POST /api/v1/integrations/secret-store/test", u(s.testSecretStore))
	mux.Handle("POST /api/v1/pull-requests/{n}/plan", u(s.replanPullRequest))
	mux.Handle("GET /api/v1/runners", u(s.listRunners))
	mux.Handle("POST /api/v1/runners", u(s.createRunner))
	mux.Handle("DELETE /api/v1/runners/{id}", u(s.revokeRunner))

	// Runners (sop_r_ tokens) claim work; run tokens (sop_t_) act on one run.
	mux.Handle("POST /api/v1/agent/claim", s.authRunner(s.claim))
	mux.Handle("POST /api/v1/agent/runs/{id}/logs", s.authRun(s.agentLogs))
	mux.Handle("POST /api/v1/agent/runs/{id}/plan", s.authRun(s.agentPlan))
	mux.Handle("GET /api/v1/agent/runs/{id}/plan", s.authRun(s.agentGetPlan))
	mux.Handle("POST /api/v1/agent/runs/{id}/finish", s.authRun(s.agentFinish))
	mux.Handle("POST /api/v1/agent/runs/{id}/outputs", s.authRun(s.agentOutputs))
	mux.Handle("GET /api/v1/agent/runs/{id}/bundles/{sha}", s.authRun(s.agentBundle))

	// OpenTofu HTTP state backend, authenticated with the run token.
	mux.HandleFunc("/state/v1/{stack}", s.state)
	mux.Handle("POST /api/v1/decommission", u(s.decommission))

	return httpx.Trace(s.log, "tenant", 2*time.Second, metrics.Default.Requests("tenant", httpx.SecurityHeaders(true, s.refuseDecommissioned(mux))))
}

// Run serves HTTPS. Client certificates are optional at the TLS layer (runners
// do not have one) and required by authUser for user requests.
func (s *Server) Run(ctx context.Context) error {
	go s.serveBreakglass(ctx)
	// Certificates and the client CA reload from disk when rotated.
	kp, err := certs.NewKeyPair(s.cfg.TLSCert, s.cfg.TLSKey)
	if err != nil {
		return fmt.Errorf("TLS certificate: %w", err)
	}
	pool, err := certs.NewPool(s.cfg.CentralClientCA)
	if err != nil {
		return fmt.Errorf("SRUSTIOPS_CENTRAL_CLIENT_CA: %w", err)
	}
	tlsCfg := certs.ServerConfig(kp, pool)
	if s.cfg.TemporalAddress != "" {
		t, err := orchestrator.NewTemporal(orchestrator.TemporalConfig{
			Address: s.cfg.TemporalAddress, Namespace: s.cfg.TemporalNamespace,
			TaskQueue: "srustiops-" + s.cfg.Tenant, Timeouts: orchestrator.DefaultTimeouts,
		}, &orchestrator.Activities{Store: orchStore{s}, OnQueue: func(ctx context.Context, ids []string) {
			for _, id := range ids {
				s.engine.RunCreated(ctx, id)
			}
			s.notify()
		}}, func(msg string, args ...any) { s.log.Warn(msg, args...) })
		if err != nil {
			return fmt.Errorf("connecting to Temporal at %s: %w", s.cfg.TemporalAddress, err)
		}
		t.Describe = s.describeRun
		defer t.Close()
		s.engine = t
		s.log.Info("run lifecycles are orchestrated by Temporal", "address", s.cfg.TemporalAddress, "task_queue", "srustiops-"+s.cfg.Tenant)
	}
	go s.reaper(ctx)
	go s.contractsSyncer(ctx)
	go s.ghWatch(ctx)
	go s.prReconciler(ctx)
	go s.prPoller(ctx)
	go s.releaseSyncer(ctx)
	go s.pendingReleaser(ctx)
	go s.listenChanges(ctx)
	s.registerMetrics(metrics.Default)
	go s.logArchiver(ctx)
	go s.scheduler(ctx)
	go s.mailer(ctx)
	go s.auditExporter(ctx)
	go s.backupLoop(ctx)
	go s.costLoop(ctx)
	go s.auditRetrier(ctx)
	go s.retentionLoop(ctx)
	go s.digestLoop(ctx)
	s.log.Info("tenant plane serving HTTPS", "tenant", s.cfg.Tenant, "listen", s.cfg.Listen, "central", s.cfg.CentralURL)
	return httpx.Serve(ctx, s.log, s.cfg.Listen, s.Handler(), tlsCfg, "", "")
}

// pendingReleaser retries deferred plans every minute (and once at start).
// A plan waits for the stacks it references; it is also started when one
// of them applies, but a plan that could not be built then (a module that
// came with a later release, say) would otherwise wait for an unrelated
// apply.
func (s *Server) pendingReleaser(ctx context.Context) {
	s.store.TryLock(ctx, 7314, s.releasePending)
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.store.TryLock(ctx, 7314, s.releasePending)
		}
	}
}

func (s *Server) reaper(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if s.engine.Name() == "builtin" { // Temporal owns run timers otherwise
				ids, err := s.store.Reap(ctx, 15*time.Minute, 24*time.Hour)
				if err != nil {
					s.log.Error("reaper", "err", err)
					continue
				}
				for _, id := range ids {
					s.audit(ctx, "system", "run.reaped", "run/"+id, "", nil)
				}
			}
			s.store.ReleaseRunLocks(ctx)
			s.cleanupPlans(ctx)
		}
	}
}

// orchStore adapts the tenant plane for workflow activities.
type orchStore struct{ s *Server }

func (o orchStore) Expire(ctx context.Context, runID string, from []string, to, reason string) (bool, error) {
	moved, err := o.s.store.Expire(ctx, runID, from, to, reason)
	if moved {
		o.s.audit(ctx, "system:temporal", "run.expired", "run/"+runID, "", map[string]string{"status": to, "reason": reason})
	}
	return moved, err
}

// runCreated wakes runners and starts the run's lifecycle in the engine.
func (s *Server) runCreated(ctx context.Context, runID string) {
	s.engine.RunCreated(ctx, runID)
	s.notify()
}

func (s *Server) notify() {
	s.wakeMu.Lock()
	close(s.wake)
	s.wake = make(chan struct{})
	s.wakeMu.Unlock()
}

func (s *Server) wakeCh() <-chan struct{} {
	s.wakeMu.Lock()
	defer s.wakeMu.Unlock()
	return s.wake
}

// ---- central signing keys ----

// centralKeys verifies assertions with central's JWKS, fetched lazily and
// refreshed (at most once a minute) when an unknown key ID appears, so
// central can rotate keys without restarting tenant planes.
type centralKeys struct {
	cfg     *config.Server
	hc      *http.Client
	mu      sync.Mutex
	av      *identity.AssertionVerifier
	fetched time.Time
	// seen is the replay cache shared by every replica of this plane.
	seen func(jti string, expires time.Time) (bool, error)
}

func newCentralKeys(cfg *config.Server) (*centralKeys, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CentralCAFile != "" {
		pem, err := os.ReadFile(cfg.CentralCAFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("SRUSTIOPS_CENTRAL_CA_FILE contains no certificates")
		}
		tc.RootCAs = pool
	}
	ck := &centralKeys{cfg: cfg, hc: &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: tc}}}
	if cfg.CentralJWKSFile != "" {
		b, err := os.ReadFile(cfg.CentralJWKSFile)
		if err != nil {
			return nil, err
		}
		if err := ck.load(b); err != nil {
			return nil, err
		}
	}
	return ck, nil
}

func (c *centralKeys) load(jwks []byte) error {
	v, err := oidc.NewVerifier(c.cfg.CentralIssuer, jwks)
	if err != nil {
		return err
	}
	c.av = identity.NewAssertionVerifier(c.cfg.Tenant, v)
	c.av.Seen = c.seen
	return nil
}

func (c *centralKeys) verifier(ctx context.Context, refresh bool) (*identity.AssertionVerifier, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.av != nil && (!refresh || c.cfg.CentralJWKSFile != "" || time.Since(c.fetched) < time.Minute) {
		return c.av, nil
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.CentralURL+"/.well-known/jwks.json", nil)
	resp, err := c.hc.Do(req)
	if err != nil {
		if c.av != nil {
			return c.av, nil
		}
		return nil, fmt.Errorf("fetching central JWKS: %w", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	c.fetched = time.Now()
	if resp.StatusCode != http.StatusOK {
		return c.av, fmt.Errorf("central JWKS: %s", resp.Status)
	}
	// Keep the replay cache across refreshes.
	v, err := oidc.NewVerifier(c.cfg.CentralIssuer, b)
	if err != nil {
		return c.av, err
	}
	if c.av == nil {
		c.av = identity.NewAssertionVerifier(c.cfg.Tenant, v)
		c.av.Seen = c.seen
		c.av.Seen = c.seen
	} else {
		c.av.SetVerifier(v)
	}
	return c.av, nil
}

// ---- principals & auth ----

type principal struct {
	Kind   string // user | runner | run
	User   *identity.Principal
	Runner *store.Runner
	Run    *store.Run
}

func (p *principal) Subject() string {
	switch p.Kind {
	case "user":
		return p.User.Actor()
	case "runner":
		return "runner:" + p.Runner.Name
	}
	return "run:" + p.Run.ID
}

type ctxKey struct{}

func who(r *http.Request) *principal { return r.Context().Value(ctxKey{}).(*principal) }

func user(r *http.Request) *identity.Principal { return who(r).User }

// authUser accepts a request only over central's mTLS client certificate with
// a valid assertion for this tenant and this exact request.
func (s *Server) authUser(h http.HandlerFunc) http.Handler {
	return s.withLimiter(func(w http.ResponseWriter, r *http.Request) bool {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			return false
		}
		tok := r.Header.Get(AssertionHeader)
		if tok == "" {
			return false
		}
		av, err := s.central.verifier(r.Context(), false)
		if err != nil {
			s.log.Error("central keys unavailable", "err", err)
			writeErr(w, http.StatusServiceUnavailable, "cannot verify requests: central plane keys unavailable")
			return true
		}
		p, err := av.Verify(tok, r.Method, r.URL.EscapedPath(), time.Now())
		if err != nil && err.Error() == "unknown signing key" {
			if av, err2 := s.central.verifier(r.Context(), true); err2 == nil {
				p, err = av.Verify(tok, r.Method, r.URL.EscapedPath(), time.Now())
			}
		}
		if err != nil {
			s.log.Warn("assertion rejected", "err", err, "ip", clientIP(r))
			return false
		}
		s.noteDirectory(r.Context(), p.BUEntity)
		rp, err := s.resolveAccess(r.Context(), p)
		var denied *accessDenied
		if errors.As(err, &denied) {
			s.log.Info("access refused by tenant policy", "code", denied.code, "subject", p.Subject)
			writeJSON(w, http.StatusForbidden, map[string]string{"error": denied.Error(), "code": denied.code})
			return true
		}
		if err != nil {
			s.writeStoreErr(w, err, "")
			return true
		}
		h(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, &principal{Kind: "user", User: rp})))
		return true
	})
}

func (s *Server) authRunner(h http.HandlerFunc) http.Handler {
	return s.withLimiter(func(w http.ResponseWriter, r *http.Request) bool {
		tok := httpx.Bearer(r)
		if len(tok) < 7 || tok[:6] != "sop_r_" {
			return false
		}
		rn, err := s.store.RunnerByHash(r.Context(), secure.HashToken(tok))
		if err != nil {
			return false
		}
		h(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, &principal{Kind: "runner", Runner: rn})))
		return true
	})
}

// authRun accepts a run token as Bearer or as the Basic-auth password (the
// form OpenTofu's HTTP backend sends). The token only works for its own run.
func (s *Server) authRun(h http.HandlerFunc) http.Handler {
	return s.withLimiter(func(w http.ResponseWriter, r *http.Request) bool {
		run, ok := s.runFromRequest(r)
		if !ok {
			return false
		}
		if id := r.PathValue("id"); id != "" && id != run.ID {
			return false
		}
		h(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, &principal{Kind: "run", Run: run})))
		return true
	})
}

func (s *Server) runFromRequest(r *http.Request) (*store.Run, bool) {
	tok := httpx.Bearer(r)
	if tok == "" {
		_, tok, _ = r.BasicAuth()
	}
	if len(tok) < 7 || tok[:6] != "sop_t_" {
		return nil, false
	}
	run, err := s.store.RunByToken(r.Context(), secure.HashToken(tok))
	return run, err == nil
}

// withLimiter rejects unauthenticated requests and rate-limits failures per client IP.
func (s *Server) withLimiter(try func(http.ResponseWriter, *http.Request) bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if s.limiter.Blocked(ip) {
			w.Header().Set("Retry-After", "300")
			writeErr(w, http.StatusTooManyRequests, "too many failed authentication attempts")
			return
		}
		if try(w, r) {
			return
		}
		if s.limiter.Fail(ip) {
			s.audit(r.Context(), "anonymous", "auth.lockout", "ip/"+ip, "", map[string]string{"path": r.URL.Path})
		}
		writeErr(w, http.StatusUnauthorized, "missing, invalid or expired credentials")
	})
}

// ---- helpers ----

var (
	writeJSON = httpx.WriteJSON
	writeErr  = httpx.WriteErr
	decode    = httpx.Decode
	errLines  = httpx.ErrLines
	clientIP  = httpx.ClientIP
)

func (s *Server) raw(f func() []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.Write(f())
	}
}

func (s *Server) audit(ctx context.Context, actor, action, target, entity string, payload any) {
	if payload == nil {
		payload = map[string]any{}
	}
	ctx = context.WithoutCancel(ctx)
	// Earlier events still waiting go first, so the chain keeps their order.
	if s.auditQ.len() == 0 {
		var err error
		for attempt := 0; attempt < 3; attempt++ {
			if err = s.store.AppendAudit(ctx, actor, action, target, entity, payload); err == nil {
				return
			}
			time.Sleep(time.Duration(100<<attempt) * time.Millisecond)
		}
		s.log.Error("audit write failed; kept to retry", "action", action, "err", err)
	}
	s.auditLater(pendingAudit{actor, action, target, entity, payload})
}

// writeStoreErr maps store errors to HTTP without leaking internals.
func (s *Server) writeStoreErr(w http.ResponseWriter, err error, conflictMsg string) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "not found")
	case errors.Is(err, store.ErrLocked):
		writeErr(w, http.StatusLocked, "the stack is locked: no plan or apply starts until it is unlocked (Stack → Unlock)")
	case errors.Is(err, store.ErrConflict):
		writeErr(w, http.StatusConflict, conflictMsg)
	case errors.As(err, new(*store.LimitError)):
		writeErr(w, http.StatusForbidden, err.Error())
	default:
		s.log.Error("store error", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
	}
}

// describeRun gives Temporal readable details of a run.
func (s *Server) describeRun(ctx context.Context, runID string) (orchestrator.RunInfo, bool) {
	run, err := s.store.GetRun(ctx, runID)
	if err != nil {
		return orchestrator.RunInfo{}, false
	}
	info := orchestrator.RunInfo{RunID: run.ID, Tenant: s.cfg.Tenant, Stack: run.StackName, BU: run.BU,
		Environment: run.Entity + "/" + run.Environment, Operation: run.Operation, Status: run.Status, RequestedBy: run.CreatedBy, Link: s.runLink(run.ID)}
	switch {
	case run.PRNumber != nil && run.ZeroDiff:
		info.Origin = fmt.Sprintf("pull request #%d (live -> code; must pass the zero-diff gate)", *run.PRNumber)
	case run.PRNumber != nil:
		info.Origin = fmt.Sprintf("pull request #%d", *run.PRNumber)
	case run.ZeroDiff && run.SourceRun != nil:
		info.Origin = "contract matched to live from run " + *run.SourceRun + " (must pass the zero-diff gate)"
	}
	return info, true
}

// registerBootstrapRunner registers the runner token bootstrap made in the
// cluster, once.
func (s *Server) registerBootstrapRunner(ctx context.Context) error {
	tok := s.cfg.BootstrapRunnerToken
	if tok == "" {
		return nil
	}
	if !strings.HasPrefix(tok, "sop_r_") {
		return errors.New("SRUSTIOPS_BOOTSTRAP_RUNNER_TOKEN must be a runner token (sop_r_...)")
	}
	hash := secure.HashToken(tok)
	if _, err := s.store.RunnerByHash(ctx, hash); err == nil {
		return nil
	}
	if _, err := s.store.CreateRunner(ctx, "bootstrap-runner", "default", hash); err != nil && !errors.Is(err, store.ErrConflict) {
		return fmt.Errorf("registering the bootstrap runner: %w", err)
	}
	s.audit(ctx, "system:install", "runner.register", "runner/bootstrap-runner", "", map[string]string{"pool": "default"})
	return nil
}
