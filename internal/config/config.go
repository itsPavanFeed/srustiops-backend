// Package config reads settings from the environment. Secrets come only from
// the environment (or files it points to), never from flags or config files
// that end up in shell history or repositories.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Server configures a tenant plane: one client's backend, database and state.
type Server struct {
	DatabaseURL string
	MasterKey   string
	Listen      string
	PublicURL   string // runners and clouds reach this plane here; it is the clouds' OIDC issuer
	TLSCert     string
	TLSKey      string
	CatalogDir  string
	TofuVersion string

	Tenant          string // this plane's tenant slug; assertions must name it
	CentralURL      string // where this plane reaches central to fetch its JWKS
	CentralIssuer   string // the iss central signs with (its public URL); defaults to CentralURL
	CentralCAFile   string // CA to trust when fetching central's JWKS (optional)
	CentralClientCA string // CA that signed central's mTLS client certificate
	CentralJWKSFile string // static JWKS instead of fetching it (optional)

	AllowLocalContracts bool // development only: contracts from a local directory

	BucketURL       string // s3://bucket[/prefix]?endpoint=...&region=... (optional)
	BucketAccessKey string
	BucketSecretKey string
	BucketCreate    bool // create the bucket on start (development)
	// LogArchiveAfter is how long after a run finishes its log moves to the
	// bucket (late chunks have landed by then). Shorter only for tests.
	LogArchiveAfter time.Duration
	// ScheduleEvery is how often scheduled checks are looked at (1m; shorter
	// only for tests, SRUSTIOPS_SCHEDULE_EVERY).
	ScheduleEvery time.Duration
	// ContractsPollFloor caps how long pull requests on polled hosts (GitLab,
	// Bitbucket, Azure DevOps) wait to be noticed; for tests
	// (SRUSTIOPS_PR_POLL_EVERY). 0 = the repository's poll interval.
	ContractsPollFloor time.Duration
	// BackupDir keeps backups when there is no bucket (SRUSTIOPS_BACKUP_DIR).
	BackupDir string
	// BackupCopyURL is a second bucket every backup is also written to
	// (another account or region): s3://, gs:// or azblob://, credentials as
	// for the tenant bucket (SRUSTIOPS_BACKUP_COPY_URL).
	BackupCopyURL string
	// Version is the running build's version (set by main, reported on /healthz).
	Version string

	TemporalAddress   string // host:port of Temporal; empty = built-in orchestration
	TemporalNamespace string

	// The assistant (Claude with retrieval over the catalog, docs, policies and
	// the caller's stacks). Off unless an API key is configured: enabling it
	// sends that context to the Anthropic API.
	AssistantAPIKey    string
	AssistantBaseURL   string // optional gateway; server-side fallbacks are then off
	AssistantModel     string
	AssistantEffort    string // low | medium | high | xhigh | max
	AssistantDocsDir   string // extra Markdown files to index (README, runbooks)
	AssistantFallbacks bool

	// EnvFile is a writable .env holding integration settings (SRUSTIOPS_GITHUB_*);
	// they are watched and reloaded. Empty keeps them sealed in the database.
	EnvFile string

	// Release bundles (vendored modules) are cached in memory and on disk so
	// the database or bucket holding them is read once per bundle.
	BundleCacheDir  string
	BundleCacheMem  int64 // bytes
	BundleCacheDisk int64
	// RegistryURL is where module builds download packages; a private mirror
	// of registry.opentofu.org may be used. Default: the public registry.
	RegistryURL string
	// CloudAPIURL sends inventory and organisation reads to a fake cloud
	// (tests and development only; loopback only). Empty = the real clouds.
	CloudAPIURL string
	// ModuleMirror is a directory of signed module packages (srustiops modules
	// mirror) used instead of the registry for release builds, for tenants
	// without internet access. ModuleMirrorKey is the base64 Ed25519 public
	// key its index must be signed with.
	ModuleMirror    string
	ModuleMirrorKey string
	// BootstrapRunnerToken is a runner token made by `srustiops bootstrap` in
	// the cluster; the plane registers it once, so its in-cluster runner can
	// connect without anyone registering it by hand.
	BootstrapRunnerToken string
	// IDPProxy is an HTTP CONNECT proxy for reaching the tenant's own identity
	// provider, normally the link agent's egress relay (air-gapped tenants).
	IDPProxy string
	// BreakglassListen is the loopback address of the break-glass listener.
	BreakglassListen string
}

// Central configures the central plane: frontend, identity, tenant routing.
type Central struct {
	// InviteSweep is how often lapsed invitations are removed (10m;
	// SRUSTIOPS_INVITE_SWEEP, shorter only for tests).
	InviteSweep  time.Duration
	Version      string // the running build (set by main)
	DatabaseURL  string
	MasterKey    string
	Listen       string
	PublicURL    string
	TLSCert      string
	TLSKey       string
	InsecureHTTP bool // only permitted on a loopback listener, for local development
	WebDir       string
	ClientCert   string // mTLS client certificate presented to tenant planes
	ClientKey    string
	// ImageRepo and ImageTag name the images install commands use, e.g.
	// docker.io/acme (images srustiops-server and srustiops-runner).
	ImageRepo string
	ImageTag  string
	// The provisioner builds clients' infrastructure as stacks in the
	// platform's own tenant (ProvisionerTenant; empty turns it off), on a
	// dedicated runner pool. Blueprints default to the built-in set;
	// ProvisionerBlueprints names a directory that replaces them. The install
	// stack uses the chart at ChartRepository, version ChartVersion.
	ProvisionerTenant string
	ProvisionerPool   string
	// ProvisionerAllowPrivateIssuer: for tests against a fake cloud only. A
	// real cloud must fetch the platform tenant's OIDC keys over the internet,
	// so a private issuer is refused unless this is set.
	ProvisionerAllowPrivateIssuer bool
	ProvisionerBlueprints         string
	ChartRepository               string
	ChartVersion                  string
	// ClientCA is the CA that issued ClientCert. Bootstrapped tenants get it
	// at install, so they accept central's calls without manual setup.
	ClientCA string

	// SSO (OpenID Connect). Empty issuer disables SSO.
	OIDCIssuer          string
	OIDCClientID        string
	OIDCClientSecret    string   // optional: public clients rely on PKCE alone
	OIDCRedirectURL     string   // default <PublicURL>/auth/callback
	OIDCAllowedDomains  []string // optional email domain allowlist
	OIDCTrustUnverified bool     // accept tokens without email_verified=true (some IdPs omit it)
	OIDCLabel           string   // button text, e.g. "Sign in with Okta"
	// SSOTestURL sends Google and GitHub sign-in calls to a local fake
	// (tests and development only; loopback only).
	SSOTestURL string

	// WebhookBaseURL is the public address Git hosts post webhooks to, when it
	// differs from PublicURL (e.g. an ngrok tunnel or a dedicated ingress).
	WebhookBaseURL string
	EnvFile        string // optional .env watched for SRUSTIOPS_WEBHOOK_BASE_URL

	// The tenant link gateway: a TLS listener that tenant link agents dial
	// out to. Empty LinkListen turns it off (tunnel tenants then stay offline).
	LinkListen       string
	LinkTLSCert      string
	LinkTLSKey       string
	LinkPublicURL    string // where agents reach the gateway (given to them at enrolment)
	LinkAdvertiseURL string // where other central replicas reach this one
	LinkServerCA     string // CA of the gateway certificate: pinned by agents, trusted by replicas

	// LinkCertTTL and WebhookQueueMax shorten the link certificate lifetime
	// and the offline webhook queue for tests (loopback listener only).
	LinkCertTTL     time.Duration
	WebhookQueueMax int
	// DevTrustDomains skips the DNS proof of tenant email domains (local
	// development and tests only; needs a loopback listener).
	DevTrustDomains bool
}

// Link configures `srustiops link`, the agent beside a tenant plane that keeps
// the outbound tunnel to the central gateway.
type Link struct {
	Tenant      string
	URL         string // gateway, https://host:port
	Target      string // host:port of the tenant API
	ServerCA    string // CA file pinning the gateway certificate (optional: system roots)
	StateDir    string
	EnrollToken string
	Connections int
	// Mode is tunnel (API streams and control) or control (control only, for
	// a tenant central reaches directly).
	Mode string
	// EgressListen serves a CONNECT relay for the tenant's own sign-in.
	EgressListen string
}

func LoadLink() (*Link, error) {
	c := &Link{
		Tenant:       os.Getenv("SRUSTIOPS_TENANT"),
		URL:          strings.TrimRight(os.Getenv("SRUSTIOPS_LINK_URL"), "/"),
		Target:       os.Getenv("SRUSTIOPS_LINK_TARGET"),
		ServerCA:     os.Getenv("SRUSTIOPS_LINK_SERVER_CA"),
		StateDir:     os.Getenv("SRUSTIOPS_LINK_STATE_DIR"),
		EnrollToken:  secret("SRUSTIOPS_LINK_ENROLL_TOKEN"),
		Connections:  envInt("SRUSTIOPS_LINK_CONNECTIONS", 2),
		Mode:         env("SRUSTIOPS_LINK_MODE", "tunnel"),
		EgressListen: os.Getenv("SRUSTIOPS_LINK_EGRESS_LISTEN"),
	}
	var errs []error
	if !slugRe.MatchString(c.Tenant) {
		errs = append(errs, errors.New("SRUSTIOPS_TENANT must be this tenant's slug"))
	}
	if u, err := url.Parse(c.URL); err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" {
		errs = append(errs, errors.New("SRUSTIOPS_LINK_URL must be the gateway's https:// origin"))
	}
	if _, _, err := net.SplitHostPort(c.Target); err != nil {
		errs = append(errs, errors.New("SRUSTIOPS_LINK_TARGET must be host:port of the tenant API, e.g. srustiops-tenant:8443"))
	}
	if c.StateDir == "" {
		errs = append(errs, errors.New("SRUSTIOPS_LINK_STATE_DIR is required: it keeps the link key and certificate"))
	}
	if c.Mode != "tunnel" && c.Mode != "control" {
		errs = append(errs, errors.New("SRUSTIOPS_LINK_MODE must be tunnel or control"))
	}
	if c.Connections < 1 || c.Connections > 8 {
		errs = append(errs, errors.New("SRUSTIOPS_LINK_CONNECTIONS must be between 1 and 8"))
	}
	return c, errors.Join(errs...)
}

type Runner struct {
	ServerURL   string
	Token       string
	StateKey    string
	CAFile      string
	TofuPath    string
	WorkRoot    string
	PluginCache string
	Name        string
	Concurrency int // runs executed at the same time, each in its own work and temp directories
	// BundleCacheDir keeps module release bundles between runs (by checksum),
	// so a runner downloads each release once.
	BundleCacheDir  string
	BundleCacheDisk int64
	// ProviderMirror is a directory laid out as an OpenTofu filesystem mirror
	// (srustiops providers mirror). When set, providers come only from it:
	// air-gapped runners never contact a registry.
	ProviderMirror string
	// ProviderSeed is a mirror of the catalog's pinned providers baked into
	// the runner image: providers in it install from disk, anything else (a
	// module release's newer pin) from the registry as usual.
	ProviderSeed string
}

// DefaultTofuVersion is the OpenTofu release runs are pinned to unless overridden.
const DefaultTofuVersion = "1.13.2"

func LoadServer() (*Server, error) {
	c := &Server{
		DatabaseURL:     secret("SRUSTIOPS_DATABASE_URL"),
		MasterKey:       secret("SRUSTIOPS_MASTER_KEY"),
		Listen:          env("SRUSTIOPS_LISTEN", ":8443"),
		PublicURL:       strings.TrimRight(os.Getenv("SRUSTIOPS_PUBLIC_URL"), "/"),
		TLSCert:         os.Getenv("SRUSTIOPS_TLS_CERT"),
		TLSKey:          os.Getenv("SRUSTIOPS_TLS_KEY"),
		CatalogDir:      env("SRUSTIOPS_CATALOG_DIR", "../srustiops-modules/catalog"),
		TofuVersion:     env("SRUSTIOPS_TOFU_VERSION", DefaultTofuVersion),
		Tenant:          os.Getenv("SRUSTIOPS_TENANT"),
		CentralURL:      strings.TrimRight(os.Getenv("SRUSTIOPS_CENTRAL_URL"), "/"),
		CentralIssuer:   strings.TrimRight(env("SRUSTIOPS_CENTRAL_ISSUER", os.Getenv("SRUSTIOPS_CENTRAL_URL")), "/"),
		CentralCAFile:   os.Getenv("SRUSTIOPS_CENTRAL_CA_FILE"),
		CentralClientCA: os.Getenv("SRUSTIOPS_CENTRAL_CLIENT_CA"),
		CentralJWKSFile: os.Getenv("SRUSTIOPS_CENTRAL_JWKS_FILE"),

		AllowLocalContracts: os.Getenv("SRUSTIOPS_ALLOW_LOCAL_CONTRACTS") == "1",

		BucketURL:       os.Getenv("SRUSTIOPS_BUCKET_URL"),
		BucketAccessKey: secret("SRUSTIOPS_BUCKET_ACCESS_KEY"),
		BucketSecretKey: secret("SRUSTIOPS_BUCKET_SECRET_KEY"),
		BucketCreate:    os.Getenv("SRUSTIOPS_BUCKET_CREATE") == "1",
		LogArchiveAfter: 5 * time.Minute,
		ScheduleEvery:   time.Minute,

		TemporalAddress:   os.Getenv("SRUSTIOPS_TEMPORAL_ADDRESS"),
		TemporalNamespace: env("SRUSTIOPS_TEMPORAL_NAMESPACE", "default"),

		AssistantAPIKey:      secret("SRUSTIOPS_ASSISTANT_API_KEY"),
		AssistantBaseURL:     os.Getenv("SRUSTIOPS_ASSISTANT_BASE_URL"),
		AssistantModel:       env("SRUSTIOPS_ASSISTANT_MODEL", "claude-opus-5-5"),
		AssistantEffort:      env("SRUSTIOPS_ASSISTANT_EFFORT", "medium"),
		AssistantDocsDir:     os.Getenv("SRUSTIOPS_ASSISTANT_DOCS_DIR"),
		AssistantFallbacks:   os.Getenv("SRUSTIOPS_ASSISTANT_FALLBACKS") != "0",
		EnvFile:              absPath(os.Getenv("SRUSTIOPS_ENV_FILE")),
		BundleCacheDir:       os.Getenv("SRUSTIOPS_BUNDLE_CACHE_DIR"),
		BundleCacheMem:       int64(envInt("SRUSTIOPS_BUNDLE_CACHE_MEMORY_MB", 256)) << 20,
		BundleCacheDisk:      int64(envInt("SRUSTIOPS_BUNDLE_CACHE_DISK_MB", 2048)) << 20,
		RegistryURL:          strings.TrimRight(os.Getenv("SRUSTIOPS_REGISTRY_URL"), "/"),
		CloudAPIURL:          strings.TrimRight(os.Getenv("SRUSTIOPS_CLOUD_API_URL"), "/"),
		ModuleMirror:         os.Getenv("SRUSTIOPS_MODULE_MIRROR"),
		ModuleMirrorKey:      os.Getenv("SRUSTIOPS_MODULE_MIRROR_KEY"),
		BootstrapRunnerToken: secret("SRUSTIOPS_BOOTSTRAP_RUNNER_TOKEN"),
		IDPProxy:             os.Getenv("SRUSTIOPS_IDP_PROXY"),
		BreakglassListen:     env("SRUSTIOPS_BREAKGLASS_LISTEN", "127.0.0.1:9444"),
	}
	if c.BundleCacheDir == "" {
		if d, err := os.UserCacheDir(); err == nil && c.Tenant != "" {
			c.BundleCacheDir = filepath.Join(d, "srustiops", "bundles", c.Tenant)
		}
	}
	var errs []error
	if v := os.Getenv("SRUSTIOPS_LOG_ARCHIVE_AFTER"); v != "" {
		if d, err := time.ParseDuration(v); err != nil || d < time.Second {
			errs = append(errs, errors.New("SRUSTIOPS_LOG_ARCHIVE_AFTER must be a duration of at least 1s"))
		} else {
			c.LogArchiveAfter = d
		}
	}
	c.BackupDir = os.Getenv("SRUSTIOPS_BACKUP_DIR")
	c.BackupCopyURL = os.Getenv("SRUSTIOPS_BACKUP_COPY_URL")
	if v := os.Getenv("SRUSTIOPS_PR_POLL_EVERY"); v != "" {
		if d, err := time.ParseDuration(v); err != nil || d < time.Second || d > time.Hour {
			errs = append(errs, errors.New("SRUSTIOPS_PR_POLL_EVERY must be a duration between 1s and 1h"))
		} else {
			c.ContractsPollFloor = d
		}
	}
	if v := os.Getenv("SRUSTIOPS_SCHEDULE_EVERY"); v != "" {
		if d, err := time.ParseDuration(v); err != nil || d < time.Second || d > time.Hour {
			errs = append(errs, errors.New("SRUSTIOPS_SCHEDULE_EVERY must be a duration between 1s and 1h"))
		} else {
			c.ScheduleEvery = d
		}
	}
	errs = append(errs, common(c.DatabaseURL, c.MasterKey, c.PublicURL, false)...)
	if c.CloudAPIURL != "" {
		if u, err := url.Parse(c.CloudAPIURL); err != nil || u.Host == "" || !loopbackHost(u.Hostname()) {
			errs = append(errs, errors.New("SRUSTIOPS_CLOUD_API_URL is for a local fake cloud only and must be a loopback URL"))
		}
	}
	if c.ModuleMirror != "" && (c.ModuleMirrorKey == "" || c.RegistryURL != "") {
		errs = append(errs, errors.New("SRUSTIOPS_MODULE_MIRROR needs SRUSTIOPS_MODULE_MIRROR_KEY (its signing key) and replaces SRUSTIOPS_REGISTRY_URL"))
	}
	if c.RegistryURL != "" {
		if u, err := url.Parse(c.RegistryURL); err != nil || u.Host == "" || !(u.Scheme == "https" || u.Scheme == "http" && loopbackHost(u.Hostname())) {
			errs = append(errs, errors.New("SRUSTIOPS_REGISTRY_URL must be an https URL (plain http only on loopback, for development)"))
		}
	}
	switch c.AssistantEffort {
	case "low", "medium", "high", "xhigh", "max":
	default:
		errs = append(errs, errors.New("SRUSTIOPS_ASSISTANT_EFFORT must be low, medium, high, xhigh or max"))
	}
	if c.AssistantBaseURL != "" {
		if u, err := url.Parse(c.AssistantBaseURL); err != nil || u.Host == "" || !(u.Scheme == "https" || u.Scheme == "http" && loopbackHost(u.Hostname())) {
			errs = append(errs, errors.New("SRUSTIOPS_ASSISTANT_BASE_URL must be an https URL (plain http only on loopback, for development)"))
		}
	}
	if c.TLSCert == "" || c.TLSKey == "" {
		errs = append(errs, errors.New("tenant planes always serve TLS: set SRUSTIOPS_TLS_CERT and SRUSTIOPS_TLS_KEY"))
	}
	if !slugRe.MatchString(c.Tenant) {
		errs = append(errs, errors.New("SRUSTIOPS_TENANT must be this plane's tenant slug (as onboarded in the central plane)"))
	}
	if u, err := url.Parse(c.CentralURL); err != nil || u.Host == "" {
		errs = append(errs, errors.New("SRUSTIOPS_CENTRAL_URL must be the central plane's URL (the assertion issuer)"))
	} else if u.Scheme != "https" && !(u.Scheme == "http" && loopbackHost(u.Hostname())) {
		errs = append(errs, errors.New("SRUSTIOPS_CENTRAL_URL must use https (plain http only for a loopback development central)"))
	}
	if c.CentralClientCA == "" {
		errs = append(errs, errors.New("SRUSTIOPS_CENTRAL_CLIENT_CA is required: user requests are accepted only from central over mTLS"))
	}
	return c, errors.Join(errs...)
}

func LoadCentral() (*Central, error) {
	c := &Central{
		DatabaseURL:  secret("SRUSTIOPS_DATABASE_URL"),
		MasterKey:    secret("SRUSTIOPS_MASTER_KEY"),
		Listen:       env("SRUSTIOPS_LISTEN", ":8443"),
		PublicURL:    strings.TrimRight(os.Getenv("SRUSTIOPS_PUBLIC_URL"), "/"),
		TLSCert:      os.Getenv("SRUSTIOPS_TLS_CERT"),
		TLSKey:       os.Getenv("SRUSTIOPS_TLS_KEY"),
		InsecureHTTP: os.Getenv("SRUSTIOPS_INSECURE_HTTP") == "1",
		WebDir:       os.Getenv("SRUSTIOPS_WEB_DIR"),
		ClientCert:   os.Getenv("SRUSTIOPS_CLIENT_CERT"),
		ClientKey:    os.Getenv("SRUSTIOPS_CLIENT_KEY"),
		ClientCA:     os.Getenv("SRUSTIOPS_CLIENT_CA"),
		ImageRepo:    strings.TrimRight(env("SRUSTIOPS_IMAGE_REPO", "docker.io/mukkarapavankumarreddy"), "/"),
		ImageTag:     env("SRUSTIOPS_IMAGE_TAG", "0.1.0"),

		ProvisionerTenant:             os.Getenv("SRUSTIOPS_PROVISIONER_TENANT"),
		ProvisionerPool:               env("SRUSTIOPS_PROVISIONER_POOL", "provisioner"),
		ProvisionerAllowPrivateIssuer: os.Getenv("SRUSTIOPS_PROVISIONER_ALLOW_PRIVATE_ISSUER") == "1",
		ProvisionerBlueprints:         absPath(os.Getenv("SRUSTIOPS_PROVISIONER_BLUEPRINTS")),
		ChartRepository:               strings.TrimRight(os.Getenv("SRUSTIOPS_CHART_REPOSITORY"), "/"),
		ChartVersion:                  os.Getenv("SRUSTIOPS_CHART_VERSION"),

		OIDCIssuer:          strings.TrimRight(os.Getenv("SRUSTIOPS_OIDC_ISSUER"), "/"),
		OIDCClientID:        os.Getenv("SRUSTIOPS_OIDC_CLIENT_ID"),
		OIDCClientSecret:    secret("SRUSTIOPS_OIDC_CLIENT_SECRET"),
		OIDCRedirectURL:     os.Getenv("SRUSTIOPS_OIDC_REDIRECT_URL"),
		OIDCTrustUnverified: os.Getenv("SRUSTIOPS_OIDC_TRUST_UNVERIFIED_EMAIL") == "1",
		OIDCLabel:           env("SRUSTIOPS_OIDC_LABEL", "Sign in with SSO"),
		SSOTestURL:          strings.TrimRight(os.Getenv("SRUSTIOPS_SSO_TEST_URL"), "/"),
		WebhookBaseURL:      strings.TrimRight(os.Getenv("SRUSTIOPS_WEBHOOK_BASE_URL"), "/"),
		EnvFile:             absPath(os.Getenv("SRUSTIOPS_ENV_FILE")),
		LinkListen:          os.Getenv("SRUSTIOPS_LINK_LISTEN"),
		LinkTLSCert:         os.Getenv("SRUSTIOPS_LINK_TLS_CERT"),
		LinkTLSKey:          os.Getenv("SRUSTIOPS_LINK_TLS_KEY"),
		LinkPublicURL:       strings.TrimRight(os.Getenv("SRUSTIOPS_LINK_PUBLIC_URL"), "/"),
		LinkAdvertiseURL:    strings.TrimRight(os.Getenv("SRUSTIOPS_LINK_ADVERTISE_URL"), "/"),
		LinkServerCA:        os.Getenv("SRUSTIOPS_LINK_SERVER_CA"),
		DevTrustDomains:     os.Getenv("SRUSTIOPS_DEV_TRUST_DOMAINS") == "1",
		LinkCertTTL:         24 * time.Hour,
		WebhookQueueMax:     envInt("SRUSTIOPS_WEBHOOK_QUEUE_MAX", 10000),
	}
	for _, d := range strings.Split(os.Getenv("SRUSTIOPS_OIDC_ALLOWED_DOMAINS"), ",") {
		if d = strings.ToLower(strings.TrimSpace(d)); d != "" {
			c.OIDCAllowedDomains = append(c.OIDCAllowedDomains, d)
		}
	}
	errs := common(c.DatabaseURL, c.MasterKey, c.PublicURL, c.InsecureHTTP)
	if c.InsecureHTTP {
		host, _, err := net.SplitHostPort(c.Listen)
		if err != nil || !loopbackHost(host) {
			errs = append(errs, errors.New("SRUSTIOPS_INSECURE_HTTP=1 is only allowed with a loopback SRUSTIOPS_LISTEN such as 127.0.0.1:8080"))
		}
	} else if c.TLSCert == "" || c.TLSKey == "" {
		errs = append(errs, errors.New("TLS is required: set SRUSTIOPS_TLS_CERT and SRUSTIOPS_TLS_KEY"))
	}
	if c.SSOTestURL != "" {
		if u, err := url.Parse(c.SSOTestURL); err != nil || u.Host == "" || !loopbackHost(u.Hostname()) {
			errs = append(errs, errors.New("SRUSTIOPS_SSO_TEST_URL is for a local fake sign-in server only and must be a loopback URL"))
		}
	}
	if c.ClientCert == "" || c.ClientKey == "" {
		errs = append(errs, errors.New("SRUSTIOPS_CLIENT_CERT and SRUSTIOPS_CLIENT_KEY are required: central calls tenant planes over mTLS"))
	}
	if c.WebhookBaseURL != "" {
		if u, err := url.Parse(c.WebhookBaseURL); err != nil || u.Host == "" || u.Path != "" || u.Scheme != "https" {
			errs = append(errs, errors.New("SRUSTIOPS_WEBHOOK_BASE_URL must be an https origin, e.g. https://hooks.example.com"))
		}
	}
	if c.OIDCIssuer != "" {
		if u, err := url.Parse(c.OIDCIssuer); err != nil || u.Host == "" || (u.Scheme != "https" && !(u.Scheme == "http" && loopbackHost(u.Hostname()))) {
			errs = append(errs, errors.New("SRUSTIOPS_OIDC_ISSUER must be an https URL"))
		}
		if c.OIDCClientID == "" {
			errs = append(errs, errors.New("SRUSTIOPS_OIDC_CLIENT_ID is required with SRUSTIOPS_OIDC_ISSUER"))
		}
		if c.OIDCRedirectURL == "" {
			c.OIDCRedirectURL = c.PublicURL + "/auth/callback"
		}
	}
	c.InviteSweep = 10 * time.Minute
	if v := os.Getenv("SRUSTIOPS_INVITE_SWEEP"); v != "" {
		if d, err := time.ParseDuration(v); err != nil || d < time.Second || d > 24*time.Hour {
			errs = append(errs, errors.New("SRUSTIOPS_INVITE_SWEEP must be a duration between 1s and 24h"))
		} else {
			c.InviteSweep = d
		}
	}
	if v := os.Getenv("SRUSTIOPS_LINK_CERT_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		host, _, _ := net.SplitHostPort(c.Listen)
		if err != nil || d < 30*time.Second || !loopbackHost(host) {
			errs = append(errs, errors.New("SRUSTIOPS_LINK_CERT_TTL is for tests: a duration of at least 30s, with a loopback SRUSTIOPS_LISTEN"))
		} else {
			c.LinkCertTTL = d
		}
	}
	if c.WebhookQueueMax < 1 || c.WebhookQueueMax > 100000 {
		errs = append(errs, errors.New("SRUSTIOPS_WEBHOOK_QUEUE_MAX must be between 1 and 100000"))
	}
	if c.DevTrustDomains {
		if host, _, err := net.SplitHostPort(c.Listen); err != nil || !loopbackHost(host) {
			errs = append(errs, errors.New("SRUSTIOPS_DEV_TRUST_DOMAINS=1 is for a local development central only (loopback SRUSTIOPS_LISTEN)"))
		}
	}
	if c.LinkListen != "" {
		if c.LinkTLSCert == "" || c.LinkTLSKey == "" {
			errs = append(errs, errors.New("the tenant link gateway always serves TLS: set SRUSTIOPS_LINK_TLS_CERT and SRUSTIOPS_LINK_TLS_KEY"))
		}
		if c.LinkPublicURL == "" {
			c.LinkPublicURL = "https://" + c.LinkListen
		}
		if u, err := url.Parse(c.LinkPublicURL); err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" {
			errs = append(errs, errors.New("SRUSTIOPS_LINK_PUBLIC_URL must be an https origin"))
		}
		if c.LinkAdvertiseURL == "" {
			c.LinkAdvertiseURL = c.LinkPublicURL
		}
	}
	return c, errors.Join(errs...)
}

var slugRe = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)

func common(db, key, public string, insecure bool) []error {
	var errs []error
	if db == "" {
		errs = append(errs, errors.New("SRUSTIOPS_DATABASE_URL is required"))
	}
	if key == "" {
		errs = append(errs, errors.New("SRUSTIOPS_MASTER_KEY is required (openssl rand -base64 32)"))
	}
	u, err := url.Parse(public)
	if public == "" || err != nil || u.Host == "" {
		errs = append(errs, errors.New("SRUSTIOPS_PUBLIC_URL is required"))
	} else if u.Scheme != "https" && !(insecure && u.Scheme == "http" && loopbackHost(u.Hostname())) {
		errs = append(errs, errors.New("SRUSTIOPS_PUBLIC_URL must use https"))
	}
	return errs
}

func LoadRunner() (*Runner, error) {
	c := &Runner{
		ServerURL:       strings.TrimRight(os.Getenv("SRUSTIOPS_SERVER_URL"), "/"),
		Token:           secret("SRUSTIOPS_RUNNER_TOKEN"),
		StateKey:        secret("SRUSTIOPS_STATE_KEY"),
		CAFile:          os.Getenv("SRUSTIOPS_CA_FILE"),
		TofuPath:        env("SRUSTIOPS_TOFU_PATH", "tofu"),
		WorkRoot:        os.Getenv("SRUSTIOPS_WORK_DIR"),
		PluginCache:     os.Getenv("SRUSTIOPS_PLUGIN_CACHE_DIR"),
		ProviderMirror:  os.Getenv("SRUSTIOPS_PROVIDER_MIRROR"),
		ProviderSeed:    os.Getenv("SRUSTIOPS_PROVIDER_SEED"),
		BundleCacheDir:  os.Getenv("SRUSTIOPS_BUNDLE_CACHE_DIR"),
		BundleCacheDisk: int64(envInt("SRUSTIOPS_BUNDLE_CACHE_DISK_MB", 1024)) << 20,
		Name:            env("SRUSTIOPS_RUNNER_NAME", hostname()),
		Concurrency:     atoiDefault(os.Getenv("SRUSTIOPS_RUNNER_CONCURRENCY"), 2),
	}
	var errs []error
	u, err := url.Parse(c.ServerURL)
	if err != nil || u.Host == "" {
		errs = append(errs, errors.New("SRUSTIOPS_SERVER_URL is required"))
	} else if u.Scheme != "https" && !(u.Scheme == "http" && loopbackHost(u.Hostname()) && os.Getenv("SRUSTIOPS_INSECURE_HTTP") == "1") {
		errs = append(errs, errors.New("SRUSTIOPS_SERVER_URL must use https"))
	}
	if !strings.HasPrefix(c.Token, "sop_r_") {
		errs = append(errs, errors.New("SRUSTIOPS_RUNNER_TOKEN must be a runner token (sop_r_...)"))
	}
	if len(c.StateKey) < 32 {
		errs = append(errs, errors.New("SRUSTIOPS_STATE_KEY must be at least 32 characters; every runner in a pool must share it"))
	}
	if c.Concurrency < 1 || c.Concurrency > 16 {
		errs = append(errs, errors.New("SRUSTIOPS_RUNNER_CONCURRENCY must be between 1 and 16"))
	}
	if c.ProviderMirror != "" {
		if fi, err := os.Stat(c.ProviderMirror); err != nil || !fi.IsDir() || !filepath.IsAbs(c.ProviderMirror) {
			errs = append(errs, errors.New("SRUSTIOPS_PROVIDER_MIRROR must be an absolute path to a provider mirror directory"))
		}
	}
	if c.ProviderSeed != "" {
		if fi, err := os.Stat(c.ProviderSeed); err != nil || !fi.IsDir() {
			c.ProviderSeed = "" // an image without the seed: install from the registry
		}
	}
	return c, errors.Join(errs...)
}

// secret reads NAME, or the file named by NAME_FILE (for Kubernetes/Docker secrets).
func secret(name string) string {
	if f := os.Getenv(name + "_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "reading %s_FILE: %v\n", name, err)
			return ""
		}
		return strings.TrimSpace(string(b))
	}
	return os.Getenv(name)
}

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func loopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}

func absPath(p string) string {
	if p == "" {
		return ""
	}
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return p
}

func atoiDefault(v string, def int) int {
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return -1 // reported by validation
	}
	return n
}

func envInt(name string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil && v > 0 {
		return v
	}
	return def
}
