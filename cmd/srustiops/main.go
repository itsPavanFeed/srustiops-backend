// Command srustiops is SrustiOps in one binary: the central plane, tenant
// planes and runners.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/api"
	"github.com/itsPavanFeed/srustiops-backend/internal/catalog"
	"github.com/itsPavanFeed/srustiops-backend/internal/central"
	"github.com/itsPavanFeed/srustiops-backend/internal/config"
	"github.com/itsPavanFeed/srustiops-backend/internal/httpx"
	"github.com/itsPavanFeed/srustiops-backend/internal/link"
	"github.com/itsPavanFeed/srustiops-backend/internal/metrics"
	"github.com/itsPavanFeed/srustiops-backend/internal/oidc"
	"github.com/itsPavanFeed/srustiops-backend/internal/runner"
	"github.com/itsPavanFeed/srustiops-backend/internal/secure"
	"github.com/itsPavanFeed/srustiops-backend/internal/store"
)

var version = "dev"

const usage = `srustiops — multi-tenant OpenTofu orchestration with pinned public modules only

Usage:
  srustiops central                        run the central plane (frontend, identity, tenant routing)
  srustiops central bootstrap -email E     create the platform root (recovery) or rotate its token
  srustiops central scim-token -name N     create a SCIM provisioning token for an identity provider
  srustiops tenant                         run a tenant plane (one client's backend, state and runs)
  srustiops tenant restore -file F         restore a backup into a new, empty database (the plane stopped)
  srustiops updater -mode k8s|compose      apply the version central's fleet rollout gives this workspace
  srustiops runner                         run an agent that executes OpenTofu for a tenant plane
  srustiops link                           run the tenant link agent: an outbound tunnel to central's gateway
  srustiops breakglass init|status|reset-idp|grant-admin  a tenant's local recovery admin (from inside the tenant only)
  srustiops bootstrap -out D | -k8s P      prepare a new tenant from a one-time install token (keys made locally)
  srustiops audit verify [-central]        verify a database's audit hash chain
  srustiops catalog verify [-dir D] [-online]  validate the module catalog (and check pins on the registry)
  srustiops policy test [-dir D] [-fixtures D]  compile policies, run their Rego unit tests and fixture plans (for CI)
  srustiops loadtest -url U -tenant T -token-file F [-c N] [-d D]  load a workspace's read paths; latency percentiles and errors
  srustiops dev-cert -dir D -name N [-host H] [-client]  issue a development certificate from a local CA
  srustiops modules mirror -catalog D -out D -key F    signed module packages for air-gapped tenants (SRUSTIOPS_MODULE_MIRROR)
  srustiops providers mirror -catalog D -out D         pinned OpenTofu providers for air-gapped runners (SRUSTIOPS_PROVIDER_MIRROR)
  srustiops dev-idp [-listen A] [-groups G]  a stand-in OpenID Connect and SAML provider for local development (loopback only)
  srustiops dev-forge [-listen A] [-seed D]  a stand-in GitLab / Bitbucket / Azure DevOps host for local development (loopback only)
  srustiops version

Configuration is read from SRUSTIOPS_* environment variables; see README.md.
`

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "central":
		if len(os.Args) > 2 && os.Args[2] == "bootstrap" {
			err = runBootstrap(ctx, os.Args[3:])
		} else if len(os.Args) > 2 && os.Args[2] == "scim-token" {
			err = runSCIMToken(ctx, os.Args[3:])
		} else {
			err = runCentral(ctx, log)
		}
	case "tenant":
		if len(os.Args) > 2 && os.Args[2] == "restore" {
			err = runTenantRestore(ctx, os.Args[3:])
		} else {
			err = runTenant(ctx, log)
		}
	case "runner":
		err = runRunner(ctx, log)
	case "link":
		err = runLink(ctx, log)
	case "breakglass":
		err = runBreakglass(os.Args[2:])
	case "bootstrap":
		err = runTenantBootstrap(ctx, os.Args[2:])
	case "audit":
		err = runAuditVerify(ctx, os.Args[2:])
	case "catalog":
		err = runCatalog(ctx, os.Args[2:])
	case "dev-cert":
		err = runDevCert(os.Args[2:])
	case "modules":
		err = runModules(ctx, os.Args[2:])
	case "providers":
		err = runProviders(ctx, os.Args[2:])
	case "updater":
		err = runUpdater(ctx, log, os.Args[2:])
	case "policy":
		err = runPolicy(ctx, os.Args[2:])
	case "loadtest":
		err = runLoadTest(ctx, os.Args[2:])
	case "dev-forge":
		err = runDevForge(ctx, os.Args[2:])
	case "dev-idp":
		err = runDevIdP(ctx, os.Args[2:])
	case "version":
		fmt.Println("srustiops", version)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func sealerFrom(key string) (*secure.Sealer, error) {
	k, err := secure.ParseKey(key)
	if err != nil {
		return nil, fmt.Errorf("SRUSTIOPS_MASTER_KEY: %w", err)
	}
	return secure.NewSealer(k)
}

type metaStore interface {
	GetMeta(ctx context.Context, key string) ([]byte, error)
	PutMetaIfAbsent(ctx context.Context, key string, v []byte) ([]byte, error)
}

// loadIssuer reads a signing key (sealed with the master key), creating it on first start.
func loadIssuer(ctx context.Context, st metaStore, sealer *secure.Sealer, name, url string) (*oidc.Issuer, error) {
	aad := []byte(name)
	sealed, err := st.GetMeta(ctx, name)
	if errors.Is(err, store.ErrNotFound) {
		k, err := oidc.GenerateKey()
		if err != nil {
			return nil, err
		}
		s, err := sealer.Seal(k, aad)
		if err != nil {
			return nil, err
		}
		if sealed, err = st.PutMetaIfAbsent(ctx, name, s); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	k, err := sealer.Open(sealed, aad)
	if err != nil {
		return nil, fmt.Errorf("cannot decrypt %s; is SRUSTIOPS_MASTER_KEY the key this database was created with? %w", name, err)
	}
	return oidc.New(url, k)
}

// trustProxies reads SRUSTIOPS_TRUSTED_PROXIES: the load balancers whose
// X-Forwarded-For names the real client, for rate limits and lockouts.
func trustProxies(log *slog.Logger) error {
	v := os.Getenv("SRUSTIOPS_TRUSTED_PROXIES")
	nets, err := httpx.ParseCIDRs(v)
	if err != nil {
		return fmt.Errorf("SRUSTIOPS_TRUSTED_PROXIES: %w", err)
	}
	httpx.SetTrustedProxies(nets)
	if len(nets) > 0 {
		log.Info("trusting X-Forwarded-For from proxies", "cidrs", v)
	}
	return nil
}

func runCentral(ctx context.Context, log *slog.Logger) error {
	go metrics.Serve(ctx, log, os.Getenv("SRUSTIOPS_METRICS_LISTEN"), metrics.Default)
	cfg, err := config.LoadCentral()
	if err != nil {
		return err
	}
	cfg.Version = version
	if err := trustProxies(log); err != nil {
		return err
	}
	sealer, err := sealerFrom(cfg.MasterKey)
	if err != nil {
		return err
	}
	st, err := central.OpenStore(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		return err
	}
	iss, err := loadIssuer(ctx, st, sealer, "assertion_signing_key", cfg.PublicURL)
	if err != nil {
		return err
	}
	srv, err := central.New(cfg, st, iss, log)
	if err != nil {
		return err
	}
	if cfg.LinkListen != "" {
		ca, err := loadCA(ctx, st, sealer, "link_ca", "SrustiOps tenant link CA")
		if err != nil {
			return err
		}
		// Issues the API certificates of tenants bootstrapped through the link.
		serverCA, err := loadCA(ctx, st, sealer, "tenant_server_ca", "SrustiOps tenant server CA")
		if err != nil {
			return err
		}
		if err := srv.EnableLink(ca, serverCA); err != nil {
			return err
		}
	}
	return srv.Run(ctx)
}

// loadCA reads a CA (sealed with the master key), creating it on first
// start. Every central replica shares it.
func loadCA(ctx context.Context, st metaStore, sealer *secure.Sealer, name, cn string) (*link.CA, error) {
	sealed, err := st.GetMeta(ctx, name)
	if errors.Is(err, store.ErrNotFound) {
		_, bundle, err := link.NewNamedCA(cn)
		if err != nil {
			return nil, err
		}
		s, err := sealer.Seal(bundle, []byte(name))
		if err != nil {
			return nil, err
		}
		if sealed, err = st.PutMetaIfAbsent(ctx, name, s); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	bundle, err := sealer.Open(sealed, []byte(name))
	if err != nil {
		return nil, fmt.Errorf("cannot decrypt %s; is SRUSTIOPS_MASTER_KEY the key this database was created with? %w", name, err)
	}
	return link.LoadCA(bundle)
}

func runLink(ctx context.Context, log *slog.Logger) error {
	cfg, err := config.LoadLink()
	if err != nil {
		return err
	}
	u, _ := url.Parse(cfg.URL)
	ac := link.AgentConfig{Tenant: cfg.Tenant, URL: u, Target: cfg.Target, StateDir: cfg.StateDir, EnrollToken: cfg.EnrollToken, Connections: cfg.Connections,
		Mode: cfg.Mode, EgressListen: cfg.EgressListen, Version: version}
	if cfg.ServerCA != "" {
		b, err := os.ReadFile(cfg.ServerCA)
		if err != nil {
			return fmt.Errorf("SRUSTIOPS_LINK_SERVER_CA: %w", err)
		}
		ac.ServerCAs = x509.NewCertPool()
		if !ac.ServerCAs.AppendCertsFromPEM(b) {
			return errors.New("SRUSTIOPS_LINK_SERVER_CA contains no certificates")
		}
	}
	log.Info("tenant link agent starting", "tenant", cfg.Tenant, "gateway", cfg.URL, "target", cfg.Target, "tunnels", cfg.Connections, "version", version)
	return link.NewAgent(ac, log).Run(ctx)
}

func runTenant(ctx context.Context, log *slog.Logger) error {
	go metrics.Serve(ctx, log, os.Getenv("SRUSTIOPS_METRICS_LISTEN"), metrics.Default)
	cfg, err := config.LoadServer()
	if err != nil {
		return err
	}
	if err := trustProxies(log); err != nil {
		return err
	}
	sealer, err := sealerFrom(cfg.MasterKey)
	if err != nil {
		return err
	}
	cat, err := catalog.Load(cfg.CatalogDir)
	if err != nil {
		return fmt.Errorf("loading catalog from %s: %w", cfg.CatalogDir, err)
	}
	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		return err
	}
	iss, err := loadIssuer(ctx, st, sealer, "oidc_signing_key", cfg.PublicURL)
	if err != nil {
		return err
	}
	cfg.Version = version
	log.Info("tenant plane starting", "tenant", cfg.Tenant, "version", version, "modules", len(cat.Modules), "tofu", cfg.TofuVersion)
	srv, err := api.New(cfg, st, cat, sealer, iss, log)
	if err != nil {
		return err
	}
	return srv.Run(ctx)
}

func runRunner(ctx context.Context, log *slog.Logger) error {
	go metrics.Serve(ctx, log, os.Getenv("SRUSTIOPS_METRICS_LISTEN"), metrics.Default)
	cfg, err := config.LoadRunner()
	if err != nil {
		return err
	}
	r, err := runner.New(cfg, log)
	if err != nil {
		return err
	}
	return r.Run(ctx)
}

// runBootstrap creates the platform root, the one recovery account, directly
// in the central database, or rotates its credential: every earlier token of
// the root is revoked and one new token is printed. Day-to-day sign-in,
// platform admins included, goes through SSO.
func runBootstrap(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("central bootstrap", flag.ExitOnError)
	email := fs.String("email", "", "the platform root's email")
	ttl := fs.Int("ttl-days", 7, "token lifetime in days (max 90)")
	fs.Parse(args)
	if *email == "" || *ttl < 1 || *ttl > 90 {
		return errors.New("usage: srustiops central bootstrap -email root@example.com [-ttl-days 7]")
	}
	db, err := databaseURL()
	if err != nil {
		return err
	}
	st, err := central.OpenStore(ctx, db)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		return err
	}
	by := "cli:" + currentUser()
	plain, err := secure.NewToken("u")
	if err != nil {
		return err
	}
	u, t, err := st.RotateRoot(ctx, *email, by, secure.HashToken(plain), time.Now().Add(time.Duration(*ttl)*24*time.Hour))
	if errors.Is(err, central.ErrRootExists) {
		return fmt.Errorf("%w; there is one root, rotate its token with its email (other people become platform admins in Platform → Admins and sign in with SSO)", err)
	}
	if err != nil {
		return err
	}
	if err := st.AppendAudit(ctx, by, "platform_root.rotate", "user/"+u.Email, "", map[string]any{"token": t.ID}); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s is the platform root. Its only token expires %s and is shown once; earlier ones are revoked.\n", u.Email, t.ExpiresAt.Format(time.RFC3339))
	fmt.Println(plain)
	return nil
}

// runSCIMToken creates a bearer token an identity provider uses for SCIM.
func runSCIMToken(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("central scim-token", flag.ExitOnError)
	name := fs.String("name", "", "identity provider name, e.g. okta")
	fs.Parse(args)
	if *name == "" {
		return errors.New("usage: srustiops central scim-token -name okta")
	}
	db, err := databaseURL()
	if err != nil {
		return err
	}
	st, err := central.OpenStore(ctx, db)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		return err
	}
	plain, err := secure.NewToken("s")
	if err != nil {
		return err
	}
	by := "cli:" + currentUser()
	if err := st.CreateSCIMToken(ctx, *name, by, secure.HashToken(plain)); err != nil {
		return err
	}
	if err := st.AppendAudit(ctx, by, "scim.token_create", "scim/"+*name, "", nil); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "SCIM token for %s (base URL <central>/scim/v2). It is shown once.\n", *name)
	fmt.Println(plain)
	return nil
}

func runAuditVerify(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] != "verify" {
		return errors.New("usage: srustiops audit verify [-central]")
	}
	fs := flag.NewFlagSet("audit verify", flag.ExitOnError)
	fs.Bool("central", false, "the database is a central plane database (same check)")
	fs.Parse(args[1:])
	db, err := databaseURL()
	if err != nil {
		return err
	}
	pool, err := store.Connect(ctx, db)
	if err != nil {
		return err
	}
	defer pool.Close()
	base := store.NewBase(pool)
	n, broken, err := base.VerifyAudit(ctx)
	if err != nil {
		return err
	}
	if broken != 0 {
		return fmt.Errorf("audit chain is BROKEN at event %d (after %d intact events)", broken, n)
	}
	fmt.Printf("audit chain intact: %d events verified\n", n)
	return nil
}

func runCatalog(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] != "verify" {
		return errors.New("usage: srustiops catalog verify [-dir DIR] [-online]")
	}
	fs := flag.NewFlagSet("catalog verify", flag.ExitOnError)
	dir := fs.String("dir", envOr("SRUSTIOPS_CATALOG_DIR", "../srustiops-modules/catalog"), "catalog directory")
	online := fs.Bool("online", false, "check every pinned version exists on registry.opentofu.org")
	fs.Parse(args[1:])
	cat, err := catalog.Load(*dir)
	if err != nil {
		return err
	}
	fmt.Printf("catalog valid: %d modules, %d providers\n", len(cat.Modules), len(cat.Providers))
	if *online {
		if err := cat.VerifyOnline(ctx); err != nil {
			return err
		}
		fmt.Println("all pinned module, dependency and provider versions exist on registry.opentofu.org")
	}
	out, _ := json.MarshalIndent(summary(cat), "", "  ")
	fmt.Println(string(out))
	return nil
}

// summary groups the catalog by cloud folder for the CLI output.
func summary(c *catalog.Catalog) map[string]map[string]any {
	out := map[string]map[string]any{}
	group := func(cloud string) map[string]any {
		if cloud == "" {
			cloud = catalog.CommonFolder
		}
		if out[cloud] == nil {
			out[cloud] = map[string]any{"providers": []string{}, "modules": []string{}}
		}
		return out[cloud]
	}
	for _, p := range c.Providers {
		g := group(p.Cloud)
		g["providers"] = append(g["providers"].([]string), p.Source+"@"+p.Version)
	}
	for _, m := range c.Modules {
		g := group(m.Cloud)
		g["modules"] = append(g["modules"].([]string), m.ID+" ("+m.Source+"@"+strings.Join(m.Versions, ",")+")")
	}
	return out
}

// runDevCert issues development certificates from a local CA kept in -dir
// (created on first use). Server certificates get -host names; -client issues
// a client-authentication certificate (central's mTLS identity).
func runDevCert(args []string) error {
	fs := flag.NewFlagSet("dev-cert", flag.ExitOnError)
	dir := fs.String("dir", ".dev-certs", "output directory (also holds the dev CA)")
	name := fs.String("name", "server", "certificate file name: <name>.pem and <name>-key.pem")
	hosts := fs.String("host", "localhost,127.0.0.1", "comma-separated DNS names and IPs (server certificates)")
	client := fs.Bool("client", false, "issue a client certificate instead of a server certificate")
	force := fs.Bool("force", false, "replace an existing certificate")
	fs.Parse(args)
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}
	out := filepath.Join(*dir, *name+".pem")
	if _, err := os.Stat(out); err == nil && !*force {
		fmt.Printf("%s exists; keeping it (use -force to replace)\n", out)
		return nil
	}
	ca, caKey, err := devCA(*dir)
	if err != nil {
		return err
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: *name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(0, 6, 0),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if *client {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		for _, h := range strings.Split(*hosts, ",") {
			h = strings.TrimSpace(h)
			if ip := net.ParseIP(h); ip != nil {
				tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			} else if h != "" {
				tmpl.DNSNames = append(tmpl.DNSNames, h)
			}
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return err
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	if err := writePEM(out, "CERTIFICATE", der, 0o644); err != nil {
		return err
	}
	if err := writePEM(filepath.Join(*dir, *name+"-key.pem"), "PRIVATE KEY", keyDER, 0o600); err != nil {
		return err
	}
	kind := "server"
	if *client {
		kind = "client"
	}
	fmt.Printf("wrote %s certificate %s (CA %s)\n", kind, out, filepath.Join(*dir, "ca.pem"))
	return nil
}

// devCA loads or creates the development CA. Its key is kept for issuing more
// development certificates; never use this for production.
func devCA(dir string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certPath, keyPath := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca-key.pem")
	if cb, err := os.ReadFile(certPath); err == nil {
		kb, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, nil, fmt.Errorf("%s exists without %s", certPath, keyPath)
		}
		cblk, _ := pem.Decode(cb)
		kblk, _ := pem.Decode(kb)
		if cblk == nil || kblk == nil {
			return nil, nil, errors.New("dev CA files are not PEM")
		}
		ca, err := x509.ParseCertificate(cblk.Bytes)
		if err != nil {
			return nil, nil, err
		}
		k, err := x509.ParsePKCS8PrivateKey(kblk.Bytes)
		if err != nil {
			return nil, nil, err
		}
		ek, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, nil, errors.New("dev CA key is not ECDSA")
		}
		return ca, ek, nil
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: "SrustiOps development CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, MaxPathLenZero: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	if err := writePEM(certPath, "CERTIFICATE", der, 0o644); err != nil {
		return nil, nil, err
	}
	if err := writePEM(keyPath, "PRIVATE KEY", keyDER, 0o600); err != nil {
		return nil, nil, err
	}
	ca, _ := x509.ParseCertificate(der)
	return ca, key, nil
}

func writePEM(path, typ string, b []byte, mode os.FileMode) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: b}), mode)
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	return n
}

func databaseURL() (string, error) {
	url := os.Getenv("SRUSTIOPS_DATABASE_URL")
	if f := os.Getenv("SRUSTIOPS_DATABASE_URL_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return "", err
		}
		url = strings.TrimSpace(string(b))
	}
	if url == "" {
		return "", errors.New("SRUSTIOPS_DATABASE_URL is required")
	}
	return url, nil
}

func currentUser() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return "unknown"
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
