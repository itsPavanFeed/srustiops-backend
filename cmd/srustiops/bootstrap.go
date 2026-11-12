package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/link"
	"github.com/itsPavanFeed/srustiops-backend/internal/secure"
)

// runTenantBootstrap prepares a tenant plane in the client's cluster from a
// one-time install token, reaching only central's gateway. Every key is made
// here and stays here (master key, runner state key, runner token, the API's
// TLS key); central receives a certificate request and returns the
// certificate, the CAs to trust and the link agent's enrolment token.
//
//	-out DIR        files for Docker Compose or a manual install
//	-k8s PREFIX     Kubernetes Secrets PREFIX-tls, -central-ca, -keys, -link-enroll
//	                in this pod's namespace (the chart's install Job)
//
// Running it again after success changes nothing, so keys are never replaced.
func runTenantBootstrap(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("bootstrap", flag.ExitOnError)
	out := fs.String("out", "", "directory to write the tenant's files to")
	k8s := fs.String("k8s", "", "write Kubernetes Secrets named PREFIX-* in this namespace instead")
	fs.Parse(args)
	tenant, gw := os.Getenv("SRUSTIOPS_TENANT"), strings.TrimRight(os.Getenv("SRUSTIOPS_LINK_URL"), "/")
	token := os.Getenv("SRUSTIOPS_INSTALL_TOKEN")
	if f := os.Getenv("SRUSTIOPS_INSTALL_TOKEN_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		token = strings.TrimSpace(string(b))
	}
	if (*out == "") == (*k8s == "") {
		return errors.New("give exactly one of -out DIR or -k8s PREFIX")
	}
	if tenant == "" || !strings.HasPrefix(gw, "https://") {
		return errors.New("set SRUSTIOPS_TENANT and SRUSTIOPS_LINK_URL (the gateway's https:// URL)")
	}
	var sink secretSink
	if *out != "" {
		sink = &dirSink{dir: *out}
	} else {
		ks, err := newKubeSink(*k8s)
		if err != nil {
			return err
		}
		sink = ks
	}
	if done, err := sink.done(ctx); err != nil {
		return err
	} else if done {
		fmt.Println("already bootstrapped; nothing changed")
		return nil
	}
	if !strings.HasPrefix(token, "sop_i_") {
		return errors.New("SRUSTIOPS_INSTALL_TOKEN must be the one-time install token from the console (sop_i_...)")
	}

	keyPEM, csrPEM, err := link.NewKeyAndCSR(link.InternalName(tenant))
	if err != nil {
		return err
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if f := os.Getenv("SRUSTIOPS_LINK_SERVER_CA"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		tc.RootCAs = x509.NewCertPool()
		if !tc.RootCAs.AppendCertsFromPEM(b) {
			return errors.New("SRUSTIOPS_LINK_SERVER_CA contains no certificates")
		}
	}
	// Names runners in the cluster use for the API (the chart passes its
	// service names); the internal name is always added by central.
	names := []string{"localhost"}
	for _, n := range strings.Split(os.Getenv("SRUSTIOPS_SERVER_NAMES"), ",") {
		if n = strings.TrimSpace(n); n != "" {
			names = append(names, n)
		}
	}
	body, _ := json.Marshal(map[string]any{"tenant": tenant, "token": token, "server_csr": string(csrPEM), "server_names": names})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, gw+"/v1/install/bootstrap", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	hc := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: tc}}
	resp, err := hc.Do(req)
	if err != nil {
		port := "443"
		if u, perr := url.Parse(gw); perr == nil && u.Port() != "" {
			port = u.Port()
		}
		return fmt.Errorf("reaching the gateway %s: %w (this machine needs outbound TCP %s to it: check firewall and security group egress)", gw, err, port)
	}
	defer resp.Body.Close()
	var got map[string]string
	json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&got)
	if resp.StatusCode != 200 {
		return fmt.Errorf("the gateway refused the install token (%d): %s", resp.StatusCode, got["error"])
	}
	master := make([]byte, 32)
	rand.Read(master)
	state := make([]byte, 32)
	rand.Read(state)
	runner, err := secure.NewToken("r")
	if err != nil {
		return err
	}
	files := map[string]map[string]string{
		"tls":         {"tls.crt": got["server_certificate"], "tls.key": string(keyPEM), "ca.crt": got["server_ca"]},
		"central-ca":  {"ca.crt": got["central_client_ca"]},
		"keys":        {"master-key": base64.StdEncoding.EncodeToString(master), "state-key": hex.EncodeToString(state), "runner-token": runner},
		"link-enroll": {"token": got["link_enroll_token"]},
	}
	// The TLS Secret goes last: it marks the bootstrap as done.
	for _, name := range []string{"central-ca", "keys", "link-enroll", "tls"} {
		if err := sink.put(ctx, name, files[name]); err != nil {
			return fmt.Errorf("writing %s: %w", name, err)
		}
	}
	fmt.Printf("bootstrapped %s: API certificate for %s; keys made here and kept here.\n", tenant, got["internal_name"])
	fmt.Printf("tenant plane settings: SRUSTIOPS_TENANT=%s SRUSTIOPS_CENTRAL_URL=%s SRUSTIOPS_CENTRAL_ISSUER=%s\n", tenant, got["link_url"], got["central_issuer"])
	return nil
}

type secretSink interface {
	done(ctx context.Context) (bool, error)
	put(ctx context.Context, name string, data map[string]string) error
}

type dirSink struct{ dir string }

func (d *dirSink) done(context.Context) (bool, error) {
	_, err := os.Stat(filepath.Join(d.dir, "tls", "tls.crt"))
	return err == nil, nil
}

func (d *dirSink) put(_ context.Context, name string, data map[string]string) error {
	dir := filepath.Join(d.dir, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for k, v := range data {
		mode := os.FileMode(0o600)
		if strings.HasSuffix(k, ".crt") {
			mode = 0o644
		}
		if err := os.WriteFile(filepath.Join(dir, k), []byte(v), mode); err != nil {
			return err
		}
	}
	return nil
}

// kubeSink writes Secrets through the in-cluster API with the pod's own
// service account (the chart grants it create/get on Secrets in its namespace).
type kubeSink struct {
	prefix, ns, api, token string
	hc                     *http.Client
}

func newKubeSink(prefix string) (*kubeSink, error) {
	const sa = "/var/run/secrets/kubernetes.io/serviceaccount/"
	tok, err := os.ReadFile(sa + "token")
	if err != nil {
		return nil, errors.New("-k8s runs inside a pod with a service account token")
	}
	ns, _ := os.ReadFile(sa + "namespace")
	ca, _ := os.ReadFile(sa + "ca.crt")
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	return &kubeSink{prefix: prefix, ns: strings.TrimSpace(string(ns)), api: "https://" + host + ":" + port, token: strings.TrimSpace(string(tok)),
		hc: &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}}, nil
}

func (k *kubeSink) do(ctx context.Context, method, path string, body any) (int, error) {
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequestWithContext(ctx, method, k.api+"/api/v1/namespaces/"+k.ns+"/secrets"+path, r)
	req.Header.Set("Authorization", "Bearer "+k.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := k.hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

func (k *kubeSink) done(ctx context.Context) (bool, error) {
	code, err := k.do(ctx, http.MethodGet, "/"+k.prefix+"-tls", nil)
	if err != nil {
		return false, err
	}
	return code == 200, nil
}

func (k *kubeSink) put(ctx context.Context, name string, data map[string]string) error {
	typ := "Opaque"
	if name == "tls" {
		typ = "kubernetes.io/tls"
	}
	code, err := k.do(ctx, http.MethodPost, "", map[string]any{
		"apiVersion": "v1", "kind": "Secret", "type": typ, "stringData": data,
		"metadata": map[string]any{"name": k.prefix + "-" + name, "labels": map[string]string{"app.kubernetes.io/managed-by": "srustiops-bootstrap"}},
	})
	switch {
	case err != nil:
		return err
	case code == http.StatusConflict:
		return nil // made by an earlier, interrupted run: never replaced
	case code >= 300:
		return fmt.Errorf("the Kubernetes API answered %d", code)
	}
	return nil
}
