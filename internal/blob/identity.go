package blob

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// ---- AWS: IRSA (AssumeRoleWithWebIdentity with the projected token) ----

type awsCreds struct {
	AccessKey, SecretKey, Token string
	Expires                     time.Time
}

type webIdentity struct {
	hc        *http.Client
	endpoint  string
	role      string
	tokenFile string
	now       func() time.Time
	mu        sync.Mutex
	cur       *awsCreds
}

func (w *webIdentity) get(ctx context.Context) (*awsCreds, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cur != nil && w.now().Before(w.cur.Expires.Add(-5*time.Minute)) {
		return w.cur, nil
	}
	tok, err := os.ReadFile(w.tokenFile)
	if err != nil {
		return nil, fmt.Errorf("reading the pod's web identity token: %w", err)
	}
	form := url.Values{"Action": {"AssumeRoleWithWebIdentity"}, "Version": {"2011-06-15"}, "RoleArn": {w.role},
		"RoleSessionName": {"srustiops-bucket"}, "WebIdentityToken": {strings.TrimSpace(string(tok))}, "DurationSeconds": {"3600"}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, w.endpoint+"/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := w.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("assuming the bucket role %s: %s %s", w.role, resp.Status, strings.TrimSpace(string(b)))
	}
	var out struct {
		Creds struct {
			AccessKeyID     string `xml:"AccessKeyId"`
			SecretAccessKey string `xml:"SecretAccessKey"`
			SessionToken    string `xml:"SessionToken"`
			Expiration      string `xml:"Expiration"`
		} `xml:"AssumeRoleWithWebIdentityResult>Credentials"`
	}
	if err := xml.Unmarshal(b, &out); err != nil || out.Creds.AccessKeyID == "" {
		return nil, errors.New("STS returned no credentials")
	}
	exp, err := time.Parse(time.RFC3339, out.Creds.Expiration)
	if err != nil {
		exp = w.now().Add(time.Hour)
	}
	w.cur = &awsCreds{AccessKey: out.Creds.AccessKeyID, SecretKey: out.Creds.SecretAccessKey, Token: out.Creds.SessionToken, Expires: exp}
	return w.cur, nil
}

// ---- bearer tokens: GKE metadata server, Entra Workload ID ----

type bearer struct {
	mu    sync.Mutex
	tok   string
	until time.Time
	fetch func(ctx context.Context) (string, time.Duration, error)
}

func (b *bearer) get(ctx context.Context) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.tok != "" && time.Now().Before(b.until) {
		return b.tok, nil
	}
	tok, ttl, err := b.fetch(ctx)
	if err != nil {
		return "", err
	}
	b.tok, b.until = tok, time.Now().Add(ttl-2*time.Minute)
	return tok, nil
}

func tokenJSON(hc *http.Client, req *http.Request, what string) (string, time.Duration, error) {
	resp, err := hc.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("%s: %w", what, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != 200 {
		return "", 0, fmt.Errorf("%s: %s %s", what, resp.Status, strings.TrimSpace(string(b)))
	}
	var out struct {
		AccessToken string          `json:"access_token"`
		ExpiresIn   json.RawMessage `json:"expires_in"` // a number (Google) or a string (Entra)
	}
	if err := json.Unmarshal(b, &out); err != nil || out.AccessToken == "" {
		return "", 0, fmt.Errorf("%s: no access token", what)
	}
	var secs float64
	fmt.Sscan(strings.Trim(string(out.ExpiresIn), `"`), &secs)
	if secs < 180 {
		secs = 600
	}
	return out.AccessToken, time.Duration(secs) * time.Second, nil
}

// gkeToken is the pod's Google service account token from the metadata
// server (Workload Identity Federation for GKE).
func gkeToken(hc *http.Client) *bearer {
	host := os.Getenv("GCE_METADATA_HOST")
	if host == "" {
		host = "metadata.google.internal"
	}
	return &bearer{fetch: func(ctx context.Context) (string, time.Duration, error) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+host+"/computeMetadata/v1/instance/service-accounts/default/token", nil)
		req.Header.Set("Metadata-Flavor", "Google")
		return tokenJSON(hc, req, "getting a token from the GKE metadata server")
	}}
}

// entraToken exchanges the pod's projected token for a Storage token
// (Microsoft Entra Workload ID).
func entraToken(hc *http.Client, scope string) (*bearer, error) {
	file, client, tenant := os.Getenv("AZURE_FEDERATED_TOKEN_FILE"), os.Getenv("AZURE_CLIENT_ID"), os.Getenv("AZURE_TENANT_ID")
	if file == "" || client == "" || tenant == "" {
		return nil, errors.New("Azure Blob Storage needs Workload ID on the pod (AZURE_FEDERATED_TOKEN_FILE, AZURE_CLIENT_ID, AZURE_TENANT_ID)")
	}
	authority := os.Getenv("AZURE_AUTHORITY_HOST")
	if authority == "" {
		authority = "https://login.microsoftonline.com/"
	}
	return &bearer{fetch: func(ctx context.Context) (string, time.Duration, error) {
		assertion, err := os.ReadFile(file)
		if err != nil {
			return "", 0, err
		}
		form := url.Values{"client_id": {client}, "grant_type": {"client_credentials"}, "scope": {scope},
			"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "client_assertion": {strings.TrimSpace(string(assertion))}}
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(authority, "/")+"/"+url.PathEscape(tenant)+"/oauth2/v2.0/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return tokenJSON(hc, req, "getting a Storage token from Entra")
	}}, nil
}
