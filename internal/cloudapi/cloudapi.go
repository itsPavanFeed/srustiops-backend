// Package cloudapi reads what exists in a tenant's clouds: the resources of
// an account, project or subscription (inventory) and the accounts or
// projects of an organisation with their OUs or folders.
//
// It talks to each cloud's own index over HTTPS with short-lived credentials
// obtained by exchanging a token from the tenant's OIDC issuer (AWS STS web
// identity, GCP workload identity federation, Azure federated credentials),
// so no cloud secret is stored. Only read APIs are called.
package cloudapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Item is one cloud resource.
type Item struct {
	ID      string            `json:"id"`   // ARN, full resource name or Azure resource ID
	Type    string            `json:"type"` // "s3:bucket", "storage.googleapis.com/Bucket", "microsoft.storage/storageaccounts"
	Name    string            `json:"name"`
	Region  string            `json:"region,omitempty"`
	Account string            `json:"account,omitempty"` // AWS account or Azure subscription
	Project string            `json:"project,omitempty"` // GCP project ID
	Tags    map[string]string `json:"tags,omitempty"`
}

// Unit is one node of an organisation: a root, OU, folder or management
// group, or an account, project or subscription.
type Unit struct {
	ID       string `json:"id"`
	ParentID string `json:"parent_id,omitempty"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`               // root | ou | folder | management_group | account | project | subscription
	External string `json:"external,omitempty"` // account ID, project ID or subscription ID
	State    string `json:"state,omitempty"`
}

// Tokens issues a short-lived OIDC token from the tenant's issuer for an audience.
type Tokens func(audience string) (string, error)

// Client calls cloud APIs. Base, when set (tests and development only),
// sends every request to that server instead: the original host becomes the
// first path segment (https://sts.amazonaws.com/x -> Base/sts.amazonaws.com/x).
type Client struct {
	HC     *http.Client
	Base   string
	Tokens Tokens
	// Static credentials (vault mode), read from the tenant's secret store;
	// used instead of exchanging a token from the tenant's issuer.
	AWSKeys     *AWSKeys
	GCPKey      []byte // service account key file (JSON)
	AzureSecret string
}

type AWSKeys struct{ AccessKeyID, SecretAccessKey string }

const maxPages = 200

func (c *Client) client() *http.Client {
	hc := c.HC
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second}
	}
	return Redirected(hc, c.Base)
}

// Redirected returns hc, or with base set (tests and development only) a
// copy that sends every request to base, the original host becoming the
// first path segment.
func Redirected(hc *http.Client, base string) *http.Client {
	if base == "" {
		return hc
	}
	cp := *hc
	u, _ := url.Parse(base)
	cp.Transport = rewrite{base: u, next: transport(hc)}
	return &cp
}

func transport(hc *http.Client) http.RoundTripper {
	if hc.Transport != nil {
		return hc.Transport
	}
	return http.DefaultTransport
}

type rewrite struct {
	base *url.URL
	next http.RoundTripper
}

func (t rewrite) RoundTrip(r *http.Request) (*http.Response, error) {
	r2 := r.Clone(r.Context())
	host := r.URL.Host
	r2.URL.Scheme, r2.URL.Host = t.base.Scheme, t.base.Host
	r2.URL.Path = strings.TrimRight(t.base.Path, "/") + "/" + host + r.URL.Path
	r2.Host = t.base.Host
	r2.Header.Set("X-Original-Host", host)
	return t.next.RoundTrip(r2)
}

// do sends a request and decodes a JSON (or, with out=nil, returns the raw) body.
func (c *Client) do(req *http.Request, out any) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(b))
		if len(msg) > 300 {
			msg = msg[:300]
		}
		if c.Base != "" {
			// Not the real cloud's answer: say so, or it reads like one.
			return nil, fmt.Errorf("%s %s (sent to the test cloud endpoint %s, SRUSTIOPS_CLOUD_API_URL): %s: %s", req.Method, req.URL.Host, c.Base, resp.Status, msg)
		}
		return nil, fmt.Errorf("%s %s: %s: %s", req.Method, req.URL.Host, resp.Status, msg)
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			return nil, fmt.Errorf("%s: unexpected response: %w", req.URL.Host, err)
		}
	}
	return b, nil
}

func lastSegment(s string, seps string) string {
	if i := strings.LastIndexAny(s, seps); i >= 0 {
		return s[i+1:]
	}
	return s
}

// ErrUnsupported is returned for auth modes discovery cannot use.
var ErrUnsupported = errors.New("discovery needs a connection with oidc auth: the tenant plane exchanges its own token for read-only credentials")

func ctxTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 10*time.Minute)
}

// SignIn checks that a read-only identity can be obtained with the tenant's
// token: AWS STS web identity, GCP federation and impersonation, or an Entra
// ID federated credential. Nothing is read from the account.
func (c *Client) SignInAWS(ctx context.Context, roleARN string) error {
	cr, err := c.awsAssume(ctx, roleARN, "srustiops-connection-test")
	if err != nil {
		return err
	}
	// Confirm the credentials work (an access key with no role to assume
	// would otherwise not be checked). GetCallerIdentity needs no permissions.
	body := []byte("Action=GetCallerIdentity&Version=2011-06-15")
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://sts.amazonaws.com/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	sigv4(req, body, cr, "us-east-1", "sts", time.Now().UTC())
	if _, err := c.do(req, nil); err != nil {
		return fmt.Errorf("checking the credentials: %w", err)
	}
	return nil
}

func (c *Client) SignInGCP(ctx context.Context, provider, serviceAccount string) error {
	_, err := c.gcpToken(ctx, provider, serviceAccount)
	return err
}

func (c *Client) SignInAzure(ctx context.Context, tenantID, clientID string) error {
	_, err := c.azureToken(ctx, tenantID, clientID)
	return err
}
