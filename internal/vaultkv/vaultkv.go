// Package vaultkv reads KV v2 secrets from OpenBao or HashiCorp Vault after
// a JWT login with a platform-issued token: the runner uses it for cloud
// credentials (vault mode), the tenant plane for discovery with those
// credentials. Values are returned to the caller and never logged.
package vaultkv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/spec"
)

type Client struct {
	Store *spec.Vault
	HC    *http.Client
	token string
}

func (c *Client) hc() *http.Client {
	if c.HC != nil {
		return c.HC
	}
	return &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.Store.Address, "/")+"/v1/"+path, rd)
	if c.Store.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.Store.Namespace)
	}
	if c.token != "" {
		req.Header.Set("X-Vault-Token", c.token)
	}
	resp, err := c.hc().Do(req)
	if err != nil {
		return fmt.Errorf("the secret store cannot be reached: %w", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Errors []string `json:"errors"`
		}
		json.Unmarshal(b, &e)
		return fmt.Errorf("the secret store answered %d %s", resp.StatusCode, strings.Join(e.Errors, "; "))
	}
	return json.Unmarshal(b, out)
}

// Login exchanges a platform-issued JWT for a Vault token (JWT auth method).
func (c *Client) Login(ctx context.Context, jwt string) error {
	var out struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := c.do(ctx, http.MethodPost, "auth/"+c.Store.Mount()+"/login", map[string]string{"role": c.Store.Role, "jwt": jwt}, &out); err != nil {
		return fmt.Errorf("logging in to the secret store: %w", err)
	}
	if out.Auth.ClientToken == "" {
		return fmt.Errorf("logging in to the secret store: no token returned")
	}
	c.token = out.Auth.ClientToken
	return nil
}

// Read returns the value a vault://mount/path#key reference names (KV v2).
func (c *Client) Read(ctx context.Context, ref string) (string, error) {
	mount, path, key, ok := spec.ParseSecretRef(ref)
	if !ok {
		return "", fmt.Errorf("%q is not a vault://mount/path#key reference", ref)
	}
	var out struct {
		Data struct {
			Data map[string]any `json:"data"`
		} `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, mount+"/data/"+path, nil, &out); err != nil {
		return "", fmt.Errorf("reading %s: %w", ref, err)
	}
	v, found := out.Data.Data[key]
	if !found {
		return "", fmt.Errorf("reading %s: the secret has no key %q", ref, key)
	}
	switch t := v.(type) {
	case string:
		return t, nil
	default: // a JSON object stored as a value (for example a service account key)
		b, _ := json.Marshal(t)
		return string(b), nil
	}
}

// ReadAll reads several references (env var -> reference) after one login.
func ReadAll(ctx context.Context, store *spec.Vault, jwt string, refs map[string]string) (map[string]string, error) {
	c := &Client{Store: store}
	if err := c.Login(ctx, jwt); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for k, ref := range refs {
		v, err := c.Read(ctx, ref)
		if err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, nil
}
