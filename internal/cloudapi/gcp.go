package cloudapi

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// GCP: workload identity federation (STS token exchange, then service account
// impersonation), then Cloud Asset Inventory and Resource Manager.

func (c *Client) gcpToken(ctx context.Context, provider, serviceAccount string) (string, error) {
	if c.GCPKey != nil {
		return c.gcpKeyToken(ctx, serviceAccount)
	}
	audience := "//iam.googleapis.com/" + provider
	tok, err := c.Tokens(audience)
	if err != nil {
		return "", err
	}
	body, _ := json.Marshal(map[string]string{
		"grantType": "urn:ietf:params:oauth:grant-type:token-exchange", "audience": audience,
		"scope": "https://www.googleapis.com/auth/cloud-platform", "requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
		"subjectToken": tok, "subjectTokenType": "urn:ietf:params:oauth:token-type:jwt"})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://sts.googleapis.com/v1/token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	var fed struct {
		AccessToken string `json:"access_token"`
	}
	if _, err := c.do(req, &fed); err != nil {
		return "", fmt.Errorf("exchanging the token with %s: %w", provider, err)
	}
	body, _ = json.Marshal(map[string]any{"scope": []string{"https://www.googleapis.com/auth/cloud-platform"}, "lifetime": "900s"})
	req, _ = http.NewRequestWithContext(ctx, http.MethodPost,
		"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/"+url.PathEscape(serviceAccount)+":generateAccessToken", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+fed.AccessToken)
	var sa struct {
		AccessToken string `json:"accessToken"`
	}
	if _, err := c.do(req, &sa); err != nil {
		return "", fmt.Errorf("impersonating %s: %w", serviceAccount, err)
	}
	return sa.AccessToken, nil
}

// gcpKeyToken signs in with a service account key (JWT bearer grant), then
// impersonates serviceAccount when it names another account.
func (c *Client) gcpKeyToken(ctx context.Context, serviceAccount string) (string, error) {
	var key struct {
		ClientEmail string `json:"client_email"`
		PrivateKey  string `json:"private_key"`
		TokenURI    string `json:"token_uri"`
	}
	if err := json.Unmarshal(c.GCPKey, &key); err != nil || key.ClientEmail == "" || key.PrivateKey == "" {
		return "", errors.New("the service account key is not a Google key file")
	}
	if key.TokenURI == "" {
		key.TokenURI = "https://oauth2.googleapis.com/token"
	}
	block, _ := pem.Decode([]byte(key.PrivateKey))
	if block == nil {
		return "", errors.New("the service account key has no private key")
	}
	pk, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	rk, ok := pk.(*rsa.PrivateKey)
	if err != nil || !ok {
		return "", errors.New("the service account key's private key is not RSA")
	}
	now := time.Now().Unix()
	b64 := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	signing := b64(map[string]string{"alg": "RS256", "typ": "JWT"}) + "." + b64(map[string]any{
		"iss": key.ClientEmail, "scope": "https://www.googleapis.com/auth/cloud-platform", "aud": key.TokenURI, "iat": now, "exp": now + 900})
	h := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, rk, crypto.SHA256, h[:])
	if err != nil {
		return "", err
	}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {signing + "." + base64.RawURLEncoding.EncodeToString(sig)}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, key.TokenURI, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if _, err := c.do(req, &tok); err != nil || tok.AccessToken == "" {
		return "", fmt.Errorf("signing in as %s: %v", key.ClientEmail, err)
	}
	if serviceAccount == "" || serviceAccount == key.ClientEmail {
		return tok.AccessToken, nil
	}
	body, _ := json.Marshal(map[string]any{"scope": []string{"https://www.googleapis.com/auth/cloud-platform"}, "lifetime": "900s"})
	req, _ = http.NewRequestWithContext(ctx, http.MethodPost,
		"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/"+url.PathEscape(serviceAccount)+":generateAccessToken", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	var sa struct {
		AccessToken string `json:"accessToken"`
	}
	if _, err := c.do(req, &sa); err != nil {
		return "", fmt.Errorf("impersonating %s: %w", serviceAccount, err)
	}
	return sa.AccessToken, nil
}

func (c *Client) gcpGet(ctx context.Context, token, u string, out any) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	_, err := c.do(req, out)
	return err
}

// GCPInventory lists a project's resources through Cloud Asset Inventory.
func (c *Client) GCPInventory(ctx context.Context, provider, serviceAccount, project string) ([]Item, error) {
	ctx, cancel := ctxTimeout(ctx)
	defer cancel()
	tok, err := c.gcpToken(ctx, provider, serviceAccount)
	if err != nil {
		return nil, err
	}
	var items []Item
	next := ""
	for page := 0; page < maxPages; page++ {
		u := "https://cloudasset.googleapis.com/v1/projects/" + url.PathEscape(project) + ":searchAllResources?pageSize=500"
		if next != "" {
			u += "&pageToken=" + url.QueryEscape(next)
		}
		var out struct {
			Results []struct {
				Name        string            `json:"name"`
				AssetType   string            `json:"assetType"`
				DisplayName string            `json:"displayName"`
				Location    string            `json:"location"`
				Labels      map[string]string `json:"labels"`
			} `json:"results"`
			NextPageToken string `json:"nextPageToken"`
		}
		if err := c.gcpGet(ctx, tok, u, &out); err != nil {
			return nil, fmt.Errorf("listing resources with Cloud Asset Inventory: %w", err)
		}
		for _, r := range out.Results {
			name := r.DisplayName
			if name == "" {
				name = lastSegment(r.Name, "/")
			}
			items = append(items, Item{ID: r.Name, Type: r.AssetType, Name: name, Region: r.Location, Project: project, Tags: r.Labels})
		}
		if next = out.NextPageToken; next == "" {
			break
		}
	}
	return items, nil
}

// GCPOrganization lists an organisation's folders and projects.
func (c *Client) GCPOrganization(ctx context.Context, provider, serviceAccount, org string) ([]Unit, error) {
	ctx, cancel := ctxTimeout(ctx)
	defer cancel()
	tok, err := c.gcpToken(ctx, provider, serviceAccount)
	if err != nil {
		return nil, err
	}
	root := "organizations/" + strings.TrimPrefix(org, "organizations/")
	units := []Unit{{ID: root, Name: root, Kind: "root"}}
	var walk func(parent string, depth int) error
	walk = func(parent string, depth int) error {
		if depth > 10 || len(units) > 20000 {
			return nil
		}
		for next, page := "", 0; page < maxPages; page++ {
			u := "https://cloudresourcemanager.googleapis.com/v3/folders?parent=" + url.QueryEscape(parent) + "&pageSize=300"
			if next != "" {
				u += "&pageToken=" + url.QueryEscape(next)
			}
			var out struct {
				Folders []struct {
					Name, DisplayName, State string
				} `json:"folders"`
				NextPageToken string `json:"nextPageToken"`
			}
			if err := c.gcpGet(ctx, tok, u, &out); err != nil {
				return err
			}
			for _, f := range out.Folders {
				units = append(units, Unit{ID: f.Name, ParentID: parent, Name: f.DisplayName, Kind: "folder", State: strings.ToLower(f.State)})
				if err := walk(f.Name, depth+1); err != nil {
					return err
				}
			}
			if next = out.NextPageToken; next == "" {
				break
			}
		}
		for next, page := "", 0; page < maxPages; page++ {
			u := "https://cloudresourcemanager.googleapis.com/v3/projects?parent=" + url.QueryEscape(parent) + "&pageSize=300"
			if next != "" {
				u += "&pageToken=" + url.QueryEscape(next)
			}
			var out struct {
				Projects []struct {
					Name, ProjectID, DisplayName, State string
				} `json:"projects"`
				NextPageToken string `json:"nextPageToken"`
			}
			if err := c.gcpGet(ctx, tok, u, &out); err != nil {
				return err
			}
			for _, p := range out.Projects {
				name := p.DisplayName
				if name == "" {
					name = p.ProjectID
				}
				units = append(units, Unit{ID: p.Name, ParentID: parent, Name: name, Kind: "project", External: p.ProjectID, State: strings.ToLower(p.State)})
			}
			if next = out.NextPageToken; next == "" {
				break
			}
		}
		return nil
	}
	if err := walk(root, 0); err != nil {
		return nil, fmt.Errorf("listing the organization: %w", err)
	}
	return units, nil
}
