package cloudapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Azure: an Entra ID token from a federated credential (the tenant's own
// token as the client assertion), then Resource Graph and management groups.

func (c *Client) azureToken(ctx context.Context, tenantID, clientID string) (string, error) {
	form := url.Values{"client_id": {clientID}, "grant_type": {"client_credentials"}, "scope": {"https://management.azure.com/.default"}}
	if c.AzureSecret != "" {
		form.Set("client_secret", c.AzureSecret)
	} else {
		tok, err := c.Tokens("api://AzureADTokenExchange")
		if err != nil {
			return "", err
		}
		form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		form.Set("client_assertion", tok)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://login.microsoftonline.com/"+url.PathEscape(tenantID)+"/oauth2/v2.0/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if _, err := c.do(req, &out); err != nil {
		return "", fmt.Errorf("signing in as %s: %w", clientID, err)
	}
	return out.AccessToken, nil
}

// AzureInventory lists a subscription's resources through Resource Graph.
func (c *Client) AzureInventory(ctx context.Context, tenantID, clientID, subscription string) ([]Item, error) {
	ctx, cancel := ctxTimeout(ctx)
	defer cancel()
	tok, err := c.azureToken(ctx, tenantID, clientID)
	if err != nil {
		return nil, err
	}
	var items []Item
	skip := ""
	for page := 0; page < maxPages; page++ {
		opts := map[string]any{"$top": 1000}
		if skip != "" {
			opts["$skipToken"] = skip
		}
		body, _ := json.Marshal(map[string]any{"subscriptions": []string{subscription}, "query": "Resources | project id, name, type, location, tags", "options": opts})
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+tok)
		var out struct {
			Data []struct {
				ID       string            `json:"id"`
				Name     string            `json:"name"`
				Type     string            `json:"type"`
				Location string            `json:"location"`
				Tags     map[string]string `json:"tags"`
			} `json:"data"`
			SkipToken string `json:"$skipToken"`
		}
		if _, err := c.do(req, &out); err != nil {
			return nil, fmt.Errorf("listing resources with Resource Graph: %w", err)
		}
		for _, r := range out.Data {
			items = append(items, Item{ID: r.ID, Type: strings.ToLower(r.Type), Name: r.Name, Region: r.Location, Account: subscription, Tags: r.Tags})
		}
		if skip = out.SkipToken; skip == "" {
			break
		}
	}
	return items, nil
}

// AzureManagementGroup lists a management group's descendants (groups and subscriptions).
func (c *Client) AzureManagementGroup(ctx context.Context, tenantID, clientID, group string) ([]Unit, error) {
	ctx, cancel := ctxTimeout(ctx)
	defer cancel()
	tok, err := c.azureToken(ctx, tenantID, clientID)
	if err != nil {
		return nil, err
	}
	rootID := "/providers/Microsoft.Management/managementGroups/" + group
	units := []Unit{{ID: rootID, Name: group, Kind: "root"}}
	u := "https://management.azure.com" + rootID + "/descendants?api-version=2020-05-01"
	for page := 0; page < maxPages && u != ""; page++ {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		var out struct {
			Value []struct {
				ID         string `json:"id"`
				Name       string `json:"name"`
				Type       string `json:"type"`
				Properties struct {
					DisplayName string `json:"displayName"`
					Parent      struct {
						ID string `json:"id"`
					} `json:"parent"`
				} `json:"properties"`
			} `json:"value"`
			NextLink string `json:"nextLink"`
		}
		if _, err := c.do(req, &out); err != nil {
			return nil, fmt.Errorf("listing the management group: %w", err)
		}
		for _, v := range out.Value {
			kind, ext := "management_group", ""
			if strings.HasSuffix(strings.ToLower(v.Type), "/subscriptions") {
				kind, ext = "subscription", v.Name
			}
			name := v.Properties.DisplayName
			if name == "" {
				name = v.Name
			}
			units = append(units, Unit{ID: v.ID, ParentID: v.Properties.Parent.ID, Name: name, Kind: kind, External: ext})
		}
		u = out.NextLink
	}
	return units, nil
}
