package cloudapi

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// AWS: credentials from STS AssumeRoleWithWebIdentity, then SigV4-signed
// calls to Resource Explorer (inventory) and Organizations (accounts).

type awsCreds struct{ AccessKey, Secret, Session string }

// AWSAssume exchanges an OIDC token for temporary credentials of roleARN.
func (c *Client) awsAssume(ctx context.Context, roleARN, session string) (*awsCreds, error) {
	if c.AWSKeys != nil {
		return c.awsAssumeWithKeys(ctx, roleARN, session)
	}
	tok, err := c.Tokens("sts.amazonaws.com")
	if err != nil {
		return nil, err
	}
	q := url.Values{"Action": {"AssumeRoleWithWebIdentity"}, "Version": {"2011-06-15"}, "RoleArn": {roleARN},
		"RoleSessionName": {session}, "WebIdentityToken": {tok}, "DurationSeconds": {"900"}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://sts.amazonaws.com/", strings.NewReader(q.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	b, err := c.do(req, nil)
	if err != nil {
		return nil, fmt.Errorf("assuming %s: %w", roleARN, err)
	}
	var out struct {
		Result struct {
			Credentials struct {
				AccessKeyID     string `xml:"AccessKeyId"`
				SecretAccessKey string `xml:"SecretAccessKey"`
				SessionToken    string `xml:"SessionToken"`
			} `xml:"Credentials"`
		} `xml:"AssumeRoleWithWebIdentityResult"`
	}
	if err := xml.Unmarshal(b, &out); err != nil || out.Result.Credentials.AccessKeyID == "" {
		return nil, fmt.Errorf("assuming %s: unexpected STS response", roleARN)
	}
	cr := out.Result.Credentials
	return &awsCreds{cr.AccessKeyID, cr.SecretAccessKey, cr.SessionToken}, nil
}

// awsAssumeWithKeys uses an access key, and assumes roleARN with it when set.
func (c *Client) awsAssumeWithKeys(ctx context.Context, roleARN, session string) (*awsCreds, error) {
	base := &awsCreds{AccessKey: c.AWSKeys.AccessKeyID, Secret: c.AWSKeys.SecretAccessKey}
	if roleARN == "" {
		return base, nil
	}
	q := url.Values{"Action": {"AssumeRole"}, "Version": {"2011-06-15"}, "RoleArn": {roleARN}, "RoleSessionName": {session}, "DurationSeconds": {"900"}}
	body := []byte(q.Encode())
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://sts.amazonaws.com/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	sigv4(req, body, base, "us-east-1", "sts", time.Now().UTC())
	b, err := c.do(req, nil)
	if err != nil {
		return nil, fmt.Errorf("assuming %s with the access key: %w", roleARN, err)
	}
	var out struct {
		Result struct {
			Credentials struct {
				AccessKeyID     string `xml:"AccessKeyId"`
				SecretAccessKey string `xml:"SecretAccessKey"`
				SessionToken    string `xml:"SessionToken"`
			} `xml:"Credentials"`
		} `xml:"AssumeRoleResult"`
	}
	if err := xml.Unmarshal(b, &out); err != nil || out.Result.Credentials.AccessKeyID == "" {
		return nil, fmt.Errorf("assuming %s: unexpected STS response", roleARN)
	}
	cr := out.Result.Credentials
	return &awsCreds{cr.AccessKeyID, cr.SecretAccessKey, cr.SessionToken}, nil
}

// awsCall makes a signed JSON call.
func (c *Client) awsCall(ctx context.Context, cr *awsCreds, region, service, endpoint, target string, body, out any) error {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(b))
	if target != "" {
		ct := "application/x-amz-json-1.1"
		if strings.HasPrefix(target, "CloudApiService.") {
			ct = "application/x-amz-json-1.0" // Cloud Control speaks JSON 1.0
		}
		req.Header.Set("Content-Type", ct)
		req.Header.Set("X-Amz-Target", target)
	} else {
		req.Header.Set("Content-Type", "application/json")
	}
	sigv4(req, b, cr, region, service, time.Now().UTC())
	_, err := c.do(req, out)
	return err
}

// sigv4 signs a request (AWS Signature Version 4).
func sigv4(req *http.Request, body []byte, cr *awsCreds, region, service string, now time.Time) {
	amzDate := now.Format("20060102T150405Z")
	day := now.Format("20060102")
	payload := sha256Hex(body)
	req.Header.Set("X-Amz-Date", amzDate)
	if cr.Session != "" {
		req.Header.Set("X-Amz-Security-Token", cr.Session)
	}
	req.Header.Set("Host", req.URL.Host)
	names := []string{}
	for k := range req.Header {
		lk := strings.ToLower(k)
		if lk == "host" || lk == "content-type" || strings.HasPrefix(lk, "x-amz-") {
			names = append(names, lk)
		}
	}
	sort.Strings(names)
	var canonHeaders strings.Builder
	for _, n := range names {
		v := req.Header.Get(n)
		if n == "host" {
			v = req.URL.Host
		}
		canonHeaders.WriteString(n + ":" + strings.TrimSpace(v) + "\n")
	}
	signed := strings.Join(names, ";")
	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	canon := strings.Join([]string{req.Method, path, req.URL.Query().Encode(), canonHeaders.String(), signed, payload}, "\n")
	scope := day + "/" + region + "/" + service + "/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + sha256Hex([]byte(canon))
	k := hmacSHA([]byte("AWS4"+cr.Secret), day)
	k = hmacSHA(k, region)
	k = hmacSHA(k, service)
	k = hmacSHA(k, "aws4_request")
	sig := hex.EncodeToString(hmacSHA(k, toSign))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+cr.AccessKey+"/"+scope+", SignedHeaders="+signed+", Signature="+sig)
}

func sha256Hex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func hmacSHA(k []byte, s string) []byte {
	m := hmac.New(sha256.New, k)
	m.Write([]byte(s))
	return m.Sum(nil)
}

// AWSInventory lists an account's resources through Resource Explorer (the
// account needs an aggregator or local index in region).
func (c *Client) AWSInventory(ctx context.Context, roleARN, region string) ([]Item, error) {
	ctx, cancel := ctxTimeout(ctx)
	defer cancel()
	cr, err := c.awsAssume(ctx, roleARN, "srustiops-inventory")
	if err != nil {
		return nil, err
	}
	var items []Item
	next := ""
	for page := 0; page < maxPages; page++ {
		body := map[string]any{"QueryString": "", "MaxResults": 1000}
		if next != "" {
			body["NextToken"] = next
		}
		var out struct {
			Resources []struct {
				Arn             string `json:"Arn"`
				ResourceType    string `json:"ResourceType"`
				Region          string `json:"Region"`
				OwningAccountID string `json:"OwningAccountId"`
				Properties      []struct {
					Name string          `json:"Name"`
					Data json.RawMessage `json:"Data"`
				} `json:"Properties"`
			} `json:"Resources"`
			NextToken string `json:"NextToken"`
		}
		if err := c.awsCall(ctx, cr, region, "resource-explorer-2", "https://resource-explorer-2."+region+".amazonaws.com/Search", "", body, &out); err != nil {
			return nil, fmt.Errorf("listing resources with Resource Explorer: %w", err)
		}
		for _, r := range out.Resources {
			it := Item{ID: r.Arn, Type: r.ResourceType, Region: r.Region, Account: r.OwningAccountID, Name: awsName(r.Arn)}
			for _, p := range r.Properties {
				if p.Name == "tags" {
					var tags []struct{ Key, Value string }
					json.Unmarshal(p.Data, &tags)
					if len(tags) > 0 {
						it.Tags = map[string]string{}
						for _, t := range tags {
							it.Tags[t.Key] = t.Value
						}
					}
				}
			}
			items = append(items, it)
		}
		if next = out.NextToken; next == "" {
			break
		}
	}
	return items, nil
}

// awsName is the resource name in an ARN: the part after the last / or :.
func awsName(arn string) string { return lastSegment(arn, "/:") }

// AWSOrganization lists an AWS Organization's OUs and accounts.
func (c *Client) AWSOrganization(ctx context.Context, roleARN string) ([]Unit, error) {
	ctx, cancel := ctxTimeout(ctx)
	defer cancel()
	cr, err := c.awsAssume(ctx, roleARN, "srustiops-organization")
	if err != nil {
		return nil, err
	}
	const ep = "https://organizations.us-east-1.amazonaws.com/"
	call := func(op string, body map[string]any, out any) error {
		return c.awsCall(ctx, cr, "us-east-1", "organizations", ep, "AWSOrganizationsV20161128."+op, body, out)
	}
	var roots struct {
		Roots []struct{ ID, Name string } `json:"Roots"`
	}
	if err := call("ListRoots", map[string]any{}, &roots); err != nil {
		return nil, fmt.Errorf("listing the organization: %w", err)
	}
	var units []Unit
	var walk func(parent string, depth int) error
	walk = func(parent string, depth int) error {
		if depth > 6 || len(units) > 20000 {
			return nil
		}
		for next, page := "", 0; page < maxPages; page++ {
			var ous struct {
				OrganizationalUnits []struct{ ID, Name string } `json:"OrganizationalUnits"`
				NextToken           string                      `json:"NextToken"`
			}
			body := map[string]any{"ParentId": parent}
			if next != "" {
				body["NextToken"] = next
			}
			if err := call("ListOrganizationalUnitsForParent", body, &ous); err != nil {
				return err
			}
			for _, ou := range ous.OrganizationalUnits {
				units = append(units, Unit{ID: ou.ID, ParentID: parent, Name: ou.Name, Kind: "ou"})
				if err := walk(ou.ID, depth+1); err != nil {
					return err
				}
			}
			if next = ous.NextToken; next == "" {
				break
			}
		}
		for next, page := "", 0; page < maxPages; page++ {
			var acc struct {
				Accounts []struct {
					ID, Name, Status string
				} `json:"Accounts"`
				NextToken string `json:"NextToken"`
			}
			body := map[string]any{"ParentId": parent}
			if next != "" {
				body["NextToken"] = next
			}
			if err := call("ListAccountsForParent", body, &acc); err != nil {
				return err
			}
			for _, a := range acc.Accounts {
				units = append(units, Unit{ID: a.ID, ParentID: parent, Name: a.Name, Kind: "account", External: a.ID, State: strings.ToLower(a.Status)})
			}
			if next = acc.NextToken; next == "" {
				break
			}
		}
		return nil
	}
	for _, r := range roots.Roots {
		units = append(units, Unit{ID: r.ID, Name: r.Name, Kind: "root"})
		if err := walk(r.ID, 0); err != nil {
			return nil, fmt.Errorf("listing the organization: %w", err)
		}
	}
	return units, nil
}

// AWSResource reads one resource's current properties through the Cloud
// Control API (typeName like AWS::EC2::SecurityGroup, identifier its primary
// identifier). Adoption uses them to find a resource's dependencies.
func (c *Client) AWSResource(ctx context.Context, roleARN, region, typeName, identifier string) (map[string]any, error) {
	ctx, cancel := ctxTimeout(ctx)
	defer cancel()
	cr, err := c.awsAssume(ctx, roleARN, "srustiops-discovery")
	if err != nil {
		return nil, err
	}
	var out struct {
		ResourceDescription struct {
			Properties string `json:"Properties"`
		} `json:"ResourceDescription"`
	}
	ep := "https://cloudcontrolapi." + region + ".amazonaws.com/"
	if err := c.awsCall(ctx, cr, region, "cloudcontrolapi", ep, "CloudApiService.GetResource", map[string]string{"TypeName": typeName, "Identifier": identifier}, &out); err != nil {
		return nil, fmt.Errorf("reading %s %s with Cloud Control: %w", typeName, identifier, err)
	}
	props := map[string]any{}
	if err := json.Unmarshal([]byte(out.ResourceDescription.Properties), &props); err != nil {
		return nil, fmt.Errorf("reading %s %s: unexpected properties", typeName, identifier)
	}
	return props, nil
}

// AWSListResources lists resources of a Cloud Control type with their
// properties (e.g. every AWS::EC2::VPCGatewayAttachment, to find the VPC an
// internet gateway is attached to).
func (c *Client) AWSListResources(ctx context.Context, roleARN, region, typeName string) ([]map[string]any, error) {
	ctx, cancel := ctxTimeout(ctx)
	defer cancel()
	cr, err := c.awsAssume(ctx, roleARN, "srustiops-discovery")
	if err != nil {
		return nil, err
	}
	ep := "https://cloudcontrolapi." + region + ".amazonaws.com/"
	var out []map[string]any
	next := ""
	for page := 0; page < maxPages; page++ {
		body := map[string]any{"TypeName": typeName, "MaxResults": 100}
		if next != "" {
			body["NextToken"] = next
		}
		var res struct {
			ResourceDescriptions []struct {
				Properties string `json:"Properties"`
			} `json:"ResourceDescriptions"`
			NextToken string `json:"NextToken"`
		}
		if err := c.awsCall(ctx, cr, region, "cloudcontrolapi", ep, "CloudApiService.ListResources", body, &res); err != nil {
			return nil, fmt.Errorf("listing %s with Cloud Control: %w", typeName, err)
		}
		for _, d := range res.ResourceDescriptions {
			props := map[string]any{}
			if json.Unmarshal([]byte(d.Properties), &props) == nil {
				out = append(out, props)
			}
		}
		if next = res.NextToken; next == "" {
			break
		}
	}
	return out, nil
}

// AWSInternetGatewayVPC returns the VPC an internet gateway is attached to
// ("" when it is detached), from EC2 DescribeInternetGateways.
func (c *Client) AWSInternetGatewayVPC(ctx context.Context, roleARN, region, igwID string) (string, error) {
	ctx, cancel := ctxTimeout(ctx)
	defer cancel()
	cr, err := c.awsAssume(ctx, roleARN, "srustiops-discovery")
	if err != nil {
		return "", err
	}
	q := url.Values{"Action": {"DescribeInternetGateways"}, "Version": {"2016-11-15"}, "InternetGatewayId.1": {igwID}}
	body := []byte(q.Encode())
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://ec2."+region+".amazonaws.com/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	sigv4(req, body, cr, region, "ec2", time.Now().UTC())
	b, err := c.do(req, nil)
	if err != nil {
		return "", fmt.Errorf("describing %s: %w", igwID, err)
	}
	var out struct {
		Attachments []struct {
			VpcID string `xml:"vpcId"`
			State string `xml:"state"`
		} `xml:"internetGatewaySet>item>attachmentSet>item"`
	}
	if err := xml.Unmarshal(b, &out); err != nil {
		return "", fmt.Errorf("describing %s: unexpected response", igwID)
	}
	for _, a := range out.Attachments {
		if a.VpcID != "" {
			return a.VpcID, nil
		}
	}
	return "", nil
}
