package cloudapi

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestSigV4 checks the signature against the AWS documentation's example
// (GET https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08).
func TestSigV4(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	now, _ := time.Parse("20060102T150405Z", "20150830T123600Z")
	sigv4(req, nil, &awsCreds{AccessKey: "AKIDEXAMPLE", Secret: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}, "us-east-1", "iam", now)
	got := req.Header.Get("Authorization")
	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
	if got != want {
		t.Fatalf("authorization header:\n got %s\nwant %s", got, want)
	}
}

func fake(t *testing.T, h map[string]func(w http.ResponseWriter, r *http.Request, body []byte)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		host, path, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
		key := host + "/" + strings.SplitN(path, ":", 2)[0]
		for k, f := range h {
			if strings.HasPrefix(key, k) {
				f(w, r, b)
				return
			}
		}
		t.Errorf("unexpected call %s %s", r.Method, r.URL)
		w.WriteHeader(404)
	}))
}

func TestAWSInventory(t *testing.T) {
	srv := fake(t, map[string]func(http.ResponseWriter, *http.Request, []byte){
		"sts.amazonaws.com/": func(w http.ResponseWriter, r *http.Request, b []byte) {
			if !strings.Contains(string(b), "WebIdentityToken=tok-sts.amazonaws.com") || !strings.Contains(string(b), "RoleArn=arn%3Aaws%3Aiam%3A%3A1%3Arole%2Fread") {
				t.Errorf("sts body %s", b)
			}
			io.WriteString(w, `<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>AK</AccessKeyId><SecretAccessKey>SK</SecretAccessKey><SessionToken>ST</SessionToken></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`)
		},
		"resource-explorer-2.eu-west-1.amazonaws.com/Search": func(w http.ResponseWriter, r *http.Request, b []byte) {
			if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AK/") || r.Header.Get("X-Amz-Security-Token") != "ST" {
				t.Errorf("unsigned call: %v", r.Header)
			}
			var in map[string]any
			json.Unmarshal(b, &in)
			if in["NextToken"] == nil {
				io.WriteString(w, `{"Resources":[{"Arn":"arn:aws:s3:::logs","ResourceType":"s3:bucket","Region":"eu-west-1","OwningAccountId":"1","Properties":[{"Name":"tags","Data":[{"Key":"team","Value":"a"}]}]}],"NextToken":"p2"}`)
				return
			}
			io.WriteString(w, `{"Resources":[{"Arn":"arn:aws:ec2:eu-west-1:1:vpc/vpc-1","ResourceType":"ec2:vpc","Region":"eu-west-1","OwningAccountId":"1"}]}`)
		},
	})
	defer srv.Close()
	c := &Client{Base: srv.URL, Tokens: func(aud string) (string, error) { return "tok-" + aud, nil }}
	items, err := c.AWSInventory(context.Background(), "arn:aws:iam::1:role/read", "eu-west-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].Name != "logs" || items[0].Tags["team"] != "a" || items[1].Name != "vpc-1" {
		t.Fatalf("items: %+v", items)
	}
}

func TestGCPInventoryAndOrg(t *testing.T) {
	srv := fake(t, map[string]func(http.ResponseWriter, *http.Request, []byte){
		"sts.googleapis.com/v1/token": func(w http.ResponseWriter, r *http.Request, b []byte) {
			if !strings.Contains(string(b), `"subjectToken":"tok-//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/x"`) {
				t.Errorf("sts body %s", b)
			}
			io.WriteString(w, `{"access_token":"fed"}`)
		},
		"iamcredentials.googleapis.com/": func(w http.ResponseWriter, r *http.Request, b []byte) {
			if r.Header.Get("Authorization") != "Bearer fed" || !strings.Contains(r.URL.Path, "read@p.iam.gserviceaccount.com") {
				t.Errorf("impersonation %v %s", r.Header, r.URL.Path)
			}
			io.WriteString(w, `{"accessToken":"sa"}`)
		},
		"cloudasset.googleapis.com/v1/projects/acme-1": func(w http.ResponseWriter, r *http.Request, b []byte) {
			io.WriteString(w, `{"results":[{"name":"//storage.googleapis.com/projects/_/buckets/b1","assetType":"storage.googleapis.com/Bucket","displayName":"b1","location":"europe-west1","labels":{"team":"a"}}]}`)
		},
		"cloudresourcemanager.googleapis.com/v3/folders": func(w http.ResponseWriter, r *http.Request, b []byte) {
			if r.URL.Query().Get("parent") == "organizations/9" {
				io.WriteString(w, `{"folders":[{"name":"folders/5","displayName":"payments","state":"ACTIVE"}]}`)
				return
			}
			io.WriteString(w, `{}`)
		},
		"cloudresourcemanager.googleapis.com/v3/projects": func(w http.ResponseWriter, r *http.Request, b []byte) {
			if r.URL.Query().Get("parent") == "folders/5" {
				io.WriteString(w, `{"projects":[{"name":"projects/77","projectId":"pay-prod","displayName":"Payments prod","state":"ACTIVE"}]}`)
				return
			}
			io.WriteString(w, `{}`)
		},
	})
	defer srv.Close()
	c := &Client{Base: srv.URL, Tokens: func(aud string) (string, error) { return "tok-" + aud, nil }}
	prov := "projects/1/locations/global/workloadIdentityPools/p/providers/x"
	items, err := c.GCPInventory(context.Background(), prov, "read@p.iam.gserviceaccount.com", "acme-1")
	if err != nil || len(items) != 1 || items[0].Name != "b1" || items[0].Project != "acme-1" {
		t.Fatalf("items %+v %v", items, err)
	}
	units, err := c.GCPOrganization(context.Background(), prov, "read@p.iam.gserviceaccount.com", "9")
	if err != nil || len(units) != 3 || units[1].Kind != "folder" || units[2].External != "pay-prod" || units[2].ParentID != "folders/5" {
		t.Fatalf("units %+v %v", units, err)
	}
}

func TestAzureInventory(t *testing.T) {
	srv := fake(t, map[string]func(http.ResponseWriter, *http.Request, []byte){
		"login.microsoftonline.com/t1/oauth2/v2.0/token": func(w http.ResponseWriter, r *http.Request, b []byte) {
			if !strings.Contains(string(b), "client_assertion=tok-api") {
				t.Errorf("token body %s", b)
			}
			io.WriteString(w, `{"access_token":"arm"}`)
		},
		"management.azure.com/providers/Microsoft.ResourceGraph/resources": func(w http.ResponseWriter, r *http.Request, b []byte) {
			io.WriteString(w, `{"data":[{"id":"/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/st1","name":"st1","type":"Microsoft.Storage/storageAccounts","location":"westeurope"}]}`)
		},
	})
	defer srv.Close()
	c := &Client{Base: srv.URL, Tokens: func(aud string) (string, error) { return "tok-" + aud, nil }}
	items, err := c.AzureInventory(context.Background(), "t1", "c1", "s1")
	if err != nil || len(items) != 1 || items[0].Type != "microsoft.storage/storageaccounts" {
		t.Fatalf("items %+v %v", items, err)
	}
}

func TestStaticCredentials(t *testing.T) {
	// AWS: an access key, assuming a role with it.
	srv := fake(t, map[string]func(http.ResponseWriter, *http.Request, []byte){
		"sts.amazonaws.com/": func(w http.ResponseWriter, r *http.Request, b []byte) {
			if !strings.Contains(string(b), "Action=AssumeRole&") || !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKIATEST/") {
				t.Errorf("assume role with keys: %s %v", b, r.Header)
			}
			io.WriteString(w, `<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>ASIAROLE</AccessKeyId><SecretAccessKey>s</SecretAccessKey><SessionToken>st</SessionToken></Credentials></AssumeRoleResult></AssumeRoleResponse>`)
		},
		"resource-explorer-2.eu-west-1.amazonaws.com/Search": func(w http.ResponseWriter, r *http.Request, b []byte) {
			io.WriteString(w, `{"Resources":[{"Arn":"arn:aws:s3:::k","ResourceType":"s3:bucket","Region":"eu-west-1","OwningAccountId":"1"}],"auth":"`+r.Header.Get("Authorization")[:40]+`"}`)
			if !strings.Contains(r.Header.Get("Authorization"), "Credential=ASIAROLE/") {
				t.Errorf("search not signed with the assumed role: %s", r.Header.Get("Authorization"))
			}
		},
	})
	defer srv.Close()
	c := &Client{Base: srv.URL, AWSKeys: &AWSKeys{AccessKeyID: "AKIATEST", SecretAccessKey: "secret"}, Tokens: func(string) (string, error) { t.Fatal("no token exchange in vault mode"); return "", nil }}
	if items, err := c.AWSInventory(context.Background(), "arn:aws:iam::1:role/read", "eu-west-1"); err != nil || len(items) != 1 {
		t.Fatalf("aws with keys: %v %v", items, err)
	}

	// GCP: a service account key signs its own token request.
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	keyJSON, _ := json.Marshal(map[string]string{"type": "service_account", "client_email": "reader@p.iam.gserviceaccount.com",
		"private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), "token_uri": "https://oauth2.googleapis.com/token"})
	gsrv := fake(t, map[string]func(http.ResponseWriter, *http.Request, []byte){
		"oauth2.googleapis.com/token": func(w http.ResponseWriter, r *http.Request, b []byte) {
			q, _ := url.ParseQuery(string(b))
			parts := strings.Split(q.Get("assertion"), ".")
			sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
			h := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
			if q.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" || rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, h[:], sig) != nil {
				t.Errorf("bad assertion")
				w.WriteHeader(400)
				return
			}
			io.WriteString(w, `{"access_token":"gcp-key-token"}`)
		},
		"cloudasset.googleapis.com/v1/projects/p1": func(w http.ResponseWriter, r *http.Request, b []byte) {
			if r.Header.Get("Authorization") != "Bearer gcp-key-token" {
				t.Errorf("asset call not authorized with the key's token")
			}
			io.WriteString(w, `{"results":[]}`)
		},
	})
	defer gsrv.Close()
	g := &Client{Base: gsrv.URL, GCPKey: keyJSON}
	if _, err := g.GCPInventory(context.Background(), "", "", "p1"); err != nil {
		t.Fatalf("gcp with key: %v", err)
	}

	// Azure: a client secret.
	asrv := fake(t, map[string]func(http.ResponseWriter, *http.Request, []byte){
		"login.microsoftonline.com/t1/oauth2/v2.0/token": func(w http.ResponseWriter, r *http.Request, b []byte) {
			if !strings.Contains(string(b), "client_secret=shh") || strings.Contains(string(b), "client_assertion") {
				t.Errorf("token body %s", b)
			}
			io.WriteString(w, `{"access_token":"arm"}`)
		},
		"management.azure.com/providers/Microsoft.ResourceGraph/resources": func(w http.ResponseWriter, r *http.Request, b []byte) {
			io.WriteString(w, `{"data":[]}`)
		},
	})
	defer asrv.Close()
	a := &Client{Base: asrv.URL, AzureSecret: "shh"}
	if _, err := a.AzureInventory(context.Background(), "t1", "c1", "s1"); err != nil {
		t.Fatalf("azure with secret: %v", err)
	}
}
