package blob

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// objects is an in-memory bucket keyed by the request's object path.
type objects struct {
	mu sync.Mutex
	m  map[string][]byte
}

func (o *objects) put(k string, b []byte) { o.mu.Lock(); o.m[k] = b; o.mu.Unlock() }
func (o *objects) get(k string) ([]byte, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	b, ok := o.m[k]
	return b, ok
}

func roundTrip(t *testing.T, s Store) {
	ctx := context.Background()
	if err := s.EnsureBucket(ctx); err != nil {
		t.Fatalf("%s ensure: %v", s, err)
	}
	if err := s.Put(ctx, "state/a b/1", []byte("hello")); err != nil {
		t.Fatalf("%s put: %v", s, err)
	}
	if b, err := s.Get(ctx, "state/a b/1"); err != nil || string(b) != "hello" {
		t.Fatalf("%s get: %q %v", s, b, err)
	}
	if _, err := s.Get(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("%s missing: %v", s, err)
	}
	if err := s.Delete(ctx, "state/a b/1"); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, "state/a b/1"); err != nil {
		t.Fatalf("%s deleting a missing object: %v", s, err)
	}
	if _, err := s.Get(ctx, "state/a b/1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("%s after delete: %v", s, err)
	}
}

func TestGCSWorkloadIdentity(t *testing.T) {
	o := &objects{m: map[string][]byte{}}
	tokens := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/computeMetadata/") {
			if r.Header.Get("Metadata-Flavor") != "Google" {
				w.WriteHeader(403)
				return
			}
			tokens++
			io.WriteString(w, `{"access_token":"gsa","expires_in":3599}`)
			return
		}
		if r.Header.Get("Authorization") != "Bearer gsa" {
			w.WriteHeader(401)
			return
		}
		p := r.URL.EscapedPath()
		switch {
		case r.Method == "POST" && strings.HasPrefix(p, "/upload/storage/v1/b/bkt/o"):
			b, _ := io.ReadAll(r.Body)
			o.put(r.URL.Query().Get("name"), b)
		case p == "/storage/v1/b/bkt":
		case strings.HasPrefix(p, "/storage/v1/b/bkt/o/"):
			name, _ := pathUnescape(strings.TrimPrefix(p, "/storage/v1/b/bkt/o/"))
			b, ok := o.get(name)
			if !ok {
				w.WriteHeader(404)
				return
			}
			if r.Method == "DELETE" {
				o.mu.Lock()
				delete(o.m, name)
				o.mu.Unlock()
				w.WriteHeader(204)
				return
			}
			w.Write(b)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	t.Setenv("GCE_METADATA_HOST", strings.TrimPrefix(srv.URL, "http://"))
	s, err := Open("gs://bkt/acme?endpoint="+srv.URL, "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, s)
	if _, ok := o.get("acme/state/a b/1"); ok {
		t.Fatal("deleted object still there")
	}
	if tokens != 1 {
		t.Fatalf("the token was fetched %d times, want once (cached)", tokens)
	}
}

func TestAzureWorkloadID(t *testing.T) {
	o := &objects{m: map[string][]byte{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token") {
			r.ParseForm()
			if r.Form.Get("client_assertion") != "projected" || r.Form.Get("scope") != "https://storage.azure.com/.default" || r.URL.Path != "/tid/oauth2/v2.0/token" {
				w.WriteHeader(400)
				return
			}
			io.WriteString(w, `{"access_token":"stor","expires_in":"3599"}`)
			return
		}
		if r.Header.Get("Authorization") != "Bearer stor" || r.Header.Get("x-ms-version") == "" {
			w.WriteHeader(401)
			return
		}
		if r.URL.Query().Get("restype") == "container" {
			w.WriteHeader(409) // exists
			return
		}
		name := r.URL.Path
		switch r.Method {
		case "PUT":
			if r.Header.Get("x-ms-blob-type") != "BlockBlob" {
				w.WriteHeader(400)
				return
			}
			b, _ := io.ReadAll(r.Body)
			o.put(name, b)
			w.WriteHeader(201)
		case "GET":
			b, ok := o.get(name)
			if !ok {
				w.WriteHeader(404)
				return
			}
			w.Write(b)
		case "DELETE":
			if _, ok := o.get(name); !ok {
				w.WriteHeader(404)
				return
			}
			o.mu.Lock()
			delete(o.m, name)
			o.mu.Unlock()
			w.WriteHeader(202)
		}
	}))
	defer srv.Close()
	f := filepath.Join(t.TempDir(), "token")
	os.WriteFile(f, []byte("projected\n"), 0o600)
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", f)
	t.Setenv("AZURE_CLIENT_ID", "cid")
	t.Setenv("AZURE_TENANT_ID", "tid")
	t.Setenv("AZURE_AUTHORITY_HOST", srv.URL)
	s, err := Open("azblob://acct/state/acme?endpoint="+srv.URL, "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, s)
}

func TestS3WithIRSA(t *testing.T) {
	o := &objects{m: map[string][]byte{}}
	sts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" && r.Method == "POST" {
			r.ParseForm()
			if r.Form.Get("Action") != "AssumeRoleWithWebIdentity" || r.Form.Get("WebIdentityToken") != "irsa-token" || r.Form.Get("RoleArn") != "arn:aws:iam::1:role/t" {
				w.WriteHeader(403)
				return
			}
			sts++
			io.WriteString(w, `<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>ASIA1</AccessKeyId><SecretAccessKey>sk</SecretAccessKey><SessionToken>st</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`)
			return
		}
		if !strings.Contains(r.Header.Get("Authorization"), "Credential=ASIA1/") || r.Header.Get("x-amz-security-token") != "st" ||
			!strings.Contains(r.Header.Get("Authorization"), "x-amz-security-token") {
			w.WriteHeader(403)
			return
		}
		switch r.Method {
		case "HEAD":
		case "PUT":
			b, _ := io.ReadAll(r.Body)
			o.put(r.URL.Path, b)
		case "GET":
			b, ok := o.get(r.URL.Path)
			if !ok {
				w.WriteHeader(404)
				return
			}
			w.Write(b)
		case "DELETE":
			o.mu.Lock()
			delete(o.m, r.URL.Path)
			o.mu.Unlock()
			w.WriteHeader(204)
		}
	}))
	defer srv.Close()
	f := filepath.Join(t.TempDir(), "token")
	os.WriteFile(f, []byte("irsa-token"), 0o600)
	t.Setenv("AWS_ROLE_ARN", "arn:aws:iam::1:role/t")
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", f)
	s, err := Open("s3://bkt?endpoint="+srv.URL+"&region=eu-west-1&sts_endpoint="+srv.URL, "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, s)
	if sts != 1 {
		t.Fatalf("STS was called %d times, want once", sts)
	}
	// Without keys or IRSA the URL is refused.
	t.Setenv("AWS_ROLE_ARN", "")
	if _, err := Open("s3://bkt?region=eu-west-1", "", "", nil); err == nil {
		t.Fatal("an S3 bucket without credentials was accepted")
	}
}

func pathUnescape(s string) (string, error) { return url.PathUnescape(s) }

func TestReadCappedRefusesOversize(t *testing.T) {
	if _, err := readCapped(strings.NewReader(strings.Repeat("x", maxObject+1)), "big"); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("an oversized object was read: %v", err)
	}
	if b, err := readCapped(strings.NewReader("ok"), "small"); err != nil || string(b) != "ok" {
		t.Fatal(err)
	}
}
