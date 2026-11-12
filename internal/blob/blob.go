// Package blob stores large objects (state versions, saved plans, backups)
// in a tenant's own bucket: any S3-compatible store (AWS S3, MinIO, Ceph,
// GCS's XML API with HMAC keys), Google Cloud Storage, or Azure Blob
// Storage. Credentials are static keys or, with none given, the workload
// identity of the pod: EKS IRSA, GKE Workload Identity, Entra Workload ID.
// Small REST clients, no third-party dependencies.
package blob

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// ErrNotFound is returned for missing objects.
var ErrNotFound = errors.New("object not found")

const maxObject = 256 << 20

// Store is a bucket.
type Store interface {
	Put(ctx context.Context, key string, data []byte) error
	Get(ctx context.Context, key string) ([]byte, error)
	Delete(ctx context.Context, key string) error
	EnsureBucket(ctx context.Context) error
	String() string // for logs: kind, bucket and endpoint
}

type Config struct {
	Endpoint  string // e.g. https://s3.eu-west-1.amazonaws.com or https://minio.internal:9000
	Bucket    string
	Region    string
	AccessKey string
	SecretKey string
	Prefix    string // optional key prefix, e.g. "acme/"
	// WebIdentity: no keys; assume AWS_ROLE_ARN with AWS_WEB_IDENTITY_TOKEN_FILE (EKS IRSA).
	WebIdentity bool
	STSEndpoint string // tests; default https://sts.<region>.amazonaws.com
}

type S3 struct {
	cfg   Config
	hc    *http.Client
	now   func() time.Time
	creds *webIdentity
}

func (s *S3) String() string { return "s3 " + s.cfg.Bucket + " at " + s.cfg.Endpoint }

// ParseURL reads s3://bucket/prefix?endpoint=https://...&region=eu-west-1.
func ParseURL(raw, accessKey, secretKey string) (Config, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "s3" || u.Host == "" {
		return Config{}, errors.New("bucket URL must look like s3://bucket[/prefix]?endpoint=https://host&region=REGION")
	}
	q := u.Query()
	c := Config{Bucket: u.Host, Prefix: strings.Trim(u.Path, "/"), Region: q.Get("region"), Endpoint: strings.TrimRight(q.Get("endpoint"), "/"), AccessKey: accessKey, SecretKey: secretKey}
	if c.Region == "" {
		c.Region = "us-east-1"
	}
	if c.Endpoint == "" {
		c.Endpoint = "https://s3." + c.Region + ".amazonaws.com"
	}
	if c.Prefix != "" {
		c.Prefix += "/"
	}
	ep, err := url.Parse(c.Endpoint)
	if err != nil || ep.Host == "" || (ep.Scheme != "https" && !(ep.Scheme == "http" && isLoopback(ep.Hostname()))) {
		return Config{}, errors.New("bucket endpoint must be https (plain http only on loopback for development)")
	}
	if c.AccessKey == "" && c.SecretKey == "" && os.Getenv("AWS_ROLE_ARN") != "" && os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE") != "" {
		c.WebIdentity = true // EKS IRSA: the pod's role, no stored keys
		c.STSEndpoint = q.Get("sts_endpoint")
		return c, nil
	}
	if c.AccessKey == "" || c.SecretKey == "" {
		return Config{}, errors.New("bucket credentials are required (SRUSTIOPS_BUCKET_ACCESS_KEY[_FILE], SRUSTIOPS_BUCKET_SECRET_KEY[_FILE]), or the pod's IRSA role (AWS_ROLE_ARN, AWS_WEB_IDENTITY_TOKEN_FILE)")
	}
	return c, nil
}

func isLoopback(h string) bool { return h == "localhost" || h == "127.0.0.1" || h == "::1" }

func New(c Config, hc *http.Client) *S3 {
	if hc == nil {
		hc = &http.Client{Timeout: 2 * time.Minute}
	}
	s := &S3{cfg: c, hc: hc, now: time.Now}
	if c.WebIdentity {
		ep := c.STSEndpoint
		if ep == "" {
			ep = "https://sts." + c.Region + ".amazonaws.com"
		}
		s.creds = &webIdentity{hc: hc, endpoint: ep, role: os.Getenv("AWS_ROLE_ARN"), tokenFile: os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE"), now: time.Now}
	}
	return s
}

// Open makes the store a bucket URL names: s3://, gs:// or azblob://.
func Open(raw, accessKey, secretKey string, hc *http.Client) (Store, error) {
	switch {
	case strings.HasPrefix(raw, "gs://"):
		return openGCS(raw, hc)
	case strings.HasPrefix(raw, "azblob://"):
		return openAzure(raw, hc)
	}
	c, err := ParseURL(raw, accessKey, secretKey)
	if err != nil {
		return nil, err
	}
	return New(c, hc), nil
}

func (s *S3) Put(ctx context.Context, key string, data []byte) error {
	resp, err := s.do(ctx, http.MethodPut, s.cfg.Prefix+key, data)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (s *S3) Get(ctx context.Context, key string) ([]byte, error) {
	resp, err := s.do(ctx, http.MethodGet, s.cfg.Prefix+key, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return readCapped(resp.Body, key)
}

// ErrTooLarge: an object larger than this client reads (never a silently
// shortened one).
var ErrTooLarge = fmt.Errorf("object larger than %d MiB", maxObject>>20)

func readCapped(r io.Reader, key string) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxObject+1))
	if err == nil && len(b) > maxObject {
		return nil, fmt.Errorf("%s: %w", key, ErrTooLarge)
	}
	return b, err
}

func (s *S3) Delete(ctx context.Context, key string) error {
	resp, err := s.do(ctx, http.MethodDelete, s.cfg.Prefix+key, nil)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if resp != nil {
		resp.Body.Close()
	}
	return nil
}

// EnsureBucket creates the bucket if it does not exist (development setups).
func (s *S3) EnsureBucket(ctx context.Context) error {
	resp, err := s.do(ctx, http.MethodHead, "", nil)
	if err == nil {
		resp.Body.Close()
		return nil
	}
	if !errors.Is(err, ErrNotFound) {
		return err
	}
	resp, err = s.do(ctx, http.MethodPut, "", nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// do sends one request, retrying network errors, 5xx and 429 up to three
// times with backoff: every call here is idempotent (whole-object PUT, GET,
// DELETE, HEAD), and one hiccup in the object store must not fail a run.
func (s *S3) do(ctx context.Context, method, key string, body []byte) (*http.Response, error) {
	var err error
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(1<<(attempt-1)) * 250 * time.Millisecond):
			}
		}
		var resp *http.Response
		var retry bool
		resp, retry, err = s.once(ctx, method, key, body)
		if err == nil || !retry {
			return resp, err
		}
	}
	return nil, err
}

func (s *S3) once(ctx context.Context, method, key string, body []byte) (*http.Response, bool, error) {
	path := "/" + s.cfg.Bucket
	if key != "" {
		path += "/" + encodePath(key)
	}
	u := s.cfg.Endpoint + path
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
	if err != nil {
		return nil, false, err
	}
	sum := sha256.Sum256(body)
	payload := hex.EncodeToString(sum[:])
	ak, sk, tok := s.cfg.AccessKey, s.cfg.SecretKey, ""
	if s.creds != nil {
		c, err := s.creds.get(ctx)
		if err != nil {
			return nil, true, err
		}
		ak, sk, tok = c.AccessKey, c.SecretKey, c.Token
	}
	if tok != "" {
		req.Header.Set("x-amz-security-token", tok)
	}
	s.sign(req, path, payload, ak, sk, tok)
	resp, err := s.hc.Do(req)
	if err != nil {
		return nil, ctx.Err() == nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
		return nil, false, ErrNotFound
	}
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		retry := resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests
		return nil, retry, fmt.Errorf("object store %s %s: %s %s", method, key, resp.Status, strings.TrimSpace(string(msg)))
	}
	return resp, false, nil
}

// sign adds AWS Signature Version 4 headers.
func (s *S3) sign(req *http.Request, path, payload, accessKey, secretKey, token string) {
	t := s.now().UTC()
	amzDate := t.Format("20060102T150405Z")
	day := t.Format("20060102")
	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", payload)
	host := req.URL.Host

	headers := map[string]string{"host": host, "x-amz-content-sha256": payload, "x-amz-date": amzDate}
	if token != "" {
		headers["x-amz-security-token"] = token
	}
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)
	var canonHeaders strings.Builder
	for _, k := range names {
		canonHeaders.WriteString(k + ":" + headers[k] + "\n")
	}
	signed := strings.Join(names, ";")
	canonical := strings.Join([]string{req.Method, path, "", canonHeaders.String(), signed, payload}, "\n")
	scope := day + "/" + s.cfg.Region + "/s3/aws4_request"
	h := sha256.Sum256([]byte(canonical))
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(h[:])
	k := hmacSHA256([]byte("AWS4"+secretKey), day)
	k = hmacSHA256(k, s.cfg.Region)
	k = hmacSHA256(k, "s3")
	k = hmacSHA256(k, "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(k, toSign))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+accessKey+"/"+scope+", SignedHeaders="+signed+", Signature="+sig)
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

// encodePath URI-encodes each segment as SigV4 requires (RFC 3986 unreserved).
func encodePath(key string) string {
	segs := strings.Split(key, "/")
	for i, seg := range segs {
		var b strings.Builder
		for _, c := range []byte(seg) {
			if 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_' || c == '.' || c == '~' {
				b.WriteByte(c)
			} else {
				fmt.Fprintf(&b, "%%%02X", c)
			}
		}
		segs[i] = b.String()
	}
	return strings.Join(segs, "/")
}
