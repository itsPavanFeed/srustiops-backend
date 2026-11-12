package blob

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// retry runs one idempotent request up to four times (network errors, 5xx, 429).
func retry(ctx context.Context, hc *http.Client, what string, mk func() (*http.Request, error)) (*http.Response, error) {
	var err error
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(1<<(attempt-1)) * 250 * time.Millisecond):
			}
		}
		var req *http.Request
		if req, err = mk(); err != nil {
			continue // token fetches can fail transiently
		}
		var resp *http.Response
		resp, err = hc.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, err
			}
			continue
		}
		if resp.StatusCode == http.StatusNotFound {
			resp.Body.Close()
			return nil, ErrNotFound
		}
		if resp.StatusCode/100 == 2 {
			return resp, nil
		}
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		err = fmt.Errorf("object store %s: %s %s", what, resp.Status, strings.TrimSpace(string(msg)))
		if resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
			return nil, &statusErr{code: resp.StatusCode, err: err}
		}
	}
	return nil, err
}

type statusErr struct {
	code int
	err  error
}

func (e *statusErr) Error() string { return e.err.Error() }

func readAll(resp *http.Response, err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return readCapped(resp.Body, resp.Request.URL.Path)
}

func discard(resp *http.Response, err error) error {
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func splitBucket(raw, scheme string) (host, rest string, q url.Values, err error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != scheme || u.Host == "" {
		return "", "", nil, fmt.Errorf("bucket URL must look like %s://...", scheme)
	}
	return u.Host, strings.Trim(u.Path, "/"), u.Query(), nil
}

// ---- Google Cloud Storage (JSON API) ----

type GCS struct {
	hc       *http.Client
	endpoint string
	bucket   string
	prefix   string
	tok      *bearer
}

// openGCS reads gs://bucket[/prefix]; credentials are the pod's GKE
// Workload Identity (the metadata server).
func openGCS(raw string, hc *http.Client) (*GCS, error) {
	b, prefix, q, err := splitBucket(raw, "gs")
	if err != nil {
		return nil, err
	}
	if hc == nil {
		hc = &http.Client{Timeout: 2 * time.Minute}
	}
	g := &GCS{hc: hc, endpoint: strings.TrimRight(q.Get("endpoint"), "/"), bucket: b, tok: gkeToken(hc)}
	if g.endpoint == "" {
		g.endpoint = "https://storage.googleapis.com"
	}
	if prefix != "" {
		g.prefix = prefix + "/"
	}
	return g, nil
}

func (g *GCS) String() string { return "gcs " + g.bucket }

func (g *GCS) req(ctx context.Context, method, u string, body []byte) func() (*http.Request, error) {
	return func() (*http.Request, error) {
		t, err := g.tok.get(ctx)
		if err != nil {
			return nil, err
		}
		r, _ := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+t)
		if body != nil {
			r.Header.Set("Content-Type", "application/octet-stream")
		}
		return r, nil
	}
}

func (g *GCS) obj(key string) string {
	return g.endpoint + "/storage/v1/b/" + url.PathEscape(g.bucket) + "/o/" + url.PathEscape(g.prefix+key)
}

func (g *GCS) Put(ctx context.Context, key string, data []byte) error {
	u := g.endpoint + "/upload/storage/v1/b/" + url.PathEscape(g.bucket) + "/o?uploadType=media&name=" + url.QueryEscape(g.prefix+key)
	return discard(retry(ctx, g.hc, "PUT "+key, g.req(ctx, http.MethodPost, u, data)))
}

func (g *GCS) Get(ctx context.Context, key string) ([]byte, error) {
	return readAll(retry(ctx, g.hc, "GET "+key, g.req(ctx, http.MethodGet, g.obj(key)+"?alt=media", nil)))
}

func (g *GCS) Delete(ctx context.Context, key string) error {
	err := discard(retry(ctx, g.hc, "DELETE "+key, g.req(ctx, http.MethodDelete, g.obj(key), nil)))
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}

// EnsureBucket checks the bucket exists; buckets are made by the landing.
func (g *GCS) EnsureBucket(ctx context.Context) error {
	err := discard(retry(ctx, g.hc, "bucket", g.req(ctx, http.MethodGet, g.endpoint+"/storage/v1/b/"+url.PathEscape(g.bucket), nil)))
	if errors.Is(err, ErrNotFound) {
		return fmt.Errorf("bucket %s does not exist", g.bucket)
	}
	return err
}

// ---- Azure Blob Storage ----

type AzureBlob struct {
	hc        *http.Client
	endpoint  string // https://<account>.blob.core.windows.net
	container string
	prefix    string
	tok       *bearer
}

// openAzure reads azblob://account/container[/prefix]; credentials are the
// pod's Entra Workload ID.
func openAzure(raw string, hc *http.Client) (*AzureBlob, error) {
	account, rest, q, err := splitBucket(raw, "azblob")
	if err != nil {
		return nil, err
	}
	container, prefix, _ := strings.Cut(rest, "/")
	if container == "" {
		return nil, errors.New("bucket URL must look like azblob://account/container[/prefix]")
	}
	if hc == nil {
		hc = &http.Client{Timeout: 2 * time.Minute}
	}
	tok, err := entraToken(hc, "https://storage.azure.com/.default")
	if err != nil {
		return nil, err
	}
	a := &AzureBlob{hc: hc, endpoint: strings.TrimRight(q.Get("endpoint"), "/"), container: container, tok: tok}
	if a.endpoint == "" {
		a.endpoint = "https://" + account + ".blob.core.windows.net"
	}
	if prefix != "" {
		a.prefix = strings.Trim(prefix, "/") + "/"
	}
	return a, nil
}

func (a *AzureBlob) String() string { return "azure blob " + a.container + " at " + a.endpoint }

func (a *AzureBlob) req(ctx context.Context, method, u string, body []byte, hdr map[string]string) func() (*http.Request, error) {
	return func() (*http.Request, error) {
		t, err := a.tok.get(ctx)
		if err != nil {
			return nil, err
		}
		r, _ := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+t)
		r.Header.Set("x-ms-version", "2023-11-03")
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		return r, nil
	}
}

func (a *AzureBlob) blob(key string) string {
	return a.endpoint + "/" + url.PathEscape(a.container) + "/" + encodePath(a.prefix+key)
}

func (a *AzureBlob) Put(ctx context.Context, key string, data []byte) error {
	return discard(retry(ctx, a.hc, "PUT "+key, a.req(ctx, http.MethodPut, a.blob(key), data, map[string]string{"x-ms-blob-type": "BlockBlob", "Content-Type": "application/octet-stream"})))
}

func (a *AzureBlob) Get(ctx context.Context, key string) ([]byte, error) {
	return readAll(retry(ctx, a.hc, "GET "+key, a.req(ctx, http.MethodGet, a.blob(key), nil, nil)))
}

func (a *AzureBlob) Delete(ctx context.Context, key string) error {
	err := discard(retry(ctx, a.hc, "DELETE "+key, a.req(ctx, http.MethodDelete, a.blob(key), nil, nil)))
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}

// EnsureBucket creates the container when it is missing (409: it exists).
func (a *AzureBlob) EnsureBucket(ctx context.Context) error {
	err := discard(retry(ctx, a.hc, "container", a.req(ctx, http.MethodPut, a.endpoint+"/"+url.PathEscape(a.container)+"?restype=container", nil, nil)))
	var se *statusErr
	if errors.As(err, &se) && se.code == http.StatusConflict {
		return nil
	}
	return err
}
