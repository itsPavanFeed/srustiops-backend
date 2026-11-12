// Package forge speaks to the Git host holding a tenant's contracts
// repository — GitHub, GitLab, Bitbucket Cloud or Azure DevOps — for the
// pull-request workflow: plans before merge, commit statuses and a comment
// per pull request, merging once applied, and proposing changes as branches
// with pull requests. Every call is made by the tenant plane (pull-based):
// nothing on the Git side needs to reach the tenant.
package forge

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"time"
)

// PR is a pull request (merge request) as the platform uses it.
type PR struct {
	Number     int    `json:"number"`
	Title      string `json:"title"`
	Author     string `json:"author"`
	URL        string `json:"url"`
	State      string `json:"state"` // open | closed | merged
	Draft      bool   `json:"draft"`
	HeadSHA    string `json:"head_sha"`
	HeadBranch string `json:"head_branch"`
	BaseBranch string `json:"base_branch"`
	Fork       bool   `json:"fork"` // the head is in another repository
}

// Forge is one repository on one Git host.
type Forge interface {
	Provider() string // github | gitlab | bitbucket | azure
	GetPR(ctx context.Context, n int) (*PR, error)
	// OpenPRs lists open pull requests into base (for hosts polled rather than hooked).
	OpenPRs(ctx context.Context, base string) ([]PR, error)
	// SetStatus reports state (pending | success | failure) on a pull
	// request's head commit, under the name.
	SetStatus(ctx context.Context, pr int, sha, state, name, description, target string) error
	// Comment posts a comment on a pull request, or edits commentID when it
	// is set (posting a new one if it was deleted). It returns the comment's ID.
	Comment(ctx context.Context, pr int, commentID int64, body string) (int64, error)
	// Merge squash-merges a pull request only if its head is still sha, and
	// returns the commit it made.
	Merge(ctx context.Context, pr int, sha, title, message string) (string, error)
	BranchSHA(ctx context.Context, branch string) (string, error)
	CreateBranch(ctx context.Context, branch, sha string) error
	// ListDir names the files directly in dir on a branch (none if it is missing).
	ListDir(ctx context.Context, dir, branch string) ([]string, error)
	// Commit writes files (nil content deletes) on a branch in one commit
	// where the host allows it, and returns the branch's new head.
	Commit(ctx context.Context, branch, message string, changes map[string]*[]byte) (string, error)
	OpenPR(ctx context.Context, head, base, title, body string) (*PR, error)
	// Files is a snapshot of the repository at a commit (path -> content).
	Files(ctx context.Context, rev string) (map[string][]byte, error)
}

// APIError is a non-success answer from a host.
type APIError struct {
	Host    string
	Status  int
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("%s returned %d: %s", e.Host, e.Status, e.Message)
}

// NotFound reports whether err is a 404 from the host.
func NotFound(err error) bool {
	var e *APIError
	return errors.As(err, &e) && e.Status == http.StatusNotFound
}

// client is the HTTP plumbing shared by the hosts.
type client struct {
	host string // for messages: "GitLab"
	hc   *http.Client
	auth func(*http.Request)
}

func newClient(host string, hc *http.Client, auth func(*http.Request)) client {
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second}
	}
	return client{host: host, hc: hc, auth: auth}
}

// do sends a request with a JSON body (or raw bytes with contentType) and decodes JSON into out.
func (c client) do(ctx context.Context, method, u string, body any, out any) error {
	var rd io.Reader
	ct := ""
	switch b := body.(type) {
	case nil:
	case rawBody:
		rd, ct = bytes.NewReader(b.data), b.contentType
	default:
		j, err := json.Marshal(b)
		if err != nil {
			return err
		}
		rd, ct = bytes.NewReader(j), "application/json"
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "SrustiOps")
	if c.auth != nil {
		c.auth(req)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		msg := strings.TrimSpace(string(b))
		var m struct {
			Message any    `json:"message"`
			Error   any    `json:"error"`
			ErrMsg  string `json:"errorMessage"`
		}
		if json.Unmarshal(b, &m) == nil {
			switch {
			case m.Message != nil:
				msg = fmt.Sprint(m.Message)
			case m.Error != nil:
				msg = fmt.Sprint(m.Error)
			case m.ErrMsg != "":
				msg = m.ErrMsg
			}
		}
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return &APIError{Host: c.host, Status: resp.StatusCode, Message: msg}
	}
	if out == nil {
		return nil
	}
	if w, ok := out.(*[]byte); ok {
		*w, err = io.ReadAll(io.LimitReader(resp.Body, maxArchive+1))
		if len(*w) > maxArchive {
			return errors.New("the repository snapshot is too large")
		}
		return err
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(out)
}

type rawBody struct {
	data        []byte
	contentType string
}

const (
	maxArchive   = 50 << 20
	maxFiles     = 2000
	maxFileBytes = 1 << 20
)

// untarGz reads a .tar.gz snapshot whose entries sit under one top folder.
func untarGz(b []byte) (map[string][]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(zr)
	out := map[string][]byte{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		name := stripTop(h.Name)
		if name == "" {
			continue
		}
		if h.Size > maxFileBytes || len(out) >= maxFiles {
			return nil, errors.New("the repository has too many or too large files")
		}
		data, err := io.ReadAll(io.LimitReader(tr, maxFileBytes))
		if err != nil {
			return nil, err
		}
		out[name] = data
	}
}

// unzipAll reads a zip snapshot (Azure DevOps). top strips the leading folder when true.
func unzipAll(b []byte, top bool) (map[string][]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		name := strings.TrimPrefix(path.Clean("/"+f.Name), "/")
		if top {
			name = stripTop(name)
		}
		if name == "" || strings.Contains(name, "..") {
			continue
		}
		if f.UncompressedSize64 > maxFileBytes || len(out) >= maxFiles {
			return nil, errors.New("the repository has too many or too large files")
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(io.LimitReader(rc, maxFileBytes))
		rc.Close()
		if err != nil {
			return nil, err
		}
		out[name] = data
	}
	return out, nil
}

func stripTop(name string) string {
	name = strings.TrimPrefix(path.Clean("/"+name), "/")
	if i := strings.IndexByte(name, '/'); i >= 0 {
		return name[i+1:]
	}
	return ""
}

func trimDesc(s string, n int) string {
	if len(s) > n {
		return s[:n-1] + "…"
	}
	return s
}
