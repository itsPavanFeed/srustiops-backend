package forge

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// Bitbucket is a repository on Bitbucket Cloud (REST API 2.0), reached with
// a repository or workspace access token (Bearer) — or, written as
// "user:app-password", an app password.
type Bitbucket struct {
	c    client
	api  string // https://api.bitbucket.org/2.0
	web  string // https://bitbucket.org
	repo string // workspace/repo
}

func NewBitbucket(api, repo, token string, hc *http.Client) *Bitbucket {
	if api == "" {
		api = "https://api.bitbucket.org/2.0"
	}
	api = strings.TrimRight(api, "/")
	web := "https://bitbucket.org"
	if !strings.Contains(api, "api.bitbucket.org") {
		web = strings.TrimSuffix(api, "/2.0") // a test double serves both
	}
	auth := func(r *http.Request) {
		if u, p, ok := strings.Cut(token, ":"); ok && !strings.Contains(u, "/") {
			r.SetBasicAuth(u, p)
		} else {
			r.Header.Set("Authorization", "Bearer "+token)
		}
	}
	return &Bitbucket{c: newClient("Bitbucket", hc, auth), api: api, web: web, repo: repo}
}

func (b *Bitbucket) Provider() string { return "bitbucket" }

func (b *Bitbucket) r() string { return b.api + "/repositories/" + b.repo }

type bbPR struct {
	ID     int    `json:"id"`
	Title  string `json:"title"`
	State  string `json:"state"` // OPEN | MERGED | DECLINED | SUPERSEDED
	Draft  bool   `json:"draft"`
	Author struct {
		Nickname    string `json:"nickname"`
		DisplayName string `json:"display_name"`
	} `json:"author"`
	Source struct {
		Branch struct {
			Name string `json:"name"`
		} `json:"branch"`
		Commit struct {
			Hash string `json:"hash"`
		} `json:"commit"`
		Repository struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
	} `json:"source"`
	Destination struct {
		Branch struct {
			Name string `json:"name"`
		} `json:"branch"`
		Repository struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
	} `json:"destination"`
	MergeCommit *struct {
		Hash string `json:"hash"`
	} `json:"merge_commit"`
	Links struct {
		HTML struct {
			Href string `json:"href"`
		} `json:"html"`
	} `json:"links"`
}

func (p *bbPR) pr(repo string) *PR {
	state := map[string]string{"OPEN": "open", "MERGED": "merged"}[p.State]
	if state == "" {
		state = "closed"
	}
	author := p.Author.Nickname
	if author == "" {
		author = p.Author.DisplayName
	}
	return &PR{Number: p.ID, Title: p.Title, Author: author, URL: p.Links.HTML.Href, State: state, Draft: p.Draft, HeadSHA: p.Source.Commit.Hash,
		HeadBranch: p.Source.Branch.Name, BaseBranch: p.Destination.Branch.Name,
		Fork: p.Source.Repository.FullName != "" && !strings.EqualFold(p.Source.Repository.FullName, repo)}
}

func (b *Bitbucket) GetPR(ctx context.Context, n int) (*PR, error) {
	var p bbPR
	if err := b.c.do(ctx, http.MethodGet, b.r()+"/pullrequests/"+strconv.Itoa(n), nil, &p); err != nil {
		return nil, err
	}
	// Bitbucket gives a short head hash: resolve it to the full commit.
	if len(p.Source.Commit.Hash) < 40 && p.Source.Commit.Hash != "" {
		var c struct {
			Hash string `json:"hash"`
		}
		if err := b.c.do(ctx, http.MethodGet, b.r()+"/commit/"+url.PathEscape(p.Source.Commit.Hash), nil, &c); err == nil && c.Hash != "" {
			p.Source.Commit.Hash = c.Hash
		}
	}
	return p.pr(b.repo), nil
}

func (b *Bitbucket) OpenPRs(ctx context.Context, base string) ([]PR, error) {
	var page struct {
		Values []bbPR `json:"values"`
	}
	q := url.Values{"state": {"OPEN"}, "pagelen": {"50"}, "q": {`destination.branch.name="` + base + `"`}}
	if err := b.c.do(ctx, http.MethodGet, b.r()+"/pullrequests?"+q.Encode(), nil, &page); err != nil {
		return nil, err
	}
	out := make([]PR, 0, len(page.Values))
	for i := range page.Values {
		if page.Values[i].Destination.Branch.Name == base {
			pr, err := b.GetPR(ctx, page.Values[i].ID) // the full head commit
			if err != nil {
				return nil, err
			}
			out = append(out, *pr)
		}
	}
	return out, nil
}

func (b *Bitbucket) SetStatus(ctx context.Context, pr int, sha, state, name, desc, target string) error {
	st := map[string]string{"pending": "INPROGRESS", "success": "SUCCESSFUL", "failure": "FAILED", "error": "FAILED"}[state]
	if target == "" {
		target = b.web + "/" + b.repo // Bitbucket requires a URL
	}
	return b.c.do(ctx, http.MethodPost, b.r()+"/commit/"+url.PathEscape(sha)+"/statuses/build",
		map[string]string{"key": name, "name": name, "state": st, "description": trimDesc(desc, 255), "url": target}, nil)
}

func (b *Bitbucket) Comment(ctx context.Context, pr int, id int64, body string) (int64, error) {
	var out struct {
		ID int64 `json:"id"`
	}
	base := b.r() + "/pullrequests/" + strconv.Itoa(pr) + "/comments"
	msg := map[string]any{"content": map[string]string{"raw": body}}
	if id != 0 {
		err := b.c.do(ctx, http.MethodPut, base+"/"+strconv.FormatInt(id, 10), msg, &out)
		if !NotFound(err) {
			return id, err
		}
	}
	err := b.c.do(ctx, http.MethodPost, base, msg, &out)
	return out.ID, err
}

// Merge checks the head is still sha (Bitbucket's merge cannot), then squashes.
func (b *Bitbucket) Merge(ctx context.Context, pr int, sha, title, msg string) (string, error) {
	cur, err := b.GetPR(ctx, pr)
	if err != nil {
		return "", err
	}
	if cur.HeadSHA != sha {
		return "", &APIError{Host: "Bitbucket", Status: http.StatusConflict, Message: "the pull request has new commits since it was applied"}
	}
	var p bbPR
	if err := b.c.do(ctx, http.MethodPost, b.r()+"/pullrequests/"+strconv.Itoa(pr)+"/merge",
		map[string]any{"type": "pullrequest", "merge_strategy": "squash", "message": title + "\n\n" + msg, "close_source_branch": false}, &p); err != nil {
		return "", err
	}
	if p.MergeCommit != nil {
		return p.MergeCommit.Hash, nil
	}
	return "", nil
}

func (b *Bitbucket) BranchSHA(ctx context.Context, branch string) (string, error) {
	var out struct {
		Target struct {
			Hash string `json:"hash"`
		} `json:"target"`
	}
	err := b.c.do(ctx, http.MethodGet, b.r()+"/refs/branches/"+url.PathEscape(branch), nil, &out)
	return out.Target.Hash, err
}

func (b *Bitbucket) CreateBranch(ctx context.Context, branch, sha string) error {
	return b.c.do(ctx, http.MethodPost, b.r()+"/refs/branches", map[string]any{"name": branch, "target": map[string]string{"hash": sha}}, nil)
}

func (b *Bitbucket) ListDir(ctx context.Context, dir, branch string) ([]string, error) {
	var page struct {
		Values []struct {
			Type string `json:"type"`
			Path string `json:"path"`
		} `json:"values"`
	}
	u := b.r() + "/src/" + url.PathEscape(branch) + "/"
	if d := escapeAll(dir); d != "" {
		u += d + "/"
	}
	err := b.c.do(ctx, http.MethodGet, u+"?pagelen=100", nil, &page)
	if NotFound(err) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, v := range page.Values {
		if v.Type == "commit_file" {
			out = append(out, v.Path[strings.LastIndexByte(v.Path, '/')+1:])
		}
	}
	sort.Strings(out)
	return out, nil
}

// Commit makes one commit with every change (the src endpoint, multipart).
func (b *Bitbucket) Commit(ctx context.Context, branch, msg string, changes map[string]*[]byte) (string, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mw.WriteField("message", msg)
	mw.WriteField("branch", branch)
	paths := make([]string, 0, len(changes))
	for p := range changes {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		if changes[p] == nil {
			mw.WriteField("files", p)
			continue
		}
		fw, _ := mw.CreateFormFile(p, p[strings.LastIndexByte(p, '/')+1:])
		fw.Write(*changes[p])
	}
	mw.Close()
	if err := b.c.do(ctx, http.MethodPost, b.r()+"/src", rawBody{buf.Bytes(), mw.FormDataContentType()}, nil); err != nil {
		return "", err
	}
	return b.BranchSHA(ctx, branch)
}

func (b *Bitbucket) OpenPR(ctx context.Context, head, base, title, body string) (*PR, error) {
	var p bbPR
	err := b.c.do(ctx, http.MethodPost, b.r()+"/pullrequests", map[string]any{"title": title, "description": body,
		"source": map[string]any{"branch": map[string]string{"name": head}}, "destination": map[string]any{"branch": map[string]string{"name": base}}}, &p)
	if err != nil {
		return nil, err
	}
	return p.pr(b.repo), nil
}

// Files downloads the snapshot Bitbucket serves for a commit.
func (b *Bitbucket) Files(ctx context.Context, rev string) (map[string][]byte, error) {
	var data []byte
	if err := b.c.do(ctx, http.MethodGet, b.web+"/"+b.repo+"/get/"+url.PathEscape(rev)+".tar.gz", nil, &data); err != nil {
		return nil, err
	}
	return untarGz(data)
}

func escapeAll(p string) string {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return strings.Join(parts, "/")
}
