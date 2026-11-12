package forge

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
)

// GitLab is a project on gitlab.com or a self-managed GitLab (REST API v4),
// reached with a project or personal access token (scope api).
type GitLab struct {
	c       client
	api     string // https://gitlab.com/api/v4
	project string // group/project
}

func NewGitLab(api, project, token string, hc *http.Client) *GitLab {
	if api == "" {
		api = "https://gitlab.com/api/v4"
	}
	return &GitLab{c: newClient("GitLab", hc, func(r *http.Request) { r.Header.Set("PRIVATE-TOKEN", token) }), api: strings.TrimRight(api, "/"), project: project}
}

func (g *GitLab) Provider() string { return "gitlab" }

func (g *GitLab) p() string { return g.api + "/projects/" + url.PathEscape(g.project) }

type glMR struct {
	IID             int    `json:"iid"`
	Title           string `json:"title"`
	State           string `json:"state"` // opened | closed | merged | locked
	Draft           bool   `json:"draft"`
	WorkInProgress  bool   `json:"work_in_progress"`
	WebURL          string `json:"web_url"`
	SHA             string `json:"sha"`
	SourceBranch    string `json:"source_branch"`
	TargetBranch    string `json:"target_branch"`
	SourceProjectID int    `json:"source_project_id"`
	TargetProjectID int    `json:"target_project_id"`
	MergeCommitSHA  string `json:"merge_commit_sha"`
	SquashCommitSHA string `json:"squash_commit_sha"`
	Author          struct {
		Username string `json:"username"`
	} `json:"author"`
}

func (m *glMR) pr() *PR {
	state := map[string]string{"opened": "open", "merged": "merged"}[m.State]
	if state == "" {
		state = "closed"
	}
	return &PR{Number: m.IID, Title: m.Title, Author: m.Author.Username, URL: m.WebURL, State: state, Draft: m.Draft || m.WorkInProgress,
		HeadSHA: m.SHA, HeadBranch: m.SourceBranch, BaseBranch: m.TargetBranch, Fork: m.SourceProjectID != m.TargetProjectID}
}

func (g *GitLab) GetPR(ctx context.Context, n int) (*PR, error) {
	var m glMR
	if err := g.c.do(ctx, http.MethodGet, g.p()+"/merge_requests/"+strconv.Itoa(n), nil, &m); err != nil {
		return nil, err
	}
	return m.pr(), nil
}

func (g *GitLab) OpenPRs(ctx context.Context, base string) ([]PR, error) {
	var ms []glMR
	if err := g.c.do(ctx, http.MethodGet, g.p()+"/merge_requests?state=opened&per_page=100&target_branch="+url.QueryEscape(base), nil, &ms); err != nil {
		return nil, err
	}
	out := make([]PR, 0, len(ms))
	for i := range ms {
		out = append(out, *ms[i].pr())
	}
	return out, nil
}

func (g *GitLab) SetStatus(ctx context.Context, pr int, sha, state, name, desc, target string) error {
	st := map[string]string{"pending": "pending", "success": "success", "failure": "failed", "error": "failed"}[state]
	q := url.Values{"state": {st}, "name": {name}, "description": {trimDesc(desc, 255)}}
	if target != "" {
		q.Set("target_url", target)
	}
	err := g.c.do(ctx, http.MethodPost, g.p()+"/statuses/"+url.PathEscape(sha)+"?"+q.Encode(), nil, nil)
	// GitLab refuses a status equal to the current one: that is not a failure.
	if e, ok := err.(*APIError); ok && e.Status == http.StatusBadRequest && strings.Contains(e.Message, "transition") {
		return nil
	}
	return err
}

func (g *GitLab) Comment(ctx context.Context, pr int, id int64, body string) (int64, error) {
	var out struct {
		ID int64 `json:"id"`
	}
	base := g.p() + "/merge_requests/" + strconv.Itoa(pr) + "/notes"
	if id != 0 {
		err := g.c.do(ctx, http.MethodPut, base+"/"+strconv.FormatInt(id, 10), map[string]string{"body": body}, &out)
		if !NotFound(err) {
			return id, err
		}
	}
	err := g.c.do(ctx, http.MethodPost, base, map[string]string{"body": body}, &out)
	return out.ID, err
}

func (g *GitLab) Merge(ctx context.Context, pr int, sha, title, msg string) (string, error) {
	var m glMR
	err := g.c.do(ctx, http.MethodPut, g.p()+"/merge_requests/"+strconv.Itoa(pr)+"/merge",
		map[string]any{"sha": sha, "squash": true, "squash_commit_message": title + "\n\n" + msg, "should_remove_source_branch": false}, &m)
	if err != nil {
		return "", err
	}
	if m.SquashCommitSHA != "" {
		return m.SquashCommitSHA, nil
	}
	return m.MergeCommitSHA, nil
}

func (g *GitLab) BranchSHA(ctx context.Context, branch string) (string, error) {
	var b struct {
		Commit struct {
			ID string `json:"id"`
		} `json:"commit"`
	}
	err := g.c.do(ctx, http.MethodGet, g.p()+"/repository/branches/"+url.PathEscape(branch), nil, &b)
	return b.Commit.ID, err
}

func (g *GitLab) CreateBranch(ctx context.Context, branch, sha string) error {
	return g.c.do(ctx, http.MethodPost, g.p()+"/repository/branches?branch="+url.QueryEscape(branch)+"&ref="+url.QueryEscape(sha), nil, nil)
}

func (g *GitLab) ListDir(ctx context.Context, dir, branch string) ([]string, error) {
	var items []struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	err := g.c.do(ctx, http.MethodGet, g.p()+"/repository/tree?per_page=100&path="+url.QueryEscape(dir)+"&ref="+url.QueryEscape(branch), nil, &items)
	if NotFound(err) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, it := range items {
		if it.Type == "blob" {
			out = append(out, it.Name)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (g *GitLab) exists(ctx context.Context, p, branch string) (bool, error) {
	err := g.c.do(ctx, http.MethodGet, g.p()+"/repository/files/"+url.PathEscape(p)+"?ref="+url.QueryEscape(branch), nil, nil)
	if NotFound(err) {
		return false, nil
	}
	return err == nil, err
}

// Commit makes one commit with every change (the commits API).
func (g *GitLab) Commit(ctx context.Context, branch, msg string, changes map[string]*[]byte) (string, error) {
	paths := make([]string, 0, len(changes))
	for p := range changes {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	actions := []map[string]string{}
	for _, p := range paths {
		ok, err := g.exists(ctx, p, branch)
		if err != nil {
			return "", err
		}
		switch {
		case changes[p] == nil && !ok:
			continue
		case changes[p] == nil:
			actions = append(actions, map[string]string{"action": "delete", "file_path": p})
		default:
			a := "create"
			if ok {
				a = "update"
			}
			actions = append(actions, map[string]string{"action": a, "file_path": p, "encoding": "base64", "content": base64.StdEncoding.EncodeToString(*changes[p])})
		}
	}
	if len(actions) == 0 {
		return g.BranchSHA(ctx, branch)
	}
	var out struct {
		ID string `json:"id"`
	}
	err := g.c.do(ctx, http.MethodPost, g.p()+"/repository/commits", map[string]any{"branch": branch, "commit_message": msg, "actions": actions}, &out)
	return out.ID, err
}

func (g *GitLab) OpenPR(ctx context.Context, head, base, title, body string) (*PR, error) {
	var m glMR
	if err := g.c.do(ctx, http.MethodPost, g.p()+"/merge_requests", map[string]any{"source_branch": head, "target_branch": base, "title": title, "description": body}, &m); err != nil {
		return nil, err
	}
	return m.pr(), nil
}

func (g *GitLab) Files(ctx context.Context, rev string) (map[string][]byte, error) {
	var b []byte
	if err := g.c.do(ctx, http.MethodGet, g.p()+"/repository/archive.tar.gz?sha="+url.QueryEscape(rev), nil, &b); err != nil {
		return nil, err
	}
	return untarGz(b)
}

var _ = path.Join
