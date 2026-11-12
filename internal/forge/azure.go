package forge

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// Azure is a repository in Azure DevOps Services (REST API 7.1), reached
// with a personal access token (Code: read & write; Code status).
type Azure struct {
	c       client
	api     string // https://dev.azure.com
	org     string
	project string
	repo    string
}

// NewAzure takes the repository as organization/project/repository.
func NewAzure(api, repo, token string, hc *http.Client) *Azure {
	if api == "" {
		api = "https://dev.azure.com"
	}
	parts := strings.SplitN(repo, "/", 3)
	for len(parts) < 3 {
		parts = append(parts, "")
	}
	return &Azure{c: newClient("Azure DevOps", hc, func(r *http.Request) { r.SetBasicAuth("", token) }),
		api: strings.TrimRight(api, "/"), org: parts[0], project: parts[1], repo: parts[2]}
}

func (a *Azure) Provider() string { return "azure" }

func (a *Azure) r(p string, q url.Values) string {
	if q == nil {
		q = url.Values{}
	}
	q.Set("api-version", "7.1")
	return a.api + "/" + url.PathEscape(a.org) + "/" + url.PathEscape(a.project) + "/_apis/git/repositories/" + url.PathEscape(a.repo) + p + "?" + q.Encode()
}

const azRefs = "refs/heads/"

type azPR struct {
	ID                    int    `json:"pullRequestId"`
	Title                 string `json:"title"`
	Status                string `json:"status"` // active | completed | abandoned
	IsDraft               bool   `json:"isDraft"`
	SourceRefName         string `json:"sourceRefName"`
	TargetRefName         string `json:"targetRefName"`
	LastMergeSourceCommit struct {
		CommitID string `json:"commitId"`
	} `json:"lastMergeSourceCommit"`
	LastMergeCommit *struct {
		CommitID string `json:"commitId"`
	} `json:"lastMergeCommit"`
	CreatedBy struct {
		UniqueName  string `json:"uniqueName"`
		DisplayName string `json:"displayName"`
	} `json:"createdBy"`
	ForkSource *struct{} `json:"forkSource"`
}

func (a *Azure) pr(p *azPR) *PR {
	state := map[string]string{"active": "open", "completed": "merged"}[p.Status]
	if state == "" {
		state = "closed"
	}
	author := p.CreatedBy.UniqueName
	if author == "" {
		author = p.CreatedBy.DisplayName
	}
	return &PR{Number: p.ID, Title: p.Title, Author: author, State: state, Draft: p.IsDraft, HeadSHA: p.LastMergeSourceCommit.CommitID,
		HeadBranch: strings.TrimPrefix(p.SourceRefName, azRefs), BaseBranch: strings.TrimPrefix(p.TargetRefName, azRefs), Fork: p.ForkSource != nil,
		URL: a.api + "/" + url.PathEscape(a.org) + "/" + url.PathEscape(a.project) + "/_git/" + url.PathEscape(a.repo) + "/pullrequest/" + strconv.Itoa(p.ID)}
}

func (a *Azure) GetPR(ctx context.Context, n int) (*PR, error) {
	var p azPR
	if err := a.c.do(ctx, http.MethodGet, a.r("/pullrequests/"+strconv.Itoa(n), nil), nil, &p); err != nil {
		return nil, err
	}
	return a.pr(&p), nil
}

func (a *Azure) OpenPRs(ctx context.Context, base string) ([]PR, error) {
	var out struct {
		Value []azPR `json:"value"`
	}
	q := url.Values{"searchCriteria.status": {"active"}, "searchCriteria.targetRefName": {azRefs + base}, "$top": {"100"}}
	if err := a.c.do(ctx, http.MethodGet, a.r("/pullrequests", q), nil, &out); err != nil {
		return nil, err
	}
	prs := make([]PR, 0, len(out.Value))
	for i := range out.Value {
		prs = append(prs, *a.pr(&out.Value[i]))
	}
	return prs, nil
}

// SetStatus posts a pull-request status (Azure DevOps shows these on the PR
// and branch policies can require them).
func (a *Azure) SetStatus(ctx context.Context, pr int, sha, state, name, desc, target string) error {
	st := map[string]string{"pending": "pending", "success": "succeeded", "failure": "failed", "error": "error"}[state]
	body := map[string]any{"state": st, "description": trimDesc(desc, 255), "context": map[string]string{"name": name, "genre": "srustiops"}}
	if target != "" {
		body["targetUrl"] = target
	}
	return a.c.do(ctx, http.MethodPost, a.r("/pullRequests/"+strconv.Itoa(pr)+"/statuses", nil), body, nil)
}

// Comment keeps one thread per pull request; editing updates its first comment.
func (a *Azure) Comment(ctx context.Context, pr int, id int64, body string) (int64, error) {
	if id != 0 {
		err := a.c.do(ctx, http.MethodPatch, a.r("/pullRequests/"+strconv.Itoa(pr)+"/threads/"+strconv.FormatInt(id, 10)+"/comments/1", nil), map[string]string{"content": body}, nil)
		if !NotFound(err) {
			return id, err
		}
	}
	var out struct {
		ID int64 `json:"id"`
	}
	err := a.c.do(ctx, http.MethodPost, a.r("/pullRequests/"+strconv.Itoa(pr)+"/threads", nil),
		map[string]any{"status": "active", "comments": []map[string]any{{"parentCommentId": 0, "content": body, "commentType": "text"}}}, &out)
	return out.ID, err
}

// Merge completes the pull request squashed, only from the commit sha.
func (a *Azure) Merge(ctx context.Context, pr int, sha, title, msg string) (string, error) {
	var p azPR
	err := a.c.do(ctx, http.MethodPatch, a.r("/pullrequests/"+strconv.Itoa(pr), nil), map[string]any{
		"status": "completed", "lastMergeSourceCommit": map[string]string{"commitId": sha},
		"completionOptions": map[string]any{"mergeStrategy": "squash", "mergeCommitMessage": title + "\n\n" + msg, "deleteSourceBranch": false}}, &p)
	if err != nil {
		return "", err
	}
	if p.LastMergeCommit == nil || p.Status != "completed" {
		// Completion can finish a moment later.
		if err := a.c.do(ctx, http.MethodGet, a.r("/pullrequests/"+strconv.Itoa(pr), nil), nil, &p); err != nil {
			return "", err
		}
	}
	if p.LastMergeCommit != nil {
		return p.LastMergeCommit.CommitID, nil
	}
	return "", nil
}

func (a *Azure) BranchSHA(ctx context.Context, branch string) (string, error) {
	var out struct {
		Value []struct {
			Name     string `json:"name"`
			ObjectID string `json:"objectId"`
		} `json:"value"`
	}
	if err := a.c.do(ctx, http.MethodGet, a.r("/refs", url.Values{"filter": {"heads/" + branch}}), nil, &out); err != nil {
		return "", err
	}
	for _, v := range out.Value {
		if v.Name == azRefs+branch {
			return v.ObjectID, nil
		}
	}
	return "", &APIError{Host: "Azure DevOps", Status: http.StatusNotFound, Message: "no branch " + branch}
}

func (a *Azure) CreateBranch(ctx context.Context, branch, sha string) error {
	var out struct {
		Value []struct {
			Success bool `json:"success"`
		} `json:"value"`
	}
	err := a.c.do(ctx, http.MethodPost, a.r("/refs", nil), []map[string]string{{"name": azRefs + branch, "oldObjectId": strings.Repeat("0", 40), "newObjectId": sha}}, &out)
	if err == nil && (len(out.Value) == 0 || !out.Value[0].Success) {
		return &APIError{Host: "Azure DevOps", Status: http.StatusConflict, Message: "the branch could not be created"}
	}
	return err
}

func (a *Azure) ListDir(ctx context.Context, dir, branch string) ([]string, error) {
	var out struct {
		Value []struct {
			Path          string `json:"path"`
			GitObjectType string `json:"gitObjectType"`
		} `json:"value"`
	}
	q := url.Values{"scopePath": {"/" + strings.Trim(dir, "/")}, "recursionLevel": {"OneLevel"}, "versionDescriptor.version": {branch}, "versionDescriptor.versionType": {"branch"}}
	err := a.c.do(ctx, http.MethodGet, a.r("/items", q), nil, &out)
	if NotFound(err) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	names := []string{}
	for _, v := range out.Value {
		if v.GitObjectType == "blob" {
			names = append(names, v.Path[strings.LastIndexByte(v.Path, '/')+1:])
		}
	}
	sort.Strings(names)
	return names, nil
}

func (a *Azure) exists(ctx context.Context, p, branch string) (bool, error) {
	q := url.Values{"path": {"/" + strings.TrimPrefix(p, "/")}, "versionDescriptor.version": {branch}, "versionDescriptor.versionType": {"branch"}}
	err := a.c.do(ctx, http.MethodGet, a.r("/items", q), nil, nil)
	if NotFound(err) {
		return false, nil
	}
	return err == nil, err
}

// Commit makes one commit with every change (a push).
func (a *Azure) Commit(ctx context.Context, branch, msg string, changes map[string]*[]byte) (string, error) {
	head, err := a.BranchSHA(ctx, branch)
	if err != nil {
		return "", err
	}
	paths := make([]string, 0, len(changes))
	for p := range changes {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	var cs []map[string]any
	for _, p := range paths {
		ok, err := a.exists(ctx, p, branch)
		if err != nil {
			return "", err
		}
		item := map[string]string{"path": "/" + strings.TrimPrefix(p, "/")}
		switch {
		case changes[p] == nil && !ok:
			continue
		case changes[p] == nil:
			cs = append(cs, map[string]any{"changeType": "delete", "item": item})
		default:
			t := "add"
			if ok {
				t = "edit"
			}
			cs = append(cs, map[string]any{"changeType": t, "item": item, "newContent": map[string]string{"content": base64.StdEncoding.EncodeToString(*changes[p]), "contentType": "base64encoded"}})
		}
	}
	if len(cs) == 0 {
		return head, nil
	}
	var out struct {
		Commits []struct {
			CommitID string `json:"commitId"`
		} `json:"commits"`
	}
	err = a.c.do(ctx, http.MethodPost, a.r("/pushes", nil), map[string]any{
		"refUpdates": []map[string]string{{"name": azRefs + branch, "oldObjectId": head}},
		"commits":    []map[string]any{{"comment": msg, "changes": cs}}}, &out)
	if err != nil {
		return "", err
	}
	if len(out.Commits) > 0 {
		return out.Commits[0].CommitID, nil
	}
	return a.BranchSHA(ctx, branch)
}

func (a *Azure) OpenPR(ctx context.Context, head, base, title, body string) (*PR, error) {
	var p azPR
	if err := a.c.do(ctx, http.MethodPost, a.r("/pullrequests", nil), map[string]string{"sourceRefName": azRefs + head, "targetRefName": azRefs + base, "title": title, "description": body}, &p); err != nil {
		return nil, err
	}
	return a.pr(&p), nil
}

// Files downloads the whole tree at a commit as a zip.
func (a *Azure) Files(ctx context.Context, rev string) (map[string][]byte, error) {
	q := url.Values{"scopePath": {"/"}, "recursionLevel": {"Full"}, "$format": {"zip"}, "download": {"true"},
		"versionDescriptor.version": {rev}, "versionDescriptor.versionType": {"commit"}}
	var data []byte
	if err := a.c.do(ctx, http.MethodGet, a.r("/items", q), nil, &data); err != nil {
		return nil, err
	}
	return unzipAll(data, false)
}
