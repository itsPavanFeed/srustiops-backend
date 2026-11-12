package forge

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Fake is an in-memory Git host for development and tests that speaks the
// parts of the GitLab, Bitbucket Cloud and Azure DevOps APIs the platform
// uses, each over its own repository:
//
//	/gitlab/api/v4/...                 GitLab (project = the configured repo)
//	/bitbucket/2.0/..., /bitbucket/... Bitbucket Cloud (API and snapshots)
//	/azure/{org}/{project}/_apis/...   Azure DevOps
//
// Test helpers (any dialect): POST /_fake/{dialect}/commit {branch, from,
// files, delete, message}, POST /_fake/{dialect}/pr {source, target, title,
// author, draft}, POST /_fake/{dialect}/close {number}, GET /_fake/{dialect}/state.
// Every request must carry the token it was started with.
type Fake struct {
	Token string
	mu    sync.Mutex
	repos map[string]*fakeRepo // by dialect
}

type fakeCommit struct {
	SHA     string            `json:"sha"`
	Parent  string            `json:"parent"`
	Message string            `json:"message"`
	Files   map[string][]byte `json:"-"`
}

type fakePR struct {
	Number   int                 `json:"number"`
	Title    string              `json:"title"`
	Body     string              `json:"body"`
	Author   string              `json:"author"`
	Source   string              `json:"source"`
	Target   string              `json:"target"`
	State    string              `json:"state"` // open | merged | closed
	Draft    bool                `json:"draft"`
	Merge    string              `json:"merge_commit,omitempty"`
	Statuses map[string]fakeStat `json:"statuses"` // by name
	Comments map[int64]string    `json:"comments"`
}

type fakeStat struct {
	State, Description, Target, SHA string
}

type fakeRepo struct {
	Commits  map[string]*fakeCommit
	Branches map[string]string
	PRs      map[int]*fakePR
	nextPR   int
	nextNote int64
}

// NewFake starts with one repository per dialect, each with branch main
// holding files.
func NewFake(token string, files map[string][]byte) *Fake {
	f := &Fake{Token: token, repos: map[string]*fakeRepo{}}
	for i, d := range []string{"gitlab", "bitbucket", "azure"} {
		// Each host numbers its pull requests in its own range (101, 201, 301).
		r := &fakeRepo{Commits: map[string]*fakeCommit{}, Branches: map[string]string{}, PRs: map[int]*fakePR{}, nextPR: 101 + 100*i, nextNote: 100}
		c := r.commit("", "initial commit", copyFiles(files))
		r.Branches["main"] = c.SHA
		f.repos[d] = r
	}
	return f
}

func copyFiles(in map[string][]byte) map[string][]byte {
	out := map[string][]byte{}
	for k, v := range in {
		out[k] = append([]byte(nil), v...)
	}
	return out
}

func (r *fakeRepo) commit(parent, msg string, files map[string][]byte) *fakeCommit {
	h := sha1.New()
	fmt.Fprintf(h, "%s\x00%s\x00%d", parent, msg, time.Now().UnixNano())
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		h.Write([]byte(n))
		h.Write(files[n])
	}
	c := &fakeCommit{SHA: hex.EncodeToString(h.Sum(nil)), Parent: parent, Message: msg, Files: files}
	r.Commits[c.SHA] = c
	return c
}

// apply writes changes (nil = delete) on a branch as one commit.
func (r *fakeRepo) apply(branch, msg string, changes map[string]*[]byte) (string, error) {
	head, ok := r.Branches[branch]
	if !ok {
		return "", fmt.Errorf("no branch %s", branch)
	}
	files := copyFiles(r.Commits[head].Files)
	for p, v := range changes {
		if v == nil {
			delete(files, p)
		} else {
			files[p] = append([]byte(nil), (*v)...)
		}
	}
	c := r.commit(head, msg, files)
	r.Branches[branch] = c.SHA
	return c.SHA, nil
}

func (f *Fake) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if !f.authorized(req) {
		http.Error(w, `{"message":"401 Unauthorized"}`, http.StatusUnauthorized)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	p := req.URL.Path
	switch {
	case strings.HasPrefix(p, "/_fake/"):
		f.helper(w, req)
	case strings.HasPrefix(p, "/gitlab/api/v4/projects/"):
		f.gitlab(w, req, f.repos["gitlab"])
	case strings.HasPrefix(p, "/bitbucket/"):
		f.bitbucket(w, req, f.repos["bitbucket"])
	case strings.HasPrefix(p, "/azure/"):
		f.azure(w, req, f.repos["azure"])
	default:
		http.NotFound(w, req)
	}
}

func (f *Fake) authorized(r *http.Request) bool {
	if r.Header.Get("PRIVATE-TOKEN") == f.Token || r.Header.Get("Authorization") == "Bearer "+f.Token {
		return true
	}
	if _, p, ok := r.BasicAuth(); ok && p == f.Token {
		return true
	}
	return false
}

func writeJSONf(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func notFoundf(w http.ResponseWriter) {
	writeJSONf(w, 404, map[string]string{"message": "404 Not Found"})
}

func (r *fakeRepo) files(rev string) (map[string][]byte, bool) {
	if sha, ok := r.Branches[rev]; ok {
		rev = sha
	}
	c, ok := r.Commits[rev]
	if !ok {
		return nil, false
	}
	return c.Files, true
}

func (r *fakeRepo) resolve(ref string) string {
	if sha, ok := r.Branches[ref]; ok {
		return sha
	}
	if _, ok := r.Commits[ref]; ok {
		return ref
	}
	for sha := range r.Commits { // short hashes (Bitbucket)
		if len(ref) >= 7 && strings.HasPrefix(sha, ref) {
			return sha
		}
	}
	return ""
}

func tarGz(top string, files map[string][]byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for n, b := range files {
		tw.WriteHeader(&tar.Header{Name: top + "/" + n, Mode: 0o644, Size: int64(len(b)), Typeflag: tar.TypeReg})
		tw.Write(b)
	}
	tw.Close()
	zw.Close()
	return buf.Bytes()
}

func dirEntries(files map[string][]byte, dir string) (names []string, exists bool) {
	dir = strings.Trim(dir, "/")
	for p := range files {
		d := ""
		if i := strings.LastIndexByte(p, '/'); i >= 0 {
			d = p[:i]
		}
		if d == dir {
			names = append(names, p[strings.LastIndexByte(p, '/')+1:])
		}
		if dir == "" || strings.HasPrefix(p, dir+"/") {
			exists = true
		}
	}
	sort.Strings(names)
	return names, exists
}

// ---- test helpers ----

func (f *Fake) helper(w http.ResponseWriter, req *http.Request) {
	parts := strings.Split(strings.TrimPrefix(req.URL.Path, "/_fake/"), "/")
	if len(parts) != 2 || f.repos[parts[0]] == nil {
		notFoundf(w)
		return
	}
	r := f.repos[parts[0]]
	var b struct {
		Branch, From, Message, Source, Target, Title, Author string
		Number                                               int
		Draft                                                bool
		Files                                                map[string]string
		Delete                                               []string
	}
	if req.Method == http.MethodPost {
		json.NewDecoder(req.Body).Decode(&b)
	}
	switch parts[1] {
	case "commit":
		if _, ok := r.Branches[b.Branch]; !ok {
			from := r.resolve(b.From)
			if from == "" {
				from = r.Branches["main"]
			}
			r.Branches[b.Branch] = from
		}
		ch := map[string]*[]byte{}
		for p, v := range b.Files {
			v := []byte(v)
			ch[p] = &v
		}
		for _, p := range b.Delete {
			ch[p] = nil
		}
		sha, err := r.apply(b.Branch, b.Message, ch)
		if err != nil {
			writeJSONf(w, 400, map[string]string{"message": err.Error()})
			return
		}
		writeJSONf(w, 200, map[string]string{"sha": sha})
	case "pr":
		n := r.nextPR
		r.nextPR++
		r.PRs[n] = &fakePR{Number: n, Title: b.Title, Author: b.Author, Source: b.Source, Target: b.Target, State: "open", Draft: b.Draft,
			Statuses: map[string]fakeStat{}, Comments: map[int64]string{}}
		writeJSONf(w, 200, map[string]int{"number": n})
	case "close":
		if p := r.PRs[b.Number]; p != nil {
			p.State = "closed"
		}
		writeJSONf(w, 200, map[string]bool{"ok": true})
	case "state":
		files := map[string]map[string]string{}
		for br, sha := range r.Branches {
			m := map[string]string{}
			for p, v := range r.Commits[sha].Files {
				m[p] = string(v)
			}
			files[br] = m
		}
		writeJSONf(w, 200, map[string]any{"branches": r.Branches, "prs": r.PRs, "files": files})
	default:
		notFoundf(w)
	}
}

func readJSON(req *http.Request, v any) { json.NewDecoder(io.LimitReader(req.Body, 8<<20)).Decode(v) }

// ---- GitLab ----

func (f *Fake) glMR(r *fakeRepo, p *fakePR) map[string]any {
	state := map[string]string{"open": "opened", "merged": "merged", "closed": "closed"}[p.State]
	return map[string]any{"iid": p.Number, "title": p.Title, "state": state, "draft": p.Draft, "web_url": "http://fake/gitlab/mr/" + strconv.Itoa(p.Number),
		"sha": r.Branches[p.Source], "source_branch": p.Source, "target_branch": p.Target, "source_project_id": 1, "target_project_id": 1,
		"merge_commit_sha": p.Merge, "squash_commit_sha": p.Merge, "author": map[string]string{"username": p.Author}}
}

func (f *Fake) gitlab(w http.ResponseWriter, req *http.Request, r *fakeRepo) {
	rest := strings.TrimPrefix(req.URL.EscapedPath(), "/gitlab/api/v4/projects/")
	_, rest, _ = strings.Cut(rest, "/") // the project
	seg := strings.Split(rest, "/")
	q := req.URL.Query()
	switch {
	case len(seg) == 1 && seg[0] == "merge_requests" && req.Method == http.MethodGet:
		out := []map[string]any{}
		for _, n := range sortedPRs(r) {
			p := r.PRs[n]
			if p.State == "open" && (q.Get("target_branch") == "" || p.Target == q.Get("target_branch")) {
				out = append(out, f.glMR(r, p))
			}
		}
		writeJSONf(w, 200, out)
	case len(seg) == 1 && seg[0] == "merge_requests" && req.Method == http.MethodPost:
		var b struct{ SourceBranch, TargetBranch, Title, Description string }
		var m map[string]string
		readJSON(req, &m)
		b.SourceBranch, b.TargetBranch, b.Title, b.Description = m["source_branch"], m["target_branch"], m["title"], m["description"]
		if _, ok := r.Branches[b.SourceBranch]; !ok {
			writeJSONf(w, 422, map[string]string{"message": "no source branch"})
			return
		}
		n := r.nextPR
		r.nextPR++
		p := &fakePR{Number: n, Title: b.Title, Body: b.Description, Author: "srustiops", Source: b.SourceBranch, Target: b.TargetBranch, State: "open", Statuses: map[string]fakeStat{}, Comments: map[int64]string{}}
		r.PRs[n] = p
		writeJSONf(w, 201, f.glMR(r, p))
	case len(seg) >= 2 && seg[0] == "merge_requests":
		n, _ := strconv.Atoi(seg[1])
		p := r.PRs[n]
		if p == nil {
			notFoundf(w)
			return
		}
		switch {
		case len(seg) == 2:
			writeJSONf(w, 200, f.glMR(r, p))
		case seg[2] == "merge" && req.Method == http.MethodPut:
			var m map[string]any
			readJSON(req, &m)
			if m["sha"] != r.Branches[p.Source] {
				writeJSONf(w, 409, map[string]string{"message": "SHA does not match HEAD of source branch"})
				return
			}
			files := copyFiles(r.Commits[r.Branches[p.Source]].Files)
			c := r.commit(r.Branches[p.Target], fmt.Sprint(m["squash_commit_message"]), files)
			r.Branches[p.Target], p.State, p.Merge = c.SHA, "merged", c.SHA
			writeJSONf(w, 200, f.glMR(r, p))
		case seg[2] == "notes":
			var m map[string]string
			readJSON(req, &m)
			if len(seg) == 4 {
				id, _ := strconv.ParseInt(seg[3], 10, 64)
				if _, ok := p.Comments[id]; !ok {
					notFoundf(w)
					return
				}
				p.Comments[id] = m["body"]
				writeJSONf(w, 200, map[string]int64{"id": id})
				return
			}
			r.nextNote++
			p.Comments[r.nextNote] = m["body"]
			writeJSONf(w, 201, map[string]int64{"id": r.nextNote})
		default:
			notFoundf(w)
		}
	case len(seg) == 2 && seg[0] == "statuses":
		sha := seg[1]
		for _, p := range r.PRs {
			if r.Branches[p.Source] == sha {
				p.Statuses[q.Get("name")] = fakeStat{State: q.Get("state"), Description: q.Get("description"), Target: q.Get("target_url"), SHA: sha}
			}
		}
		writeJSONf(w, 201, map[string]string{"status": q.Get("state")})
	case len(seg) >= 2 && seg[0] == "repository" && seg[1] == "branches":
		if req.Method == http.MethodPost {
			if r.resolve(q.Get("ref")) == "" {
				writeJSONf(w, 400, map[string]string{"message": "invalid ref"})
				return
			}
			r.Branches[q.Get("branch")] = r.resolve(q.Get("ref"))
			writeJSONf(w, 201, map[string]string{"name": q.Get("branch")})
			return
		}
		name, _ := url.PathUnescape(strings.Join(seg[2:], "/"))
		sha, ok := r.Branches[name]
		if !ok {
			notFoundf(w)
			return
		}
		writeJSONf(w, 200, map[string]any{"name": name, "commit": map[string]string{"id": sha}})
	case len(seg) == 2 && seg[0] == "repository" && seg[1] == "tree":
		files, ok := r.files(q.Get("ref"))
		names, exists := dirEntries(files, q.Get("path"))
		if !ok || !exists {
			notFoundf(w)
			return
		}
		out := []map[string]string{}
		for _, n := range names {
			out = append(out, map[string]string{"name": n, "type": "blob"})
		}
		writeJSONf(w, 200, out)
	case len(seg) == 3 && seg[0] == "repository" && seg[1] == "files":
		p, _ := url.PathUnescape(seg[2])
		files, ok := r.files(q.Get("ref"))
		if _, has := files[p]; !ok || !has {
			notFoundf(w)
			return
		}
		writeJSONf(w, 200, map[string]string{"file_path": p})
	case len(seg) == 2 && seg[0] == "repository" && seg[1] == "commits" && req.Method == http.MethodPost:
		var b struct {
			Branch  string `json:"branch"`
			Message string `json:"commit_message"`
			Actions []struct {
				Action, FilePath, Content string
			} `json:"actions"`
		}
		var raw struct {
			Branch  string              `json:"branch"`
			Message string              `json:"commit_message"`
			Actions []map[string]string `json:"actions"`
		}
		readJSON(req, &raw)
		b.Branch, b.Message = raw.Branch, raw.Message
		files, ok := r.files(b.Branch)
		if !ok {
			writeJSONf(w, 400, map[string]string{"message": "no branch"})
			return
		}
		ch := map[string]*[]byte{}
		for _, a := range raw.Actions {
			_, has := files[a["file_path"]]
			switch a["action"] {
			case "create", "update":
				if (a["action"] == "create") == has {
					writeJSONf(w, 400, map[string]string{"message": "A file with this name " + map[bool]string{true: "already exists", false: "doesn't exist"}[has]})
					return
				}
				v, _ := base64.StdEncoding.DecodeString(a["content"])
				ch[a["file_path"]] = &v
			case "delete":
				ch[a["file_path"]] = nil
			}
		}
		sha, _ := r.apply(b.Branch, b.Message, ch)
		writeJSONf(w, 201, map[string]string{"id": sha})
	case len(seg) == 2 && seg[0] == "repository" && seg[1] == "archive.tar.gz":
		files, ok := r.files(q.Get("sha"))
		if !ok {
			notFoundf(w)
			return
		}
		w.Write(tarGz("project-"+q.Get("sha"), files))
	default:
		notFoundf(w)
	}
}

func sortedPRs(r *fakeRepo) []int {
	ns := make([]int, 0, len(r.PRs))
	for n := range r.PRs {
		ns = append(ns, n)
	}
	sort.Ints(ns)
	return ns
}

// ---- Bitbucket Cloud ----

func (f *Fake) bbPR(r *fakeRepo, repo string, p *fakePR) map[string]any {
	state := map[string]string{"open": "OPEN", "merged": "MERGED", "closed": "DECLINED"}[p.State]
	pr := map[string]any{"id": p.Number, "title": p.Title, "state": state, "draft": p.Draft, "author": map[string]string{"nickname": p.Author},
		"source":      map[string]any{"branch": map[string]string{"name": p.Source}, "commit": map[string]string{"hash": r.Branches[p.Source][:12]}, "repository": map[string]string{"full_name": repo}},
		"destination": map[string]any{"branch": map[string]string{"name": p.Target}, "repository": map[string]string{"full_name": repo}},
		"links":       map[string]any{"html": map[string]string{"href": "http://fake/bitbucket/pr/" + strconv.Itoa(p.Number)}}}
	if p.Merge != "" {
		pr["merge_commit"] = map[string]string{"hash": p.Merge}
	}
	return pr
}

func (f *Fake) bitbucket(w http.ResponseWriter, req *http.Request, r *fakeRepo) {
	path := strings.TrimPrefix(req.URL.EscapedPath(), "/bitbucket/")
	if !strings.HasPrefix(path, "2.0/") { // snapshots: {ws}/{repo}/get/{rev}.tar.gz
		parts := strings.Split(path, "/")
		if len(parts) == 4 && parts[2] == "get" && strings.HasSuffix(parts[3], ".tar.gz") {
			rev := strings.TrimSuffix(parts[3], ".tar.gz")
			files, ok := r.files(r.resolve(rev))
			if !ok {
				notFoundf(w)
				return
			}
			w.Write(tarGz(parts[1]+"-"+rev[:min(12, len(rev))], files))
			return
		}
		notFoundf(w)
		return
	}
	seg := strings.Split(strings.TrimPrefix(path, "2.0/repositories/"), "/")
	if len(seg) < 3 {
		notFoundf(w)
		return
	}
	repo := seg[0] + "/" + seg[1]
	seg = seg[2:]
	q := req.URL.Query()
	switch {
	case seg[0] == "pullrequests" && len(seg) == 1 && req.Method == http.MethodGet:
		vals := []map[string]any{}
		for _, n := range sortedPRs(r) {
			if r.PRs[n].State == "open" {
				vals = append(vals, f.bbPR(r, repo, r.PRs[n]))
			}
		}
		writeJSONf(w, 200, map[string]any{"values": vals})
	case seg[0] == "pullrequests" && len(seg) == 1 && req.Method == http.MethodPost:
		var b struct {
			Title, Description  string
			Source, Destination struct {
				Branch struct{ Name string } `json:"branch"`
			}
		}
		readJSON(req, &b)
		n := r.nextPR
		r.nextPR++
		p := &fakePR{Number: n, Title: b.Title, Body: b.Description, Author: "srustiops", Source: b.Source.Branch.Name, Target: b.Destination.Branch.Name, State: "open", Statuses: map[string]fakeStat{}, Comments: map[int64]string{}}
		r.PRs[n] = p
		writeJSONf(w, 201, f.bbPR(r, repo, p))
	case seg[0] == "pullrequests":
		n, _ := strconv.Atoi(seg[1])
		p := r.PRs[n]
		if p == nil {
			notFoundf(w)
			return
		}
		switch {
		case len(seg) == 2:
			writeJSONf(w, 200, f.bbPR(r, repo, p))
		case seg[2] == "merge":
			var m map[string]any
			readJSON(req, &m)
			c := r.commit(r.Branches[p.Target], fmt.Sprint(m["message"]), copyFiles(r.Commits[r.Branches[p.Source]].Files))
			r.Branches[p.Target], p.State, p.Merge = c.SHA, "merged", c.SHA
			writeJSONf(w, 200, f.bbPR(r, repo, p))
		case seg[2] == "comments":
			var m struct {
				Content struct{ Raw string } `json:"content"`
			}
			readJSON(req, &m)
			if len(seg) == 4 {
				id, _ := strconv.ParseInt(seg[3], 10, 64)
				if _, ok := p.Comments[id]; !ok {
					notFoundf(w)
					return
				}
				p.Comments[id] = m.Content.Raw
				writeJSONf(w, 200, map[string]int64{"id": id})
				return
			}
			r.nextNote++
			p.Comments[r.nextNote] = m.Content.Raw
			writeJSONf(w, 201, map[string]int64{"id": r.nextNote})
		default:
			notFoundf(w)
		}
	case seg[0] == "commit" && len(seg) == 2:
		sha := r.resolve(seg[1])
		if sha == "" {
			notFoundf(w)
			return
		}
		writeJSONf(w, 200, map[string]string{"hash": sha})
	case seg[0] == "commit" && len(seg) == 4 && seg[2] == "statuses":
		sha := r.resolve(seg[1])
		var m map[string]string
		readJSON(req, &m)
		for _, p := range r.PRs {
			if r.Branches[p.Source] == sha {
				p.Statuses[m["key"]] = fakeStat{State: m["state"], Description: m["description"], Target: m["url"], SHA: sha}
			}
		}
		writeJSONf(w, 201, m)
	case seg[0] == "refs" && seg[1] == "branches" && len(seg) == 2 && req.Method == http.MethodPost:
		var b struct {
			Name   string
			Target struct{ Hash string }
		}
		readJSON(req, &b)
		r.Branches[b.Name] = r.resolve(b.Target.Hash)
		writeJSONf(w, 201, map[string]string{"name": b.Name})
	case seg[0] == "refs" && seg[1] == "branches" && len(seg) >= 3:
		name, _ := url.PathUnescape(strings.Join(seg[2:], "/"))
		sha, ok := r.Branches[name]
		if !ok {
			notFoundf(w)
			return
		}
		writeJSONf(w, 200, map[string]any{"name": name, "target": map[string]string{"hash": sha}})
	case seg[0] == "src" && len(seg) == 1 && req.Method == http.MethodPost:
		if err := req.ParseMultipartForm(8 << 20); err != nil {
			writeJSONf(w, 400, map[string]string{"message": err.Error()})
			return
		}
		ch := map[string]*[]byte{}
		for name, fhs := range req.MultipartForm.File {
			fh, _ := fhs[0].Open()
			v, _ := io.ReadAll(fh)
			fh.Close()
			ch[name] = &v
		}
		for _, d := range req.MultipartForm.Value["files"] {
			ch[d] = nil
		}
		if _, err := r.apply(req.FormValue("branch"), req.FormValue("message"), ch); err != nil {
			writeJSONf(w, 400, map[string]string{"message": err.Error()})
			return
		}
		w.WriteHeader(201)
	case seg[0] == "src" && len(seg) >= 2:
		ref, _ := url.PathUnescape(seg[1])
		files, ok := r.files(r.resolve(ref))
		dir, _ := url.PathUnescape(strings.Join(seg[2:], "/"))
		names, exists := dirEntries(files, dir)
		if !ok || !exists {
			notFoundf(w)
			return
		}
		vals := []map[string]string{}
		for _, n := range names {
			vals = append(vals, map[string]string{"type": "commit_file", "path": strings.Trim(strings.Trim(dir, "/")+"/"+n, "/")})
		}
		writeJSONf(w, 200, map[string]any{"values": vals})
	default:
		notFoundf(w)
	}
	_ = q
}

// ---- Azure DevOps ----

func (f *Fake) azPR(r *fakeRepo, p *fakePR) map[string]any {
	state := map[string]string{"open": "active", "merged": "completed", "closed": "abandoned"}[p.State]
	pr := map[string]any{"pullRequestId": p.Number, "title": p.Title, "status": state, "isDraft": p.Draft, "sourceRefName": azRefs + p.Source, "targetRefName": azRefs + p.Target,
		"lastMergeSourceCommit": map[string]string{"commitId": r.Branches[p.Source]}, "createdBy": map[string]string{"uniqueName": p.Author}}
	if p.Merge != "" {
		pr["lastMergeCommit"] = map[string]string{"commitId": p.Merge}
	}
	return pr
}

func (f *Fake) azure(w http.ResponseWriter, req *http.Request, r *fakeRepo) {
	parts := strings.Split(strings.TrimPrefix(req.URL.EscapedPath(), "/azure/"), "/")
	// {org}/{project}/_apis/git/repositories/{repo}/...
	if len(parts) < 6 || parts[2] != "_apis" || parts[4] != "repositories" {
		notFoundf(w)
		return
	}
	seg := parts[6:]
	q := req.URL.Query()
	if q.Get("api-version") == "" {
		writeJSONf(w, 400, map[string]string{"message": "api-version is required"})
		return
	}
	lower := func(i int) string {
		if i < len(seg) {
			return strings.ToLower(seg[i])
		}
		return ""
	}
	switch {
	case lower(0) == "pullrequests" && len(seg) == 1 && req.Method == http.MethodGet:
		vals := []map[string]any{}
		for _, n := range sortedPRs(r) {
			p := r.PRs[n]
			if p.State == "open" && (q.Get("searchCriteria.targetRefName") == "" || azRefs+p.Target == q.Get("searchCriteria.targetRefName")) {
				vals = append(vals, f.azPR(r, p))
			}
		}
		writeJSONf(w, 200, map[string]any{"value": vals})
	case lower(0) == "pullrequests" && len(seg) == 1 && req.Method == http.MethodPost:
		var b map[string]string
		readJSON(req, &b)
		n := r.nextPR
		r.nextPR++
		p := &fakePR{Number: n, Title: b["title"], Body: b["description"], Author: "srustiops", Source: strings.TrimPrefix(b["sourceRefName"], azRefs),
			Target: strings.TrimPrefix(b["targetRefName"], azRefs), State: "open", Statuses: map[string]fakeStat{}, Comments: map[int64]string{}}
		r.PRs[n] = p
		writeJSONf(w, 201, f.azPR(r, p))
	case lower(0) == "pullrequests":
		n, _ := strconv.Atoi(seg[1])
		p := r.PRs[n]
		if p == nil {
			notFoundf(w)
			return
		}
		switch {
		case len(seg) == 2 && req.Method == http.MethodGet:
			writeJSONf(w, 200, f.azPR(r, p))
		case len(seg) == 2 && req.Method == http.MethodPatch:
			var b struct {
				Status                string `json:"status"`
				LastMergeSourceCommit struct {
					CommitID string `json:"commitId"`
				} `json:"lastMergeSourceCommit"`
				CompletionOptions struct {
					MergeCommitMessage string `json:"mergeCommitMessage"`
				} `json:"completionOptions"`
			}
			readJSON(req, &b)
			if b.Status == "completed" {
				if b.LastMergeSourceCommit.CommitID != r.Branches[p.Source] {
					writeJSONf(w, 409, map[string]string{"message": "TF401192: the source branch has new commits"})
					return
				}
				c := r.commit(r.Branches[p.Target], b.CompletionOptions.MergeCommitMessage, copyFiles(r.Commits[r.Branches[p.Source]].Files))
				r.Branches[p.Target], p.State, p.Merge = c.SHA, "merged", c.SHA
			}
			writeJSONf(w, 200, f.azPR(r, p))
		case lower(2) == "statuses":
			var b struct {
				State       string            `json:"state"`
				Description string            `json:"description"`
				TargetURL   string            `json:"targetUrl"`
				Context     map[string]string `json:"context"`
			}
			readJSON(req, &b)
			p.Statuses[b.Context["name"]] = fakeStat{State: b.State, Description: b.Description, Target: b.TargetURL, SHA: r.Branches[p.Source]}
			writeJSONf(w, 201, map[string]string{"state": b.State})
		case lower(2) == "threads" && len(seg) == 3:
			var b struct {
				Comments []struct {
					Content string `json:"content"`
				} `json:"comments"`
			}
			readJSON(req, &b)
			r.nextNote++
			if len(b.Comments) > 0 {
				p.Comments[r.nextNote] = b.Comments[0].Content
			}
			writeJSONf(w, 200, map[string]int64{"id": r.nextNote})
		case lower(2) == "threads" && len(seg) == 6:
			id, _ := strconv.ParseInt(seg[3], 10, 64)
			if _, ok := p.Comments[id]; !ok {
				notFoundf(w)
				return
			}
			var b map[string]string
			readJSON(req, &b)
			p.Comments[id] = b["content"]
			writeJSONf(w, 200, map[string]int64{"id": 1})
		default:
			notFoundf(w)
		}
	case lower(0) == "refs" && req.Method == http.MethodGet:
		vals := []map[string]string{}
		for b, sha := range r.Branches {
			if "heads/"+b == q.Get("filter") {
				vals = append(vals, map[string]string{"name": azRefs + b, "objectId": sha})
			}
		}
		writeJSONf(w, 200, map[string]any{"value": vals})
	case lower(0) == "refs" && req.Method == http.MethodPost:
		var b []map[string]string
		readJSON(req, &b)
		out := []map[string]bool{}
		for _, u := range b {
			name := strings.TrimPrefix(u["name"], azRefs)
			_, exists := r.Branches[name]
			ok := !exists && r.resolve(u["newObjectId"]) != ""
			if ok {
				r.Branches[name] = u["newObjectId"]
			}
			out = append(out, map[string]bool{"success": ok})
		}
		writeJSONf(w, 200, map[string]any{"value": out})
	case lower(0) == "items":
		rev := q.Get("versionDescriptor.version")
		files, ok := r.files(r.resolve(rev))
		if !ok {
			notFoundf(w)
			return
		}
		if q.Get("$format") == "zip" {
			var buf bytes.Buffer
			zw := zip.NewWriter(&buf)
			for n, b := range files {
				fw, _ := zw.Create(n)
				fw.Write(b)
			}
			zw.Close()
			w.Write(buf.Bytes())
			return
		}
		if p := q.Get("path"); p != "" {
			if _, has := files[strings.TrimPrefix(p, "/")]; !has {
				notFoundf(w)
				return
			}
			writeJSONf(w, 200, map[string]string{"path": p})
			return
		}
		names, exists := dirEntries(files, q.Get("scopePath"))
		if !exists {
			notFoundf(w)
			return
		}
		dir := strings.TrimRight(q.Get("scopePath"), "/")
		vals := []map[string]string{}
		for _, n := range names {
			vals = append(vals, map[string]string{"path": dir + "/" + n, "gitObjectType": "blob"})
		}
		writeJSONf(w, 200, map[string]any{"value": vals})
	case lower(0) == "pushes":
		var b struct {
			RefUpdates []struct {
				Name        string `json:"name"`
				OldObjectID string `json:"oldObjectId"`
			} `json:"refUpdates"`
			Commits []struct {
				Comment string `json:"comment"`
				Changes []struct {
					ChangeType string `json:"changeType"`
					Item       struct {
						Path string `json:"path"`
					} `json:"item"`
					NewContent struct {
						Content string `json:"content"`
					} `json:"newContent"`
				} `json:"changes"`
			} `json:"commits"`
		}
		readJSON(req, &b)
		if len(b.RefUpdates) != 1 || len(b.Commits) != 1 {
			writeJSONf(w, 400, map[string]string{"message": "one ref and one commit"})
			return
		}
		branch := strings.TrimPrefix(b.RefUpdates[0].Name, azRefs)
		if r.Branches[branch] != b.RefUpdates[0].OldObjectID {
			writeJSONf(w, 409, map[string]string{"message": "TF401028: the reference has already been updated"})
			return
		}
		files := r.Commits[r.Branches[branch]].Files
		ch := map[string]*[]byte{}
		for _, c := range b.Commits[0].Changes {
			p := strings.TrimPrefix(c.Item.Path, "/")
			_, has := files[p]
			switch c.ChangeType {
			case "add", "edit":
				if (c.ChangeType == "add") == has {
					writeJSONf(w, 400, map[string]string{"message": "TF402455: " + c.ChangeType + " of " + p + " does not match the tree"})
					return
				}
				v, _ := base64.StdEncoding.DecodeString(c.NewContent.Content)
				ch[p] = &v
			case "delete":
				ch[p] = nil
			}
		}
		sha, _ := r.apply(branch, b.Commits[0].Comment, ch)
		writeJSONf(w, 201, map[string]any{"commits": []map[string]string{{"commitId": sha}}})
	default:
		notFoundf(w)
	}
}
