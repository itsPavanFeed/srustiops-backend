package forge

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/itsPavanFeed/srustiops-backend/internal/githubapp"
)

// GitHub is a repository reached through the tenant's GitHub App installation.
type GitHub struct {
	App  *githubapp.App
	Inst int64
	Repo string // owner/name
}

func (g *GitHub) Provider() string { return "github" }

func fromGitHub(p *githubapp.PR, repo string) *PR {
	state := p.State
	if p.Merged {
		state = "merged"
	}
	return &PR{Number: p.Number, Title: p.Title, Author: p.User.Login, URL: p.HTMLURL, State: state, Draft: p.Draft, HeadSHA: p.Head.SHA,
		HeadBranch: p.Head.Ref, BaseBranch: p.Base.Ref, Fork: p.Head.Repo.FullName != "" && !strings.EqualFold(p.Head.Repo.FullName, repo)}
}

func (g *GitHub) GetPR(ctx context.Context, n int) (*PR, error) {
	p, err := g.App.GetPR(ctx, g.Inst, g.Repo, n)
	if err != nil {
		return nil, ghErr(err)
	}
	return fromGitHub(p, g.Repo), nil
}

func (g *GitHub) OpenPRs(ctx context.Context, base string) ([]PR, error) {
	var ps []githubapp.PR
	if err := g.App.Do(ctx, g.Inst, http.MethodGet, "/repos/"+g.Repo+"/pulls?state=open&per_page=100&base="+url.QueryEscape(base), nil, &ps); err != nil {
		return nil, ghErr(err)
	}
	out := make([]PR, 0, len(ps))
	for i := range ps {
		out = append(out, *fromGitHub(&ps[i], g.Repo))
	}
	return out, nil
}

func (g *GitHub) SetStatus(ctx context.Context, pr int, sha, state, name, desc, target string) error {
	return ghErr(g.App.SetStatus(ctx, g.Inst, g.Repo, sha, state, name, desc, target))
}

func (g *GitHub) Comment(ctx context.Context, pr int, id int64, body string) (int64, error) {
	id, err := g.App.Comment(ctx, g.Inst, g.Repo, pr, id, body)
	return id, ghErr(err)
}

func (g *GitHub) Merge(ctx context.Context, pr int, sha, title, msg string) (string, error) {
	s, err := g.App.MergeSHA(ctx, g.Inst, g.Repo, pr, sha, title, msg)
	return s, ghErr(err)
}

func (g *GitHub) BranchSHA(ctx context.Context, branch string) (string, error) {
	s, err := g.App.BranchSHA(ctx, g.Inst, g.Repo, branch)
	return s, ghErr(err)
}

func (g *GitHub) CreateBranch(ctx context.Context, branch, sha string) error {
	return ghErr(g.App.CreateBranch(ctx, g.Inst, g.Repo, branch, sha))
}

func (g *GitHub) ListDir(ctx context.Context, dir, branch string) ([]string, error) {
	m, err := g.App.DirFiles(ctx, g.Inst, g.Repo, dir, branch)
	if err != nil {
		return nil, ghErr(err)
	}
	out := make([]string, 0, len(m))
	for n := range m {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

// Commit writes the files one commit each (the contents API), in path order.
func (g *GitHub) Commit(ctx context.Context, branch, msg string, changes map[string]*[]byte) (string, error) {
	paths := make([]string, 0, len(changes))
	for p := range changes {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		sha, err := g.App.FileSHA(ctx, g.Inst, g.Repo, p, branch)
		if err != nil {
			return "", ghErr(err)
		}
		switch {
		case changes[p] == nil && sha == "":
		case changes[p] == nil:
			err = g.App.DeleteFile(ctx, g.Inst, g.Repo, p, branch, msg, sha)
		default:
			err = g.App.PutFile(ctx, g.Inst, g.Repo, p, branch, msg, *changes[p], sha)
		}
		if err != nil {
			return "", ghErr(err)
		}
	}
	return g.BranchSHA(ctx, branch)
}

func (g *GitHub) OpenPR(ctx context.Context, head, base, title, body string) (*PR, error) {
	p, err := g.App.OpenPR(ctx, g.Inst, g.Repo, head, base, title, body)
	if err != nil {
		return nil, ghErr(err)
	}
	return fromGitHub(p, g.Repo), nil
}

func (g *GitHub) Files(ctx context.Context, rev string) (map[string][]byte, error) {
	tok, err := g.App.Token(ctx, g.Inst)
	if err != nil {
		return nil, ghErr(err)
	}
	api := g.App.API
	if api == "" {
		api = githubapp.DefaultAPI
	}
	c := newClient("GitHub", g.App.HC, func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tok) })
	var b []byte
	if err := c.do(ctx, http.MethodGet, strings.TrimRight(api, "/")+"/repos/"+g.Repo+"/tarball/"+url.PathEscape(rev), nil, &b); err != nil {
		return nil, err
	}
	return untarGz(b)
}

// ghErr maps the GitHub client's errors to this package's.
func ghErr(err error) error {
	var e *githubapp.APIError
	if errors.As(err, &e) {
		return &APIError{Host: "GitHub", Status: e.Status, Message: e.Message}
	}
	return err
}

var _ = strconv.Itoa
