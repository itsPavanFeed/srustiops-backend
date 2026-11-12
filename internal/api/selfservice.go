package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strings"

	"github.com/itsPavanFeed/srustiops-backend/internal/contracts"
	"github.com/itsPavanFeed/srustiops-backend/internal/forge"
	"github.com/itsPavanFeed/srustiops-backend/internal/identity"
	"github.com/itsPavanFeed/srustiops-backend/internal/spec"
	"github.com/itsPavanFeed/srustiops-backend/internal/store"
)

// Self-service through Git: instead of creating a stack directly, the console
// (or an assistant draft) writes the stack's contract files (one YAML file per
// resource) to a new branch of the contracts
// repository and opens a pull request. The pull request is then planned,
// approved and applied before it merges, so Git stays the source of truth.

type proposeBody struct {
	Name        string          `json:"name"`
	BU          string          `json:"bu"`
	Environment string          `json:"environment"`
	Connection  string          `json:"connection,omitempty"`
	Spec        json.RawMessage `json:"spec"`
	Title       string          `json:"title,omitempty"`
}

func (s *Server) proposeStack(w http.ResponseWriter, r *http.Request) {
	var b proposeBody
	if !decode(w, r, &b) {
		return
	}
	p := user(r)
	if !spec.StackNameRe.MatchString(b.Name) {
		writeErr(w, 422, "name must start with a letter and use lowercase letters, digits and dashes (2-63)")
		return
	}
	bu, env := s.target(w, r, b.BU, b.Environment)
	if env == nil {
		return
	}
	if !p.CanChange(bu) {
		writeErr(w, http.StatusForbidden, "proposing stacks needs the developer or admin role in "+bu)
		return
	}
	env, _, prob := pickConnection(env, b.Connection)
	if prob != "" {
		writeErr(w, 422, prob)
		return
	}
	gen, _, probs := s.buildAllowWaiting(r.Context(), b.Name, bu, env, b.Spec)
	if probs != nil {
		writeErr(w, 422, "stack spec rejected", probs...)
		return
	}
	out, code, err := s.openContractPR(r.Context(), p, b.Name, bu, env, gen, b.Title, "")
	if err != nil {
		writeErr(w, code, err.Error())
		return
	}
	writeJSON(w, 201, out)
}

// openContractPR writes a stack's contract files (one YAML file per
// resource) to a new branch of the contracts repository and opens a pull
// request, which is then planned and applied before it merges. It returns the
// HTTP status to answer with when it fails.
func (s *Server) openContractPR(ctx context.Context, p *identity.Principal, name, bu string, env *store.Environment, gen *spec.Generated, title, note string) (map[string]any, int, error) {
	return s.openContractPRWith(ctx, p, name, bu, env, gen, title, note, nil)
}

// liveMatch marks a pull request opened from live -> code: its plan is held
// to the zero-diff gate, and it may take over the console stack it matches.
type liveMatch struct {
	StackID, SourceRun string
}

func (s *Server) openContractPRWith(ctx context.Context, p *identity.Principal, name, bu string, env *store.Environment, gen *spec.Generated, title, note string, live *liveMatch) (map[string]any, int, error) {
	return s.openStacksPR(ctx, p, []prStack{{Name: name, BU: bu, Env: env, Spec: gen.Spec}}, title, note, live)
}

// prStack is one stack a contract pull request adds or updates.
type prStack struct {
	Name string
	BU   string
	Env  *store.Environment
	Spec json.RawMessage
}

// openStacksPR writes one or more stacks' contracts to a branch of the
// contracts repository and opens one pull request (an adoption with its
// dependencies, in dependency order). SrustiOps plans it, collects
// approvals and applies before merging.
func (s *Server) openStacksPR(ctx context.Context, p *identity.Principal, stacks []prStack, title, note string, live *liveMatch) (map[string]any, int, error) {
	fg, cfg, err := s.prContext(ctx)
	if err != nil {
		return nil, http.StatusConflict, err
	}
	actions := map[string]string{}
	for _, ps := range stacks {
		action := "Add"
		if st, err := s.store.GetStack(ctx, ps.Name); err == nil {
			switch {
			case st.ManagedBy != "git" && (live == nil || live.StackID != st.ID):
				return nil, http.StatusConflict, fmt.Errorf("stack %s is managed in the console; it cannot be changed through Git", ps.Name)
			case st.BU != ps.BU || st.EnvironmentID != ps.Env.ID:
				return nil, http.StatusConflict, fmt.Errorf("stack %s cannot move to another environment or business unit; use a new name", ps.Name)
			}
			action = "Update"
		} else if !errors.Is(err, store.ErrNotFound) {
			return nil, http.StatusInternalServerError, err
		}
		actions[ps.Name] = action
	}
	first := stacks[len(stacks)-1] // the stack asked for comes last (dependencies first)

	rnd := make([]byte, 3)
	rand.Read(rnd)
	branch := "srustiops/" + first.Name + "-" + hex.EncodeToString(rnd)
	msg := fmt.Sprintf("%s stack %s (requested by %s)", actions[first.Name], first.Name, p.Subject)
	if len(stacks) > 1 {
		msg = fmt.Sprintf("Adopt %s with %d dependency stack(s) (requested by %s)", first.Name, len(stacks)-1, p.Subject)
	}
	base, err := fg.BranchSHA(ctx, cfg.Branch)
	if err == nil {
		err = fg.CreateBranch(ctx, branch, base)
	}
	var files []string
	lastFolder := ""
	for _, ps := range stacks {
		if err != nil {
			break
		}
		var folder string
		folder, err = s.writeStackContract(ctx, fg, cfg, branch, msg, ps)
		lastFolder = folder
		files = append(files, fmt.Sprintf("- %s `%s` (%s/%s, business unit `%s`)", actions[ps.Name], folder+"/", ps.Env.Entity, ps.Env.Name, ps.BU))
	}
	if err != nil {
		return nil, http.StatusBadGateway, errors.New("writing to the contracts repository failed: " + err.Error())
	}
	if title == "" {
		title = fmt.Sprintf("%s stack %s (%s, %s/%s)", actions[first.Name], first.Name, first.BU, first.Env.Entity, first.Env.Name)
	}
	order := ""
	if len(stacks) > 1 {
		order = "Stacks are planned in dependency order: a stack that references another stack's outputs is planned once that stack has applied them.\n\n"
	}
	body := fmt.Sprintf("Requested in SrustiOps by **%s**.\n\n%s\n\n%s%s"+
		"SrustiOps plans this change, collects the required approvals and applies it **before** merging; the pull request merges itself once applied.",
		p.Subject, strings.Join(files, "\n"), order, note)
	pr, err := fg.OpenPR(ctx, branch, cfg.Branch, title, body)
	if err != nil {
		return nil, http.StatusBadGateway, errors.New("opening the pull request failed: " + err.Error())
	}
	// It is opened with the workspace's token: record who asked, so they
	// cannot approve its plans.
	if err := s.store.SetPRProposer(ctx, pr.Number, p.Subject); err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("recording the pull request: %w", err)
	}
	if live != nil {
		if err := s.store.AddZeroDiffPR(ctx, pr.Number, live.StackID, live.SourceRun, p.Subject); err != nil {
			return nil, http.StatusInternalServerError, fmt.Errorf("recording the pull request: %w", err)
		}
	}
	names := make([]string, 0, len(stacks))
	for _, ps := range stacks {
		names = append(names, ps.Name)
	}
	s.audit(ctx, p.Actor(), "stack.propose", "stack/"+first.Name, first.BU, map[string]any{"pr": pr.Number, "branch": branch, "stacks": names, "live_to_code": live != nil})
	n := pr.Number
	s.async(func(ctx2 context.Context) error { return s.planPR(ctx2, n) }) // also started by the webhook; planning twice reuses runs
	return map[string]any{"pr_number": pr.Number, "html_url": pr.URL, "branch": branch, "stacks": names, "file": lastFolder + "/", "provider": fg.Provider()}, 201, nil
}

// writeStackContract writes one stack's resource files to a branch; files of
// resources no longer in the stack are deleted (other files are kept).
func (s *Server) writeStackContract(ctx context.Context, fg forge.Forge, cfg *contracts.Config, branch, msg string, ps prStack) (string, error) {
	folder := path.Join(cfg.Path, ps.Name)
	if cfg.Layout == "nested" {
		folder = path.Join(cfg.Path, ps.Env.Entity, ps.Env.Name, ps.BU, ps.Name)
	}
	files, err := contracts.Render(ps.Spec, ps.Env.Name, ps.BU, ps.Env.Connection, cfg.Layout != "nested")
	if err != nil {
		return folder, errors.New("stack " + ps.Name + " cannot be written as contracts: " + err.Error())
	}
	existing, err := fg.ListDir(ctx, folder, branch)
	if err != nil {
		return folder, err
	}
	changes := map[string]*[]byte{}
	for n, b := range files {
		b := b
		changes[folder+"/"+n] = &b
	}
	for _, n := range existing {
		if _, keep := files[n]; !keep && (strings.HasSuffix(n, ".yaml") || strings.HasSuffix(n, ".yml")) {
			changes[folder+"/"+n] = nil
		}
	}
	_, err = fg.Commit(ctx, branch, msg, changes)
	return folder, err
}
