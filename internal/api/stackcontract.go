package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/itsPavanFeed/srustiops-backend/internal/contracts"
	"github.com/itsPavanFeed/srustiops-backend/internal/policy"
	"github.com/itsPavanFeed/srustiops-backend/internal/spec"
	"github.com/itsPavanFeed/srustiops-backend/internal/store"
)

// A stack's contract, as the YAML files a person reads and edits: one file
// per resource, naming its environment and business unit. Console stacks are
// updated directly (and planned); Git-managed stacks get a pull request.

func (s *Server) getStackContract(w http.ResponseWriter, r *http.Request) {
	st := s.visibleStack(w, r)
	if st == nil {
		return
	}
	env, err := s.stackEnv(r.Context(), st)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	files, err := contracts.Render(s.withKinds(st.Spec), env.Name, st.BU, env.Connection, true)
	if err != nil {
		writeErr(w, 422, "the stack cannot be written as a contract: "+err.Error())
		return
	}
	out := map[string]string{}
	for k, v := range files {
		out[k] = string(v)
	}
	writeJSON(w, 200, map[string]any{"stack": st.Name, "managed_by": st.ManagedBy, "files": out, "imports_pending": st.ImportsPending > 0})
}

// putStackContract parses edited contract files back into the stack.
func (s *Server) putStackContract(w http.ResponseWriter, r *http.Request) {
	p := user(r)
	st := s.visibleStack(w, r)
	if st == nil {
		return
	}
	if !p.CanChange(st.BU) {
		writeErr(w, http.StatusForbidden, "editing stacks needs the developer or admin role in "+st.BU)
		return
	}
	var b struct {
		Files map[string]string `json:"files"`
		Plan  bool              `json:"plan"` // console stacks: start a plan after saving
	}
	if !decode(w, r, &b) {
		return
	}
	if len(b.Files) == 0 || len(b.Files) > 100 {
		writeErr(w, 422, "a contract has 1 to 100 resource files")
		return
	}
	ctx := r.Context()
	env, err := s.stackEnv(ctx, st)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	raw := map[string][]byte{}
	for name, content := range b.Files {
		base := path.Base(strings.TrimSpace(name))
		if !strings.HasSuffix(base, ".yaml") && !strings.HasSuffix(base, ".yml") || base != strings.TrimSpace(name) {
			writeErr(w, 422, "file names are <resource>.yaml, without folders: "+name)
			return
		}
		raw[st.Name+"/"+base] = []byte(content)
	}
	cs, probs := contracts.ParseLayout(raw, "", "flat")
	if len(probs) > 0 || len(cs) != 1 {
		lines := make([]string, 0, len(probs))
		for f, p := range probs {
			lines = append(lines, strings.TrimPrefix(f, st.Name+"/")+": "+p)
		}
		sort.Strings(lines)
		writeErr(w, 422, "the contract has problems", lines...)
		return
	}
	c := cs[0]
	switch {
	case c.Environment != env.Name && c.Environment != env.Entity+":"+env.Name:
		writeErr(w, 422, fmt.Sprintf("a stack cannot move to another environment (metadata.environment is %q, the stack is in %q); create a new stack instead", c.Environment, env.Name))
		return
	case c.BU != st.BU:
		writeErr(w, 422, fmt.Sprintf("a stack cannot move to another business unit (metadata.bu is %q, the stack belongs to %q)", c.BU, st.BU))
		return
	case c.Connection != "" && c.Connection != env.Connection:
		writeErr(w, 422, "a stack cannot move to another cloud connection; create a new stack instead")
		return
	}
	gen, waits, probs2 := s.buildAllowWaiting(ctx, st.Name, st.BU, env, c.Spec)
	if probs2 != nil {
		writeErr(w, 422, "stack spec rejected", probs2...)
		return
	}
	if st.ManagedBy == "git" {
		out, code, err := s.openContractPR(ctx, p, st.Name, st.BU, env, gen, "Update stack "+st.Name, "Edited in the console.\n\n")
		if err != nil {
			writeErr(w, code, err.Error())
			return
		}
		s.audit(ctx, p.Actor(), "stack.contract.propose", "stack/"+st.Name, st.BU, map[string]any{"pr": out["pr_number"]})
		writeJSON(w, 201, map[string]any{"pull_request": out})
		return
	}
	if err := s.store.UpdateStack(ctx, st.ID, gen.Spec); err != nil {
		s.writeStoreErr(w, err, "the stack has an active run; finish or discard it first")
		return
	}
	s.audit(ctx, p.Actor(), "stack.update", "stack/"+st.Name, st.BU, map[string]any{"before": st.Spec, "after": gen.Spec, "via": "contract"})
	resp := map[string]any{}
	if b.Plan && len(waits) > 0 {
		if err := s.deferRun(ctx, st, p.Subject, "contract edited by "+p.Subject, waits); err != nil {
			s.writeStoreErr(w, err, "")
			return
		}
		resp["waits_on"] = waits
	} else if b.Plan {
		run, err := s.store.CreateRun(ctx, st.ID, "apply", p.Subject, gen.Hash)
		if err != nil {
			s.writeStoreErr(w, err, "")
			return
		}
		s.audit(ctx, p.Actor(), "run.create", "run/"+run.ID, st.BU, map[string]string{"stack": st.Name, "operation": "apply"})
		s.runCreated(ctx, run.ID)
		resp["run"] = run
	}
	st, _ = s.store.GetStack(ctx, st.ID)
	resp["stack"] = st
	writeJSON(w, 200, resp)
}

func stackImports(spec json.RawMessage) int {
	var v struct {
		Imports []json.RawMessage `json:"imports"`
	}
	json.Unmarshal(spec, &v)
	return len(v.Imports)
}

// settleImports removes the import blocks of a console stack once its import
// has been applied: the resources are in state, and the stack is from then on
// like any stack written by hand. (Git stacks keep them until the contract is
// edited; an import of a resource already in state changes nothing.)
func (s *Server) settleImports(ctx context.Context, run *store.Run) {
	st, err := s.store.GetStack(ctx, run.StackID)
	if err != nil || st.ManagedBy != "ui" || stackImports(st.Spec) == 0 {
		return
	}
	var v map[string]json.RawMessage
	if json.Unmarshal(st.Spec, &v) != nil {
		return
	}
	delete(v, "imports")
	spec, _ := json.Marshal(v)
	if err := s.store.UpdateStack(ctx, st.ID, spec); err != nil {
		s.log.Warn("removing applied imports from the stack", "stack", st.Name, "err", err)
		return
	}
	s.audit(ctx, "system:imports", "stack.imports_settled", "stack/"+st.Name, st.BU, map[string]any{"run": run.ID, "imports": stackImports(st.Spec)})
}

// withKinds fills in the kind of resources stored by module ID only (stacks
// created before kinds), so every stack renders as a contract.
func (s *Server) withKinds(spec json.RawMessage) json.RawMessage {
	var v map[string]json.RawMessage
	if json.Unmarshal(spec, &v) != nil {
		return spec
	}
	var mods []map[string]json.RawMessage
	if json.Unmarshal(v["modules"], &mods) != nil {
		return spec
	}
	cat := s.plat().cat
	for _, m := range mods {
		var kind, module string
		json.Unmarshal(m["kind"], &kind)
		json.Unmarshal(m["module"], &module)
		if kind == "" && module != "" {
			if cm := cat.Module(module); cm != nil {
				m["kind"], _ = json.Marshal(cm.Kind)
			}
		}
	}
	v["modules"], _ = json.Marshal(mods)
	out, _ := json.Marshal(v)
	return out
}

var importAddrRe = regexp.MustCompile(`^module\.([A-Za-z0-9_-]+)\.(.+)$`)

// adoptAsItExists handles a plan that failed because import targets do not
// exist in the cloud (a bucket without a policy). When every one of them is
// an optional import of its kind, the console stack drops those imports,
// records the kind's baseline gaps for them, so the code describes exactly
// what exists, and plans again; the zero-diff gate still applies to that plan.
// It returns a note for the run's error, or "" when nothing was done.
func (s *Server) adoptAsItExists(ctx context.Context, run *store.Run, missing []string) string {
	if len(missing) == 0 || run.Operation != "apply" {
		return ""
	}
	st, err := s.store.GetStack(ctx, run.StackID)
	if err != nil {
		return ""
	}
	if st.ManagedBy != "ui" {
		return "Not in the cloud: " + strings.Join(missing, ", ") + ". Remove these imports from the contract and add the kind's baseline gaps for them."
	}
	var sp spec.Stack
	if json.Unmarshal(runSpec(st, run), &sp) != nil {
		return ""
	}
	cat := s.plat().cat
	gaps := map[string]map[string]any{} // module instance -> gaps
	drop := map[string]bool{}
	for _, addr := range missing {
		m := importAddrRe.FindStringSubmatch(addr)
		listed := false
		for _, im := range sp.Imports {
			listed = listed || im.To == addr
		}
		var ref *spec.ModuleRef
		for i := range sp.Modules {
			if m != nil && sp.Modules[i].Name == m[1] {
				ref = &sp.Modules[i]
			}
		}
		if !listed || ref == nil {
			return ""
		}
		cm := cat.Kind(ref.Kind)
		if cm == nil {
			cm = cat.Module(ref.Module)
		}
		var g map[string]any
		ok := false
		if cm != nil && cm.Adopt != nil {
			g, ok = cm.Adopt.GapsFor(m[2])
		}
		if !ok {
			return fmt.Sprintf("%s does not exist in the cloud, and %s cannot be adopted without it.", addr, ref.Kind)
		}
		drop[addr] = true
		if gaps[ref.Name] == nil {
			gaps[ref.Name] = map[string]any{}
		}
		for k, v := range g {
			gaps[ref.Name][k] = v
		}
	}
	kept := sp.Imports[:0]
	for _, im := range sp.Imports {
		if !drop[im.To] {
			kept = append(kept, im)
		}
	}
	sp.Imports = kept
	for i := range sp.Modules {
		for k, v := range gaps[sp.Modules[i].Name] {
			if sp.Modules[i].BaselineGaps == nil {
				sp.Modules[i].BaselineGaps = map[string]json.RawMessage{}
			}
			sp.Modules[i].BaselineGaps[k], _ = json.Marshal(v)
		}
	}
	raw, _ := json.Marshal(sp)
	next, err := s.planCandidate(ctx, st, run, raw, "system:adopt", run.CreatedBy, "adopt as it exists", map[string]any{"missing": missing, "gaps": gaps})
	if err != nil {
		s.log.Warn("adopting as it exists", "stack", st.Name, "err", err)
		return ""
	}
	return fmt.Sprintf("Not in the cloud, so not imported: %s. Run %s plans the contract without them (recorded as baseline gaps); the stack saves it once that plan passes the zero-diff gate.", strings.Join(missing, ", "), next.ID)
}

// applyLiveProposal plans a console stack's live -> code proposal as a
// candidate: the stack keeps its contract until that plan passes the
// zero-diff gate, and then saves the proposal automatically.
func (s *Server) applyLiveProposal(ctx context.Context, st *store.Stack, run *store.Run, prop *liveProposal, actor, subject, reason string) (*store.Run, error) {
	return s.planCandidate(ctx, st, run, prop.Spec, actor, subject, reason, map[string]any{"changes": prop.Changes})
}

// planCandidate queues a plan of a proposed contract for a console stack.
func (s *Server) planCandidate(ctx context.Context, st *store.Stack, run *store.Run, candidate json.RawMessage, actor, subject, reason string, detail map[string]any) (*store.Run, error) {
	env, err := s.stackEnv(ctx, st)
	if err != nil {
		return nil, err
	}
	gen, _, probs := s.build(ctx, st.Name, st.BU, env, candidate)
	if probs != nil {
		return nil, fmt.Errorf("stack spec rejected: %s", strings.Join(probs, "; "))
	}
	next, err := s.store.CreateCandidateRun(ctx, st.ID, subject, gen.Hash, gen.Spec, run.ID)
	if err != nil {
		return nil, err
	}
	detail["run"], detail["candidate_run"], detail["before"], detail["proposed"] = run.ID, next.ID, runSpec(st, run), gen.Spec
	s.audit(ctx, actor, "stack.contract.candidate", "stack/"+st.Name, st.BU, detail)
	s.audit(ctx, actor, "run.create", "run/"+next.ID, st.BU, map[string]string{"stack": st.Name, "operation": "apply", "reason": reason})
	s.runCreated(ctx, next.ID)
	return next, nil
}

// saveCandidate keeps a candidate run's contract once it is proven: after
// its apply succeeded, or right away when its plan changes nothing at all.
// Imports of resources already in state (the plan did not import them) are
// left out. Pull-request runs are recorded by adoptPRSpec instead.
func (s *Server) saveCandidate(ctx context.Context, run *store.Run, sum *policy.Summary) {
	if len(run.Spec) == 0 || run.PRNumber != nil {
		return
	}
	st, err := s.store.GetStack(ctx, run.StackID)
	if err != nil || st.ManagedBy != "ui" {
		return
	}
	saved := run.Spec
	if sum != nil {
		saved, _ = withoutSettledImports(run.Spec, sum)
	}
	if err := s.store.SaveCandidateSpec(ctx, st.ID, saved); err != nil {
		s.log.Warn("saving the matched contract", "stack", st.Name, "err", err)
		return
	}
	s.audit(ctx, "system:zero-diff", "stack.update", "stack/"+st.Name, st.BU, map[string]any{"before": st.Spec, "after": json.RawMessage(saved), "via": "matched contract proven by run", "run": run.ID})
}

// settleImportsFromPlan removes from a console stack's contract the imports
// its latest plan did not perform: those resources are already in state, so
// the blocks only make the stack look as if imports were pending.
func (s *Server) settleImportsFromPlan(ctx context.Context, run *store.Run, sum *policy.Summary) {
	if len(run.Spec) > 0 || run.PRNumber != nil {
		return // candidates and pull requests carry their own contract
	}
	st, err := s.store.GetStack(ctx, run.StackID)
	if err != nil || st.ManagedBy != "ui" {
		return
	}
	spec, removed := withoutSettledImports(st.Spec, sum)
	if len(removed) == 0 {
		return
	}
	if err := s.store.SaveCandidateSpec(ctx, st.ID, spec); err != nil {
		return
	}
	s.audit(ctx, "system:imports", "stack.imports_settled", "stack/"+st.Name, st.BU, map[string]any{"run": run.ID, "already_in_state": removed})
}

// withoutSettledImports drops the imports a plan did not perform.
func withoutSettledImports(raw json.RawMessage, sum *policy.Summary) (json.RawMessage, []string) {
	var v map[string]json.RawMessage
	var imps []spec.Import
	if json.Unmarshal(raw, &v) != nil || json.Unmarshal(v["imports"], &imps) != nil || len(imps) == 0 {
		return raw, nil
	}
	importing := map[string]bool{}
	for _, r := range sum.Resources {
		if r.Importing {
			importing[r.Address] = true
		}
	}
	var kept []spec.Import
	var removed []string
	for _, im := range imps {
		if importing[im.To] {
			kept = append(kept, im)
		} else {
			removed = append(removed, im.To)
		}
	}
	if len(removed) == 0 {
		return raw, nil
	}
	if len(kept) == 0 {
		delete(v, "imports")
	} else {
		v["imports"], _ = json.Marshal(kept)
	}
	out, _ := json.Marshal(v)
	return out, removed
}

// livePath walks a live attribute value: "rule.0.bucket_key_enabled".
func livePath(live map[string]any, path string) (any, bool) {
	parts := strings.Split(path, ".")
	v, ok := live[parts[0]]
	if !ok {
		return nil, false
	}
	for _, p := range parts[1:] {
		switch t := v.(type) {
		case []any:
			i, err := strconv.Atoi(p)
			if err != nil || i < 0 || i >= len(t) {
				return nil, true
			}
			v = t[i]
		case map[string]any:
			v = t[p]
		case nil:
			return nil, true
		default:
			return nil, false
		}
	}
	if str, ok := v.(string); ok && (str == "(sensitive)" || str == "(large value)") {
		return nil, false
	}
	return v, true
}

func liveMatches(live map[string]any, when map[string]any) bool {
	for path, want := range when {
		got, ok := livePath(live, path)
		a, _ := json.Marshal(got)
		b, _ := json.Marshal(want)
		if !ok || string(a) != string(b) {
			return false
		}
	}
	return true
}

var liveTmplRe = regexp.MustCompile(`^\{\{live:([A-Za-z0-9_.]+)\}\}$`)

// fillLive replaces "{{live:path}}" values; nulls are left out.
func fillLive(v any, live map[string]any) (any, bool) {
	switch t := v.(type) {
	case string:
		if m := liveTmplRe.FindStringSubmatch(t); m != nil {
			return livePath(live, m[1])
		}
		return t, true
	case map[string]any:
		out := map[string]any{}
		for k, x := range t {
			y, ok := fillLive(x, live)
			if !ok {
				return nil, false
			}
			if y != nil {
				out[k] = y
			}
		}
		return out, true
	case []any:
		out := make([]any, 0, len(t))
		for _, x := range t {
			y, ok := fillLive(x, live)
			if !ok {
				return nil, false
			}
			out = append(out, y)
		}
		return out, true
	}
	return v, true
}

// importAddrs lists a spec's import addresses.
func importAddrs(raw json.RawMessage) []string {
	var sp struct {
		Imports []spec.Import `json:"imports"`
	}
	json.Unmarshal(raw, &sp)
	out := make([]string, 0, len(sp.Imports))
	for _, im := range sp.Imports {
		out = append(out, im.To)
	}
	return out
}

// recordSettledImports marks imports as done so the stack stops showing them
// as pending: all of an applied run's imports, or (sum given) those a plan
// with no changes did not perform because the resources are in state.
func (s *Server) recordSettledImports(ctx context.Context, run *store.Run, sum *policy.Summary) {
	st, err := s.store.GetStack(ctx, run.StackID)
	if err != nil {
		return
	}
	addrs := importAddrs(runSpec(st, run))
	if sum != nil {
		_, addrs = withoutSettledImports(runSpec(st, run), sum)
	}
	if err := s.store.SettleImports(ctx, st.ID, addrs); err != nil {
		s.log.Warn("recording applied imports", "stack", st.Name, "err", err)
	}
}
