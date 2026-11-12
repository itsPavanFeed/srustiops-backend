package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/itsPavanFeed/srustiops-backend/internal/catalog"
	"github.com/itsPavanFeed/srustiops-backend/internal/policy"
	"github.com/itsPavanFeed/srustiops-backend/internal/spec"
	"github.com/itsPavanFeed/srustiops-backend/internal/store"
)

// Live -> code: when a drift check (or an import plan stopped by the
// zero-diff gate) shows that live resources differ from the code, the
// platform proposes the contract change that makes the code match the live
// resources. Attributes a kind maps to one of its inputs take the live value.
// For resources being adopted (imported), the kind's live rules also record
// baseline gaps and drop imports the module cannot express, so the contract
// matches the resource as it exists. Enforced baselines of resources already
// managed never change this way: drift in them can only be reverted.
// Ownership labels and OpenTofu-only attributes are not differences: the
// zero-diff gate allows them.

type liveChange struct {
	Resource string          `json:"resource"` // module instance (resource name in the contract)
	Kind     string          `json:"kind"`     // input | baseline_gap | drop_import
	Input    string          `json:"input"`    // the input or gap argument ("" for drop_import)
	Address  string          `json:"address"`
	Path     string          `json:"path"`
	From     json.RawMessage `json:"from,omitempty"`
	To       json.RawMessage `json:"to"`
}

type liveSkip struct {
	Address string `json:"address"`
	Path    string `json:"path"`
	Live    any    `json:"live,omitempty"`
	Code    any    `json:"code,omitempty"`
	Reason  string `json:"reason"`
}

type liveProposal struct {
	Run       string          `json:"run"`
	Stack     string          `json:"stack"`
	ManagedBy string          `json:"managed_by"`
	Changes   []liveChange    `json:"changes"`
	Skipped   []liveSkip      `json:"skipped"`
	Problems  []string        `json:"problems,omitempty"` // the changed spec does not validate
	Spec      json.RawMessage `json:"spec,omitempty"`
	// Stale says why this run can no longer be matched (a newer run, or the
	// contract or state changed since); "" when it can.
	Stale string `json:"stale,omitempty"`
	// Via is how applying it proceeds: "pull_request" or "candidate".
	Via string `json:"via"`
}

var placeholderAny = regexp.MustCompile(`\{\{[a-z]+\}\}`)

// addrMatches compares an address inside a module with a kind's mapping,
// where placeholders ({{name}}) match any key.
func addrMatches(pattern, addr string) bool {
	if !strings.Contains(pattern, "{{") {
		return pattern == addr
	}
	parts := placeholderAny.Split(pattern, -1)
	for i := range parts {
		parts[i] = regexp.QuoteMeta(parts[i])
	}
	re, err := regexp.Compile("^" + strings.Join(parts, `[^"\]]+`) + "$")
	return err == nil && re.MatchString(addr)
}

// ownershipLabel reports keys the platform (or the Google provider's
// attribution) adds to every resource; they never flow into a contract.
func ownershipLabel(k string) bool { return policy.OwnershipLabel(k) }

func (s *Server) liveToCode(ctx context.Context, st *store.Stack, run *store.Run) (*liveProposal, error) {
	var sum policy.Summary
	if err := json.Unmarshal(run.PlanSummary, &sum); err != nil {
		return nil, fmt.Errorf("the run has no plan to compare")
	}
	resources := sum.Resources
	if run.Operation == "drift" {
		resources = sum.Drift
	}
	var stack spec.Stack
	if err := json.Unmarshal(runSpec(st, run), &stack); err != nil {
		return nil, err
	}
	cat := s.plat().cat
	out := &liveProposal{Run: run.ID, Stack: st.Name, ManagedBy: st.ManagedBy, Changes: []liveChange{}, Skipped: []liveSkip{}}
	byName := map[string]*spec.ModuleRef{}
	for i := range stack.Modules {
		byName[stack.Modules[i].Name] = &stack.Modules[i]
	}
	drop := map[string]bool{}
	for _, rc := range resources {
		if policy.OwnershipLabelsOnly(rc) {
			continue // allowed by the gate: not a difference
		}
		inst, inner, ok := splitModuleAddr(rc.Address)
		m := byName[inst]
		var cm *catalog.Module
		if ok && m != nil {
			cm = cat.Module(m.Module)
			if cm == nil {
				cm = cat.Kind(m.Kind)
			}
		}
		// The kind's live rule for the resource, if any, covers all of its
		// differences at once (an import being adopted, or drift).
		covered := false
		if cm != nil && cm.Adopt != nil {
			live := map[string]any{}
			for _, d := range rc.Diff {
				live[d.Path] = d.Live
			}
			for _, rule := range cm.Adopt.Live {
				if rule.Resource != inner || !liveMatches(live, rule.When) {
					continue
				}
				gaps, ok := fillLive(rule.Gaps, live)
				if !ok {
					break // a needed live value is hidden: a person decides
				}
				for _, k := range sortedAnyKeys(gaps.(map[string]any)) {
					to, _ := json.Marshal(gaps.(map[string]any)[k])
					if string(m.BaselineGaps[k]) == string(to) {
						continue
					}
					out.Changes = append(out.Changes, liveChange{Resource: inst, Kind: "baseline_gap", Input: k, Address: rc.Address, From: m.BaselineGaps[k], To: to})
					if m.BaselineGaps == nil {
						m.BaselineGaps = map[string]json.RawMessage{}
					}
					m.BaselineGaps[k] = to
				}
				for _, k := range rule.ClearGaps {
					if from, ok := m.BaselineGaps[k]; ok {
						out.Changes = append(out.Changes, liveChange{Resource: inst, Kind: "baseline_gap", Input: k, Address: rc.Address, From: from, To: json.RawMessage(`"removed: the baseline applies again"`)})
						delete(m.BaselineGaps, k)
					}
				}
				if im := rule.AddImport; im != nil {
					to := "module." + inst + "." + im.To
					id, ok := fillInputs(im.ID, m.Inputs)
					listed := false
					for _, x := range stack.Imports {
						listed = listed || x.To == to
					}
					if ok && !listed {
						stack.Imports = append(stack.Imports, spec.Import{To: to, ID: id})
						idj, _ := json.Marshal(id)
						out.Changes = append(out.Changes, liveChange{Resource: inst, Kind: "add_import", Input: im.To, Address: to, To: idj})
					}
				}
				if rule.DropImport && !drop[rc.Address] {
					drop[rc.Address] = true
					out.Changes = append(out.Changes, liveChange{Resource: inst, Kind: "drop_import", Address: rc.Address, To: json.RawMessage(`"not managed: the module cannot express its live state"`)})
				}
				covered = true
				break
			}
		}
		if covered {
			continue
		}
		for _, d := range rc.Diff {
			if policy.LocalOnly(d.Path) {
				continue
			}
			skip := liveSkip{Address: rc.Address, Path: d.Path, Live: d.Live, Code: d.Code}
			switch {
			case cm == nil:
				skip.Reason = "not part of a resource in this stack"
			case d.Live == "(sensitive)" || d.Live == "(large value)":
				skip.Reason = "the live value is sensitive or too large to copy; update it by hand"
			case cm.Adopt == nil:
				skip.Reason = "kind " + cm.Kind + " does not map live attributes to inputs yet"
			}
			if skip.Reason != "" {
				out.Skipped = append(out.Skipped, skip)
				continue
			}
			input := ""
			for name, ref := range cm.Adopt.Attributes {
				if ref.Path == d.Path && addrMatches(ref.Resource, inner) {
					input = name
					break
				}
			}
			if input == "" {
				skip.Reason = "this attribute does not map to an input of " + cm.Kind + " (it may be part of the enforced baseline, which can only be reverted)"
				out.Skipped = append(out.Skipped, skip)
				continue
			}
			live := d.Live
			if mm, ok := live.(map[string]any); ok && cm.Input(input) != nil && strings.HasPrefix(cm.Input(input).Type, "map(") {
				clean := map[string]any{}
				for k, v := range mm {
					if !ownershipLabel(k) {
						clean[k] = v
					}
				}
				live = clean
			}
			to, _ := json.Marshal(live)
			if string(m.Inputs[input]) == string(to) {
				continue
			}
			if m.Inputs == nil {
				m.Inputs = map[string]json.RawMessage{}
			}
			out.Changes = append(out.Changes, liveChange{Resource: inst, Kind: "input", Input: input, Address: rc.Address, Path: d.Path, From: m.Inputs[input], To: to})
			m.Inputs[input] = to
		}
	}
	sort.SliceStable(out.Changes, func(i, j int) bool {
		return out.Changes[i].Resource+out.Changes[i].Input < out.Changes[j].Resource+out.Changes[j].Input
	})
	if len(out.Changes) == 0 {
		return out, nil
	}
	kept := stack.Imports[:0]
	for _, im := range stack.Imports {
		if !drop[im.To] {
			kept = append(kept, im)
		}
	}
	stack.Imports = kept
	raw, _ := json.Marshal(stack)
	env, err := s.stackEnv(ctx, st)
	if err != nil {
		return nil, err
	}
	gen, _, probs := s.build(ctx, st.Name, st.BU, env, raw)
	if probs != nil {
		out.Problems = probs
		return out, nil
	}
	out.Spec = gen.Spec
	return out, nil
}

func sortedAnyKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// splitModuleAddr splits module.<instance>.<rest> into the instance and the
// address inside it.
func splitModuleAddr(addr string) (string, string, bool) {
	rest, ok := strings.CutPrefix(addr, "module.")
	if !ok {
		return "", "", false
	}
	inst, inner, ok := strings.Cut(rest, ".")
	return inst, inner, ok
}

func (s *Server) liveRun(w http.ResponseWriter, r *http.Request) (*store.Stack, *store.Run, bool) {
	run := s.visibleRun(w, r)
	if run == nil {
		return nil, nil, false
	}
	st, err := s.store.GetStack(r.Context(), run.StackID)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return nil, nil, false
	}
	return st, run, true
}

// liveStale says why a run can no longer be matched to live, or "". Only the
// stack's latest run, made against its current contract and state, reflects
// what is live now; an older one would push back values no longer there.
func (s *Server) liveStale(ctx context.Context, st *store.Stack, run *store.Run) string {
	if runs, err := s.store.LatestRuns(ctx, st.ID, 1); err == nil && len(runs) > 0 && runs[0].ID != run.ID {
		return fmt.Sprintf("a newer run (%s, %s) exists for this stack; check drift again or use the latest run", runs[0].ID[:8], runs[0].Operation)
	}
	if _, serial, err := s.store.CurrentState(ctx, st.ID); err == nil && run.StateSerial != nil && serial != *run.StateSerial {
		return "the stack's state changed after this run; check drift again"
	}
	if env, err := s.stackEnv(ctx, st); err == nil {
		if gen, _, probs := s.build(ctx, st.Name, st.BU, env, runSpec(st, run)); probs == nil && gen.Hash != run.ConfigHash {
			return "the contract changed after this run; check drift again"
		}
	}
	return ""
}

// liveVia: pull requests for Git stacks, and for console stacks once the
// tenant has a contracts repository; otherwise a candidate plan.
func (s *Server) liveVia(ctx context.Context, st *store.Stack) string {
	if st.ManagedBy == "git" {
		return "pull_request"
	}
	if _, _, err := s.prContext(ctx); err == nil {
		return "pull_request"
	}
	return "candidate"
}

// getLiveToCode shows what live -> code would change.
func (s *Server) getLiveToCode(w http.ResponseWriter, r *http.Request) {
	st, run, ok := s.liveRun(w, r)
	if !ok {
		return
	}
	prop, err := s.liveToCode(r.Context(), st, run)
	if err != nil {
		writeErr(w, 422, err.Error())
		return
	}
	prop.Stale, prop.Via = s.liveStale(r.Context(), st, run), s.liveVia(r.Context(), st)
	writeJSON(w, 200, prop)
}

// applyLiveToCode makes the contract match the live resources. With a
// contracts repository it opens a pull request (its plan must pass the
// zero-diff gate, then approvals, apply and merge, and the database takes the
// contract); without one, a candidate plan does the same and the stack keeps
// the contract once that is applied (or changes nothing at all).
func (s *Server) applyLiveToCode(w http.ResponseWriter, r *http.Request) {
	p := user(r)
	st, run, ok := s.liveRun(w, r)
	if !ok {
		return
	}
	if !p.CanChange(st.BU) {
		writeErr(w, http.StatusForbidden, "changing this stack needs the developer or admin role in "+st.BU)
		return
	}
	ctx := r.Context()
	if why := s.liveStale(ctx, st, run); why != "" {
		writeErr(w, 409, why)
		return
	}
	prop, err := s.liveToCode(ctx, st, run)
	switch {
	case err != nil:
		writeErr(w, 422, err.Error())
		return
	case len(prop.Changes) == 0:
		writeErr(w, 422, "no live value maps to this stack's contract; update it by hand")
		return
	case len(prop.Problems) > 0:
		writeErr(w, 422, "the live values do not pass the kind's checks", prop.Problems...)
		return
	}
	if prop.Via = s.liveVia(ctx, st); prop.Via == "pull_request" {
		env, err := s.stackEnv(ctx, st)
		if err != nil {
			s.writeStoreErr(w, err, "")
			return
		}
		gen, _, probs := s.build(ctx, st.Name, st.BU, env, prop.Spec)
		if probs != nil {
			writeErr(w, 422, "stack spec rejected", probs...)
			return
		}
		note := fmt.Sprintf("Live -> code from run `%s`: the contract now matches the live resources (%d change(s)). Its plan must pass the zero-diff gate.\n\n", run.ID[:8], len(prop.Changes))
		if st.ManagedBy != "git" {
			note += "This stack was managed in the console; once this pull request is applied it is managed through Git.\n\n"
		}
		out, code, err := s.openContractPRWith(ctx, p, st.Name, st.BU, env, gen, "Match live resources: "+st.Name, note, &liveMatch{StackID: st.ID, SourceRun: run.ID})
		if err != nil {
			writeErr(w, code, err.Error())
			return
		}
		s.audit(ctx, p.Actor(), "stack.live_to_code", "stack/"+st.Name, st.BU, map[string]any{"run": run.ID, "changes": prop.Changes, "pr": out["pr_number"]})
		writeJSON(w, 201, map[string]any{"proposal": prop, "pull_request": out})
		return
	}
	next, err := s.applyLiveProposal(ctx, st, run, prop, p.Actor(), p.Subject, "live -> code")
	if err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	writeJSON(w, 201, map[string]any{"proposal": prop, "run": next})
}

var inputTmplRe = regexp.MustCompile(`\{\{input:([A-Za-z0-9_-]+)\}\}`)

// fillInputs replaces {{input:<name>}} with the resource's string inputs.
func fillInputs(t string, inputs map[string]json.RawMessage) (string, bool) {
	ok := true
	out := inputTmplRe.ReplaceAllStringFunc(t, func(m string) string {
		var v string
		if json.Unmarshal(inputs[inputTmplRe.FindStringSubmatch(m)[1]], &v) != nil || v == "" {
			ok = false
		}
		return v
	})
	return out, ok
}
