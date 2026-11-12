package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/itsPavanFeed/srustiops-backend/internal/spec"
	"github.com/itsPavanFeed/srustiops-backend/internal/store"
)

// Dependencies between stacks: a stack references another stack's outputs
// (stack/<stack>/<resource>.<output>). Before a stack is built, each
// reference becomes the other stack's applied output value. The stacks and
// their references form a DAG: a stack plans only once every stack it
// references has applied the outputs it needs, cycles are refused, and when
// an apply changes a stack's outputs, the stacks referencing it are planned.

// waitPrefix starts the problems that only mean "a referenced stack has not
// applied the output yet"; such a plan waits instead of failing.
const waitPrefix = "waits for stack "

// errWaiting marks an output that is not applied yet.
var errWaiting = errors.New("not applied yet")

// resolveStackRefs replaces a spec's references to other stacks with their
// applied outputs. It refuses unknown stacks, self-references and cycles.
func (s *Server) resolveStackRefs(ctx context.Context, stackName string, raw []byte) ([]byte, []string) {
	refs, err := spec.StackRefs(raw)
	if err != nil || len(refs) == 0 {
		return raw, nil
	}
	for _, r := range refs {
		if r.Stack == stackName {
			return nil, []string{r.String() + ": a stack cannot reference its own outputs; use " + r.Key()}
		}
	}
	if cyc := s.dependencyCycle(ctx, stackName, raw); cyc != "" {
		return nil, []string{"dependency cycle between stacks: " + cyc}
	}
	cache := map[string]map[string][]byte{}
	ids := map[string]string{}
	var probs []string
	out, errs := spec.ResolveStackRefs(raw, func(r spec.StackRef) (json.RawMessage, error) {
		if r.Stack == stackName {
			return nil, errors.New("a stack cannot reference its own outputs; use resource.output")
		}
		outs, ok := cache[r.Stack]
		if !ok {
			st, err := s.store.GetStack(ctx, r.Stack)
			if err != nil {
				return nil, fmt.Errorf("no stack named %s", r.Stack)
			}
			ids[r.Stack] = st.ID
			outs, _ = s.store.StackOutputs(ctx, st.ID)
			cache[r.Stack] = outs
		}
		sealed, ok := outs[r.Key()]
		if !ok {
			return nil, errWaiting
		}
		return s.sealer.Open(sealed, outputAAD(ids[r.Stack], r.Key()))
	})
	for _, e := range errs {
		msg := e.Error()
		if errors.Is(e, errWaiting) || strings.HasSuffix(msg, errWaiting.Error()) {
			p := spec.StackRefRe.FindStringSubmatch(strings.SplitN(msg, ":", 2)[0])
			stack := ""
			if p != nil {
				stack = p[1]
			}
			probs = append(probs, fmt.Sprintf("%s%s: %s is not applied yet", waitPrefix, stack, strings.SplitN(msg, ":", 2)[0]))
			continue
		}
		probs = append(probs, msg)
	}
	if len(probs) > 0 {
		sort.Strings(probs)
		return nil, probs
	}
	return out, nil
}

// dependencyCycle returns "a -> b -> a" when the stack, with this spec,
// would take part in a cycle of references.
func (s *Server) dependencyCycle(ctx context.Context, stackName string, raw []byte) string {
	specs, err := s.store.StackSpecs(ctx)
	if err != nil {
		return ""
	}
	specs[stackName] = raw
	state := map[string]int{} // 0 new, 1 visiting, 2 done
	var path []string
	var visit func(n string) string
	visit = func(n string) string {
		switch state[n] {
		case 1:
			i := 0
			for i < len(path) && path[i] != n {
				i++
			}
			return strings.Join(append(append([]string{}, path[i:]...), n), " -> ")
		case 2:
			return ""
		}
		state[n] = 1
		path = append(path, n)
		for _, d := range spec.DependsOn(specs[n]) {
			if c := visit(d); c != "" {
				return c
			}
		}
		path = path[:len(path)-1]
		state[n] = 2
		return ""
	}
	return visit(stackName)
}

// waitingOn lists the stacks build problems wait for; ok is false when any
// problem is something else.
func waitingOn(probs []string) (stacks []string, ok bool) {
	seen := map[string]bool{}
	for _, p := range probs {
		rest, is := strings.CutPrefix(p, waitPrefix)
		if !is {
			return nil, false
		}
		name, _, _ := strings.Cut(rest, ":")
		if !seen[name] {
			seen[name] = true
			stacks = append(stacks, name)
		}
	}
	sort.Strings(stacks)
	return stacks, len(probs) > 0
}

// deferRun records a plan to start once the stacks it waits for are applied.
func (s *Server) deferRun(ctx context.Context, st *store.Stack, by, reason string, waits []string) error {
	if err := s.store.AddPendingRun(ctx, st.ID, by, reason, waits); err != nil {
		return err
	}
	s.audit(ctx, by, "run.deferred", "stack/"+st.Name, st.BU, map[string]any{"waits_on": waits, "reason": reason})
	return nil
}

// afterApply moves the DAG on once a stack applied: deferred plans whose
// references are now all applied start, and when the stack's outputs
// changed, the stacks referencing it are planned.
func (s *Server) afterApply(ctx context.Context, run *store.Run) {
	if v, ok := s.outputsChanged.LoadAndDelete(run.StackID); ok && v.(bool) {
		if deps, err := s.store.Dependents(ctx, run.StackName); err == nil {
			for _, name := range deps {
				st, err := s.store.GetStack(ctx, name)
				if err != nil {
					continue
				}
				if _, err := s.store.PendingRunFor(ctx, st.ID); err == nil {
					continue // started below once it can
				}
				s.startStackPlan(ctx, st, "system:dependency", "outputs of stack "+run.StackName+" changed")
			}
		}
	}
	s.releasePending(ctx)
}

// releasePending starts every deferred plan that no longer waits.
func (s *Server) releasePending(ctx context.Context) {
	pend, err := s.store.PendingRuns(ctx)
	if err != nil {
		return
	}
	for _, p := range pend {
		st, err := s.store.GetStack(ctx, p.StackID)
		if err != nil {
			s.store.DeletePendingRun(ctx, p.StackID)
			continue
		}
		if s.startStackPlan(ctx, st, p.RequestedBy, p.Reason) {
			s.store.DeletePendingRun(ctx, p.StackID)
		}
	}
}

// startStackPlan queues an apply plan of a stack's contract, or defers it
// while referenced stacks are not applied. It reports whether a run started.
func (s *Server) startStackPlan(ctx context.Context, st *store.Stack, by, reason string) bool {
	env, err := s.stackEnv(ctx, st)
	if err != nil {
		return false
	}
	gen, _, probs := s.build(ctx, st.Name, st.BU, env, st.Spec)
	if probs != nil {
		if waits, ok := waitingOn(probs); ok {
			s.deferRun(ctx, st, by, reason, waits)
		} else {
			s.log.Warn("dependent stack does not build", "stack", st.Name, "problems", probs)
		}
		return false
	}
	run, err := s.store.CreateRun(ctx, st.ID, "apply", by, gen.Hash)
	if err != nil {
		return false // busy: its next plan picks the new outputs up
	}
	s.audit(ctx, by, "run.create", "run/"+run.ID, st.BU, map[string]string{"stack": st.Name, "operation": "apply", "reason": reason})
	s.runCreated(ctx, run.ID)
	return true
}

// stackDependencies lists the stacks a stack references, the stacks
// referencing it, and what a deferred plan of it waits for.
func (s *Server) stackDependencies(w http.ResponseWriter, r *http.Request) {
	st := s.visibleStack(w, r)
	if st == nil {
		return
	}
	deps, err := s.store.Dependents(r.Context(), st.Name)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	on := spec.DependsOn(st.Spec)
	if on == nil {
		on = []string{}
	}
	if deps == nil {
		deps = []string{}
	}
	writeJSON(w, 200, map[string]any{"depends_on": on, "dependents": deps, "waits_on": st.WaitsOn})
}

// buildAllowWaiting builds a spec, but accepts one whose only problems are
// references to stacks that have not applied those outputs yet: the spec is
// kept as written (validated in full when it first plans) and waits reports
// the stacks it plans after.
func (s *Server) buildAllowWaiting(ctx context.Context, name, bu string, env *store.Environment, raw []byte) (*spec.Generated, []string, []string) {
	gen, _, probs := s.build(ctx, name, bu, env, raw)
	if probs == nil {
		return gen, nil, nil
	}
	if waits, ok := waitingOn(probs); ok {
		if _, err := spec.Decode(raw); err != nil {
			return nil, nil, []string{err.Error()}
		}
		return &spec.Generated{Spec: raw}, waits, nil
	}
	return nil, nil, probs
}

// graphStack is one node of the dependency graph between stacks.
type graphStack struct {
	Name        string          `json:"name"`
	ID          string          `json:"id"`
	BU          string          `json:"bu"`
	Environment string          `json:"environment"`
	ManagedBy   string          `json:"managed_by"`
	Applied     bool            `json:"applied"`
	LastStatus  string          `json:"last_status,omitempty"`
	Resources   []graphResource `json:"resources"`
	DependsOn   []string        `json:"depends_on"`
	WaitsOn     []string        `json:"waits_on,omitempty"`
	Depth       int             `json:"depth"` // 0 = no dependencies; plans after every stack of a lower depth it references
}

type graphResource struct {
	Name      string   `json:"name"`
	Kind      string   `json:"kind"`
	Outputs   []string `json:"outputs"`             // what other resources may reference
	Available []string `json:"available,omitempty"` // outputs already applied (referencable now)
	Uses      []string `json:"uses,omitempty"`      // resources of the same stack it references
}

// stackGraph returns the stacks a person can see as a DAG: each stack's
// resources and their outputs, the stacks it references, and its depth in
// the creation order.
func (s *Server) stackGraph(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sts, err := s.store.ListStacks(ctx, visible(r))
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	cat := s.plat().cat
	nodes := map[string]*graphStack{}
	var out []*graphStack
	for _, st := range sts {
		n := &graphStack{Name: st.Name, ID: st.ID, BU: st.BU, Environment: st.Entity + "/" + st.Environment, ManagedBy: st.ManagedBy,
			Applied: st.LastAppliedAt != nil, DependsOn: spec.DependsOn(st.Spec), WaitsOn: st.WaitsOn, Resources: []graphResource{}}
		if n.DependsOn == nil {
			n.DependsOn = []string{}
		}
		if st.LastRun != nil {
			n.LastStatus = st.LastRun.Status
		}
		applied, _ := s.store.StackOutputs(ctx, st.ID)
		var sp spec.Stack
		json.Unmarshal(st.Spec, &sp)
		for _, m := range sp.Modules {
			cm := cat.Kind(m.Kind)
			if cm == nil {
				cm = cat.Module(m.Module)
			}
			gr := graphResource{Name: m.Name, Kind: m.Kind, Outputs: []string{}}
			if cm != nil {
				gr.Kind = cm.Kind
				gr.Outputs = append(gr.Outputs, cm.Outputs...)
			}
			for _, o := range gr.Outputs {
				if _, ok := applied[m.Name+"."+o]; ok {
					gr.Available = append(gr.Available, o)
				}
			}
			raw, _ := json.Marshal(m.Inputs)
			for _, other := range sp.Modules {
				if other.Name != m.Name && strings.Contains(string(raw), `"`+other.Name+`.`) {
					gr.Uses = append(gr.Uses, other.Name)
				}
			}
			n.Resources = append(n.Resources, gr)
		}
		nodes[st.Name] = n
		out = append(out, n)
	}
	// Depth: the longest chain of references below a stack (stacks not
	// visible to this person still count as one level).
	memo := map[string]int{}
	var depth func(name string, seen map[string]bool) int
	depth = func(name string, seen map[string]bool) int {
		if d, ok := memo[name]; ok {
			return d
		}
		n := nodes[name]
		if n == nil || seen[name] {
			return 0
		}
		seen[name] = true
		d := 0
		for _, dep := range n.DependsOn {
			if x := depth(dep, seen) + 1; x > d {
				d = x
			}
		}
		delete(seen, name)
		memo[name] = d
		return d
	}
	for _, n := range out {
		n.Depth = depth(n.Name, map[string]bool{})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Depth != out[j].Depth {
			return out[i].Depth < out[j].Depth
		}
		return out[i].Name < out[j].Name
	})
	if out == nil {
		out = []*graphStack{}
	}
	writeJSON(w, 200, map[string]any{"stacks": out})
}
