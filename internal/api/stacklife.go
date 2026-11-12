package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/identity"
	"github.com/itsPavanFeed/srustiops-backend/internal/policy"
	"github.com/itsPavanFeed/srustiops-backend/internal/spec"
	"github.com/itsPavanFeed/srustiops-backend/internal/store"
)

// ---- the stack page: resources, outputs, lock, delete ----

// stackResources turns the resources a plan saw in state into the stack's list.
func stackResources(rs []policy.StateResource) []store.StackResource {
	out := make([]store.StackResource, 0, len(rs))
	for _, r := range rs {
		mod := ""
		if rest, ok := strings.CutPrefix(r.Address, "module."); ok {
			mod, _, _ = strings.Cut(rest, ".")
			if i := strings.IndexByte(mod, '['); i >= 0 {
				mod = mod[:i]
			}
		}
		out = append(out, store.StackResource{Address: r.Address, Type: r.Type, Module: mod, ID: r.ID})
	}
	return out
}

// stackResourceView lists what a stack manages (from its last plan or apply)
// and the inventory items its cloud tags tie to it.
func (s *Server) stackResourceView(w http.ResponseWriter, r *http.Request) {
	st := s.visibleStack(w, r)
	if st == nil {
		return
	}
	rs := []store.StackResource{}
	if len(st.Resources) > 0 {
		json.Unmarshal(st.Resources, &rs)
	}
	inv, err := s.store.StackInventory(r.Context(), st.Name)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	// Only the inventory of the stack's own connection: it may see that one.
	mine := []*store.InventoryItem{}
	for _, it := range inv {
		if st.ConnectionID == nil || it.ConnectionID == *st.ConnectionID {
			mine = append(mine, it)
		}
	}
	writeJSON(w, 200, map[string]any{"resources": rs, "resources_at": st.ResourcesAt, "inventory": mine, "known": st.ResourcesAt != nil})
}

// stackOutputs lists a stack's exported outputs. Values stay sealed unless
// someone who may change the stack asks to reveal them (audited).
func (s *Server) stackOutputs(w http.ResponseWriter, r *http.Request) {
	st := s.visibleStack(w, r)
	if st == nil {
		return
	}
	reveal := r.URL.Query().Get("reveal") == "true"
	p := user(r)
	if reveal && !p.CanChange(st.BU) {
		writeErr(w, http.StatusForbidden, "revealing output values needs the developer or admin role in "+st.BU)
		return
	}
	rows, err := s.store.StackOutputRows(r.Context(), st.ID)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	type out struct {
		Name     string          `json:"name"`
		Resource string          `json:"resource"`
		Output   string          `json:"output"`
		Ref      string          `json:"ref"` // how another stack references it
		RunID    *string         `json:"run_id,omitempty"`
		Value    json.RawMessage `json:"value,omitempty"`
	}
	list := []out{}
	for _, o := range rows {
		res, name, _ := strings.Cut(o.Name, ".")
		x := out{Name: o.Name, Resource: res, Output: name, Ref: "stack/" + st.Name + "/" + o.Name, RunID: o.RunID}
		if reveal {
			if v, err := s.sealer.Open(o.Value, outputAAD(st.ID, o.Name)); err == nil {
				x.Value = v
			}
		}
		list = append(list, x)
	}
	if reveal {
		s.audit(r.Context(), p.Actor(), "stack.outputs.reveal", "stack/"+st.Name, st.BU, map[string]int{"outputs": len(list)})
	}
	writeJSON(w, 200, map[string]any{"outputs": list, "revealed": reveal})
}

const reasonMaxLock = 500

func (s *Server) lockStack(w http.ResponseWriter, r *http.Request) {
	p := user(r)
	st := s.visibleStack(w, r)
	if st == nil {
		return
	}
	if !p.CanChange(st.BU) {
		writeErr(w, http.StatusForbidden, "locking stacks needs the developer or admin role in "+st.BU)
		return
	}
	var b struct {
		Reason string `json:"reason"`
	}
	if !decode(w, r, &b) {
		return
	}
	b.Reason = strings.TrimSpace(b.Reason)
	if b.Reason == "" || len(b.Reason) > reasonMaxLock {
		writeErr(w, 422, "say why the stack is locked (up to 500 characters)")
		return
	}
	if err := s.store.LockStack(r.Context(), st.ID, p.Subject, b.Reason); err != nil {
		s.writeStoreErr(w, err, "the stack is already locked")
		return
	}
	s.audit(r.Context(), p.Actor(), "stack.lock", "stack/"+st.Name, st.BU, map[string]string{"reason": b.Reason})
	st, _ = s.store.GetStack(r.Context(), st.ID)
	writeJSON(w, 200, st)
}

func (s *Server) unlockStack(w http.ResponseWriter, r *http.Request) {
	p := user(r)
	st := s.visibleStack(w, r)
	if st == nil {
		return
	}
	if !p.CanChange(st.BU) {
		writeErr(w, http.StatusForbidden, "unlocking stacks needs the developer or admin role in "+st.BU)
		return
	}
	if err := s.store.UnlockStack(r.Context(), st.ID); err != nil {
		s.writeStoreErr(w, err, "the stack is not locked")
		return
	}
	var was map[string]any
	if st.Lock != nil {
		was = map[string]any{"locked_by": st.Lock.By, "reason": st.Lock.Reason, "locked_at": st.Lock.At}
	}
	s.audit(r.Context(), p.Actor(), "stack.unlock", "stack/"+st.Name, st.BU, was)
	st, _ = s.store.GetStack(r.Context(), st.ID)
	writeJSON(w, 200, st)
}

// deletable says why a stack cannot be deleted yet ("" when it can): it must
// manage nothing (never applied, or its last apply was a destroy) and no
// other stack may reference it.
func (s *Server) deletable(r *http.Request, st *store.Stack) string {
	ctx := r.Context()
	if st.ManagedBy == "git" {
		return "this stack is managed by the contracts repository: remove its contract there (after a destroy) instead"
	}
	if st.LastRun != nil && !slicesContains(store.Terminal, st.LastRun.Status) {
		return "the stack has an active run; let it finish or discard it first"
	}
	has, err := s.store.StackHasState(ctx, st.ID)
	if err != nil {
		return "could not check the stack's state"
	}
	if has {
		op, err := s.store.LastAppliedOperation(ctx, st.ID)
		if err != nil {
			return "could not check the stack's runs"
		}
		if op != "destroy" {
			return "the stack still manages resources: plan a destroy, apply it, then delete the stack"
		}
	}
	if deps, _ := s.store.Dependents(ctx, st.Name); len(deps) > 0 {
		return "other stacks reference this stack's outputs: " + strings.Join(deps, ", ")
	}
	return ""
}

func slicesContains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// deleteStack removes a stack that manages nothing. Its runs, state history
// and audit stay; its name can be used again.
func (s *Server) deleteStack(w http.ResponseWriter, r *http.Request) {
	p := user(r)
	st := s.visibleStack(w, r)
	if st == nil {
		return
	}
	if !p.CanChange(st.BU) {
		writeErr(w, http.StatusForbidden, "deleting stacks needs the developer or admin role in "+st.BU)
		return
	}
	if why := s.deletable(r, st); why != "" {
		writeErr(w, http.StatusConflict, why)
		return
	}
	if err := s.store.DeleteStack(r.Context(), st.ID, p.Subject); err != nil {
		s.writeStoreErr(w, err, "the stack has an active run; let it finish or discard it first")
		return
	}
	s.audit(r.Context(), p.Actor(), "stack.delete", "stack/"+st.Name, st.BU, map[string]any{"environment": st.Environment, "spec": st.Spec})
	w.WriteHeader(http.StatusNoContent)
}

// stackLifecycle says what can be done with a stack now (for the stack page).
func (s *Server) stackLifecycle(w http.ResponseWriter, r *http.Request) {
	st := s.visibleStack(w, r)
	if st == nil {
		return
	}
	env, _ := s.store.GetEnvironment(r.Context(), st.EnvironmentID)
	has, _ := s.store.StackHasState(r.Context(), st.ID)
	clones, _ := s.store.StackClones(r.Context(), st.ID)
	targets := s.promotionTargets(r, st)
	writeJSON(w, 200, map[string]any{
		"can_change":      user(r).CanChange(st.BU),
		"has_state":       has,
		"delete_blocked":  s.deletable(r, st),
		"destroy_allowed": env != nil && env.AllowDestroy,
		"clones":          briefStacks(clones),
		"promote_to":      briefStacks(targets),
	})
}

type stackBrief struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	BU          string `json:"bu"`
	Environment string `json:"environment"`
	ManagedBy   string `json:"managed_by"`
}

func briefStacks(sts []*store.Stack) []stackBrief {
	out := []stackBrief{}
	for _, x := range sts {
		out = append(out, stackBrief{ID: x.ID, Name: x.Name, BU: x.BU, Environment: x.Environment, ManagedBy: x.ManagedBy})
	}
	return out
}

// ---- cancelling runs ----

// cancelRun stops a run: queued ones end at once; a plan or apply in
// progress is interrupted by its runner (OpenTofu stops cleanly and saves
// state). Planned runs are discarded instead.
func (s *Server) cancelRun(w http.ResponseWriter, r *http.Request) {
	p := user(r)
	run := s.visibleRun(w, r)
	if run == nil {
		return
	}
	if !p.CanChange(run.BU) && !p.ManagesTenant() {
		writeErr(w, http.StatusForbidden, "cancelling runs needs the developer or admin role in "+run.BU)
		return
	}
	if run.Status == "planned" {
		writeErr(w, http.StatusConflict, "this plan is waiting for approval: discard it instead")
		return
	}
	status, err := s.store.RequestCancel(r.Context(), run.ID, p.Subject)
	if err != nil {
		s.writeStoreErr(w, err, "only queued, planning or applying runs can be cancelled (status is "+run.Status+")")
		return
	}
	if status == "cancelled" {
		s.engine.Finished(r.Context(), run.ID)
		s.audit(r.Context(), p.Actor(), "run.cancel", "run/"+run.ID, run.BU, map[string]string{"stack": run.StackName, "was": run.Status})
		s.notifyRun(r.Context(), run, "run.cancelled", "warning", "Cancelled: "+run.StackName, "Cancelled by "+p.Subject+" before a runner started it.", nil)
	} else {
		s.audit(r.Context(), p.Actor(), "run.cancel_requested", "run/"+run.ID, run.BU, map[string]string{"stack": run.StackName, "status": status})
		s.store.NotifyChange(r.Context(), "run", run.ID, run.BU)
		s.store.AppendLog(r.Context(), run.ID, "\n==> "+p.Subject+" asked to cancel this run; the runner stops OpenTofu at its next check-in\n")
	}
	run, _ = s.store.GetRun(r.Context(), run.ID)
	writeJSON(w, 200, map[string]any{"run": run, "cancel_requested": status != "cancelled"})
}

// ---- cloning and promotion ----

// portableSpec is a spec without what belongs to one environment's live
// resources: import blocks and baseline gaps of adopted resources.
func portableSpec(raw []byte) ([]byte, error) {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	delete(m, "imports")
	if mods, ok := m["modules"].([]any); ok {
		for _, x := range mods {
			if mm, ok := x.(map[string]any); ok {
				delete(mm, "baseline_gaps")
			}
		}
	}
	return json.Marshal(m)
}

// keepLocal puts the target's own imports and baseline gaps back into a
// promoted spec, for the resources it still has.
func keepLocal(promoted, target []byte) []byte {
	var p, t map[string]any
	if json.Unmarshal(promoted, &p) != nil || json.Unmarshal(target, &t) != nil {
		return promoted
	}
	gaps := map[string]any{}
	if mods, ok := t["modules"].([]any); ok {
		for _, x := range mods {
			if mm, ok := x.(map[string]any); ok && mm["baseline_gaps"] != nil {
				gaps[mm["name"].(string)] = mm["baseline_gaps"]
			}
		}
	}
	names := map[string]bool{}
	if mods, ok := p["modules"].([]any); ok {
		for _, x := range mods {
			if mm, ok := x.(map[string]any); ok {
				n, _ := mm["name"].(string)
				names[n] = true
				if g, ok := gaps[n]; ok {
					mm["baseline_gaps"] = g
				}
			}
		}
	}
	if ims, ok := t["imports"].([]any); ok {
		var keep []any
		for _, x := range ims {
			im, _ := x.(map[string]any)
			to, _ := im["to"].(string)
			mod := strings.TrimPrefix(to, "module.")
			mod, _, _ = strings.Cut(mod, ".")
			if names[mod] {
				keep = append(keep, x)
			}
		}
		if len(keep) > 0 {
			p["imports"] = keep
		}
	}
	b, err := json.Marshal(p)
	if err != nil {
		return promoted
	}
	return b
}

var stackRefNameRe = regexp.MustCompile(`"stack/([a-z][a-z0-9-]{1,62})/`)

// lineage groups stacks cloned from one another: a stack, its origin, and
// every clone of either.
func lineage(all []*store.Stack, st *store.Stack) []*store.Stack {
	root := st.ID
	if st.ClonedFrom != nil {
		root = *st.ClonedFrom
	}
	var out []*store.Stack
	for _, x := range all {
		if x.ID == st.ID {
			continue
		}
		from := ""
		if x.ClonedFrom != nil {
			from = *x.ClonedFrom
		}
		if x.ID == root || from == root || from == st.ID {
			out = append(out, x)
		}
	}
	return out
}

// retarget points a spec's references to other stacks at their counterparts
// in the target environment (clones of the same stack), so a promoted prod
// stack reads prod outputs, not dev ones. It returns references it could
// not map.
func retarget(raw []byte, all []*store.Stack, envID string) ([]byte, []string) {
	byName := map[string]*store.Stack{}
	for _, x := range all {
		byName[x.Name] = x
	}
	var unmapped []string
	seen := map[string]bool{}
	out := stackRefNameRe.ReplaceAllFunc(raw, func(m []byte) []byte {
		name := string(stackRefNameRe.FindSubmatch(m)[1])
		ref := byName[name]
		if ref == nil || ref.EnvironmentID == envID {
			return m
		}
		for _, c := range lineage(all, ref) {
			if c.EnvironmentID == envID {
				return []byte(`"stack/` + c.Name + `/`)
			}
		}
		if !seen[name] {
			seen[name] = true
			unmapped = append(unmapped, name)
		}
		return m
	})
	return out, unmapped
}

// promotionTargets are the stacks of the same lineage in other environments
// the caller may change.
func (s *Server) promotionTargets(r *http.Request, st *store.Stack) []*store.Stack {
	all, err := s.store.ListStacks(r.Context(), visible(r))
	if err != nil {
		return nil
	}
	var out []*store.Stack
	for _, x := range lineage(all, st) {
		if x.EnvironmentID != st.EnvironmentID && x.ManagedBy == "ui" && user(r).CanChange(x.BU) {
			out = append(out, x)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// cloneStack copies a stack's spec into a new stack, usually in another
// environment (dev → prod). Imports and adopted-resource gaps are left out;
// references to other stacks follow to their clones there.
func (s *Server) cloneStack(w http.ResponseWriter, r *http.Request) {
	src := s.visibleStack(w, r)
	if src == nil {
		return
	}
	var b stackBody
	if !decode(w, r, &b) {
		return
	}
	sp, err := portableSpec(src.Spec)
	if err != nil {
		writeErr(w, 422, "the stack's spec cannot be copied: "+err.Error())
		return
	}
	bu, env := s.target(w, r, firstNonEmpty(b.BU, src.BU), firstNonEmpty(b.Environment, src.Environment))
	if env == nil {
		return
	}
	all, _ := s.store.ListStacks(r.Context(), nil)
	sp, unmapped := retarget(sp, all, env.ID)
	b.BU, b.Spec, b.Template = bu, sp, src.Template
	b.Environment = env.Entity + ":" + env.Name
	st := s.createStackFrom(w, r, b, src)
	if st == nil {
		return
	}
	writeJSON(w, 201, map[string]any{"stack": st, "unmapped_refs": nonNil(unmapped)})
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func nonNil(x []string) []string {
	if x == nil {
		return []string{}
	}
	return x
}

// promotion is what promoting a stack into a target would change.
func (s *Server) promotion(w http.ResponseWriter, r *http.Request, src *store.Stack, target string) (*store.Stack, []byte, []string, bool) {
	dst, err := s.store.GetStack(r.Context(), target)
	if err == nil && (!user(r).CanView(dst.BU) || dst.DeletedAt != nil) {
		err = store.ErrNotFound
	}
	if err != nil {
		writeErr(w, 422, "unknown target stack "+target)
		return nil, nil, nil, false
	}
	if dst.ID == src.ID {
		writeErr(w, 422, "a stack cannot be promoted into itself")
		return nil, nil, nil, false
	}
	if dst.ManagedBy == "git" {
		writeErr(w, http.StatusConflict, "stack "+dst.Name+" is managed by the contracts repository; promote through a pull request there")
		return nil, nil, nil, false
	}
	sp, err := portableSpec(src.Spec)
	if err != nil {
		writeErr(w, 422, "the stack's spec cannot be copied: "+err.Error())
		return nil, nil, nil, false
	}
	all, _ := s.store.ListStacks(r.Context(), nil)
	sp, unmapped := retarget(sp, all, dst.EnvironmentID)
	sp = keepLocal(sp, dst.Spec)
	return dst, sp, unmapped, true
}

// promotePreview shows the target's spec now and after promotion.
func (s *Server) promotePreview(w http.ResponseWriter, r *http.Request) {
	src := s.visibleStack(w, r)
	if src == nil {
		return
	}
	dst, sp, unmapped, ok := s.promotion(w, r, src, r.URL.Query().Get("to"))
	if !ok {
		return
	}
	env, err := s.stackEnv(r.Context(), dst)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	_, _, probs := s.buildAllowWaiting(r.Context(), dst.Name, dst.BU, env, sp)
	writeJSON(w, 200, map[string]any{"target": briefStacks([]*store.Stack{dst})[0], "before": dst.Spec, "after": json.RawMessage(sp),
		"changed": !sameJSON(dst.Spec, sp), "problems": nonNil(probs), "unmapped_refs": nonNil(unmapped)})
}

// promoteStack replaces the target's spec with the source's (keeping the
// target's imports) and, if asked, plans it. The plan needs the target
// environment's approvals like any other.
func (s *Server) promoteStack(w http.ResponseWriter, r *http.Request) {
	p := user(r)
	src := s.visibleStack(w, r)
	if src == nil {
		return
	}
	var b struct {
		To   string `json:"to"`
		Plan bool   `json:"plan"`
	}
	if !decode(w, r, &b) {
		return
	}
	dst, sp, unmapped, ok := s.promotion(w, r, src, b.To)
	if !ok {
		return
	}
	if !p.CanChange(dst.BU) {
		writeErr(w, http.StatusForbidden, "promoting into "+dst.Name+" needs the developer or admin role in "+dst.BU)
		return
	}
	env, err := s.stackEnv(r.Context(), dst)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	gen, _, probs := s.buildAllowWaiting(r.Context(), dst.Name, dst.BU, env, sp)
	if probs != nil {
		writeErr(w, 422, "the promoted spec does not validate in "+dst.Environment, probs...)
		return
	}
	changed := !sameJSON(dst.Spec, gen.Spec)
	if changed {
		if err := s.store.UpdateStack(r.Context(), dst.ID, gen.Spec); err != nil {
			s.writeStoreErr(w, err, "stack "+dst.Name+" has an active run; let it finish or discard it first")
			return
		}
		s.audit(r.Context(), p.Actor(), "stack.promote", "stack/"+dst.Name, dst.BU, map[string]any{"from": src.Name, "before": dst.Spec, "after": json.RawMessage(gen.Spec), "unmapped_refs": unmapped})
	}
	planned := false
	if b.Plan {
		dst, _ = s.store.GetStack(r.Context(), dst.ID)
		if dst.Lock != nil {
			writeErr(w, http.StatusLocked, "the spec was promoted, but "+dst.Name+" is locked: unlock it to plan")
			return
		}
		planned = s.startStackPlan(r.Context(), dst, p.Subject, "promoted from "+src.Name)
	}
	dst, _ = s.store.GetStack(r.Context(), dst.ID)
	writeJSON(w, 200, map[string]any{"stack": dst, "changed": changed, "planned": planned, "unmapped_refs": nonNil(unmapped)})
}

// ---- stack templates ----

var templateNameRe = regexp.MustCompile(`^[a-z][a-z0-9-]{1,47}$`)

func (s *Server) listTemplates(w http.ResponseWriter, r *http.Request) {
	ts, err := s.store.ListTemplates(r.Context(), user(r).VisibleEntities())
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	writeJSON(w, 200, ts)
}

func (s *Server) getTemplate(w http.ResponseWriter, r *http.Request) {
	t, err := s.store.GetTemplate(r.Context(), r.PathValue("id"))
	if err == nil && t.Entity != "" && !user(r).CanViewEntity(t.Entity) {
		err = store.ErrNotFound
	}
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	writeJSON(w, 200, t)
}

// canWriteTemplate: tenant-wide templates need tenant admin or devops; a
// product's templates anyone who writes stacks in that product.
func canWriteTemplate(p *identity.Principal, entity string) bool {
	if entity == "" {
		return p.ManagesTenant()
	}
	return p.ManagesTenant() || len(p.WritableBUs(entity)) > 0
}

type templateBody struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Entity      string          `json:"entity"`
	Spec        json.RawMessage `json:"spec"`
	FromStack   string          `json:"from_stack"` // save a stack's spec as the template
}

func (s *Server) templateSpec(w http.ResponseWriter, r *http.Request, b *templateBody) bool {
	if b.FromStack != "" {
		st, err := s.store.GetStack(r.Context(), b.FromStack)
		if err != nil || !user(r).CanView(st.BU) || st.DeletedAt != nil {
			writeErr(w, 422, "unknown stack "+b.FromStack)
			return false
		}
		b.Spec, b.FromStack = st.Spec, st.Name
		if b.Entity == "-" {
			b.Entity = st.Entity
		}
	}
	sp, err := portableSpec(b.Spec)
	var parsed spec.Stack
	if err == nil {
		err = json.Unmarshal(sp, &parsed)
	}
	if err != nil || len(parsed.Modules) == 0 {
		writeErr(w, 422, "a template needs a spec with at least one resource")
		return false
	}
	if prob := s.platformKindProblem(r, sp); prob != "" {
		writeErr(w, 422, prob)
		return false
	}
	b.Spec = sp
	return true
}

func (s *Server) createTemplate(w http.ResponseWriter, r *http.Request) {
	p := user(r)
	var b templateBody
	if !decode(w, r, &b) {
		return
	}
	if !templateNameRe.MatchString(b.Name) {
		writeErr(w, 422, "name must be lowercase letters, digits and dashes (2-48)")
		return
	}
	if len(b.Description) > 1000 {
		writeErr(w, 422, "description is too long")
		return
	}
	if !s.templateSpec(w, r, &b) {
		return
	}
	if b.Entity != "" && !p.CanViewEntity(b.Entity) {
		writeErr(w, 422, "unknown product "+b.Entity)
		return
	}
	if !canWriteTemplate(p, b.Entity) {
		writeErr(w, http.StatusForbidden, "templates for every product need tenant_admin or devops; product templates need the developer role in that product")
		return
	}
	t, err := s.store.CreateTemplate(r.Context(), &store.StackTemplate{Name: b.Name, Description: b.Description, Entity: b.Entity, Spec: b.Spec, SourceStack: b.FromStack, CreatedBy: p.Subject})
	if err != nil {
		s.writeStoreErr(w, err, "a template with that name exists")
		return
	}
	s.audit(r.Context(), p.Actor(), "template.create", "template/"+t.Name, "", map[string]any{"entity": t.Entity, "from_stack": t.SourceStack, "spec": t.Spec})
	writeJSON(w, 201, t)
}

func (s *Server) updateTemplate(w http.ResponseWriter, r *http.Request) {
	p := user(r)
	cur, err := s.store.GetTemplate(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	if !canWriteTemplate(p, cur.Entity) && cur.CreatedBy != p.Subject {
		writeErr(w, http.StatusForbidden, "you cannot change this template")
		return
	}
	var b templateBody
	if !decode(w, r, &b) {
		return
	}
	if len(b.Spec) == 0 && b.FromStack == "" {
		b.Spec = cur.Spec
	}
	if len(b.Description) > 1000 {
		writeErr(w, 422, "description is too long")
		return
	}
	if !s.templateSpec(w, r, &b) {
		return
	}
	if b.Entity != cur.Entity && !canWriteTemplate(p, b.Entity) {
		writeErr(w, http.StatusForbidden, "you cannot share templates with that scope")
		return
	}
	t, err := s.store.UpdateTemplate(r.Context(), &store.StackTemplate{ID: cur.ID, Description: b.Description, Entity: b.Entity, Spec: b.Spec})
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.audit(r.Context(), p.Actor(), "template.update", "template/"+t.Name, "", map[string]any{"before": cur.Spec, "after": t.Spec, "entity": t.Entity})
	writeJSON(w, 200, t)
}

func (s *Server) deleteTemplate(w http.ResponseWriter, r *http.Request) {
	p := user(r)
	cur, err := s.store.GetTemplate(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	if !canWriteTemplate(p, cur.Entity) && cur.CreatedBy != p.Subject {
		writeErr(w, http.StatusForbidden, "you cannot delete this template")
		return
	}
	if err := s.store.DeleteTemplate(r.Context(), cur.ID); err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.audit(r.Context(), p.Actor(), "template.delete", "template/"+cur.Name, "", cur)
	w.WriteHeader(http.StatusNoContent)
}

var (
	_ = bytes.Equal
	_ = errors.New
	_ = time.Now
)
