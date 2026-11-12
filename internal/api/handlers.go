package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/audit"
	"github.com/itsPavanFeed/srustiops-backend/internal/auditexport"
	"github.com/itsPavanFeed/srustiops-backend/internal/catalog"
	"github.com/itsPavanFeed/srustiops-backend/internal/identity"
	"github.com/itsPavanFeed/srustiops-backend/internal/policy"
	"github.com/itsPavanFeed/srustiops-backend/internal/risk"
	"github.com/itsPavanFeed/srustiops-backend/internal/secure"
	"github.com/itsPavanFeed/srustiops-backend/internal/spec"
	"github.com/itsPavanFeed/srustiops-backend/internal/store"
)

var (
	envNameRe = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)
	poolRe    = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)
	runnerRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,62}$`)
	reasonMax = 500
)

// forbidden answers 404 rather than 403 for resources in BUs the caller
// cannot see, so business units cannot discover each other's stacks.
func forbidden(w http.ResponseWriter, visible bool, msg string) {
	if !visible {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	writeErr(w, http.StatusForbidden, msg)
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, user(r))
}

// provisionerCaller is the provisioner or central itself: the only callers that
// see and use the catalog's platform kinds.
func provisionerCaller(p *identity.Principal) bool {
	return p.Subject == "provisioner@srustiops.internal" || p.Subject == "system:central"
}

// platformKindProblem refuses a spec naming a platform-only kind, unless the
// provisioner sends it.
func (s *Server) platformKindProblem(r *http.Request, raw json.RawMessage) string {
	if provisionerCaller(user(r)) {
		return ""
	}
	var sp struct {
		Modules []struct {
			Kind string `json:"kind"`
		} `json:"modules"`
	}
	json.Unmarshal(raw, &sp)
	cat := s.plat().cat
	for _, m := range sp.Modules {
		if k := cat.Kind(m.Kind); k != nil && k.Platform {
			return "kind " + m.Kind + " is reserved for the platform's provisioner"
		}
	}
	return ""
}

func (s *Server) getCatalog(w http.ResponseWriter, r *http.Request) {
	p := s.plat()
	mods := p.cat.Modules
	if !provisionerCaller(user(r)) {
		mods = make([]*catalog.Module, 0, len(p.cat.Modules))
		for _, m := range p.cat.Modules {
			if !m.Platform {
				mods = append(mods, m)
			}
		}
	}
	resp := map[string]any{"registry": "registry.opentofu.org", "modules": mods, "providers": p.cat.Providers, "tofu_version": s.cfg.TofuVersion,
		"defaults": p.defaults.Kinds}
	if p.release != nil {
		resp["release"] = map[string]any{"id": p.release.ID, "number": p.release.Number, "sha256": p.release.SHA256}
	}
	writeJSON(w, 200, resp)
}

// ---- environments ----

type envBody struct {
	Name         string   `json:"name"`
	Entity       string   `json:"entity"` // the product the environment belongs to; all its BUs may deploy here
	Tier         string   `json:"tier"`
	Connections  []string `json:"connections"` // cloud connection names; each belongs to this environment only
	Connection   string   `json:"connection"`  // one connection (older clients); "" = no cloud
	RunnerPool   string   `json:"runner_pool"`
	MaxDestroys  *int     `json:"max_destroys"`
	MaxCreates   int      `json:"max_creates"`         // per run; 0 = no limit
	MaxImports   int      `json:"max_imports"`         // per run; 0 = no limit
	MaxRunning   int      `json:"max_concurrent_runs"` // plans and applies at once; 0 = no cap
	AllowDestroy bool     `json:"allow_destroy"`
}

func (b *envBody) validate(create bool) []string {
	var probs []string
	if create && !envNameRe.MatchString(b.Name) {
		probs = append(probs, "name must be lowercase letters, digits and dashes (2-32)")
	}
	if create && !identity.SlugRe.MatchString(b.Entity) {
		probs = append(probs, "entity must be the entity's (product's) slug")
	}
	if b.Tier != risk.TierProd && b.Tier != risk.TierNonProd {
		probs = append(probs, `tier must be "prod" or "nonprod"`)
	}
	if !poolRe.MatchString(b.RunnerPool) {
		probs = append(probs, "runner_pool must be lowercase letters, digits and dashes (2-32)")
	}
	if b.MaxDestroys == nil || *b.MaxDestroys < 0 || *b.MaxDestroys > 1000 {
		probs = append(probs, "max_destroys must be between 0 and 1000")
	}
	if b.MaxCreates < 0 || b.MaxCreates > 10000 || b.MaxImports < 0 || b.MaxImports > 10000 {
		probs = append(probs, "max_creates and max_imports must be between 0 (no limit) and 10000")
	}
	if b.MaxRunning < 0 || b.MaxRunning > 1000 {
		probs = append(probs, "max_concurrent_runs must be between 0 (no cap) and 1000")
	}
	return probs
}

// connectionsFor resolves an environment's connections and checks the entity
// may use each; none means no cloud. envID is the environment being changed
// ("" when creating): a connection of another environment is refused.
func (s *Server) connectionsFor(w http.ResponseWriter, r *http.Request, b *envBody, entity, envID string) ([]string, bool) {
	names := b.Connections
	if names == nil && b.Connection != "" {
		names = []string{b.Connection}
	}
	ids, seen := []string{}, map[string]bool{}
	for _, name := range names {
		c, err := s.store.GetConnection(r.Context(), name)
		if err != nil {
			writeErr(w, 422, "unknown cloud connection "+name)
			return nil, false
		}
		if !c.Allows(entity) {
			writeErr(w, http.StatusForbidden, "cloud connection "+c.Name+" is not available to entity "+entity)
			return nil, false
		}
		if c.EnvironmentID != nil && *c.EnvironmentID != envID {
			writeErr(w, http.StatusConflict, "cloud connection "+c.Name+" already belongs to environment "+c.Environment+"; a connection serves one environment")
			return nil, false
		}
		if !seen[c.ID] {
			seen[c.ID] = true
			ids = append(ids, c.ID)
		}
	}
	return ids, true
}

func (s *Server) listEnvironments(w http.ResponseWriter, r *http.Request) {
	envs, err := s.store.ListEnvironments(r.Context(), user(r).VisibleEntities())
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	writeJSON(w, 200, envs)
}

func (s *Server) getEnvironment(w http.ResponseWriter, r *http.Request) {
	e, err := s.store.GetEnvironment(r.Context(), r.PathValue("id"))
	if err == nil && !user(r).CanViewEntity(e.Entity) {
		err = store.ErrNotFound
	}
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	resp := map[string]any{"environment": e}
	trust := map[string]map[string]string{}
	for _, ec := range e.Connections {
		if c, err := spec.DecodeCloud(ec.Cloud); err == nil && c.NeedsOIDCToken() {
			trust[ec.Name] = map[string]string{"issuer": s.issuer.URL, "audience": c.Audience(), "subject_pattern": "srustiops:entity:" + e.Entity + ":env:" + e.Name + ":stack:*"}
		}
	}
	if len(trust) > 0 {
		resp["oidc_by_connection"] = trust
	}
	if c, err := spec.DecodeCloud(e.Cloud); err == nil && c.NeedsOIDCToken() {
		resp["oidc"] = map[string]string{
			"issuer":          s.issuer.URL,
			"audience":        c.Audience(),
			"subject_pattern": "srustiops:entity:" + e.Entity + ":env:" + e.Name + ":stack:*",
		}
	} else if len(e.Connections) > 1 {
		resp["oidc"] = map[string]string{"issuer": s.issuer.URL, "subject_pattern": "srustiops:entity:" + e.Entity + ":env:" + e.Name + ":stack:*"}
	}
	writeJSON(w, 200, resp)
}

func (s *Server) createEnvironment(w http.ResponseWriter, r *http.Request) {
	var b envBody
	if !decode(w, r, &b) {
		return
	}
	p := user(r)
	if !p.CanManageEnvironments(b.Entity) {
		forbidden(w, p.CanViewEntity(b.Entity) || b.Entity == "", "managing environments needs tenant_admin, or admin of the entity")
		return
	}
	if probs := b.validate(true); len(probs) > 0 {
		writeErr(w, 422, "invalid environment", probs...)
		return
	}
	if !s.knownEntity(r, b.Entity) {
		writeErr(w, 422, "unknown entity "+b.Entity)
		return
	}
	connIDs, ok := s.connectionsFor(w, r, &b, b.Entity, "")
	if !ok {
		return
	}
	e, err := s.store.CreateEnvironment(r.Context(), &store.Environment{Name: b.Name, Entity: b.Entity, Tier: b.Tier,
		RunnerPool: b.RunnerPool, MaxDestroys: *b.MaxDestroys, MaxCreates: b.MaxCreates, MaxImports: b.MaxImports, MaxRunning: b.MaxRunning, AllowDestroy: b.AllowDestroy, CreatedBy: p.Subject})
	if err != nil {
		s.writeStoreErr(w, err, "the entity already has an environment with that name")
		return
	}
	if len(connIDs) > 0 {
		if err := s.store.SetEnvironmentConnections(r.Context(), e.ID, connIDs); err != nil {
			s.store.DeleteEnvironment(r.Context(), e.ID)
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		e, _ = s.store.GetEnvironment(r.Context(), e.ID)
	}
	s.audit(r.Context(), p.Actor(), "environment.create", "environment/"+e.Entity+"/"+e.Name, "", e)
	writeJSON(w, 201, e)
}

func (s *Server) updateEnvironment(w http.ResponseWriter, r *http.Request) {
	p := user(r)
	cur, err := s.store.GetEnvironment(r.Context(), r.PathValue("id"))
	if err == nil && !p.CanViewEntity(cur.Entity) {
		err = store.ErrNotFound
	}
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	if !p.CanManageEnvironments(cur.Entity) {
		writeErr(w, http.StatusForbidden, "managing environments needs tenant_admin, or admin of the entity")
		return
	}
	var b envBody
	if !decode(w, r, &b) {
		return
	}
	if probs := b.validate(false); len(probs) > 0 {
		writeErr(w, 422, "invalid environment", probs...)
		return
	}
	connIDs, ok := s.connectionsFor(w, r, &b, cur.Entity, cur.ID)
	if !ok {
		return
	}
	if err := s.store.SetEnvironmentConnections(r.Context(), cur.ID, connIDs); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeErr(w, http.StatusConflict, err.Error())
		} else {
			s.writeStoreErr(w, err, "")
		}
		return
	}
	e, err := s.store.UpdateEnvironment(r.Context(), &store.Environment{ID: cur.ID, Tier: b.Tier, RunnerPool: b.RunnerPool, MaxDestroys: *b.MaxDestroys, MaxCreates: b.MaxCreates, MaxImports: b.MaxImports, MaxRunning: b.MaxRunning, AllowDestroy: b.AllowDestroy})
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.audit(r.Context(), p.Actor(), "environment.update", "environment/"+e.Entity+"/"+e.Name, "", map[string]any{"before": cur, "after": e})
	writeJSON(w, 200, e)
}

// deleteEnvironment removes an environment that has no stacks.
func (s *Server) deleteEnvironment(w http.ResponseWriter, r *http.Request) {
	p := user(r)
	cur, err := s.store.GetEnvironment(r.Context(), r.PathValue("id"))
	if err == nil && !p.CanViewEntity(cur.Entity) {
		err = store.ErrNotFound
	}
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	if !p.CanManageEnvironments(cur.Entity) {
		writeErr(w, http.StatusForbidden, "managing environments needs tenant_admin, or admin of the entity")
		return
	}
	if err := s.store.DeleteEnvironment(r.Context(), cur.ID); err != nil {
		s.writeStoreErr(w, err, "the environment still has stacks")
		return
	}
	s.audit(r.Context(), p.Actor(), "environment.delete", "environment/"+cur.Entity+"/"+cur.Name, "", cur)
	w.WriteHeader(http.StatusNoContent)
}

// ---- stacks ----

type stackBody struct {
	Name        string          `json:"name"`
	BU          string          `json:"bu"`          // the business unit that owns the stack
	Environment string          `json:"environment"` // an environment of the BU's entity
	Connection  string          `json:"connection"`  // one of the environment's connections ("" = its only one)
	Spec        json.RawMessage `json:"spec"`
	Template    string          `json:"template,omitempty"` // the template it was made from, if any
}

// build validates a spec for an environment and generates its configuration.
func (s *Server) build(ctx context.Context, stackName, bu string, env *store.Environment, raw []byte) (*spec.Generated, *spec.Cloud, []string) {
	return s.buildWith(ctx, s.plat(), stackName, bu, env, raw)
}

// buildWith generates against one platform snapshot, so a caller that also
// hands out the snapshot's bundle (a run claim) sees one consistent release.
func (s *Server) buildWith(ctx context.Context, p *platform, stackName, bu string, env *store.Environment, raw []byte) (*spec.Generated, *spec.Cloud, []string) {
	if env.ConnectionID == nil && len(env.Connections) > 1 {
		return nil, nil, []string{fmt.Sprintf("environment %s has %d cloud connections; choose the one this stack deploys to (\"connection\")", env.Name, len(env.Connections))}
	}
	c, err := spec.DecodeCloud(env.Cloud)
	if err != nil {
		return nil, nil, []string{"environment cloud integration is invalid: " + err.Error()}
	}
	original := raw
	raw, probs := s.resolveStackRefs(ctx, stackName, raw)
	if probs != nil {
		return nil, nil, probs
	}
	st, err := spec.Decode(raw)
	if err != nil {
		return nil, nil, []string{err.Error()}
	}
	gen, err := st.Generate(p.cat, s.generateInput(ctx, p, spec.GenerateInput{
		StackName: stackName, Environment: env.Name, Tier: env.Tier, Cloud: c, Entity: env.Entity, BU: bu,
	}))
	if err != nil {
		return nil, nil, errLines(err)
	}
	// The code was generated with the referenced outputs' values; the spec
	// that is kept (the contract) keeps the references themselves.
	gen.Spec = spec.RestoreStackRefs(gen.Spec, original)
	return gen, c, nil
}

// stackEnv loads a stack's environment, set to the connection the stack
// deploys to.
func (s *Server) stackEnv(ctx context.Context, st *store.Stack) (*store.Environment, error) {
	env, err := s.store.GetEnvironment(ctx, st.EnvironmentID)
	if err != nil {
		return nil, err
	}
	conn := ""
	if st.ConnectionID != nil {
		conn = *st.ConnectionID
	}
	e, ok := env.ForConnection(conn)
	if !ok {
		return nil, fmt.Errorf("the connection of stack %s is no longer part of environment %s", st.Name, env.Name)
	}
	return e, nil
}

// pickConnection chooses the connection a new stack deploys to: the one
// named, or the environment's only one.
func pickConnection(env *store.Environment, name string) (*store.Environment, *string, string) {
	if name == "" {
		if len(env.Connections) > 1 {
			names := make([]string, 0, len(env.Connections))
			for _, c := range env.Connections {
				names = append(names, c.Name)
			}
			return nil, nil, fmt.Sprintf("environment %s has %d cloud connections (%s); name the one this stack deploys to with \"connection\"", env.Name, len(names), strings.Join(names, ", "))
		}
		return env, env.ConnectionID, ""
	}
	e, ok := env.ForConnection(name)
	if !ok {
		return nil, nil, "connection " + name + " is not part of environment " + env.Name
	}
	return e, e.ConnectionID, ""
}

// visibleEnv loads an environment the caller can see, or answers 422.
// target resolves where a stack goes: its business unit and an environment of
// that BU's entity. Without a bu, the caller's only writable BU in the
// environment's entity is used.
func (s *Server) target(w http.ResponseWriter, r *http.Request, bu, envName string) (string, *store.Environment) {
	p := user(r)
	if bu == "" {
		env, err := s.store.GetEnvironment(r.Context(), envName)
		if err != nil || !p.CanViewEntity(env.Entity) {
			writeErr(w, 422, "unknown environment "+envName+" (name the business unit with \"bu\")")
			return "", nil
		}
		if bus := p.WritableBUs(env.Entity); len(bus) == 1 {
			return bus[0], env
		}
		writeErr(w, 422, "bu is required: environment "+env.Name+" is shared by the business units of "+env.Entity)
		return "", nil
	}
	if !p.KnownBU(bu) || !p.CanView(bu) {
		writeErr(w, 422, "unknown business unit "+bu)
		return "", nil
	}
	entity := p.EntityOf(bu)
	ref := envName
	if !strings.Contains(ref, ":") {
		ref = entity + ":" + envName
	}
	env, err := s.store.GetEnvironment(r.Context(), ref)
	if err != nil || env.Entity != entity {
		writeErr(w, 422, "unknown environment "+envName+" in entity "+entity)
		return "", nil
	}
	return bu, env
}

func (s *Server) previewStack(w http.ResponseWriter, r *http.Request) {
	var b stackBody
	if !decode(w, r, &b) {
		return
	}
	if prob := s.platformKindProblem(r, b.Spec); prob != "" {
		writeErr(w, 422, prob)
		return
	}
	bu, env := s.target(w, r, b.BU, b.Environment)
	if env == nil {
		return
	}
	name := b.Name
	if !spec.StackNameRe.MatchString(name) {
		name = "preview"
	}
	env, _, prob := pickConnection(env, b.Connection)
	if prob != "" {
		writeJSON(w, 200, map[string]any{"valid": false, "problems": []string{prob}})
		return
	}
	gen, _, probs := s.build(r.Context(), name, bu, env, b.Spec)
	if probs != nil {
		writeJSON(w, 200, map[string]any{"valid": false, "problems": probs})
		return
	}
	files := map[string]string{}
	for k, v := range gen.Files {
		files[k] = string(v)
	}
	writeJSON(w, 200, map[string]any{"valid": true, "files": files, "providers": gen.Providers, "modules": gen.Modules, "hash": gen.Hash})
}

// createStack: the stack belongs to a business unit and deploys to an
// environment of that BU's entity.
func (s *Server) createStack(w http.ResponseWriter, r *http.Request) {
	var b stackBody
	if !decode(w, r, &b) {
		return
	}
	if st := s.createStackFrom(w, r, b, nil); st != nil {
		writeJSON(w, 201, st)
	}
}

// createStackFrom creates a stack (from a body, a clone or a template). It
// writes the error and returns nil when refused.
func (s *Server) createStackFrom(w http.ResponseWriter, r *http.Request, b stackBody, clonedFrom *store.Stack) *store.Stack {
	if prob := s.platformKindProblem(r, b.Spec); prob != "" {
		writeErr(w, 422, prob)
		return nil
	}
	p := user(r)
	if !spec.StackNameRe.MatchString(b.Name) {
		writeErr(w, 422, "name must start with a letter and use lowercase letters, digits and dashes (2-63)")
		return nil
	}
	bu, env := s.target(w, r, b.BU, b.Environment)
	if env == nil {
		return nil
	}
	if !p.CanChange(bu) {
		writeErr(w, http.StatusForbidden, "creating stacks needs the developer or admin role in "+bu)
		return nil
	}
	env, connID, prob := pickConnection(env, b.Connection)
	if prob != "" {
		writeErr(w, 422, prob)
		return nil
	}
	if b.Template != "" {
		t, err := s.store.GetTemplate(r.Context(), b.Template)
		if err != nil || (t.Entity != "" && t.Entity != env.Entity) {
			writeErr(w, 422, "unknown template "+b.Template)
			return nil
		}
		b.Template = t.Name
	}
	gen, waits, probs := s.buildAllowWaiting(r.Context(), b.Name, bu, env, b.Spec)
	if probs != nil {
		writeErr(w, 422, "stack spec rejected", probs...)
		return nil
	}
	st, err := s.store.CreateStack(r.Context(), b.Name, bu, env.Entity, env.ID, connID, gen.Spec, p.Subject)
	if err != nil {
		s.writeStoreErr(w, err, "a stack with that name exists")
		return nil
	}
	var from *string
	origin := map[string]any{}
	if clonedFrom != nil {
		from = &clonedFrom.ID
		origin["cloned_from"] = clonedFrom.Name
	}
	if b.Template != "" {
		origin["template"] = b.Template
	}
	if from != nil || b.Template != "" {
		s.store.SetStackOrigin(r.Context(), st.ID, from, b.Template)
		st, _ = s.store.GetStack(r.Context(), st.ID)
	}
	s.audit(r.Context(), p.Actor(), "stack.create", "stack/"+st.Name, st.BU, map[string]any{"environment": env.Name, "spec": st.Spec, "waits_on": waits, "origin": origin})
	st.WaitsOn = waits // its plan waits for these stacks (planned with "Plan changes")
	return st
}

// visibleStack loads a stack the caller can see, or answers 404.
func (s *Server) visibleStack(w http.ResponseWriter, r *http.Request) *store.Stack {
	st, err := s.store.GetStack(r.Context(), r.PathValue("id"))
	if err == nil && !user(r).CanView(st.BU) {
		err = store.ErrNotFound
	}
	// A deleted stack can still be read (its runs link to it), never changed.
	if err == nil && st.DeletedAt != nil && r.Method != http.MethodGet {
		err = store.ErrNotFound
	}
	if err != nil {
		s.writeStoreErr(w, err, "")
		return nil
	}
	return st
}

func (s *Server) updateStack(w http.ResponseWriter, r *http.Request) {
	p := user(r)
	st := s.visibleStack(w, r)
	if st == nil {
		return
	}
	if !p.CanChange(st.BU) {
		writeErr(w, http.StatusForbidden, "editing stacks needs the developer or admin role in "+st.BU)
		return
	}
	if st.ManagedBy == "git" {
		writeErr(w, http.StatusConflict, "this stack is managed by the contracts repository; change it there")
		return
	}
	var b struct {
		Spec json.RawMessage `json:"spec"`
	}
	if !decode(w, r, &b) {
		return
	}
	if prob := s.platformKindProblem(r, b.Spec); prob != "" {
		writeErr(w, 422, prob)
		return
	}
	env, err := s.stackEnv(r.Context(), st)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	gen, _, probs := s.build(r.Context(), st.Name, st.BU, env, b.Spec)
	if probs != nil {
		writeErr(w, 422, "stack spec rejected", probs...)
		return
	}
	if err := s.store.UpdateStack(r.Context(), st.ID, gen.Spec); err != nil {
		s.writeStoreErr(w, err, "the stack has an active run; finish or discard it first")
		return
	}
	s.audit(r.Context(), p.Actor(), "stack.update", "stack/"+st.Name, st.BU, map[string]any{"before": st.Spec, "after": gen.Spec})
	st, _ = s.store.GetStack(r.Context(), st.ID)
	writeJSON(w, 200, st)
}

func visible(r *http.Request) []string { return user(r).VisibleBUs() }

// listStacks returns stack summaries (module names and kinds, no inputs or
// resources; ?full=1 for whole stacks), all or a page (?limit=&offset=),
// with the total in X-Total-Count.
func (s *Server) listStacks(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("full") == "1" {
		sts, err := s.store.ListStacks(r.Context(), visible(r))
		if err != nil {
			s.writeStoreErr(w, err, "")
			return
		}
		writeJSON(w, 200, sts)
		return
	}
	lim, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	off, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if lim < 0 || lim > 1000 || off < 0 {
		writeErr(w, 422, "limit is 1-1000 and offset 0 or more")
		return
	}
	sts, total, err := s.store.ListStackSummaries(r.Context(), visible(r), lim, off)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	w.Header().Set("X-Total-Count", strconv.Itoa(total))
	writeJSON(w, 200, sts)
}

func (s *Server) getStack(w http.ResponseWriter, r *http.Request) {
	if st := s.visibleStack(w, r); st != nil {
		writeJSON(w, 200, st)
	}
}

func (s *Server) listStateVersions(w http.ResponseWriter, r *http.Request) {
	st := s.visibleStack(w, r)
	if st == nil {
		return
	}
	vs, err := s.store.StateVersions(r.Context(), st.ID)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	writeJSON(w, 200, vs)
}

// ---- runs ----

func (s *Server) createRun(w http.ResponseWriter, r *http.Request) {
	p := user(r)
	st := s.visibleStack(w, r)
	if st == nil {
		return
	}
	if !p.CanChange(st.BU) {
		writeErr(w, http.StatusForbidden, "starting runs needs the developer or admin role in "+st.BU)
		return
	}
	var b struct {
		Operation string `json:"operation"`
	}
	if !decode(w, r, &b) {
		return
	}
	if b.Operation == "" {
		b.Operation = "apply"
	}
	if b.Operation != "apply" && b.Operation != "destroy" && b.Operation != "drift" {
		writeErr(w, 422, `operation must be "apply", "destroy" or "drift"`)
		return
	}
	env, err := s.stackEnv(r.Context(), st)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	if b.Operation == "destroy" && !env.AllowDestroy {
		writeErr(w, http.StatusForbidden, "destroy runs are disabled for environment "+env.Name)
		return
	}
	gen, _, probs := s.build(r.Context(), st.Name, st.BU, env, st.Spec)
	if probs != nil {
		if waits, ok := waitingOn(probs); ok && b.Operation == "apply" {
			if err := s.deferRun(r.Context(), st, p.Subject, "planned by "+p.Subject, waits); err != nil {
				s.writeStoreErr(w, err, "")
				return
			}
			writeJSON(w, 202, map[string]any{"pending": true, "waits_on": waits,
				"message": "this stack references outputs of " + strings.Join(waits, ", ") + " that are not applied yet; it plans as soon as they are"})
			return
		}
		writeErr(w, 422, "stack no longer validates against the catalog", probs...)
		return
	}
	run, err := s.store.CreateRun(r.Context(), st.ID, b.Operation, p.Subject, gen.Hash)
	if err != nil {
		s.writeStoreErr(w, err, "the stack already has an active run")
		return
	}
	s.audit(r.Context(), p.Actor(), "run.create", "run/"+run.ID, st.BU, map[string]string{"stack": st.Name, "operation": b.Operation, "config_hash": gen.Hash})
	s.runCreated(r.Context(), run.ID)
	writeJSON(w, 201, run)
}

// listRuns pages through runs, newest first: ?before=<created_at of the last
// run shown> for the next page, and ?operation=, ?status= (comma-separated)
// and ?stack= to filter. X-Next-Before names the next page when there is one.
func (s *Server) listRuns(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	rq := store.RunQuery{BUs: visible(r), Limit: limit(r, 50, 200), Stack: strings.TrimSpace(q.Get("stack"))}
	if v := q.Get("before"); v != "" {
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			writeErr(w, 422, "before must be an RFC 3339 time")
			return
		}
		rq.Before = t
	}
	split := func(v string) []string {
		var out []string
		for _, x := range strings.Split(v, ",") {
			if x = strings.TrimSpace(x); x != "" {
				out = append(out, x)
			}
		}
		return out
	}
	rq.Operations, rq.Statuses = split(q.Get("operation")), split(q.Get("status"))
	if len(rq.Stack) > 100 {
		writeErr(w, 422, "stack filter is too long")
		return
	}
	runs, err := s.store.QueryRuns(r.Context(), rq)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	if len(runs) == rq.Limit {
		w.Header().Set("X-Next-Before", runs[len(runs)-1].CreatedAt.Format(time.RFC3339Nano))
	}
	writeJSON(w, 200, runs)
}

func (s *Server) listStackRuns(w http.ResponseWriter, r *http.Request) {
	st := s.visibleStack(w, r)
	if st == nil {
		return
	}
	runs, err := s.store.ListRuns(r.Context(), st.ID, nil, limit(r, 50, 200))
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	writeJSON(w, 200, runs)
}

func (s *Server) visibleRun(w http.ResponseWriter, r *http.Request) *store.Run {
	run, err := s.store.GetRun(r.Context(), r.PathValue("id"))
	if err == nil && !user(r).CanView(run.BU) {
		err = store.ErrNotFound
	}
	if err != nil {
		s.writeStoreErr(w, err, "")
		return nil
	}
	return run
}

func (s *Server) getRun(w http.ResponseWriter, r *http.Request) {
	if run := s.visibleRun(w, r); run != nil {
		writeJSON(w, 200, run)
	}
}

func (s *Server) getRunLogs(w http.ResponseWriter, r *http.Request) {
	run := s.visibleRun(w, r)
	if run == nil {
		return
	}
	after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	logs, err := s.runLogs(r.Context(), run, after)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	writeJSON(w, 200, logs)
}

// approveRun signs one step of the run's approval chain (manager, finops,
// security, as its risk requires). Every signature re-checks that the plan is
// still current; the last one queues the apply.
func (s *Server) approveRun(w http.ResponseWriter, r *http.Request) {
	p := user(r)
	run := s.visibleRun(w, r)
	if run == nil {
		return
	}
	var b struct {
		Step   string `json:"step"`
		Reason string `json:"reason"`
	}
	if !decode(w, r, &b) {
		return
	}
	if len(b.Reason) > reasonMax {
		writeErr(w, 422, "reason is too long")
		return
	}
	if !p.CanApprove(b.Step, run.BU) {
		writeErr(w, http.StatusForbidden, "you cannot sign the "+b.Step+" approval for "+run.BU)
		return
	}
	if run.Status != "planned" {
		writeErr(w, http.StatusConflict, "only planned runs can be approved (status is "+run.Status+")")
		return
	}
	var pr policy.Result
	if json.Unmarshal(run.PolicyResult, &pr) != nil || !pr.Passed {
		writeErr(w, http.StatusConflict, "the plan did not pass policy")
		return
	}
	st, err := s.store.GetStack(r.Context(), run.StackID)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	env, err := s.stackEnv(r.Context(), st)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	if stale := s.planStale(r.Context(), run, st, env); stale != "" {
		s.store.Discard(r.Context(), run.ID, "stale plan: "+stale)
		s.engine.Finished(r.Context(), run.ID)
		s.audit(r.Context(), p.Actor(), "run.discard", "run/"+run.ID, run.BU, map[string]string{"reason": "stale plan: " + stale})
		writeErr(w, http.StatusConflict, "plan is stale and was discarded: "+stale+"; start a new run")
		return
	}
	complete, err := s.store.Approve(r.Context(), run.ID, b.Step, p.Subject, b.Reason)
	switch {
	case errors.Is(err, store.ErrSelfApproval), errors.Is(err, store.ErrTwoSteps):
		writeErr(w, http.StatusForbidden, err.Error())
		return
	case errors.Is(err, store.ErrNotPlanned), errors.Is(err, store.ErrStepDone), errors.Is(err, store.ErrStepNotRequired):
		writeErr(w, http.StatusConflict, err.Error())
		return
	case err != nil:
		s.writeStoreErr(w, err, "")
		return
	}
	s.audit(r.Context(), p.Actor(), "run.approve", "run/"+run.ID, run.BU, map[string]any{
		"stack": st.Name, "step": b.Step, "reason": b.Reason, "plan_sha256": deref(run.PlanSHA256), "chain_complete": complete})
	if complete {
		s.engine.Approved(r.Context(), run.ID)
		s.notify()
	}
	run, _ = s.store.GetRun(r.Context(), run.ID)
	if complete {
		s.notifyRun(r.Context(), run, "run.approved", "info", fmt.Sprintf("Approved: %s is being applied", run.StackName),
			fmt.Sprintf("%s approved by %s; every required approval is in.", b.Step, p.Subject), nil)
	} else {
		left := remainingSteps(run)
		s.notifyRun(r.Context(), run, "run.awaiting_approval", "action", fmt.Sprintf("%s approved %s; still needs %s", p.Subject, run.StackName, strings.Join(left, ", ")),
			"Plan "+short(deref(run.PlanSHA256))+" in "+run.Environment+".", left)
	}
	writeJSON(w, 200, run)
}

// planStale reports why a plan can no longer be applied, or "".
func (s *Server) planStale(ctx context.Context, run *store.Run, st *store.Stack, env *store.Environment) string {
	gen, _, probs := s.build(ctx, st.Name, st.BU, env, runSpec(st, run))
	_, serial, serr := s.store.CurrentState(ctx, st.ID)
	switch {
	case probs != nil || gen.Hash != run.ConfigHash:
		return "the stack or environment changed after this plan was made"
	case serr != nil || run.StateSerial == nil || serial != *run.StateSerial:
		return "the stack's state changed after this plan was made"
	}
	return ""
}

// overrideRun lets DevOps sign every remaining approval step of a plan at
// once, with a reason. Each step is recorded as "override:<who>:<step>" so the
// audit trail and the run show exactly what was bypassed. Policy is never
// bypassed: only plans that passed policy can be overridden.
func (s *Server) overrideRun(w http.ResponseWriter, r *http.Request) {
	p := user(r)
	if !p.HasTenantRole(identity.DevOps) {
		writeErr(w, http.StatusForbidden, "overriding approvals needs the devops role")
		return
	}
	run := s.visibleRun(w, r)
	if run == nil {
		return
	}
	var b struct {
		Reason string `json:"reason"`
	}
	if !decode(w, r, &b) {
		return
	}
	if strings.TrimSpace(b.Reason) == "" || len(b.Reason) > reasonMax {
		writeErr(w, 422, "an override needs a reason")
		return
	}
	if run.Status != "planned" {
		writeErr(w, http.StatusConflict, "only plans waiting for approval can be overridden (status is "+run.Status+")")
		return
	}
	var pr policy.Result
	if json.Unmarshal(run.PolicyResult, &pr) != nil || !pr.Passed {
		writeErr(w, http.StatusConflict, "the plan did not pass policy; policy cannot be overridden")
		return
	}
	st, err := s.store.GetStack(r.Context(), run.StackID)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	env, err := s.stackEnv(r.Context(), st)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	if stale := s.planStale(r.Context(), run, st, env); stale != "" {
		s.store.Discard(r.Context(), run.ID, "stale plan: "+stale)
		s.engine.Finished(r.Context(), run.ID)
		writeErr(w, http.StatusConflict, "plan is stale and was discarded: "+stale+"; start a new run")
		return
	}
	left := remainingSteps(run)
	complete := false
	for _, step := range left {
		if complete, err = s.store.Approve(r.Context(), run.ID, step, "override:"+p.Subject+":"+step, "override: "+b.Reason); err != nil {
			s.writeStoreErr(w, err, "")
			return
		}
	}
	s.audit(r.Context(), p.Actor(), "run.override", "run/"+run.ID, run.BU, map[string]any{
		"stack": st.Name, "steps": left, "reason": b.Reason, "plan_sha256": deref(run.PlanSHA256)})
	if complete {
		s.engine.Approved(r.Context(), run.ID)
		s.notify()
	}
	run, _ = s.store.GetRun(r.Context(), run.ID)
	s.notifyRun(r.Context(), run, "run.overridden", "warning", fmt.Sprintf("Approvals overridden: %s is being applied", run.StackName),
		fmt.Sprintf("%s overrode %s: %s", p.Subject, strings.Join(left, ", "), b.Reason), nil)
	writeJSON(w, 200, run)
}

// remainingSteps lists the approval steps a run still needs.
func remainingSteps(run *store.Run) []string {
	done := map[string]bool{}
	for _, a := range run.Approvals {
		done[a.Step] = true
	}
	left := []string{}
	for _, st := range run.RequiredApprovals {
		if !done[st] {
			left = append(left, st)
		}
	}
	return left
}

func (s *Server) discardRun(w http.ResponseWriter, r *http.Request) {
	p := user(r)
	run := s.visibleRun(w, r)
	if run == nil {
		return
	}
	if !p.CanChange(run.BU) && !p.HasBURole(run.BU, identity.Manager) {
		writeErr(w, http.StatusForbidden, "discarding runs needs the developer, manager or admin role in "+run.BU)
		return
	}
	var b struct {
		Reason string `json:"reason"`
	}
	if !decode(w, r, &b) {
		return
	}
	if len(b.Reason) > reasonMax {
		writeErr(w, 422, "reason is too long")
		return
	}
	if err := s.store.Discard(r.Context(), run.ID, "discarded by "+p.Subject+": "+b.Reason); err != nil {
		s.writeStoreErr(w, err, "only queued or planned runs can be discarded")
		return
	}
	s.engine.Finished(r.Context(), run.ID)
	s.audit(r.Context(), p.Actor(), "run.discard", "run/"+run.ID, run.BU, map[string]string{"reason": b.Reason})
	run, _ = s.store.GetRun(r.Context(), run.ID)
	s.notifyRun(r.Context(), run, "run.discarded", "warning", "Rejected: "+run.StackName, "Discarded by "+p.Subject+": "+b.Reason, nil)
	writeJSON(w, 200, run)
}

// ---- audit ----

// listAudit: tenant-wide roles see everything; BU members see their BUs'
// events only (not tenant-wide ones).
// listAudit pages through the audit log (?before=, ?q=, ?since=, ?until=);
// ?format=csv downloads every matching event.
func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	since, until, err := auditexport.ParseRange(q)
	if err != nil {
		writeErr(w, 422, err.Error())
		return
	}
	aq := store.AuditQuery{Limit: limit(r, 100, 500), Filter: q.Get("q"), Scopes: visible(r), Since: since, Until: until}
	if q.Get("format") == "csv" {
		aq.Limit = 1000
		s.audit(r.Context(), user(r).Actor(), "audit.download", "audit", "", map[string]any{"q": aq.Filter, "since": q.Get("since"), "until": q.Get("until")})
		auditexport.ServeCSV(w, "srustiops-"+s.cfg.Tenant+"-audit.csv", func(before int64) ([]audit.Event, error) {
			aq.Before = before
			return s.store.ListAudit(r.Context(), aq)
		})
		return
	}
	aq.Before, _ = strconv.ParseInt(q.Get("before"), 10, 64)
	evs, err := s.store.ListAudit(r.Context(), aq)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	writeJSON(w, 200, evs)
}

func (s *Server) verifyAudit(w http.ResponseWriter, r *http.Request) {
	if !user(r).SeesAllBUs() {
		writeErr(w, http.StatusForbidden, "verifying the whole audit chain needs a tenant-wide role")
		return
	}
	v, err := s.store.VerifyAuditFast(r.Context(), s.sealer, r.URL.Query().Get("full") == "1")
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	writeJSON(w, 200, map[string]any{"intact": v.FirstBrokenID == 0, "checked": v.Checked, "first_broken_id": v.FirstBrokenID, "from_checkpoint": v.FromCheckpoint})
}

// ---- runners (tenant admins) ----

func tenantAdmin(w http.ResponseWriter, r *http.Request) bool {
	if !user(r).HasTenantRole(identity.TenantAdmin) {
		writeErr(w, http.StatusForbidden, "this needs the tenant_admin role")
		return false
	}
	return true
}

func (s *Server) listRunners(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	rs, err := s.store.ListRunners(r.Context())
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	writeJSON(w, 200, rs)
}

func (s *Server) createRunner(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	var b struct {
		Name string `json:"name"`
		Pool string `json:"pool"`
	}
	if !decode(w, r, &b) {
		return
	}
	if !runnerRe.MatchString(b.Name) || !poolRe.MatchString(b.Pool) {
		writeErr(w, 422, "name and pool must be lowercase letters, digits and dashes")
		return
	}
	plain, err := secure.NewToken("r")
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	rn, err := s.store.CreateRunner(r.Context(), b.Name, b.Pool, secure.HashToken(plain))
	if err != nil {
		s.writeStoreErr(w, err, "a runner with that name exists")
		return
	}
	s.audit(r.Context(), user(r).Actor(), "runner.create", "runner/"+rn.Name, "", map[string]string{"pool": rn.Pool})
	writeJSON(w, 201, map[string]any{"runner": rn, "secret": plain})
}

func (s *Server) revokeRunner(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	id := r.PathValue("id")
	if err := s.store.RevokeRunner(r.Context(), id); err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.audit(r.Context(), user(r).Actor(), "runner.revoke", "runner/"+id, "", nil)
	w.WriteHeader(http.StatusNoContent)
}

func limit(r *http.Request, def, max int) int {
	n, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || n <= 0 {
		return def
	}
	if n > max {
		return max
	}
	return n
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// knownEntity: the entity exists in this tenant (central lists every BU with its entity).
func (s *Server) knownEntity(r *http.Request, entity string) bool {
	p := user(r)
	for _, e := range p.BUEntity {
		if e == entity {
			return true
		}
	}
	_, ok := p.EntityRoles[entity]
	return ok
}

// runSpec is the spec a run plans and applies: a pull-request run's own, else the stack's.
func runSpec(st *store.Stack, run *store.Run) []byte {
	if len(run.Spec) > 0 {
		return run.Spec
	}
	return st.Spec
}
