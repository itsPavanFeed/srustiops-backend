package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/assistant"
	"github.com/itsPavanFeed/srustiops-backend/internal/spec"
)

const assistantTimeout = 5 * time.Minute

// assistantState is the assistant in use and how it was configured.
type assistantState struct {
	a      *assistant.Assistant
	model  string
	source string // console | environment
}

// assistantConfig is the console's setting (Integrations → Assistant); the
// API key is sealed. It takes precedence over SRUSTIOPS_ASSISTANT_*.
type assistantConfig struct {
	Enabled bool   `json:"enabled"`
	APIKey  string `json:"api_key,omitempty"`
	Model   string `json:"model"`
	Effort  string `json:"effort"`
}

const assistantSetting = "assistant"

func (s *Server) assistantSettings(ctx context.Context) (*assistantConfig, bool) {
	b, ok := s.openSetting(ctx, assistantSetting, assistantSetting)
	if !ok {
		return nil, false
	}
	var c assistantConfig
	return &c, json.Unmarshal(b, &c) == nil
}

// enableAssistant turns the assistant on (or off) from the console's
// setting, else from the environment.
func (s *Server) enableAssistant() error {
	ctx := context.Background()
	key, model, effort, source := s.cfg.AssistantAPIKey, s.cfg.AssistantModel, s.cfg.AssistantEffort, "environment"
	if c, ok := s.assistantSettings(ctx); ok {
		source = "console"
		key, model, effort = "", c.Model, c.Effort
		if c.Enabled {
			key = c.APIKey
		}
	}
	if key == "" {
		s.assistant.Store(nil)
		return nil
	}
	if s.assistantExtra == nil {
		extra, err := assistant.DirDocs(s.cfg.AssistantDocsDir)
		if err != nil {
			return fmt.Errorf("SRUSTIOPS_ASSISTANT_DOCS_DIR: %w", err)
		}
		s.assistantExtra = extra
	}
	if model == "" {
		model = s.cfg.AssistantModel
	}
	if effort == "" {
		effort = s.cfg.AssistantEffort
	}
	a := assistant.New(assistant.Config{APIKey: key, BaseURL: s.cfg.AssistantBaseURL, Model: model, Effort: effort, Fallbacks: s.cfg.AssistantFallbacks})
	s.assistant.Store(&assistantState{a: a, model: model, source: source})
	s.refreshAssistantDocs()
	s.log.Info("assistant enabled: questions and retrieved passages are sent to the Anthropic API",
		"model", model, "source", source, "passages", len(*s.assistantDocs.Load()))
	return nil
}

// refreshAssistantDocs rebuilds the static passages (catalog, guide,
// runbooks); called again when a module release is deployed.
func (s *Server) refreshAssistantDocs() {
	if s.assistant.Load() == nil {
		return
	}
	docs := append(append(assistant.CatalogDocs(s.plat().cat), assistant.GuideDocs()...), s.assistantExtra...)
	s.assistantDocs.Store(&docs)
}

func (s *Server) assistantInfo(w http.ResponseWriter, r *http.Request) {
	st := s.assistant.Load()
	if st == nil {
		writeJSON(w, 200, map[string]any{"enabled": false})
		return
	}
	writeJSON(w, 200, map[string]any{"enabled": true, "model": st.model})
}

// ---- Integrations → Assistant (tenant admins) ----

var assistantModelRe = regexp.MustCompile(`^claude-[a-z0-9.-]{1,60}$`)

func (s *Server) getAssistantIntegration(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	out := map[string]any{"enabled": false, "source": "none", "model": s.cfg.AssistantModel, "effort": s.cfg.AssistantEffort, "env_key": s.cfg.AssistantAPIKey != ""}
	if st := s.assistant.Load(); st != nil {
		out["enabled"], out["source"], out["model"] = true, st.source, st.model
	}
	if c, ok := s.assistantSettings(r.Context()); ok {
		out["source"], out["key_set"], out["model"], out["effort"] = "console", c.APIKey != "", c.Model, c.Effort
		out["enabled"] = c.Enabled && c.APIKey != ""
	}
	writeJSON(w, 200, out)
}

func (s *Server) putAssistantIntegration(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	var b assistantConfig
	if !decode(w, r, &b) {
		return
	}
	cur, had := s.assistantSettings(r.Context())
	if b.APIKey == "" && had {
		b.APIKey = cur.APIKey
	}
	var probs []string
	if b.Model == "" {
		b.Model = s.cfg.AssistantModel
	}
	if !assistantModelRe.MatchString(b.Model) {
		probs = append(probs, "model must be a Claude model id, e.g. claude-opus-5-5")
	}
	if b.Effort == "" {
		b.Effort = "medium"
	}
	if !slices.Contains([]string{"low", "medium", "high", "xhigh", "max"}, b.Effort) {
		probs = append(probs, "effort must be low, medium, high, xhigh or max")
	}
	if b.Enabled && (len(b.APIKey) < 20 || strings.ContainsAny(b.APIKey, " \n\t")) {
		probs = append(probs, "an Anthropic API key is needed to turn the assistant on")
	}
	if len(probs) > 0 {
		writeErr(w, 422, "invalid assistant settings", probs...)
		return
	}
	if s.dryRun(w, r) {
		return
	}
	raw, _ := json.Marshal(b)
	if err := s.sealSetting(r.Context(), assistantSetting, assistantSetting, raw, user(r).Subject); err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	if err := s.enableAssistant(); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.audit(r.Context(), user(r).Actor(), "integration.assistant.configure", "integration/assistant", "", map[string]any{"enabled": b.Enabled, "model": b.Model, "effort": b.Effort, "key_changed": !had || cur.APIKey != b.APIKey})
	s.getAssistantIntegration(w, r)
}

func (s *Server) deleteAssistantIntegration(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	if s.dryRun(w, r) {
		return
	}
	s.store.DeleteSetting(r.Context(), assistantSetting)
	s.enableAssistant() // back to the environment's settings, if any
	s.audit(r.Context(), user(r).Actor(), "integration.assistant.remove", "integration/assistant", "", nil)
	w.WriteHeader(http.StatusNoContent)
}

// askAssistant streams newline-delimited JSON: {"type":"status"} events while
// the assistant works, then one {"type":"answer"} or {"type":"error"}.
func (s *Server) askAssistant(w http.ResponseWriter, r *http.Request) {
	st := s.assistant.Load()
	if st == nil {
		writeErr(w, http.StatusNotFound, assistant.ErrDisabled.Error())
		return
	}
	p := user(r)
	if s.askLimiter.Blocked(p.Subject) {
		writeErr(w, http.StatusTooManyRequests, "too many assistant questions; try again later")
		return
	}
	var b struct {
		Question string           `json:"question"`
		History  []assistant.Turn `json:"history"`
	}
	if !decode(w, r, &b) {
		return
	}
	if q := strings.TrimSpace(b.Question); q == "" || len(q) > 4000 {
		writeErr(w, 422, "the question must be 1 to 4000 characters")
		return
	}
	s.askLimiter.Fail(p.Subject) // counts every question
	ctx, cancel := context.WithTimeout(r.Context(), assistantTimeout)
	defer cancel()

	ix, envs, err := s.assistantCorpus(ctx, r)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	rc := http.NewResponseController(w)
	rc.SetWriteDeadline(time.Now().Add(assistantTimeout + 30*time.Second))
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(200)
	enc := json.NewEncoder(w)
	emit := func(v any) {
		enc.Encode(v)
		rc.Flush()
	}
	emit(map[string]string{"type": "status", "text": fmt.Sprintf("Searching %d passages", ix.Len())})

	ans, err := st.a.Ask(ctx, assistant.Request{
		Question: b.Question, History: b.History, Index: ix, Environments: envs,
		Validate: func(ctx context.Context, name, bu, envName string, raw json.RawMessage) []string {
			return s.validateDraft(ctx, r, name, bu, envName, raw)
		},
		Progress: func(t string) { emit(map[string]string{"type": "status", "text": t}) },
	})
	sum := sha256.Sum256([]byte(b.Question))
	meta := map[string]any{"question_sha256": hex.EncodeToString(sum[:]), "question_chars": len(b.Question)}
	if err != nil {
		s.log.Warn("assistant request failed", "err", err)
		meta["error"] = true
		s.audit(r.Context(), p.Actor(), "assistant.ask", "assistant", "", meta)
		emit(map[string]string{"type": "error", "error": "the assistant could not answer right now"})
		return
	}
	meta["model_calls"], meta["input_tokens"], meta["output_tokens"] = ans.Usage.ModelCalls, ans.Usage.InputTokens, ans.Usage.OutputTokens
	meta["sources"] = len(ans.Sources)
	if ans.Draft != nil {
		meta["draft_environment"] = ans.Draft.Environment
	}
	s.audit(r.Context(), p.Actor(), "assistant.ask", "assistant", "", meta)
	emit(map[string]any{"type": "answer", "answer": ans})
}

// assistantCorpus is the static knowledge plus what this caller may see:
// stacks and environments in their visible BUs, the tenant's policies and the
// risk policy (both readable by every member).
func (s *Server) assistantCorpus(ctx context.Context, r *http.Request) (*assistant.Index, []assistant.Environment, error) {
	p := user(r)
	var docs []assistant.Doc
	var envs []assistant.Environment
	es, err := s.store.ListEnvironments(ctx, p.VisibleEntities())
	if err != nil {
		return nil, nil, err
	}
	for _, e := range es {
		cloud, region := "unknown", ""
		if c, err := spec.DecodeCloud(e.Cloud); err == nil {
			cloud = c.Provider
			switch {
			case c.AWS != nil:
				region = c.AWS.Region
			case c.GCP != nil:
				region = c.GCP.Region + ", project " + c.GCP.ProjectID
			}
		}
		bus := p.WritableBUs(e.Entity)
		writable := len(bus) > 0
		envs = append(envs, assistant.Environment{Name: e.Name, Entity: e.Entity, WritableBUs: bus, Tier: e.Tier, Cloud: cloud, Writable: writable})
		docs = append(docs, assistant.Doc{ID: "environment:" + e.Name, Kind: "environment", Title: "Environment " + e.Name,
			Text: fmt.Sprintf("Environment %q of entity (product) %s, shared by all its business units: tier %s, cloud %s %s, connection %s, runner pool %s, destroys allowed: %v, max destroys per run: %d. Business units the person can create stacks for here: %v.",
				e.Name, e.Entity, e.Tier, cloud, region, e.Connection, e.RunnerPool, e.AllowDestroy, e.MaxDestroys, bus)})
	}
	sts, err := s.store.ListStacks(ctx, visible(r))
	if err != nil {
		return nil, nil, err
	}
	for _, st := range sts {
		var b strings.Builder
		fmt.Fprintf(&b, "Stack %q in environment %s (business unit %s), managed by %s.", st.Name, st.Environment, st.BU, st.ManagedBy)
		if st.LastRun != nil {
			lr, _ := json.Marshal(st.LastRun)
			fmt.Fprintf(&b, " Last run: %s.", lr)
		}
		fmt.Fprintf(&b, "\nSpec: %s", st.Spec)
		docs = append(docs, assistant.Doc{ID: "stack:" + st.Name, Kind: "stack", Title: "Stack " + st.Name, Text: b.String()})
	}
	ps, err := s.store.ListPolicySets(ctx)
	if err != nil {
		return nil, nil, err
	}
	for _, pol := range ps {
		docs = append(docs, assistant.Doc{ID: "policy:" + pol.Name, Kind: "policy", Title: "Policy set " + pol.Name,
			Text: fmt.Sprintf("OPA policy set %q, level %s (hard blocks runs, advisory only warns), scope %q, enabled %v:\n%s", pol.Name, pol.Level, pol.Scope, pol.Enabled, pol.Module)})
	}
	rs, _ := json.Marshal(s.riskSettings(ctx))
	docs = append(docs, assistant.Doc{ID: "settings:risk", Kind: "settings", Title: "Risk policy",
		Text: "This tenant's risk policy (approval steps per risk level, the risk of production changes, cost thresholds): " + string(rs)})
	return assistant.NewIndex(*s.assistantDocs.Load(), docs), envs, nil
}

// validateDraft runs the same checks as creating the stack, without saving.
func (s *Server) validateDraft(ctx context.Context, r *http.Request, name, bu, envName string, raw json.RawMessage) []string {
	var probs []string
	if !spec.StackNameRe.MatchString(name) {
		probs = append(probs, "the stack name must be lowercase letters, digits and dashes")
		name = "draft"
	}
	p := user(r)
	if !p.CanChange(bu) {
		return append(probs, fmt.Sprintf("the person cannot create stacks in business unit %q", bu))
	}
	env, err := s.store.EntityEnvironment(ctx, p.EntityOf(bu), envName)
	if err != nil {
		return append(probs, fmt.Sprintf("business unit %s's entity has no environment %q", bu, envName))
	}
	if _, _, more := s.build(ctx, name, bu, env, raw); more != nil {
		probs = append(probs, more...)
	}
	return probs
}
