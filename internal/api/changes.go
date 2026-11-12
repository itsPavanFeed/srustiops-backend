package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"

	"github.com/itsPavanFeed/srustiops-backend/internal/identity"
	"github.com/itsPavanFeed/srustiops-backend/internal/store"
)

// Integration changes. Editing or deleting an integration is a request:
// the change is recorded (its body sealed, a redacted preview kept) and is
// applied only when another tenant admin or DevOps engineer approves it.
// DevOps may override with a reason, which is recorded. Creating an
// integration is not gated: it changes nothing that already works.

type changeCtxKey struct{}
type dryRunKey struct{}

// dryRun reports a validation pass: the handler stops just before it saves,
// answering 200, so a change request is checked before it is recorded.
func (s *Server) dryRun(w http.ResponseWriter, r *http.Request) bool {
	if r.Context().Value(dryRunKey{}) == nil {
		return false
	}
	w.WriteHeader(http.StatusOK)
	return true
}

// gate is a registered integration route whose changes need approval.
type gate struct {
	action string // e.g. connection.update
	label  string // e.g. "Cloud connection"
	h      http.HandlerFunc
	params []string // path values the handler reads
}

// gated wraps an edit or delete handler: without an approved change in the
// context it records a change request instead of applying.
func (s *Server) gated(action, label string, h http.HandlerFunc, params ...string) http.HandlerFunc {
	if s.gates == nil {
		s.gates = map[string]*gate{}
	}
	g := &gate{action: action, label: label, h: h, params: params}
	s.gates[action] = g
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Context().Value(changeCtxKey{}) != nil {
			h(w, r)
			return
		}
		s.requestChange(w, r, g)
	}
}

var secretKeyRe = regexp.MustCompile(`(?i)secret|token|password|private|key_pem|webhook_url|credential`)

// hideSecrets hides values whose key looks secret, recursively.
func hideSecrets(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, x := range t {
			if secretKeyRe.MatchString(k) {
				if x == nil || x == "" {
					out[k] = x
				} else {
					out[k] = "(hidden)"
				}
				continue
			}
			out[k] = hideSecrets(x)
		}
		return out
	case []any:
		for i := range t {
			t[i] = hideSecrets(t[i])
		}
	}
	return v
}

func (s *Server) requestChange(w http.ResponseWriter, r *http.Request, g *gate) {
	p := user(r)
	if !p.ManagesTenant() {
		writeErr(w, http.StatusForbidden, "changing integrations needs the tenant admin or devops role")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20+1))
	if err != nil || len(body) > 1<<20 {
		writeErr(w, http.StatusRequestEntityTooLarge, "request too large")
		return
	}
	var reason string
	var preview json.RawMessage
	if len(bytes.TrimSpace(body)) > 0 {
		var v map[string]any
		if err := json.Unmarshal(body, &v); err != nil {
			writeErr(w, 400, "the request body is not valid JSON")
			return
		}
		if rs, ok := v["change_reason"].(string); ok {
			reason = strings.TrimSpace(rs)
			delete(v, "change_reason")
		}
		preview, _ = json.Marshal(hideSecrets(v))
	} else if rs := r.URL.Query().Get("reason"); rs != "" {
		reason = rs
	}
	// Check the request now, so a mistake is reported at once rather than
	// when someone approves it.
	dry := r.Clone(context.WithValue(r.Context(), dryRunKey{}, true))
	dry.Body = io.NopCloser(bytes.NewReader(stripReason(body)))
	dry.ContentLength = -1
	rec := httptest.NewRecorder()
	g.h(rec, dry)
	if rec.Code >= 300 {
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(rec.Code)
		w.Write(rec.Body.Bytes())
		return
	}
	pv := map[string]string{}
	target := ""
	for _, k := range g.params {
		pv[k] = r.PathValue(k)
		target = pv[k]
	}
	ch, err := s.store.CreateChange(r.Context(), &store.IntegrationChange{Action: g.action, Target: target, PathValues: pv, Preview: preview, RequestedBy: p.Subject, Reason: reason})
	if err != nil {
		s.writeStoreErr(w, err, "this integration already has a change waiting for approval; approve, reject or cancel it first")
		return
	}
	if len(body) > 0 {
		sealed, err := s.sealer.Seal(body, []byte("integration-change:"+ch.ID))
		if err == nil {
			err = s.store.SealChangeBody(r.Context(), ch.ID, sealed)
		}
		if err != nil {
			s.store.DecideChange(r.Context(), ch.ID, "failed", "system", "cancel", "", ptr("could not seal the request"))
			s.writeStoreErr(w, err, "")
			return
		}
	}
	s.audit(r.Context(), p.Actor(), "integration.change.request", g.action+"/"+target, "", map[string]any{"change": ch.ID, "preview": preview, "reason": reason})
	s.notifyEvent(r.Context(), store.Notification{Kind: "integration.change", Severity: "action", Title: g.label + " change waiting for approval",
		Body: p.Subject + " asked to " + verb(g.action) + " " + nonEmpty(target, strings.ToLower(g.label)) + ". Another tenant admin or DevOps engineer approves it.", Link: "approvals"})
	writeJSON(w, http.StatusAccepted, s.changeView(ch))
}

func ptr(s string) *string { return &s }

func verb(action string) string {
	if strings.HasSuffix(action, ".delete") {
		return "delete"
	}
	return "change"
}

func nonEmpty(s, alt string) string {
	if s == "" {
		return alt
	}
	return s
}

func (s *Server) changeView(ch *store.IntegrationChange) map[string]any {
	label := ch.Action
	if g := s.gates[ch.Action]; g != nil {
		label = g.label
	}
	return map[string]any{"change": ch, "label": label, "verb": verb(ch.Action)}
}

func (s *Server) listChanges(w http.ResponseWriter, r *http.Request) {
	if !user(r).ManagesTenant() && !user(r).HasTenantRole("auditor") {
		writeJSON(w, 200, []any{})
		return
	}
	chs, err := s.store.ListChanges(r.Context(), r.URL.Query().Get("status"), limit(r, 50, 200))
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	out := make([]map[string]any, 0, len(chs))
	for _, c := range chs {
		out = append(out, s.changeView(c))
	}
	writeJSON(w, 200, out)
}

// decideChange approves (or overrides) and applies a change, or rejects it.
func (s *Server) decideChange(decision string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := user(r)
		var b struct {
			Reason string `json:"reason"`
		}
		if r.ContentLength != 0 && !decode(w, r, &b) {
			return
		}
		b.Reason = strings.TrimSpace(b.Reason)
		ctx := r.Context()
		ch, err := s.store.GetChange(ctx, r.PathValue("id"))
		if err != nil {
			s.writeStoreErr(w, err, "")
			return
		}
		if ch.Status != "pending" {
			writeErr(w, http.StatusConflict, "this change was already "+ch.Status)
			return
		}
		own := ch.RequestedBy == p.Subject
		switch decision {
		case "cancel":
			if !own {
				writeErr(w, http.StatusForbidden, "only the requester can cancel a change; others reject it")
				return
			}
		case "reject":
			if !p.FullControl() {
				writeErr(w, http.StatusForbidden, "deciding integration changes needs the tenant admin or devops role")
				return
			}
		case "approve":
			if !p.FullControl() {
				writeErr(w, http.StatusForbidden, "deciding integration changes needs the tenant admin or devops role")
				return
			}
			if own {
				writeErr(w, http.StatusForbidden, "you requested this change; another tenant admin or DevOps engineer must approve it (DevOps can override with a reason)")
				return
			}
		case "override":
			if !p.HasTenantRole(identity.DevOps) {
				writeErr(w, http.StatusForbidden, "only DevOps can override the approval of an integration change")
				return
			}
			if b.Reason == "" {
				writeErr(w, 422, "an override needs a reason")
				return
			}
		}
		if decision == "reject" || decision == "cancel" {
			status := map[string]string{"reject": "rejected", "cancel": "cancelled"}[decision]
			if err := s.store.DecideChange(ctx, ch.ID, status, p.Subject, decision, b.Reason, nil); err != nil {
				s.writeStoreErr(w, err, "this change was already decided")
				return
			}
			s.audit(ctx, p.Actor(), "integration.change."+decision, ch.Action+"/"+ch.Target, "", map[string]any{"change": ch.ID, "reason": b.Reason})
			ch, _ = s.store.GetChange(ctx, ch.ID)
			writeJSON(w, 200, s.changeView(ch))
			return
		}
		claimed, err := s.store.ClaimChange(ctx, ch.ID)
		if err != nil {
			s.writeStoreErr(w, err, "this change is already being applied")
			return
		}
		code, msg := s.applyChange(ctx, r, claimed)
		status, errp := "applied", (*string)(nil)
		if code >= 300 {
			status, errp = "failed", &msg
		}
		if err := s.store.DecideChange(ctx, ch.ID, status, p.Subject, decision, b.Reason, errp); err != nil {
			s.writeStoreErr(w, err, "")
			return
		}
		s.audit(ctx, p.Actor(), "integration.change."+decision, ch.Action+"/"+ch.Target, "", map[string]any{"change": ch.ID, "requested_by": ch.RequestedBy, "reason": b.Reason, "result": status, "error": msg})
		ch, _ = s.store.GetChange(ctx, ch.ID)
		if status == "failed" {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "the change could not be applied: " + msg, "change": ch})
			return
		}
		writeJSON(w, 200, s.changeView(ch))
	}
}

// applyChange runs the original handler with the stored request, as the
// approver, marked as an approved change.
func (s *Server) applyChange(ctx context.Context, r *http.Request, ch *store.IntegrationChange) (int, string) {
	g := s.gates[ch.Action]
	if g == nil {
		return 500, "unknown change " + ch.Action
	}
	var body []byte
	if len(ch.Body) > 0 {
		b, err := s.sealer.Open(ch.Body, []byte("integration-change:"+ch.ID))
		if err != nil {
			return 500, "the stored request cannot be decrypted"
		}
		body = stripReason(b)
	}
	method := http.MethodPut
	if strings.HasSuffix(ch.Action, ".delete") {
		method = http.MethodDelete
	}
	req := r.Clone(context.WithValue(ctx, changeCtxKey{}, ch.ID))
	req.Method = method
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range ch.PathValues {
		req.SetPathValue(k, v)
	}
	rec := httptest.NewRecorder()
	g.h(rec, req)
	if rec.Code >= 300 {
		var e struct {
			Error   string   `json:"error"`
			Details []string `json:"details"`
		}
		json.Unmarshal(rec.Body.Bytes(), &e)
		msg := e.Error
		if len(e.Details) > 0 {
			msg += ": " + strings.Join(e.Details, "; ")
		}
		if msg == "" {
			msg = http.StatusText(rec.Code)
		}
		return rec.Code, msg
	}
	return rec.Code, ""
}

// gatedIfConfigured gates a tenant-wide integration's PUT once it is set up:
// the first setup changes nothing that already works, later edits do.
func (s *Server) gatedIfConfigured(name, label string, h http.HandlerFunc) http.HandlerFunc {
	gh := s.gated(name+".update", label, h)
	return func(w http.ResponseWriter, r *http.Request) {
		if s.integrationConfigured(r.Context(), name) {
			gh(w, r)
			return
		}
		h(w, r)
	}
}

func (s *Server) integrationConfigured(ctx context.Context, name string) bool {
	switch name {
	case "github":
		return s.ghState().OK
	case "slack":
		return s.slack().WebhookURL != ""
	case "email":
		return s.emailConfig(ctx) != nil
	case "assistant":
		_, ok := s.assistantSettings(ctx)
		return ok
	case "audit-export":
		_, ok := s.exportConfig(ctx)
		return ok
	case "channels":
		_, ok := s.channels(ctx)
		return ok
	case "secret-store":
		return s.secretStore(ctx) != nil
	case "contracts":
		_, ok := s.contractsConfig(ctx)
		return ok
	case "contracts-token":
		return s.contractsToken(ctx) != ""
	}
	return true
}

// stripReason removes the change_reason field a requester may add.
func stripReason(b []byte) []byte {
	var v map[string]any
	if len(bytes.TrimSpace(b)) == 0 || json.Unmarshal(b, &v) != nil {
		return b
	}
	if _, ok := v["change_reason"]; !ok {
		return b
	}
	delete(v, "change_reason")
	out, _ := json.Marshal(v)
	return out
}
