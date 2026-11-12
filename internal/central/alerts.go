package central

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/httpx"
)

// ---- platform alerts ----
//
// Every minute one replica (the one holding the alert lock) compares what
// needs attention now (workspaces offline or never connected, lapsed link
// certificates, failed provisioning) with what it last reported, and sends
// "firing" for new problems and "resolved" for ones that cleared, to a Slack
// incoming webhook and/or a generic webhook. Platform admins set the
// destinations in the console (Platform → Alerts); every alert sent is in
// the platform audit log.

type AlertSettings struct {
	Enabled  bool   `json:"enabled"`
	SlackURL string `json:"slack_webhook_url"` // https://hooks.slack.com/...
	Webhook  string `json:"webhook_url"`       // any https endpoint; JSON body below
}

type alertEvent struct {
	Status    string     `json:"status"` // firing | resolved
	Key       string     `json:"key"`
	Workspace string     `json:"workspace"`
	Name      string     `json:"name"`
	Problem   string     `json:"problem"`
	Since     *time.Time `json:"since,omitempty"`
	URL       string     `json:"url"`
	At        time.Time  `json:"at"`
}

func (s *Store) AlertSettings(ctx context.Context) AlertSettings {
	var a AlertSettings
	var raw []byte
	if s.Pool().QueryRow(ctx, `SELECT value FROM platform_settings WHERE key = 'platform_alerts'`).Scan(&raw) == nil {
		json.Unmarshal(raw, &a)
	}
	return a
}

func (s *Store) PutAlertSettings(ctx context.Context, a AlertSettings, by string) error {
	raw, _ := json.Marshal(a)
	_, err := s.Pool().Exec(ctx, `INSERT INTO platform_settings (key, value, updated_by) VALUES ('platform_alerts', $1, $2)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_by = EXCLUDED.updated_by, updated_at = now()`, raw, by)
	return err
}

// alertState is what was last reported as firing, by key, kept in
// platform_settings so a restart or another replica does not repeat it.
func (s *Store) alertState(ctx context.Context) map[string]alertEvent {
	m := map[string]alertEvent{}
	var raw []byte
	if s.Pool().QueryRow(ctx, `SELECT value FROM platform_settings WHERE key = 'platform_alert_state'`).Scan(&raw) == nil {
		json.Unmarshal(raw, &m)
	}
	return m
}

func (s *Store) putAlertState(ctx context.Context, m map[string]alertEvent) {
	raw, _ := json.Marshal(m)
	s.Pool().Exec(ctx, `INSERT INTO platform_settings (key, value, updated_by) VALUES ('platform_alert_state', $1, 'system:alerts')
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`, raw)
}

func checkAlertURL(name, v string, slack bool) string {
	if v == "" {
		return ""
	}
	u, err := url.Parse(v)
	if err != nil || u.Host == "" || (u.Scheme != "https" && !(u.Scheme == "http" && isLoopbackHost(u.Hostname()))) {
		return name + " must be an https URL"
	}
	if slack && u.Host != "hooks.slack.com" && !isLoopbackHost(u.Hostname()) {
		return name + " must be a Slack incoming webhook (https://hooks.slack.com/...)"
	}
	return ""
}

func isLoopbackHost(h string) bool { return h == "localhost" || h == "127.0.0.1" || h == "::1" }

// currentProblems is what needs attention now, keyed for de-duplication.
func (s *Server) currentProblems(ctx context.Context) (map[string]alertEvent, error) {
	att, err := s.attentionList(ctx)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	out := map[string]alertEvent{}
	for _, a := range att {
		kind := "offline"
		if strings.HasPrefix(a.Reason, "never connected") {
			kind = "never-connected"
		}
		key := a.Slug + "/" + kind
		out[key] = alertEvent{Status: "firing", Key: key, Workspace: a.Slug, Name: a.Name, Problem: a.Reason, Since: a.Since, At: now}
	}
	rows, err := s.store.Pool().Query(ctx, `SELECT t.slug, t.name, p.detail, p.updated_at FROM provisionings p JOIN tenants t ON t.id = p.tenant_id
		WHERE p.status = 'failed' AND t.status <> 'removed'`)
	if err == nil {
		for rows.Next() {
			var slug, name, detail string
			var at time.Time
			if rows.Scan(&slug, &name, &detail, &at) == nil {
				key := slug + "/provisioning-failed"
				out[key] = alertEvent{Status: "firing", Key: key, Workspace: slug, Name: name, Problem: "provisioning failed: " + detail, Since: &at, At: now}
			}
		}
		rows.Close()
	}
	return out, nil
}

// alertLoop evaluates alerts every minute on whichever replica holds the lock.
func (s *Server) alertLoop(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s.evaluateAlerts(ctx)
	}
}

func (s *Server) evaluateAlerts(ctx context.Context) {
	cfg := s.store.AlertSettings(ctx)
	if !cfg.Enabled || (cfg.SlackURL == "" && cfg.Webhook == "") {
		return
	}
	conn, err := s.store.Pool().Acquire(ctx)
	if err != nil {
		return
	}
	defer conn.Release()
	var got bool
	if conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(7201)`).Scan(&got); !got {
		return // another replica sends this minute's alerts
	}
	defer conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock(7201)`)
	now, err := s.currentProblems(ctx)
	if err != nil {
		return
	}
	before := s.store.alertState(ctx)
	next := map[string]alertEvent{}
	for k, e := range now {
		if old, ok := before[k]; ok {
			next[k] = old // still firing: already reported
			continue
		}
		if s.sendAlert(ctx, cfg, e) == nil {
			next[k] = e
		}
	}
	for k, e := range before {
		if _, ok := now[k]; ok {
			continue
		}
		e.Status, e.At = "resolved", time.Now()
		if s.sendAlert(ctx, cfg, e) != nil {
			next[k] = before[k] // try the resolution again next minute
		}
	}
	s.store.putAlertState(ctx, next)
}

func (s *Server) sendAlert(ctx context.Context, cfg AlertSettings, e alertEvent) error {
	e.URL = strings.TrimRight(s.cfg.PublicURL, "/") + "/#/platform/tenants/" + e.Workspace
	var errs []string
	hc := &http.Client{Timeout: 10 * time.Second}
	post := func(u string, body any) {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "SrustiOps-Alerts")
		resp, err := hc.Do(req)
		if err != nil {
			errs = append(errs, err.Error())
			return
		}
		resp.Body.Close()
		if resp.StatusCode >= 300 {
			errs = append(errs, fmt.Sprintf("%s answered %d", u, resp.StatusCode))
		}
	}
	if cfg.SlackURL != "" {
		icon := ":red_circle:"
		if e.Status == "resolved" {
			icon = ":large_green_circle:"
		}
		post(cfg.SlackURL, map[string]string{"text": fmt.Sprintf("%s *%s* %s: %s\n<%s|Open in SrustiOps>", icon, e.Name, e.Status, e.Problem, e.URL)})
	}
	if cfg.Webhook != "" {
		post(cfg.Webhook, e)
	}
	s.audit(ctx, "system:alerts", "platform.alert."+e.Status, "tenant/"+e.Workspace, e.Workspace, map[string]any{"problem": e.Problem, "errors": errs})
	if len(errs) > 0 {
		s.log.Warn("sending a platform alert failed", "workspace", e.Workspace, "errors", errs)
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// ---- console API ----

func (s *Server) getAlertSettings(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(w, r) {
		return
	}
	cfg := s.store.AlertSettings(r.Context())
	firing := []alertEvent{}
	for _, e := range s.store.alertState(r.Context()) {
		firing = append(firing, e)
	}
	httpx.WriteJSON(w, 200, map[string]any{"settings": cfg, "firing": firing})
}

func (s *Server) putAlertSettings(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(w, r) {
		return
	}
	var a AlertSettings
	if !httpx.Decode(w, r, &a) {
		return
	}
	var probs []string
	for _, p := range []string{checkAlertURL("slack_webhook_url", a.SlackURL, true), checkAlertURL("webhook_url", a.Webhook, false)} {
		if p != "" {
			probs = append(probs, p)
		}
	}
	if a.Enabled && a.SlackURL == "" && a.Webhook == "" {
		probs = append(probs, "name a Slack webhook or a webhook URL to turn alerts on")
	}
	if len(probs) > 0 {
		httpx.WriteErr(w, 422, "invalid alert settings", probs...)
		return
	}
	if err := s.store.PutAlertSettings(r.Context(), a, current(r).Email); err != nil {
		s.storeErr(w, err, "")
		return
	}
	// The destinations are secrets of a kind: the audit names which are set.
	s.audit(r.Context(), current(r).Email, "platform.alert_settings", "platform/alerts", "", map[string]bool{"enabled": a.Enabled, "slack": a.SlackURL != "", "webhook": a.Webhook != ""})
	httpx.WriteJSON(w, 200, a)
}

// testAlert sends one test alert to the saved destinations.
func (s *Server) testAlert(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(w, r) {
		return
	}
	cfg := s.store.AlertSettings(r.Context())
	if cfg.SlackURL == "" && cfg.Webhook == "" {
		httpx.WriteErr(w, 409, "save a Slack webhook or a webhook URL first")
		return
	}
	e := alertEvent{Status: "test", Key: "test", Workspace: "test", Name: "Test alert", Problem: "sent from Platform → Alerts by " + current(r).Email, At: time.Now()}
	if err := s.sendAlert(r.Context(), cfg, e); err != nil {
		httpx.WriteErr(w, 502, "the alert was not delivered: "+err.Error())
		return
	}
	httpx.WriteJSON(w, 200, map[string]string{"status": "sent"})
}
