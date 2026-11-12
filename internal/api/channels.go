package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/mail"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/store"
)

// ---- more notification channels (Integrations → Channels) ----
//
// Beside Slack and email: a Microsoft Teams channel (incoming webhook or
// Workflows URL), PagerDuty (Events API v2: errors open incidents, success
// resolves them by the same key), and a daily digest email of what happened.
// Each channel takes notifications from a minimum severity up.

const (
	channelsSetting = "notify_channels"
	channelsAAD     = "notify_channels"
	digestLock      = 7317
)

type channelsConfig struct {
	Teams struct {
		URL         string `json:"url"`
		MinSeverity string `json:"min_severity"` // info | warning | error (default warning)
	} `json:"teams"`
	PagerDuty struct {
		RoutingKey  string `json:"routing_key"`
		MinSeverity string `json:"min_severity"` // default error
		APIURL      string `json:"api_url,omitempty"`
	} `json:"pagerduty"`
	Digest struct {
		Enabled bool     `json:"enabled"`
		To      []string `json:"to"`
		HourUTC int      `json:"hour_utc"`
	} `json:"digest"`
}

var severityRank = map[string]int{"info": 0, "success": 0, "action": 1, "warning": 1, "error": 2}

func atLeast(sev, min string, def string) bool {
	if min == "" {
		min = def
	}
	return severityRank[sev] >= severityRank[min]
}

func (s *Server) channels(ctx context.Context) (*channelsConfig, bool) {
	b, ok := s.openSetting(ctx, channelsSetting, channelsAAD)
	if !ok {
		return nil, false
	}
	var c channelsConfig
	if json.Unmarshal(b, &c) != nil {
		return nil, false
	}
	return &c, true
}

// sendChannels delivers a notification to the configured channels.
func (s *Server) sendChannels(ctx context.Context, n *store.Notification) {
	c, ok := s.channels(ctx)
	if !ok {
		return
	}
	if c.Teams.URL != "" && atLeast(n.Severity, c.Teams.MinSeverity, "warning") {
		go s.postJSON(c.Teams.URL, s.teamsMessage(n), "teams", n.Kind)
	}
	if c.PagerDuty.RoutingKey != "" {
		action := ""
		switch {
		case atLeast(n.Severity, c.PagerDuty.MinSeverity, "error"):
			action = "trigger"
		case n.Severity == "success":
			action = "resolve" // a later success for the same thing closes the incident
		}
		if action != "" {
			api := c.PagerDuty.APIURL
			if api == "" {
				api = "https://events.pagerduty.com/v2/enqueue"
			}
			go s.postJSON(api, s.pagerDutyEvent(c.PagerDuty.RoutingKey, action, n), "pagerduty", n.Kind)
		}
	}
}

// dedupKey groups a notification's trigger and resolve in PagerDuty: the
// run (or the kind's subject) it is about.
func (s *Server) dedupKey(n *store.Notification) string {
	if n.RunID != nil {
		return s.cfg.Tenant + ":run:" + *n.RunID
	}
	base, _, _ := strings.Cut(n.Kind, ".")
	return s.cfg.Tenant + ":" + base + ":" + n.BU + ":" + n.Link
}

func (s *Server) pagerDutyEvent(key, action string, n *store.Notification) map[string]any {
	ev := map[string]any{"routing_key": key, "event_action": action, "dedup_key": s.dedupKey(n)}
	if action == "trigger" {
		sev := map[string]string{"error": "error", "warning": "warning", "action": "warning"}[n.Severity]
		if sev == "" {
			sev = "info"
		}
		ev["payload"] = map[string]any{"summary": trimTo(n.Title+": "+n.Body, 1000), "source": "srustiops/" + s.cfg.Tenant, "severity": sev,
			"component": n.BU, "group": n.Entity, "class": n.Kind}
		if n.Link != "" {
			ev["links"] = []map[string]string{{"href": s.consoleURL(n.Link), "text": "Open in SrustiOps"}}
		}
	}
	return ev
}

func (s *Server) teamsMessage(n *store.Notification) map[string]any {
	color := map[string]string{"error": "attention", "warning": "warning", "success": "good", "action": "accent"}[n.Severity]
	body := []map[string]any{{"type": "TextBlock", "text": n.Title, "weight": "bolder", "size": "medium", "wrap": true, "color": color}}
	if n.Body != "" {
		body = append(body, map[string]any{"type": "TextBlock", "text": n.Body, "wrap": true})
	}
	facts := []map[string]string{{"title": "Workspace", "value": s.cfg.Tenant}}
	if n.BU != "" {
		facts = append(facts, map[string]string{"title": "Business unit", "value": n.Entity + " / " + n.BU})
	}
	body = append(body, map[string]any{"type": "FactSet", "facts": facts})
	card := map[string]any{"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4", "body": body}
	if n.Link != "" {
		card["actions"] = []map[string]string{{"type": "Action.OpenUrl", "title": "Open in SrustiOps", "url": s.consoleURL(n.Link)}}
	}
	return map[string]any{"type": "message", "attachments": []map[string]any{{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}}}
}

func (s *Server) postJSON(u string, v any, channel, kind string) error {
	b, _ := json.Marshal(v)
	hc := &http.Client{Timeout: 10 * time.Second}
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt*2) * time.Second)
		}
		resp, err := hc.Post(u, "application/json", bytes.NewReader(b))
		if err != nil {
			last = err
			continue
		}
		resp.Body.Close()
		if resp.StatusCode < 300 {
			return nil
		}
		last = fmt.Errorf("%s returned %s", channel, resp.Status)
		if resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
			break
		}
	}
	s.log.Warn("sending a notification failed", "channel", channel, "kind", kind, "err", last)
	return last
}

// ---- daily digest ----

func (s *Server) digestLoop(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		c, ok := s.channels(ctx)
		if !ok || !c.Digest.Enabled || len(c.Digest.To) == 0 || time.Now().UTC().Hour() != c.Digest.HourUTC {
			continue
		}
		s.store.TryLock(ctx, digestLock, func(ctx context.Context) {
			day := time.Now().UTC().Format("2006-01-02")
			var last string
			if s.store.Setting(ctx, "digest_sent", &last); last == day {
				return
			}
			if err := s.sendDigest(ctx, c, time.Now().Add(-24*time.Hour)); err == nil {
				s.store.PutSetting(ctx, "digest_sent", day, "system:digest")
			}
		})
	}
}

func (s *Server) sendDigest(ctx context.Context, c *channelsConfig, since time.Time) error {
	if s.emailConfig(ctx) == nil {
		return fmt.Errorf("the digest is sent by email: set up Integrations → Email first")
	}
	ns, err := s.store.NotificationsSince(ctx, since, 2000)
	if err != nil {
		return err
	}
	byKind := map[string]int{}
	var problems []*store.Notification
	for _, n := range ns {
		byKind[kindLabel(n.Kind)]++
		if n.Severity == "error" && len(problems) < 15 {
			problems = append(problems, n)
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "What happened in %s in the last 24 hours (%d notifications).\n\n", s.cfg.Tenant, len(ns))
	kinds := make([]string, 0, len(byKind))
	for k := range byKind {
		kinds = append(kinds, k)
	}
	sort.Slice(kinds, func(i, j int) bool { return byKind[kinds[i]] > byKind[kinds[j]] })
	for _, k := range kinds {
		fmt.Fprintf(&b, "  %4d  %s\n", byKind[k], k)
	}
	if len(problems) > 0 {
		b.WriteString("\nProblems:\n")
		for _, n := range problems {
			fmt.Fprintf(&b, "  - %s%s\n", n.Title, map[bool]string{true: " (" + s.consoleURL(n.Link) + ")", false: ""}[n.Link != ""])
		}
	}
	if len(ns) == 0 {
		b.WriteString("Nothing to report.\n")
	}
	b.WriteString("\nSent by SrustiOps; change it under Integrations → Channels.\n")
	for _, to := range c.Digest.To {
		s.store.EnqueueEmail(ctx, to, "[SrustiOps · "+s.cfg.Tenant+"] Daily digest", b.String())
	}
	s.kickMailer()
	return nil
}

// ---- API ----

func (c *channelsConfig) validate() []string {
	var probs []string
	if u := c.Teams.URL; u != "" {
		p, err := url.Parse(u)
		loopback := p != nil && p.Scheme == "http" && (p.Hostname() == "127.0.0.1" || p.Hostname() == "localhost") // local tests
		if err != nil || (p.Scheme != "https" && !loopback) || p.Host == "" {
			probs = append(probs, "the Teams URL must be an https webhook or Workflows URL")
		}
	}
	if k := c.PagerDuty.RoutingKey; k != "" && (len(k) < 20 || len(k) > 64) {
		probs = append(probs, "the PagerDuty routing key is the 32-character integration key of an Events API v2 integration")
	}
	if u := c.PagerDuty.APIURL; u != "" && !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://127.0.0.1") {
		probs = append(probs, "the PagerDuty API URL must be https")
	}
	for _, m := range []string{c.Teams.MinSeverity, c.PagerDuty.MinSeverity} {
		if m != "" && m != "info" && m != "warning" && m != "error" {
			probs = append(probs, "a minimum severity is info, warning or error")
		}
	}
	if c.Digest.HourUTC < 0 || c.Digest.HourUTC > 23 {
		probs = append(probs, "the digest hour is 0-23 (UTC)")
	}
	for _, a := range c.Digest.To {
		if _, err := mail.ParseAddress(a); err != nil {
			probs = append(probs, "not an email address: "+a)
		}
	}
	if c.Digest.Enabled && len(c.Digest.To) == 0 {
		probs = append(probs, "the digest needs at least one address")
	}
	return probs
}

func (s *Server) getChannels(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	c, ok := s.channels(r.Context())
	if !ok {
		writeJSON(w, 200, map[string]any{"configured": false})
		return
	}
	// Webhook URLs and keys are secrets: shown only as set or not.
	writeJSON(w, 200, map[string]any{"configured": true,
		"teams":     map[string]any{"set": c.Teams.URL != "", "min_severity": c.Teams.MinSeverity},
		"pagerduty": map[string]any{"set": c.PagerDuty.RoutingKey != "", "min_severity": c.PagerDuty.MinSeverity},
		"digest":    c.Digest})
}

func (s *Server) putChannels(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	var b channelsConfig
	if !decode(w, r, &b) {
		return
	}
	cur, had := s.channels(r.Context())
	if had { // blank secrets keep the stored ones
		if b.Teams.URL == "" {
			b.Teams.URL = cur.Teams.URL
		}
		if b.PagerDuty.RoutingKey == "" {
			b.PagerDuty.RoutingKey = cur.PagerDuty.RoutingKey
		}
	}
	if b.Teams.URL == "-" {
		b.Teams.URL = "" // "-" removes a channel
	}
	if b.PagerDuty.RoutingKey == "-" {
		b.PagerDuty.RoutingKey = ""
	}
	if probs := b.validate(); len(probs) > 0 {
		writeErr(w, 422, "invalid channels", probs...)
		return
	}
	if s.dryRun(w, r) {
		return
	}
	raw, _ := json.Marshal(b)
	if err := s.sealSetting(r.Context(), channelsSetting, channelsAAD, raw, user(r).Subject); err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.audit(r.Context(), user(r).Actor(), "integration.channels.configure", "integration/channels", "", map[string]any{
		"teams": b.Teams.URL != "", "pagerduty": b.PagerDuty.RoutingKey != "", "digest": b.Digest})
	s.getChannels(w, r)
}

// testChannels sends a test notification to every channel (and the digest
// of the last day, when it is on).
func (s *Server) testChannels(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	c, ok := s.channels(r.Context())
	if !ok {
		writeErr(w, 422, "no channels are set up")
		return
	}
	n := &store.Notification{Kind: "channels.test", Severity: "error", Title: "Test from SrustiOps", Body: "This is a test notification from " + s.cfg.Tenant + ".", Link: "integrations/channels"}
	out := map[string]string{}
	if c.Teams.URL != "" {
		out["teams"] = errText(s.postJSON(c.Teams.URL, s.teamsMessage(n), "teams", n.Kind))
	}
	if c.PagerDuty.RoutingKey != "" {
		api := c.PagerDuty.APIURL
		if api == "" {
			api = "https://events.pagerduty.com/v2/enqueue"
		}
		ev := s.pagerDutyEvent(c.PagerDuty.RoutingKey, "trigger", n)
		ev["dedup_key"] = s.cfg.Tenant + ":channels-test"
		out["pagerduty"] = errText(s.postJSON(api, ev, "pagerduty", n.Kind))
		ev["event_action"] = "resolve"
		delete(ev, "payload")
		s.postJSON(api, ev, "pagerduty", n.Kind)
	}
	if c.Digest.Enabled {
		out["digest"] = errText(s.sendDigest(r.Context(), c, time.Now().Add(-24*time.Hour)))
	}
	s.audit(r.Context(), user(r).Actor(), "integration.channels.test", "integration/channels", "", out)
	writeJSON(w, 200, out)
}

func errText(err error) string {
	if err != nil {
		return err.Error()
	}
	return "ok"
}
