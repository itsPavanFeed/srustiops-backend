package api

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/config"
	"github.com/itsPavanFeed/srustiops-backend/internal/store"
)

func TestChannelMessages(t *testing.T) {
	s := &Server{cfg: &config.Server{Tenant: "acme", CentralURL: "https://srustiops.example.com"}}
	run := "r1"
	n := &store.Notification{Kind: "run.failed", Severity: "error", Title: "Apply failed", Body: "boom", BU: "payments", Entity: "retail", Link: "runs/r1", RunID: &run}
	ev := s.pagerDutyEvent("k", "trigger", n)
	b, _ := json.Marshal(ev)
	for _, want := range []string{`"dedup_key":"acme:run:r1"`, `"severity":"error"`, `"event_action":"trigger"`, `"component":"payments"`} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("pagerduty event lacks %s: %s", want, b)
		}
	}
	ok := *n
	ok.Severity = "success"
	if s.dedupKey(&ok) != s.dedupKey(n) {
		t.Fatal("the resolve must use the trigger's key")
	}
	tm, _ := json.Marshal(s.teamsMessage(n))
	if !strings.Contains(string(tm), "AdaptiveCard") || !strings.Contains(string(tm), "Apply failed") || !strings.Contains(string(tm), "runs/r1") {
		t.Fatalf("teams card: %s", tm)
	}
	if !atLeast("error", "", "warning") || atLeast("info", "", "warning") || atLeast("warning", "error", "") {
		t.Fatal("severity threshold")
	}
	var c channelsConfig
	c.Teams.URL, c.PagerDuty.RoutingKey, c.Digest.Enabled, c.Digest.HourUTC = "http://x", "short", true, 30
	if probs := c.validate(); len(probs) != 4 {
		t.Fatalf("problems: %v", probs)
	}
}

func TestForecast(t *testing.T) {
	// November has 30 days; on the 11th, 9 full billed days have passed.
	now := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
	if f := forecast(90, now); f < 299 || f > 301 {
		t.Fatalf("forecast %v, want 300", f)
	}
	if f := forecast(50, time.Date(2026, 11, 1, 6, 0, 0, 0, time.UTC)); f != 50*30 {
		t.Fatalf("early in the month the pace counts one day: %v", f)
	}
}
