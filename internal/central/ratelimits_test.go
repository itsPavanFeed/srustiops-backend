package central

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/itsPavanFeed/srustiops-backend/internal/httpx"
)

func TestRateLimitPolicy(t *testing.T) {
	l := defaultRateLimits()
	if p := l.validate(); len(p) > 0 {
		t.Fatalf("defaults are invalid: %v", p)
	}
	l.Overrides["big"] = WorkspaceLimits{MaxInFlight: 500, PerWorkspace: httpx.Rate{PerSecond: 1000, Burst: 2000}}
	w := l.forWorkspace("big")
	if w.MaxInFlight != 500 || w.PerWorkspace.PerSecond != 1000 || w.MaxBulkInFlight != l.MaxBulkInFlight || w.PerUserWrites != l.PerUserWrites {
		t.Fatalf("override not applied field by field: %+v", w)
	}
	if l.forWorkspace("other").MaxInFlight != l.MaxInFlight {
		t.Fatal("override leaked to another workspace")
	}
	bad := defaultRateLimits()
	bad.PerIP = httpx.Rate{PerSecond: 0.01, Burst: 1} // would lock out the console
	bad.MaxTunnels = 1
	bad.Overrides["Not A Slug"] = WorkspaceLimits{}
	if p := bad.validate(); len(p) != 3 {
		t.Fatalf("want 3 problems, got %v", p)
	}
}

func TestRateLimitsAnswer429And503(t *testing.T) {
	s := &Server{shape: newShaper()}
	l := defaultRateLimits()
	l.PerIP = httpx.Rate{PerSecond: 1, Burst: 20}
	l.MaxInFlight, l.QueueWaitMS = 1, 0
	s.shape.limits.Store(&l)

	h := s.limitIP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	hit := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest("GET", path, nil)
		r.RemoteAddr = "192.0.2.10:1234"
		h.ServeHTTP(rec, r)
		return rec
	}
	for i := 0; i < 20; i++ {
		if c := hit("/api/v1/me").Code; c != 204 {
			t.Fatalf("request %d within the burst: %d", i+1, c)
		}
	}
	rec := hit("/api/v1/me")
	if rec.Code != 429 || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("over the limit: %d %q", rec.Code, rec.Header().Get("Retry-After"))
	}
	if c := hit("/api/v1/rate-limits").Code; c != 204 {
		t.Fatalf("the rate-limit settings must stay reachable: %d", c)
	}
	if c := hit("/healthz").Code; c != 204 {
		t.Fatalf("health probes must not be limited: %d", c)
	}

	u := &User{ID: "u1"}
	r := httptest.NewRequest("GET", "/api/v1/t/acme/stacks", nil)
	release := s.admitWorkspace(httptest.NewRecorder(), r, u, "acme", false, false)
	if release == nil {
		t.Fatal("first request to the workspace refused")
	}
	busy := httptest.NewRecorder()
	if s.admitWorkspace(busy, r, u, "acme", false, false) != nil || busy.Code != 503 {
		t.Fatalf("a full workspace must answer 503: %d", busy.Code)
	}
	if s.admitWorkspace(httptest.NewRecorder(), r, u, "acme", true, false) == nil {
		t.Fatal("bulk requests have their own slots")
	}
	release()
	if s.admitWorkspace(httptest.NewRecorder(), r, u, "acme", false, false) == nil {
		t.Fatal("the slot was not freed")
	}
	v := s.rateLimitView()["workspaces"].([]workspaceLoad)
	if len(v) != 1 || v[0].Limited["busy"] != 1 || v[0].HourRequests != 4 {
		t.Fatalf("counters: %+v", v)
	}
}
