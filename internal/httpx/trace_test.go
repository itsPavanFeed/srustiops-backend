package httpx

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTraceKeepsAndPassesTheTrace(t *testing.T) {
	var inner string
	h := Trace(nil, "test", 0, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, _ := http.NewRequestWithContext(r.Context(), "GET", "http://x", nil)
		SetTrace(r.Context(), req)
		inner = req.Header.Get("traceparent")
	}))
	in := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("traceparent", in)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Header().Get("X-Request-Id") != "4bf92f3577b34da6a3ce929d0e0e4736" || !strings.HasPrefix(inner, "00-4bf92f3577b34da6a3ce929d0e0e4736-") || inner == in {
		t.Fatalf("trace not kept: %q %q", w.Header().Get("X-Request-Id"), inner)
	}
	// Without one, a trace starts.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if len(w.Header().Get("X-Request-Id")) != 32 {
		t.Fatalf("no trace started: %v", w.Header())
	}
	// A malformed header is replaced, not passed on.
	r = httptest.NewRequest("GET", "/", nil)
	r.Header.Set("traceparent", "00-zz-bad")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if strings.Contains(w.Header().Get("traceparent"), "zz") {
		t.Fatal("a malformed traceparent was kept")
	}
}
