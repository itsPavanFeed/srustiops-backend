package central

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRequestCacheExpiresAndPurgesOnChange(t *testing.T) {
	s := &Server{cache: newReqCache()}
	s.cache.put("tenant:acme", &Tenant{Slug: "acme"}, 50*time.Millisecond)
	if _, ok := s.cache.get("tenant:acme"); !ok {
		t.Fatal("fresh entry missing")
	}
	time.Sleep(60 * time.Millisecond)
	if _, ok := s.cache.get("tenant:acme"); ok {
		t.Fatal("expired entry served")
	}
	s.cache.put("tenant:acme", &Tenant{Slug: "acme"}, time.Minute)
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	bad := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(422) })
	s.purgeOnChange(ok).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/v1/me", nil))
	s.purgeOnChange(bad).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("PUT", "/api/v1/tenants/acme", nil))
	if _, ok := s.cache.get("tenant:acme"); !ok {
		t.Fatal("a read or a refused change must not purge")
	}
	s.purgeOnChange(ok).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("PUT", "/api/v1/tenants/acme", nil))
	if _, ok := s.cache.get("tenant:acme"); ok {
		t.Fatal("a successful change must purge")
	}
}
