package central

import (
	"context"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/identity"
)

// ---- the request-path cache ----
//
// Every request through central needs the caller's session, and every
// request to a workspace its tenant record and the caller's principal there:
// three or more database round trips before the request even leaves. They
// change rarely, so central keeps them for a few seconds.
//
// Staleness is bounded two ways: entries live at most sessionCacheTTL/recordTTL,
// and any change made through this replica (any request that is not a read)
// clears the whole cache once it succeeds. A change made on another replica
// is seen within the TTL.

const (
	sessionCacheTTL = 10 * time.Second
	recordTTL       = 5 * time.Second
	cacheMax        = 50000
)

type cacheEntry struct {
	v   any
	exp time.Time
}

type reqCache struct {
	mu     sync.Mutex
	m      map[string]cacheEntry
	hits   atomic.Int64
	misses atomic.Int64
}

func newReqCache() *reqCache { return &reqCache{m: map[string]cacheEntry{}} }

func (c *reqCache) get(key string) (any, bool) {
	c.mu.Lock()
	e, ok := c.m[key]
	c.mu.Unlock()
	if ok && time.Now().Before(e.exp) {
		c.hits.Add(1)
		return e.v, true
	}
	c.misses.Add(1)
	return nil, false
}

func (c *reqCache) put(key string, v any, ttl time.Duration) {
	c.mu.Lock()
	if len(c.m) >= cacheMax {
		c.m = map[string]cacheEntry{} // simplest bound: start over
	}
	c.m[key] = cacheEntry{v: v, exp: time.Now().Add(ttl)}
	c.mu.Unlock()
}

// purge drops everything: called after any change through this replica.
func (c *reqCache) purge() {
	c.mu.Lock()
	c.m = map[string]cacheEntry{}
	c.mu.Unlock()
}

type cachedSession struct {
	u    *User
	sess *AuthSession
}

// session is SessionByToken through the cache. Misses (unknown or revoked
// tokens) are never cached, so a new token works at once.
func (s *Server) session(ctx context.Context, hash []byte) (*User, *AuthSession, error) {
	key := "sess:" + hex.EncodeToString(hash)
	if v, ok := s.cache.get(key); ok {
		cs := v.(cachedSession)
		return cs.u, cs.sess, nil
	}
	u, sess, err := s.store.SessionByToken(ctx, hash)
	if err == nil && u != nil {
		s.cache.put(key, cachedSession{u, sess}, sessionCacheTTL)
	}
	return u, sess, err
}

// tenant is store.Tenant through the cache.
func (s *Server) tenant(ctx context.Context, slug string) (*Tenant, error) {
	key := "tenant:" + slug
	if v, ok := s.cache.get(key); ok {
		return v.(*Tenant), nil
	}
	t, err := s.store.Tenant(ctx, slug)
	if err == nil {
		s.cache.put(key, t, recordTTL)
	}
	return t, err
}

// principal is assertionPrincipal through the cache, per person, session and
// workspace.
func (s *Server) principal(ctx context.Context, u *User, sess *AuthSession, t *Tenant) (*identity.Principal, error) {
	key := "principal:" + u.ID + "/" + t.Slug
	if sess != nil {
		key += "/" + sess.TokenID
	}
	if v, ok := s.cache.get(key); ok {
		p, _ := v.(*identity.Principal)
		if p == nil {
			return nil, nil
		}
		cp := *p // a shallow copy: the proxy only reads it
		return &cp, nil
	}
	p, err := s.assertionPrincipal(ctx, u, sess, t)
	if err == nil {
		s.cache.put(key, p, recordTTL)
	}
	return p, err
}

// purgeOnChange clears the cache after any successful request that is not a
// read, so this replica never serves its own change stale.
func (s *Server) purgeOnChange(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions || strings.HasPrefix(r.URL.Path, "/webhooks/") {
			next.ServeHTTP(w, r)
			return
		}
		sw := &statusWriter{ResponseWriter: w, code: 200}
		next.ServeHTTP(sw, r)
		if sw.code < 400 {
			s.cache.purge()
		}
	})
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(code int) {
	w.code = code
	w.ResponseWriter.WriteHeader(code)
}

// Flush and Unwrap keep streaming responses (the assistant, logs) working.
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
