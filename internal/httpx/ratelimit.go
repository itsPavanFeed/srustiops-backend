package httpx

import (
	"context"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Rate is a token bucket: PerSecond requests on average, with bursts of up
// to Burst. A PerSecond of zero or less means no limit.
type Rate struct {
	PerSecond float64 `json:"per_second"`
	Burst     int     `json:"burst"`
}

func (r Rate) Off() bool { return r.PerSecond <= 0 }

func (r Rate) burst() float64 {
	if r.Burst < 1 {
		return math.Max(1, math.Ceil(r.PerSecond))
	}
	return float64(r.Burst)
}

// Buckets holds one token bucket per key (a client address, a person, a
// workspace). The rate is passed on every call, so a changed policy applies
// at once; buckets idle for ten minutes are dropped.
type Buckets struct {
	mu    sync.Mutex
	m     map[string]*bucket
	swept time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func NewBuckets() *Buckets { return &Buckets{m: map[string]*bucket{}, swept: time.Now()} }

// Verdict is the answer to one Take.
type Verdict struct {
	OK        bool
	Limit     int           // the burst, as RateLimit-Limit
	Remaining int           // whole tokens left
	Reset     time.Duration // until the bucket is full again
	Retry     time.Duration // until one token is back (when !OK)
}

const maxBuckets = 200000

// Take spends one token from key's bucket, if it has one.
func (b *Buckets) Take(key string, r Rate) Verdict {
	if r.Off() {
		return Verdict{OK: true, Limit: -1}
	}
	now := time.Now()
	burst := r.burst()
	b.mu.Lock()
	defer b.mu.Unlock()
	if now.Sub(b.swept) > time.Minute || len(b.m) > maxBuckets {
		for k, v := range b.m {
			if now.Sub(v.last) > 10*time.Minute {
				delete(b.m, k)
			}
		}
		b.swept = now
	}
	bk := b.m[key]
	if bk == nil {
		if len(b.m) > maxBuckets {
			// Too many distinct callers to track: let it through rather than
			// grow without bound (the per-workspace limits still hold).
			return Verdict{OK: true, Limit: int(burst), Remaining: int(burst)}
		}
		bk = &bucket{tokens: burst, last: now}
		b.m[key] = bk
	}
	bk.tokens = math.Min(burst, bk.tokens+now.Sub(bk.last).Seconds()*r.PerSecond)
	bk.last = now
	v := Verdict{Limit: int(burst)}
	if bk.tokens >= 1 {
		bk.tokens--
		v.OK = true
	} else {
		v.Retry = time.Duration((1 - bk.tokens) / r.PerSecond * float64(time.Second))
	}
	v.Remaining = int(bk.tokens)
	v.Reset = time.Duration((burst - bk.tokens) / r.PerSecond * float64(time.Second))
	return v
}

// Gate caps how many requests per key run at once. A request over the cap
// waits up to the given time for a slot, so a short burst queues instead of
// failing.
type Gate struct {
	mu sync.Mutex
	m  map[string]*sem
}

type sem struct {
	ch   chan struct{}
	peak int
}

func NewGate() *Gate { return &Gate{m: map[string]*sem{}} }

// Acquire takes one of key's limit slots, waiting up to wait. It returns the
// release function, or nil if no slot freed in time. limit < 1 means no cap.
func (g *Gate) Acquire(ctx context.Context, key string, limit int, wait time.Duration) func() {
	if limit < 1 {
		return func() {}
	}
	g.mu.Lock()
	s := g.m[key]
	if s == nil || cap(s.ch) != limit {
		// A new cap takes a new semaphore; requests holding the old one
		// release into it, so the change is exact once they finish.
		s = &sem{ch: make(chan struct{}, limit)}
		g.m[key] = s
	}
	g.mu.Unlock()
	held := func() func() {
		g.mu.Lock()
		s.peak = max(s.peak, len(s.ch))
		g.mu.Unlock()
		var once sync.Once
		return func() { once.Do(func() { <-s.ch }) }
	}
	select {
	case s.ch <- struct{}{}:
		return held()
	default:
	}
	if wait <= 0 {
		return nil
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case s.ch <- struct{}{}:
		return held()
	case <-t.C:
	case <-ctx.Done():
	}
	return nil
}

// InFlight is how many requests hold a slot of key now, and the most seen.
func (g *Gate) InFlight(key string) (now, peak int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if s := g.m[key]; s != nil {
		return len(s.ch), s.peak
	}
	return 0, 0
}

// SetRateHeaders reports a bucket's state with the IETF RateLimit headers.
func SetRateHeaders(w http.ResponseWriter, v Verdict) {
	if v.Limit < 0 {
		return
	}
	h := w.Header()
	h.Set("RateLimit-Limit", strconv.Itoa(v.Limit))
	h.Set("RateLimit-Remaining", strconv.Itoa(max(v.Remaining, 0)))
	h.Set("RateLimit-Reset", strconv.Itoa(int(math.Ceil(v.Reset.Seconds()))))
}

// WriteLimited answers 429 (code "rate_limited") or, for a full workspace,
// 503 (code "busy"), with Retry-After in whole seconds.
func WriteLimited(w http.ResponseWriter, status int, code, scope, msg string, retry time.Duration) {
	secs := max(1, int(math.Ceil(retry.Seconds())))
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	WriteJSON(w, status, map[string]any{"error": code + ": " + msg, "code": code, "scope": scope, "retry_after_seconds": secs})
}

// ---- client addresses behind a proxy ----

var (
	proxyMu sync.RWMutex
	proxies []*net.IPNet
)

// SetTrustedProxies names the load balancers and ingress controllers in front
// of the server. X-Forwarded-For is believed only from these; without them
// every client would share the proxy's address for rate limits and lockouts.
func SetTrustedProxies(cidrs []*net.IPNet) {
	proxyMu.Lock()
	proxies = cidrs
	proxyMu.Unlock()
}

// ParseCIDRs reads a comma-separated list of CIDRs or single addresses.
func ParseCIDRs(s string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		if !strings.Contains(p, "/") {
			if ip := net.ParseIP(p); ip != nil && ip.To4() != nil {
				p += "/32"
			} else {
				p += "/128"
			}
		}
		_, n, err := net.ParseCIDR(p)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}

func trusted(ip net.IP) bool {
	proxyMu.RLock()
	defer proxyMu.RUnlock()
	for _, n := range proxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// forwardedFor walks X-Forwarded-For from the right, past trusted proxies,
// to the first address a trusted proxy saw connect.
func forwardedFor(r *http.Request, peer string) string {
	ip := net.ParseIP(peer)
	if ip == nil || !trusted(ip) {
		return peer
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		h := strings.TrimSpace(hops[i])
		hip := net.ParseIP(h)
		if hip == nil {
			break
		}
		if !trusted(hip) {
			return h
		}
		peer = h
	}
	return peer
}
