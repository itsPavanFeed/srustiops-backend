package central

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/httpx"
	"github.com/itsPavanFeed/srustiops-backend/internal/identity"
)

// ---- rate limits ----
//
// Central sits in front of every workspace, so it is where load is shaped:
// each client address, each person and each workspace gets a token bucket,
// and each workspace a cap on requests running at once, so one busy client,
// script or workspace cannot slow the others or swamp a tenant plane. A
// request over a rate gets 429 with Retry-After; a request that finds its
// workspace full waits briefly for a slot, then gets 503 with Retry-After.
// The gateway limits how often an address may enrol, bootstrap or open a
// tunnel, and how many tunnels a workspace holds.
//
// Platform admins set the limits in the console (Platform → Rate limits),
// with overrides per workspace. They hold per central replica.

type RateLimits struct {
	Enabled bool `json:"enabled"`
	// PerIP: every request from one client address (sign-in pages, SCIM,
	// the API), checked before anything else.
	PerIP httpx.Rate `json:"per_ip"`
	// PerUser: one person or API token, across all workspaces.
	PerUser httpx.Rate `json:"per_user"`
	// PerUserWrites: changes (POST, PUT, PATCH, DELETE) by one person in one
	// workspace.
	PerUserWrites httpx.Rate `json:"per_user_writes"`
	// PerWorkspace: every request central sends to one workspace.
	PerWorkspace httpx.Rate `json:"per_workspace"`
	// MaxInFlight and MaxBulkInFlight cap a workspace's requests running at
	// once: interactive ones, and bulk ones (log streams, state, exports,
	// the assistant), which run long. QueueWaitMS is how long a request
	// waits for a slot before it is turned away.
	MaxInFlight     int `json:"max_in_flight"`
	MaxBulkInFlight int `json:"max_bulk_in_flight"`
	QueueWaitMS     int `json:"queue_wait_ms"`
	// MaxStreams caps a workspace's open live streams (run logs and change
	// events, one or two per open console tab), which last minutes.
	MaxStreams int `json:"max_streams"`
	// GatewayPerIP: enrolments, renewals, bootstraps and tunnel opens from
	// one address. MaxTunnels: tunnels one workspace holds on a replica.
	GatewayPerIP httpx.Rate `json:"gateway_per_ip"`
	MaxTunnels   int        `json:"max_tunnels_per_workspace"`
	// Overrides replace the workspace limits for one workspace, by slug.
	Overrides map[string]WorkspaceLimits `json:"overrides"`
}

// WorkspaceLimits overrides one workspace's limits; a zero field keeps the
// platform default.
type WorkspaceLimits struct {
	PerWorkspace    httpx.Rate `json:"per_workspace"`
	PerUserWrites   httpx.Rate `json:"per_user_writes"`
	MaxInFlight     int        `json:"max_in_flight"`
	MaxBulkInFlight int        `json:"max_bulk_in_flight"`
	Note            string     `json:"note,omitempty"`
}

func defaultRateLimits() RateLimits {
	return RateLimits{
		Enabled:         true,
		PerIP:           httpx.Rate{PerSecond: 100, Burst: 400},
		PerUser:         httpx.Rate{PerSecond: 20, Burst: 120},
		PerUserWrites:   httpx.Rate{PerSecond: 5, Burst: 30},
		PerWorkspace:    httpx.Rate{PerSecond: 200, Burst: 600},
		MaxInFlight:     64,
		MaxBulkInFlight: 16,
		QueueWaitMS:     3000,
		MaxStreams:      300,
		GatewayPerIP:    httpx.Rate{PerSecond: 2, Burst: 30},
		MaxTunnels:      16,
		Overrides:       map[string]WorkspaceLimits{},
	}
}

// forWorkspace is the workspace part of the limits, overrides applied.
func (l *RateLimits) forWorkspace(slug string) WorkspaceLimits {
	w := WorkspaceLimits{PerWorkspace: l.PerWorkspace, PerUserWrites: l.PerUserWrites, MaxInFlight: l.MaxInFlight, MaxBulkInFlight: l.MaxBulkInFlight}
	o, ok := l.Overrides[slug]
	if !ok {
		return w
	}
	if o.PerWorkspace.PerSecond > 0 {
		w.PerWorkspace = o.PerWorkspace
	}
	if o.PerUserWrites.PerSecond > 0 {
		w.PerUserWrites = o.PerUserWrites
	}
	if o.MaxInFlight > 0 {
		w.MaxInFlight = o.MaxInFlight
	}
	if o.MaxBulkInFlight > 0 {
		w.MaxBulkInFlight = o.MaxBulkInFlight
	}
	w.Note = o.Note
	return w
}

func checkRate(name string, r httpx.Rate, floor float64, minBurst int) []string {
	var probs []string
	if r.PerSecond < 0 || r.PerSecond > 100000 || r.Burst < 0 || r.Burst > 1000000 {
		probs = append(probs, name+": per_second must be 0-100000 and burst 0-1000000")
	} else if r.PerSecond > 0 && (r.PerSecond < floor || r.Burst < minBurst) {
		// A limit this tight would turn away the console itself.
		probs = append(probs, fmt.Sprintf("%s: at least %g per second with a burst of %d (or 0 for no limit)", name, floor, minBurst))
	}
	return probs
}

func (l *RateLimits) validate() []string {
	var p []string
	p = append(p, checkRate("per_ip", l.PerIP, 1, 20)...)
	p = append(p, checkRate("per_user", l.PerUser, 1, 20)...)
	p = append(p, checkRate("per_user_writes", l.PerUserWrites, 0.1, 1)...)
	p = append(p, checkRate("per_workspace", l.PerWorkspace, 1, 20)...)
	p = append(p, checkRate("gateway_per_ip", l.GatewayPerIP, 0.1, 5)...)
	if l.MaxInFlight < 0 || l.MaxInFlight > 10000 || l.MaxBulkInFlight < 0 || l.MaxBulkInFlight > 10000 {
		p = append(p, "max_in_flight and max_bulk_in_flight must be 0-10000 (0 for no cap)")
	}
	if l.MaxStreams < 0 || l.MaxStreams > 100000 {
		p = append(p, "max_streams must be 0-100000 (0 for no cap)")
	}
	if l.QueueWaitMS < 0 || l.QueueWaitMS > 30000 {
		p = append(p, "queue_wait_ms must be 0-30000")
	}
	if l.MaxTunnels < 0 || l.MaxTunnels > 256 {
		p = append(p, "max_tunnels_per_workspace must be 0-256 (0 for no cap)")
	} else if l.MaxTunnels > 0 && l.MaxTunnels < 2 {
		p = append(p, "max_tunnels_per_workspace must be at least 2, so an agent can replace a tunnel")
	}
	if l.Overrides == nil {
		l.Overrides = map[string]WorkspaceLimits{}
	}
	for slug, o := range l.Overrides {
		if !identity.SlugRe.MatchString(slug) {
			p = append(p, "overrides: \""+slug+"\" is not a workspace slug")
			continue
		}
		p = append(p, checkRate("overrides."+slug+".per_workspace", o.PerWorkspace, 1, 20)...)
		p = append(p, checkRate("overrides."+slug+".per_user_writes", o.PerUserWrites, 0.1, 1)...)
		if o.MaxInFlight < 0 || o.MaxInFlight > 10000 || o.MaxBulkInFlight < 0 || o.MaxBulkInFlight > 10000 {
			p = append(p, "overrides."+slug+": in-flight caps must be 0-10000")
		}
		if len(o.Note) > 200 {
			p = append(p, "overrides."+slug+".note: at most 200 characters")
		}
	}
	return p
}

func (s *Store) RateLimits(ctx context.Context) RateLimits {
	l := defaultRateLimits()
	var raw []byte
	if s.Pool().QueryRow(ctx, `SELECT value FROM platform_settings WHERE key = 'rate_limits'`).Scan(&raw) == nil {
		json.Unmarshal(raw, &l)
	}
	if l.Overrides == nil {
		l.Overrides = map[string]WorkspaceLimits{}
	}
	return l
}

// HeartbeatReplica records this replica and returns how many were seen in
// the last 45 seconds (0 if the database could not be asked).
func (s *Store) HeartbeatReplica(ctx context.Context, id string) int {
	var n int
	s.Pool().Exec(ctx, `INSERT INTO central_replicas (id) VALUES ($1) ON CONFLICT (id) DO UPDATE SET seen_at = now()`, id)
	s.Pool().Exec(ctx, `DELETE FROM central_replicas WHERE seen_at < now() - interval '10 minutes'`)
	if s.Pool().QueryRow(ctx, `SELECT count(*) FROM central_replicas WHERE seen_at > now() - interval '45 seconds'`).Scan(&n) != nil {
		return 0
	}
	return n
}

func replicaID() string {
	h, _ := os.Hostname()
	return h + "-" + randHex(4)
}

func (s *Store) PutRateLimits(ctx context.Context, l RateLimits, by string) error {
	raw, _ := json.Marshal(l)
	_, err := s.Pool().Exec(ctx, `INSERT INTO platform_settings (key, value, updated_by) VALUES ('rate_limits', $1, $2)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_by = EXCLUDED.updated_by, updated_at = now()`, raw, by)
	return err
}

// shaper holds the live limits, the buckets and gates, and what they did.
type shaper struct {
	limits  atomic.Pointer[RateLimits]
	buckets *httpx.Buckets
	gate    *httpx.Gate
	since   time.Time

	mu sync.Mutex
	ws map[string]*wsCounters
	ip map[string]*ipCounter

	// replicas is how many central replicas share the traffic; each enforces
	// its share of every limit, so together they hold the limit.
	replicas atomic.Int32
	id       string
}

// share is one replica's part of a rate.
func (sh *shaper) share(r httpx.Rate) httpx.Rate {
	n := float64(max(sh.replicas.Load(), 1))
	if n == 1 || r.Off() {
		return r
	}
	return httpx.Rate{PerSecond: r.PerSecond / n, Burst: max(1, int(math.Ceil(float64(r.Burst)/n)))}
}

// slots is one replica's part of an in-flight cap.
func (sh *shaper) slots(n int) int {
	if n < 1 {
		return n
	}
	return max(1, int(math.Ceil(float64(n)/float64(max(sh.replicas.Load(), 1)))))
}

type wsCounters struct {
	Requests    int64            `json:"requests"`
	Limited     map[string]int64 `json:"limited"` // by scope: workspace, user, writes, busy
	LastLimited *time.Time       `json:"last_limited_at,omitempty"`
	minutes     [60]minute       // the last hour, one slot per minute
}

type minute struct{ at, req, lim int64 }

type ipCounter struct {
	Limited int64     `json:"limited"`
	Last    time.Time `json:"last_limited_at"`
	Scope   string    `json:"scope"`
}

func newShaper() *shaper {
	sh := &shaper{buckets: httpx.NewBuckets(), gate: httpx.NewGate(), since: time.Now(), ws: map[string]*wsCounters{}, ip: map[string]*ipCounter{}, id: replicaID()}
	sh.replicas.Store(1)
	d := defaultRateLimits()
	sh.limits.Store(&d)
	return sh
}

func (sh *shaper) get() *RateLimits { return sh.limits.Load() }

func (sh *shaper) counters(slug string) *wsCounters {
	c := sh.ws[slug]
	if c == nil {
		c = &wsCounters{Limited: map[string]int64{}}
		sh.ws[slug] = c
	}
	return c
}

func (c *wsCounters) slot(now time.Time) *minute {
	m := now.Unix() / 60
	sl := &c.minutes[m%60]
	if sl.at != m {
		*sl = minute{at: m}
	}
	return sl
}

// note records one request to a workspace and, if it was turned away, why.
func (sh *shaper) note(slug, scope string) {
	now := time.Now()
	sh.mu.Lock()
	defer sh.mu.Unlock()
	c := sh.counters(slug)
	sl := c.slot(now)
	c.Requests++
	sl.req++
	if scope != "" {
		limitedTotal.Inc("scope", scope)
		c.Limited[scope]++
		sl.lim++
		c.LastLimited = &now
	}
}

func (sh *shaper) noteIP(ip, scope string) {
	limitedTotal.Inc("scope", scope)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if len(sh.ip) > 1000 {
		// Keep the most recent few hundred.
		cut := time.Now().Add(-10 * time.Minute)
		for k, v := range sh.ip {
			if v.Last.Before(cut) {
				delete(sh.ip, k)
			}
		}
		if len(sh.ip) > 1000 {
			sh.ip = map[string]*ipCounter{}
		}
	}
	c := sh.ip[ip]
	if c == nil {
		c = &ipCounter{}
		sh.ip[ip] = c
	}
	c.Limited++
	c.Last = time.Now()
	c.Scope = scope
}

// rateLimitLoop reloads the limits and counts the live replicas now and
// every 15 seconds, so a change on one replica reaches the others.
func (s *Server) rateLimitLoop(ctx context.Context) {
	for {
		l := s.store.RateLimits(ctx)
		s.shape.limits.Store(&l)
		if n := s.store.HeartbeatReplica(ctx, s.shape.id); n > 0 {
			s.shape.replicas.Store(int32(n))
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(15 * time.Second):
		}
	}
}

// rateLimitExempt are paths no limit applies to: probes and keys, the built
// console's files, Git hosts' webhooks (signed, queued, and sent from a few
// shared addresses), and the rate-limit settings, so an admin can always undo
// a limit that is too tight.
func rateLimitExempt(p string) bool {
	return p == "/healthz" || strings.HasPrefix(p, "/.well-known/") || strings.HasPrefix(p, "/assets/") ||
		strings.HasPrefix(p, "/webhooks/") || p == "/api/v1/rate-limits"
}

// limitIP applies the per-address limit to every request.
func (s *Server) limitIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l := s.shape.get()
		if !l.Enabled || rateLimitExempt(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		ip := httpx.ClientIP(r)
		if v := s.shape.buckets.Take("ip:"+ip, s.shape.share(l.PerIP)); !v.OK {
			s.shape.noteIP(ip, "ip")
			httpx.SetRateHeaders(w, v)
			httpx.WriteLimited(w, http.StatusTooManyRequests, "rate_limited", "ip", "too many requests from this address; slow down", v.Retry)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// limitUser applies the per-person limit once the caller is known. It
// reports false after answering 429.
func (s *Server) limitUser(w http.ResponseWriter, r *http.Request, u *User) bool {
	l := s.shape.get()
	if !l.Enabled || rateLimitExempt(r.URL.Path) {
		return true
	}
	v := s.shape.buckets.Take("user:"+u.ID, s.shape.share(l.PerUser))
	httpx.SetRateHeaders(w, v)
	if !v.OK {
		s.shape.noteIP(httpx.ClientIP(r), "user")
		httpx.WriteLimited(w, http.StatusTooManyRequests, "rate_limited", "user", "you are sending too many requests; wait a moment", v.Retry)
		return false
	}
	return true
}

func writeMethod(m string) bool {
	return m != http.MethodGet && m != http.MethodHead && m != http.MethodOptions
}

// admitWorkspace applies a workspace's limits to a request central is about
// to send it. It returns the release for the request's in-flight slot, or
// nil after answering 429 or 503.
func (s *Server) admitWorkspace(w http.ResponseWriter, r *http.Request, u *User, slug string, bulk, stream bool) func() {
	l := s.shape.get()
	if !l.Enabled {
		return func() {}
	}
	wl := l.forWorkspace(slug)
	if v := s.shape.buckets.Take("ws:"+slug, s.shape.share(wl.PerWorkspace)); !v.OK {
		s.shape.note(slug, "workspace")
		httpx.WriteLimited(w, http.StatusTooManyRequests, "rate_limited", "workspace", "workspace "+slug+" is receiving more requests than its limit; try again shortly", v.Retry)
		return nil
	}
	if writeMethod(r.Method) {
		if v := s.shape.buckets.Take("writes:"+u.ID+"/"+slug, s.shape.share(wl.PerUserWrites)); !v.OK {
			s.shape.note(slug, "writes")
			httpx.WriteLimited(w, http.StatusTooManyRequests, "rate_limited", "writes", "you are making changes in "+slug+" faster than its limit; wait a moment", v.Retry)
			return nil
		}
	}
	key, slots := "ws:"+slug, wl.MaxInFlight
	switch {
	case stream:
		key, slots = "ws-stream:"+slug, l.MaxStreams
	case bulk:
		key, slots = "ws-bulk:"+slug, wl.MaxBulkInFlight
	}
	release := s.shape.gate.Acquire(r.Context(), key, s.shape.slots(slots), time.Duration(l.QueueWaitMS)*time.Millisecond)
	if release == nil {
		s.shape.note(slug, "busy")
		httpx.WriteLimited(w, http.StatusServiceUnavailable, "busy", "workspace", "workspace "+slug+" is handling as many requests as it allows at once; try again shortly", time.Second)
		return nil
	}
	s.shape.note(slug, "")
	return release
}

// admitGateway applies the gateway's per-address limit.
func (s *Server) admitGateway(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l := s.shape.get()
		switch r.URL.Path {
		case "/v1/link/enroll", "/v1/link/renew", "/v1/link/reenroll", "/v1/link/connect", "/v1/install/bootstrap":
		default:
			next.ServeHTTP(w, r)
			return
		}
		if l.Enabled {
			ip := httpx.ClientIP(r)
			if v := s.shape.buckets.Take("gw:"+ip, s.shape.share(l.GatewayPerIP)); !v.OK {
				s.shape.noteIP(ip, "gateway")
				httpx.WriteLimited(w, http.StatusTooManyRequests, "rate_limited", "gateway", "too many link requests from this address; back off", v.Retry)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// tunnelsFull reports whether a workspace already holds its tunnel cap here.
func (s *Server) tunnelsFull(slug string) bool {
	l := s.shape.get()
	return l.Enabled && l.MaxTunnels > 0 && len(s.link.hub.Tunnels(slug)) >= l.MaxTunnels
}

// ---- console API ----

type workspaceLoad struct {
	Slug         string           `json:"slug"`
	Requests     int64            `json:"requests"`
	Limited      map[string]int64 `json:"limited"`
	HourRequests int64            `json:"requests_last_hour"`
	HourLimited  int64            `json:"limited_last_hour"`
	LastLimited  *time.Time       `json:"last_limited_at,omitempty"`
	InFlight     int              `json:"in_flight"`
	Peak         int              `json:"peak_in_flight"`
	BulkInFlight int              `json:"bulk_in_flight"`
	BulkPeak     int              `json:"peak_bulk_in_flight"`
	Streams      int              `json:"streams"`
	Tunnels      int              `json:"tunnels"`
	Effective    WorkspaceLimits  `json:"effective"`
}

type addressLoad struct {
	IP string `json:"ip"`
	ipCounter
}

// rateLimitView is the limits and what this replica did with them.
func (s *Server) rateLimitView() map[string]any {
	l := s.shape.get()
	now := time.Now()
	s.shape.mu.Lock()
	ws := make([]workspaceLoad, 0, len(s.shape.ws))
	for slug, c := range s.shape.ws {
		x := workspaceLoad{Slug: slug, Requests: c.Requests, Limited: map[string]int64{}, LastLimited: c.LastLimited}
		for k, v := range c.Limited {
			x.Limited[k] = v
		}
		cut := now.Unix()/60 - 59
		for _, m := range c.minutes {
			if m.at >= cut {
				x.HourRequests += m.req
				x.HourLimited += m.lim
			}
		}
		ws = append(ws, x)
	}
	ips := make([]addressLoad, 0, len(s.shape.ip))
	for ip, c := range s.shape.ip {
		ips = append(ips, addressLoad{IP: ip, ipCounter: *c})
	}
	s.shape.mu.Unlock()
	for i := range ws {
		ws[i].InFlight, ws[i].Peak = s.shape.gate.InFlight("ws:" + ws[i].Slug)
		ws[i].BulkInFlight, ws[i].BulkPeak = s.shape.gate.InFlight("ws-bulk:" + ws[i].Slug)
		ws[i].Streams, _ = s.shape.gate.InFlight("ws-stream:" + ws[i].Slug)
		if s.link != nil {
			ws[i].Tunnels = len(s.link.hub.Tunnels(ws[i].Slug))
		}
		ws[i].Effective = l.forWorkspace(ws[i].Slug)
	}
	sort.Slice(ws, func(i, j int) bool {
		if ws[i].HourLimited != ws[j].HourLimited {
			return ws[i].HourLimited > ws[j].HourLimited
		}
		return ws[i].HourRequests > ws[j].HourRequests
	})
	sort.Slice(ips, func(i, j int) bool { return ips[i].Last.After(ips[j].Last) })
	if len(ips) > 50 {
		ips = ips[:50]
	}
	n := max(s.shape.replicas.Load(), 1)
	note := "One central replica: it enforces every limit in full."
	if n > 1 {
		note = fmt.Sprintf("%d central replicas share the traffic: each enforces 1/%d of every limit, so together they hold it. Counts on this page are this replica's.", n, n)
	}
	return map[string]any{"limits": l, "defaults": defaultRateLimits(), "since": s.shape.since, "workspaces": ws, "addresses": ips,
		"replicas": n, "replica_note": note}
}

func (s *Server) getRateLimits(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(w, r) {
		return
	}
	httpx.WriteJSON(w, 200, s.rateLimitView())
}

func (s *Server) putRateLimits(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(w, r) {
		return
	}
	var l RateLimits
	if !httpx.Decode(w, r, &l) {
		return
	}
	probs := l.validate()
	for slug := range l.Overrides {
		if _, err := s.store.Tenant(r.Context(), slug); err != nil && identity.SlugRe.MatchString(slug) {
			probs = append(probs, "overrides: no workspace \""+slug+"\"")
		}
	}
	if len(probs) > 0 {
		httpx.WriteErr(w, 422, "invalid rate limits", probs...)
		return
	}
	if err := s.store.PutRateLimits(r.Context(), l, current(r).Email); err != nil {
		s.storeErr(w, err, "")
		return
	}
	s.shape.limits.Store(&l)
	s.audit(r.Context(), current(r).Email, "platform.rate_limits", "platform/rate-limits", "", l)
	httpx.WriteJSON(w, 200, s.rateLimitView())
}
