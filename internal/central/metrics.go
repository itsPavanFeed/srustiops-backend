package central

import (
	"context"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/metrics"
)

var limitedTotal = metrics.Default.Counter("srustiops_rate_limited_total", "Requests turned away by a rate limit or a full workspace, by scope.")

// registerMetrics adds central's series: workspaces and their links, load
// per workspace, and the request-path cache.
func (s *Server) registerMetrics(r *metrics.Registry) {
	online := r.Gauge("srustiops_workspace_online", "1 if the workspace's tenant plane is reachable, by workspace.")
	inflight := r.Gauge("srustiops_workspace_in_flight", "Requests to a workspace running now, by kind (interactive, bulk, stream).")
	tunnels := r.Gauge("srustiops_workspace_tunnels", "Open link tunnels on this replica, by workspace.")
	replicas := r.Gauge("srustiops_central_replicas", "Central replicas sharing the traffic.")
	cache := r.Gauge("srustiops_central_cache_lookups", "Request-path cache lookups since start, by result.")
	r.OnCollect(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		ts, err := s.store.ListTenants(ctx)
		if err != nil {
			return
		}
		online.Reset()
		inflight.Reset()
		tunnels.Reset()
		for _, t := range ts {
			v := 0.0
			if s.online(ctx, t) {
				v = 1
			}
			online.Set(v, "workspace", t.Slug)
			for kind, key := range map[string]string{"interactive": "ws:", "bulk": "ws-bulk:", "stream": "ws-stream:"} {
				n, _ := s.shape.gate.InFlight(key + t.Slug)
				inflight.Set(float64(n), "workspace", t.Slug, "kind", kind)
			}
			if s.link != nil {
				tunnels.Set(float64(len(s.link.hub.Tunnels(t.Slug))), "workspace", t.Slug)
			}
		}
		replicas.Set(float64(max(s.shape.replicas.Load(), 1)))
		cache.Set(float64(s.cache.hits.Load()), "result", "hit")
		cache.Set(float64(s.cache.misses.Load()), "result", "miss")
	})
}
