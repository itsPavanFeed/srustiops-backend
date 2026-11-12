package api

import (
	"context"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/metrics"
)

// registerMetrics adds the tenant plane's series: the run queue (what an
// autoscaler for runners watches), runner freshness and live streams.
func (s *Server) registerMetrics(r *metrics.Registry) {
	queued := r.Gauge("srustiops_runs_queued", "Runs waiting for a runner, by pool and phase (plan or apply).")
	active := r.Gauge("srustiops_runs_active", "Runs in each non-final status.")
	oldest := r.Gauge("srustiops_runs_queued_oldest_seconds", "Age of the oldest run waiting for a runner, by pool.")
	seen := r.Gauge("srustiops_runner_last_seen_seconds", "Seconds since each runner last asked for work.")
	streams := r.Gauge("srustiops_live_streams", "Open live streams (run logs and change feeds).")
	r.OnCollect(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		queued.Reset()
		oldest.Reset()
		rows, err := s.store.Pool().Query(ctx, `SELECT e.runner_pool, r.status, count(*), EXTRACT(EPOCH FROM now() - min(r.updated_at))
			FROM runs r JOIN stacks st ON st.id = r.stack_id JOIN environments e ON e.id = st.environment_id
			WHERE r.status IN ('queued', 'apply_queued') GROUP BY 1, 2`)
		if err == nil {
			old := map[string]float64{}
			for rows.Next() {
				var pool, status string
				var n, age float64
				if rows.Scan(&pool, &status, &n, &age) == nil {
					phase := "plan"
					if status == "apply_queued" {
						phase = "apply"
					}
					queued.Set(n, "pool", pool, "phase", phase)
					old[pool] = max(old[pool], age)
				}
			}
			rows.Close()
			for pool, age := range old {
				oldest.Set(age, "pool", pool)
			}
		}
		active.Reset()
		if rows, err := s.store.Pool().Query(ctx, `SELECT status, count(*) FROM runs WHERE status IN ('queued', 'planning', 'planned', 'apply_queued', 'applying') GROUP BY 1`); err == nil {
			for rows.Next() {
				var st string
				var n float64
				if rows.Scan(&st, &n) == nil {
					active.Set(n, "status", st)
				}
			}
			rows.Close()
		}
		seen.Reset()
		if rs, err := s.store.ListRunners(ctx); err == nil {
			for _, rn := range rs {
				if rn.RevokedAt == nil && rn.LastSeenAt != nil {
					seen.Set(time.Since(*rn.LastSeenAt).Seconds(), "runner", rn.Name, "pool", rn.Pool)
				}
			}
		}
		streams.Set(float64(s.changes.count()))
	})
}
