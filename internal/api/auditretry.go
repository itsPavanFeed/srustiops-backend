package api

import (
	"context"
	"sync"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/metrics"
)

// Audit events are written after the change they record. A write that
// fails (the database briefly unreachable, a failover) is retried, then
// kept in a backlog that is written as soon as the database answers again,
// in order. The backlog is bounded, counted in metrics and shown in health,
// so a lost event is never silent; only a crash of this process with events
// still in the backlog loses them.

var (
	auditFailures = metrics.Default.Counter("srustiops_audit_write_failures_total", "Audit writes that failed and went to the backlog")
	auditBacklogG = metrics.Default.Gauge("srustiops_audit_backlog", "Audit events waiting to be written")
	auditDropped  = metrics.Default.Counter("srustiops_audit_dropped_total", "Audit events dropped because the backlog was full")
)

const auditBacklogMax = 10000

type pendingAudit struct {
	actor, action, target, scope string
	payload                      any
}

type auditBacklog struct {
	mu   sync.Mutex
	q    []pendingAudit
	wake chan struct{}
}

func (b *auditBacklog) len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.q)
}

func (s *Server) auditLater(e pendingAudit) {
	b := &s.auditQ
	b.mu.Lock()
	if len(b.q) >= auditBacklogMax {
		b.mu.Unlock()
		auditDropped.Inc()
		s.log.Error("audit backlog full: event dropped", "action", e.action, "target", e.target)
		return
	}
	b.q = append(b.q, e)
	auditBacklogG.Set(float64(len(b.q)))
	b.mu.Unlock()
	auditFailures.Inc()
	select {
	case b.wake <- struct{}{}:
	default:
	}
}

// auditRetrier writes the backlog, oldest first, backing off while the
// database does not answer.
func (s *Server) auditRetrier(ctx context.Context) {
	b := &s.auditQ
	wait := time.Second
	for {
		select {
		case <-ctx.Done():
			return
		case <-b.wake:
		case <-time.After(wait):
		}
		for {
			b.mu.Lock()
			if len(b.q) == 0 {
				b.mu.Unlock()
				wait = time.Second
				break
			}
			e := b.q[0]
			b.mu.Unlock()
			if err := s.store.AppendAudit(ctx, e.actor, e.action, e.target, e.scope, e.payload); err != nil {
				wait = min(wait*2, time.Minute)
				break
			}
			b.mu.Lock()
			b.q = b.q[1:]
			auditBacklogG.Set(float64(len(b.q)))
			b.mu.Unlock()
		}
	}
}
