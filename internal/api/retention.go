package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/store"
)

// ---- retention (Tenant settings → Backups → Retention) ----

const (
	retentionKey  = "retention"
	retentionLock = 7316
)

func (s *Server) retention(ctx context.Context) store.Retention {
	r := store.DefaultRetention()
	s.store.Setting(ctx, retentionKey, &r)
	return r
}

// retentionLoop prunes every few hours, on one replica.
func (s *Server) retentionLoop(ctx context.Context) {
	every := 6 * time.Hour
	if s.cfg.ScheduleEvery > 0 && s.cfg.ScheduleEvery < time.Minute {
		every = s.cfg.ScheduleEvery * 10 // the tests' short timers
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s.store.TryLock(ctx, retentionLock, func(ctx context.Context) { s.prune(ctx, "system:retention") })
	}
}

func (s *Server) prune(ctx context.Context, by string) map[string]int64 {
	n, objects, err := s.store.Prune(ctx, s.retention(ctx))
	if err != nil {
		s.log.Error("pruning failed", "err", err)
	}
	if s.objects != nil {
		for _, k := range objects {
			s.objects.Delete(ctx, k)
		}
	}
	var total int64
	for _, v := range n {
		total += v
	}
	if total > 0 {
		s.audit(ctx, by, "retention.prune", "retention", "", n)
	}
	return n
}

func (s *Server) getRetention(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	writeJSON(w, 200, s.retention(r.Context()))
}

func (s *Server) putRetention(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	var b store.Retention
	if !decode(w, r, &b) {
		return
	}
	for _, v := range []int{b.NotificationsDays, b.CloudEventsDays, b.WebhookDeliveriesDays, b.RunLogsDays} {
		if v != 0 && (v < 7 || v > 3650) {
			writeErr(w, 422, "days are 0 (keep everything) or 7-3650")
			return
		}
	}
	if (b.InventoryScansKeep != 0 && b.InventoryScansKeep < 1) || (b.StateVersionsKeep != 0 && b.StateVersionsKeep < 5) || b.InventoryScansKeep < 0 || b.StateVersionsKeep < 0 {
		writeErr(w, 422, "keep at least 5 state versions per stack (or 0 to keep all)")
		return
	}
	if err := s.store.PutSetting(r.Context(), retentionKey, b, user(r).Subject); err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.audit(r.Context(), user(r).Actor(), "retention.set", "retention", "", b)
	writeJSON(w, 200, b)
}

// pruneNow applies retention at once (tenant admins; tests).
func (s *Server) pruneNow(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	var n map[string]int64
	if !s.store.TryLock(r.Context(), retentionLock, func(ctx context.Context) { n = s.prune(ctx, user(r).Actor()) }) {
		writeErr(w, http.StatusConflict, "pruning is running; try again in a moment")
		return
	}
	writeJSON(w, 200, map[string]any{"pruned": n})
}

// jobName names a single-replica job by its lock.
func jobName(k int64) string {
	names := map[int64]string{scheduleLock: "schedules", mailerLock: "email", 7303: "pull-request polling", 7304: "audit export",
		backupLock: "backups", costLock: "billing read", prLock: "pull requests", contractsLock: "contracts sync", 7313: "release polling",
		7314: "pending releases", 7315: "log archive", retentionLock: "retention", digestLock: "digest"}
	if n, ok := names[k]; ok {
		return n
	}
	return fmt.Sprint(k)
}
