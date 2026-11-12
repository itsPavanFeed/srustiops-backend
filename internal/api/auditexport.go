package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/audit"
	"github.com/itsPavanFeed/srustiops-backend/internal/auditexport"
	"github.com/itsPavanFeed/srustiops-backend/internal/store"
)

// ---- audit export to a SIEM (Integrations → Audit export) ----
//
// A tenant admin sends this workspace's audit log to a signed webhook, a
// Splunk HTTP Event Collector or an S3 bucket. One replica exports at a time,
// from a cursor, so every event goes out once and in order, and failures are
// retried where they stopped.

const (
	exportSetting = "audit_export"
	exportStatus  = "audit_export_status"
	exportLock    = 7304
)

func (s *Server) exportConfig(ctx context.Context) (*auditexport.Config, bool) {
	b, ok := s.openSetting(ctx, exportSetting, exportSetting)
	if !ok {
		return nil, false
	}
	var c auditexport.Config
	if json.Unmarshal(b, &c) != nil {
		return nil, false
	}
	return &c, true
}

func (s *Server) exportState(ctx context.Context) auditexport.Status {
	var st auditexport.Status
	s.store.Setting(ctx, exportStatus, &st)
	return st
}

func (s *Server) getAuditExport(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	out := map[string]any{"configured": false, "status": s.exportState(r.Context()), "latest_id": s.store.LastAuditID(r.Context())}
	if c, ok := s.exportConfig(r.Context()); ok {
		out["configured"] = true
		out["config"] = map[string]any{"enabled": c.Enabled, "kind": c.Kind, "url": c.URL, "access_key": c.AccessKey, "index": c.Index, "secret_set": c.Secret != ""}
	}
	writeJSON(w, 200, out)
}

func (s *Server) putAuditExport(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	var b struct {
		auditexport.Config
		From string `json:"from"` // all (default): send the history too | now: only new events
	}
	if !decode(w, r, &b) {
		return
	}
	cur, had := s.exportConfig(r.Context())
	if b.Secret == "" && had && cur.Kind == b.Kind {
		b.Secret = cur.Secret // keep the stored secret
	}
	if probs := b.Config.Validate(); len(probs) > 0 {
		writeErr(w, 422, "invalid audit export", probs...)
		return
	}
	if s.dryRun(w, r) {
		return
	}
	raw, _ := json.Marshal(b.Config)
	if err := s.sealSetting(r.Context(), exportSetting, exportSetting, raw, user(r).Subject); err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	// A new destination starts over (from the beginning, or from now).
	if !had || cur.Kind != b.Kind || cur.URL != b.URL {
		st := auditexport.Status{}
		if b.From == "now" {
			st.Cursor = s.store.LastAuditID(r.Context())
		}
		s.store.PutSetting(r.Context(), exportStatus, st, user(r).Subject)
	}
	s.audit(r.Context(), user(r).Actor(), "integration.audit_export.configure", "integration/audit-export", "", map[string]any{"kind": b.Kind, "url": b.URL, "enabled": b.Enabled, "from": b.From})
	s.getAuditExport(w, r)
}

func (s *Server) deleteAuditExport(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	if s.dryRun(w, r) {
		return
	}
	s.store.DeleteSetting(r.Context(), exportSetting)
	s.store.DeleteSetting(r.Context(), exportStatus)
	s.audit(r.Context(), user(r).Actor(), "integration.audit_export.remove", "integration/audit-export", "", nil)
	w.WriteHeader(http.StatusNoContent)
}

// testAuditExport sends one synthetic event (not part of the chain).
func (s *Server) testAuditExport(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	c, ok := s.exportConfig(r.Context())
	if !ok {
		writeErr(w, http.StatusConflict, "no audit export is configured")
		return
	}
	x := &auditexport.Exporter{Plane: "tenant:" + s.cfg.Tenant}
	ev := audit.Event{ID: 0, TS: time.Now().UTC(), Actor: user(r).Subject, Action: "audit_export.test", Target: "integration/audit-export", Payload: json.RawMessage(`{"test":true}`)}
	if err := x.Send(r.Context(), *c, []audit.Event{ev}); err != nil {
		writeErr(w, http.StatusBadGateway, "the destination refused: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"status": "sent"})
}

// auditExporter ships new events every tick on one replica.
func (s *Server) auditExporter(ctx context.Context) {
	every := min(s.cfg.ScheduleEvery, 30*time.Second)
	if every <= 0 {
		every = 30 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	x := &auditexport.Exporter{Plane: "tenant:" + s.cfg.Tenant}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		c, ok := s.exportConfig(ctx)
		if !ok || !c.Enabled {
			continue
		}
		s.store.TryLock(ctx, exportLock, func(ctx context.Context) {
			before := s.exportState(ctx)
			after := x.Run(ctx, *c, s.store, before, 20)
			if after != before {
				s.store.PutSetting(ctx, exportStatus, after, "system:audit-export")
			}
			if after.LastError != "" && before.LastError == "" {
				s.log.Warn("audit export failed", "kind", c.Kind, "err", after.LastError)
				s.notifyEvent(ctx, store.Notification{Kind: "integration.audit_export_failed", Severity: "error", Title: "Audit export is failing",
					Body: after.LastError + ". It is retried from where it stopped.", Link: "integrations/audit-export"})
			}
		})
	}
}
