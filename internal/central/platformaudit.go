package central

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/audit"
	"github.com/itsPavanFeed/srustiops-backend/internal/auditexport"
	"github.com/itsPavanFeed/srustiops-backend/internal/httpx"
	"github.com/itsPavanFeed/srustiops-backend/internal/store"
)

// ---- the platform's own audit log ----
//
// Central records what platform admins, sign-ins and the gateway do
// (onboarding, removals, admin changes, rate limits, link enrolments) in its
// own hash-chained log; platform admins read and verify it here.

func (s *Server) platformAuditLog(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(w, r) {
		return
	}
	q := r.URL.Query()
	since, until, err := auditexport.ParseRange(q)
	if err != nil {
		httpx.WriteErr(w, 422, err.Error())
		return
	}
	before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
	n, _ := strconv.Atoi(q.Get("limit"))
	if n <= 0 || n > 500 {
		n = 100
	}
	aq := store.AuditQuery{Before: before, Limit: n, Filter: q.Get("q"), Since: since, Until: until}
	if q.Get("format") == "csv" {
		aq.Limit, aq.Before = 1000, 0
		s.audit(r.Context(), current(r).Email, "audit.download", "platform/audit", "", map[string]any{"q": aq.Filter, "since": q.Get("since"), "until": q.Get("until")})
		auditexport.ServeCSV(w, "srustiops-platform-audit.csv", func(b int64) ([]audit.Event, error) {
			aq.Before = b
			return s.store.ListAudit(r.Context(), aq)
		})
		return
	}
	evs, err := s.store.ListAudit(r.Context(), aq)
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	httpx.WriteJSON(w, 200, evs)
}

func (s *Server) verifyPlatformAudit(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(w, r) {
		return
	}
	var cs store.CheckpointSealer
	if sl, err := s.sealer(); err == nil {
		cs = sl
	}
	v, err := s.store.VerifyAuditFast(r.Context(), cs, r.URL.Query().Get("full") == "1")
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	httpx.WriteJSON(w, 200, map[string]any{"intact": v.FirstBrokenID == 0, "checked": v.Checked, "first_broken_id": v.FirstBrokenID, "from_checkpoint": v.FromCheckpoint})
}

// ---- platform audit export (Platform → Audit log → Export) ----

func (s *Server) platformExport(ctx context.Context) (*auditexport.Config, bool) {
	var raw []byte
	var stored struct {
		Sealed string `json:"sealed"`
	}
	if s.store.Pool().QueryRow(ctx, `SELECT value FROM platform_settings WHERE key = 'audit_export'`).Scan(&raw) != nil || json.Unmarshal(raw, &stored) != nil {
		return nil, false
	}
	sealer, err := s.sealer()
	if err != nil {
		return nil, false
	}
	b, _ := base64.StdEncoding.DecodeString(stored.Sealed)
	pt, err := sealer.Open(b, []byte("platform-audit-export"))
	if err != nil {
		return nil, false
	}
	var c auditexport.Config
	return &c, json.Unmarshal(pt, &c) == nil
}

func (s *Server) platformExportStatus(ctx context.Context) auditexport.Status {
	var st auditexport.Status
	var raw []byte
	if s.store.Pool().QueryRow(ctx, `SELECT value FROM platform_settings WHERE key = 'audit_export_status'`).Scan(&raw) == nil {
		json.Unmarshal(raw, &st)
	}
	return st
}

func (s *Server) putPlatformSetting(ctx context.Context, key string, v any, by string) error {
	raw, _ := json.Marshal(v)
	_, err := s.store.Pool().Exec(ctx, `INSERT INTO platform_settings (key, value, updated_by) VALUES ($1, $2, $3)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_by = EXCLUDED.updated_by, updated_at = now()`, key, raw, by)
	return err
}

func (s *Server) getPlatformExport(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(w, r) {
		return
	}
	var latest int64
	s.store.Pool().QueryRow(r.Context(), `SELECT COALESCE(max(id), 0) FROM audit_events`).Scan(&latest)
	out := map[string]any{"configured": false, "status": s.platformExportStatus(r.Context()), "latest_id": latest}
	if c, ok := s.platformExport(r.Context()); ok {
		out["configured"] = true
		out["config"] = map[string]any{"enabled": c.Enabled, "kind": c.Kind, "url": c.URL, "access_key": c.AccessKey, "index": c.Index, "secret_set": c.Secret != ""}
	}
	httpx.WriteJSON(w, 200, out)
}

func (s *Server) putPlatformExport(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(w, r) {
		return
	}
	var b struct {
		auditexport.Config
		From string `json:"from"`
	}
	if !httpx.Decode(w, r, &b) {
		return
	}
	cur, had := s.platformExport(r.Context())
	if b.Secret == "" && had && cur.Kind == b.Kind {
		b.Secret = cur.Secret
	}
	if probs := b.Config.Validate(); len(probs) > 0 {
		httpx.WriteErr(w, 422, "invalid audit export", probs...)
		return
	}
	sealer, err := s.sealer()
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	pt, _ := json.Marshal(b.Config)
	ct, err := sealer.Seal(pt, []byte("platform-audit-export"))
	if err == nil {
		err = s.putPlatformSetting(r.Context(), "audit_export", map[string]string{"sealed": base64.StdEncoding.EncodeToString(ct)}, current(r).Email)
	}
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	if !had || cur.Kind != b.Kind || cur.URL != b.URL {
		st := auditexport.Status{}
		if b.From == "now" {
			s.store.Pool().QueryRow(r.Context(), `SELECT COALESCE(max(id), 0) FROM audit_events`).Scan(&st.Cursor)
		}
		s.putPlatformSetting(r.Context(), "audit_export_status", st, current(r).Email)
	}
	s.audit(r.Context(), current(r).Email, "platform.audit_export", "platform/audit-export", "", map[string]any{"kind": b.Kind, "url": b.URL, "enabled": b.Enabled, "from": b.From})
	s.getPlatformExport(w, r)
}

func (s *Server) deletePlatformExport(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(w, r) {
		return
	}
	s.store.Pool().Exec(r.Context(), `DELETE FROM platform_settings WHERE key IN ('audit_export', 'audit_export_status')`)
	s.audit(r.Context(), current(r).Email, "platform.audit_export_removed", "platform/audit-export", "", nil)
	w.WriteHeader(http.StatusNoContent)
}

// platformExporter ships central's audit events to the platform's SIEM.
func (s *Server) platformExporter(ctx context.Context) {
	every := 30 * time.Second
	if s.cfg.InviteSweep > 0 && s.cfg.InviteSweep < every {
		every = s.cfg.InviteSweep // the tests' short timers
	}
	t := time.NewTicker(every)
	defer t.Stop()
	x := &auditexport.Exporter{Plane: "central"}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		c, ok := s.platformExport(ctx)
		if !ok || !c.Enabled {
			continue
		}
		conn, err := s.store.Pool().Acquire(ctx)
		if err != nil {
			continue
		}
		var got bool
		if conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(7205)`).Scan(&got); got {
			before := s.platformExportStatus(ctx)
			after := x.Run(ctx, *c, s.store, before, 20)
			if after != before {
				s.putPlatformSetting(ctx, "audit_export_status", after, "system:audit-export")
			}
			conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock(7205)`)
		}
		conn.Release()
	}
}
