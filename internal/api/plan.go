package api

import (
	"net/http"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/store"
)

// putPlanLimits: central sets this workspace's plan limits.
func (s *Server) putPlanLimits(w http.ResponseWriter, r *http.Request) {
	if !central(w, r) {
		return
	}
	var b store.Limits
	if !decode(w, r, &b) {
		return
	}
	for _, n := range []int{b.Stacks, b.Environments, b.Connections, b.Runners, b.RunsPerMonth, b.People} {
		if n < 0 {
			writeErr(w, 422, "limits must be 0 (none) or more")
			return
		}
	}
	b.SetAt = time.Now().UTC()
	cur := s.store.PlanLimits(r.Context())
	cur.SetAt = b.SetAt
	if cur != b {
		if err := s.store.PutSetting(r.Context(), store.PlanLimitsSetting, b, user(r).Subject); err != nil {
			s.writeStoreErr(w, err, "")
			return
		}
		s.audit(r.Context(), user(r).Subject, "plan.limits", "tenant/"+s.cfg.Tenant, "", b)
	}
	s.getUsage(w, r)
}

// getUsage shows the plan's limits beside what the workspace uses.
func (s *Server) getUsage(w http.ResponseWriter, r *http.Request) {
	if !user(r).ManagesTenant() && user(r).Subject != CentralSubject {
		writeErr(w, http.StatusForbidden, "this needs the tenant_admin or devops role")
		return
	}
	u, err := s.store.Usage(r.Context())
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	writeJSON(w, 200, map[string]any{"limits": s.store.PlanLimits(r.Context()), "usage": u})
}
