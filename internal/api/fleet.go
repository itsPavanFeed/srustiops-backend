package api

import (
	"net/http"
	"regexp"
	"time"
)

// ---- versions and staged upgrades (the tenant side) ----
//
// Central runs fleet rollouts: when this workspace's wave comes, it tells
// this plane the version to run. The target is kept here; `srustiops
// updater`, running beside the plane, applies it (rolling the Kubernetes
// Deployments, or pulling and recreating the Compose services) and records
// the result, which tenant admins and central see.

const (
	fleetTarget = "fleet_target"
	fleetStatus = "fleet_status" // written by the updater
)

var versionRe = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$`)

type FleetTarget struct {
	Version string    `json:"version"`
	Rollout string    `json:"rollout"`
	Wave    string    `json:"wave"`
	SetAt   time.Time `json:"set_at"`
	SetBy   string    `json:"set_by"`
}

type FleetStatus struct {
	Running   string    `json:"running"`
	Target    string    `json:"target"`
	State     string    `json:"state"` // idle | upgrading | done | failed
	Detail    string    `json:"detail"`
	UpdatedAt time.Time `json:"updated_at"`
}

// putFleetTarget: central sets the version this workspace should run.
func (s *Server) putFleetTarget(w http.ResponseWriter, r *http.Request) {
	if !central(w, r) {
		return
	}
	var b FleetTarget
	if !decode(w, r, &b) {
		return
	}
	if !versionRe.MatchString(b.Version) {
		writeErr(w, 422, "version is invalid")
		return
	}
	b.SetAt, b.SetBy = time.Now().UTC(), user(r).Subject
	var cur FleetTarget
	s.store.Setting(r.Context(), fleetTarget, &cur)
	if cur.Version != b.Version {
		if err := s.store.PutSetting(r.Context(), fleetTarget, b, b.SetBy); err != nil {
			s.writeStoreErr(w, err, "")
			return
		}
		s.audit(r.Context(), b.SetBy, "fleet.target", "tenant/"+s.cfg.Tenant, "", map[string]string{"version": b.Version, "from": s.cfg.Version, "rollout": b.Rollout, "wave": b.Wave})
	}
	writeJSON(w, 200, map[string]string{"running": s.cfg.Version, "target": b.Version})
}

// getFleet shows the running and target versions and the updater's report.
func (s *Server) getFleet(w http.ResponseWriter, r *http.Request) {
	if !user(r).ManagesTenant() && user(r).Subject != CentralSubject {
		writeErr(w, http.StatusForbidden, "this needs the tenant_admin or devops role")
		return
	}
	var t FleetTarget
	var st FleetStatus
	s.store.Setting(r.Context(), fleetTarget, &t)
	s.store.Setting(r.Context(), fleetStatus, &st)
	writeJSON(w, 200, map[string]any{"running": s.cfg.Version, "target": t, "updater": st})
}
