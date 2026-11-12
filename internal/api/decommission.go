package api

import (
	"net/http"
	"strings"
	"time"
)

// decommissionSetting marks a tenant plane whose workspace was removed from
// the platform. From then on it refuses all work (users, runners, state) and
// answers only its health check; its data is kept as it is, for the customer
// to keep, export or delete themselves.
const decommissionSetting = "decommissioned"

type decommissioned struct {
	By string    `json:"by"`
	At time.Time `json:"at"`
}

// decommission is called by the central plane when the workspace is removed.
func (s *Server) decommission(w http.ResponseWriter, r *http.Request) {
	if !central(w, r) {
		return
	}
	var b struct {
		By string `json:"by"`
	}
	if !decode(w, r, &b) {
		return
	}
	d := decommissioned{By: b.By, At: time.Now().UTC()}
	if err := s.store.PutSetting(r.Context(), decommissionSetting, d, "central"); err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.decom.Store(&d)
	s.audit(r.Context(), "central", "tenant.decommission", "tenant/"+s.cfg.Tenant, "", d)
	s.log.Warn("workspace removed from the platform: this tenant plane now refuses all work; its data is kept", "by", b.By)
	writeJSON(w, 200, map[string]any{"decommissioned": true})
}

// refuseDecommissioned wraps the API: once decommissioned, every request but
// the health check gets 410.
func (s *Server) refuseDecommissioned(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if d := s.decom.Load(); d != nil && r.URL.Path != "/healthz" && !strings.HasPrefix(r.URL.Path, "/.well-known/") {
			writeErr(w, http.StatusGone, "decommissioned: this workspace was removed from the platform on "+d.At.Format("2 Jan 2006")+"; its data is kept in this tenant's database")
			return
		}
		next.ServeHTTP(w, r)
	})
}
