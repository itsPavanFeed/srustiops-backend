package central

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/httpx"
)

// ---- workspaces that need a platform admin ----
//
// The Platform page leads with these, so an outage is seen without opening
// each workspace: a tunnel workspace offline for an hour, one that never
// connected, and link certificates that lapsed or are about to (an online
// agent renews daily; one whose certificate lapsed can re-enrol for 30 days).

type attention struct {
	Slug     string     `json:"slug"`
	Name     string     `json:"name"`
	Severity string     `json:"severity"` // bad | wait
	Reason   string     `json:"reason"`
	Since    *time.Time `json:"since,omitempty"`
}

const (
	offlineAfter = time.Hour
	reenrollDays = 30
)

func (s *Server) platformAttention(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(w, r) {
		return
	}
	out, err := s.attentionList(r.Context())
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	httpx.WriteJSON(w, 200, out)
}

// attentionList is every workspace that needs a platform admin now.
func (s *Server) attentionList(ctx context.Context) ([]attention, error) {
	ts, err := s.store.ListTenants(ctx)
	if err != nil {
		return nil, err
	}
	out := []attention{}
	now := time.Now()
	for _, t := range ts {
		if t.Connectivity != "tunnel" || s.online(ctx, t) {
			continue
		}
		a := attention{Slug: t.Slug, Name: t.Name, Severity: "bad"}
		switch {
		case t.LinkSeenAt == nil && now.Sub(t.CreatedAt) > staleAfter:
			a.Reason, a.Since = "never connected: its install or link agent has not reached the gateway", &t.CreatedAt
		case t.LinkSeenAt == nil:
			continue // still being set up
		case now.Sub(*t.LinkSeenAt) > offlineAfter:
			a.Reason, a.Since = "offline: its link agent stopped reporting", t.LinkSeenAt
		default:
			continue
		}
		if cs, err := s.store.LinkCerts(ctx, t.ID, 5); err == nil {
			for _, c := range cs {
				if c.RevokedAt != nil {
					continue
				}
				if left := c.NotAfter.Add(reenrollDays * 24 * time.Hour).Sub(now); c.NotAfter.Before(now) {
					if left <= 0 {
						a.Reason += "; its link certificate lapsed over 30 days ago, so it needs a new enrolment token"
					} else {
						a.Reason += fmt.Sprintf("; its link certificate lapsed, and it can re-enrol on its own for %d more days", int(left.Hours()/24)+1)
					}
				}
				break // the newest unrevoked certificate is the one that matters
			}
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Since == nil || out[j].Since == nil {
			return out[i].Since != nil
		}
		return out[i].Since.Before(*out[j].Since)
	})
	return out, nil
}
