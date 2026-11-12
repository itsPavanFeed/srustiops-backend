package api

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"net/http"
	"regexp"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/spec"
	"github.com/itsPavanFeed/srustiops-backend/internal/store"
)

// ---- scheduled checks (opt-in, detect-only) ----
//
// An environment may schedule drift checks of its stacks and inventory
// rescans of its connections. Both are off by default. Scheduled drift
// checks are refresh-only plans: they flag stacks and notify, and never
// change anything — what to do about drift (live → code, or an approved
// apply) stays a person's decision. Quiet hours hold every scheduled check;
// checks are spread out (a few per minute, each stack offset by a fixed
// jitter) so a large environment does not start them all at once.

type envSchedule struct {
	Drift     scheduleItem `json:"drift"`
	Inventory scheduleItem `json:"inventory"`
	Quiet     *quietHours  `json:"quiet_hours,omitempty"`
}

type scheduleItem struct {
	Enabled    bool `json:"enabled"`
	EveryHours int  `json:"every_hours"`
}

type quietHours struct {
	Start    string `json:"start"` // "22:00"
	End      string `json:"end"`   // "06:00"
	Timezone string `json:"timezone"`
}

var hhmmRe = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)

const (
	scheduleLock     = 7301
	maxDriftPerTick  = 3  // per environment
	maxChecksPerTick = 10 // across the tenant
)

func parseSchedule(raw []byte) envSchedule {
	var sc envSchedule
	json.Unmarshal(raw, &sc)
	return sc
}

func (sc *envSchedule) validate() []string {
	var probs []string
	for name, it := range map[string]*scheduleItem{"drift": &sc.Drift, "inventory": &sc.Inventory} {
		if it.EveryHours == 0 {
			it.EveryHours = 24
		}
		if it.EveryHours < 1 || it.EveryHours > 720 {
			probs = append(probs, name+".every_hours must be between 1 and 720")
		}
	}
	if q := sc.Quiet; q != nil {
		if !hhmmRe.MatchString(q.Start) || !hhmmRe.MatchString(q.End) {
			probs = append(probs, "quiet_hours start and end must be HH:MM")
		}
		if q.Timezone == "" {
			q.Timezone = "UTC"
		}
		if _, err := time.LoadLocation(q.Timezone); err != nil {
			probs = append(probs, "quiet_hours timezone is unknown: "+q.Timezone)
		}
	}
	return probs
}

// quiet reports whether t falls in the quiet hours (which may wrap midnight).
func (q *quietHours) quiet(t time.Time) bool {
	if q == nil || q.Start == q.End {
		return false
	}
	loc, err := time.LoadLocation(q.Timezone)
	if err != nil {
		loc = time.UTC
	}
	now := t.In(loc).Format("15:04")
	if q.Start < q.End {
		return now >= q.Start && now < q.End
	}
	return now >= q.Start || now < q.End
}

// jitter spreads a stack's checks over the first tenth of the interval.
func jitter(id string, every time.Duration) time.Duration {
	h := fnv.New32a()
	h.Write([]byte(id))
	span := every / 10
	if span <= 0 {
		return 0
	}
	return time.Duration(h.Sum32()) % span
}

func (s *Server) getSchedule(w http.ResponseWriter, r *http.Request) {
	env, ok := s.visibleEnvironment(w, r)
	if !ok {
		return
	}
	sc := parseSchedule(env.Schedule)
	stacks, _ := s.store.DriftCandidates(r.Context(), env.ID)
	type stackCheck struct {
		Name      string     `json:"name"`
		LastCheck *time.Time `json:"last_check,omitempty"`
		NextCheck *time.Time `json:"next_check,omitempty"`
	}
	sl := []stackCheck{}
	for _, c := range stacks {
		if !user(r).CanView(c.BU) {
			continue
		}
		x := stackCheck{Name: c.Name, LastCheck: c.LastCheck}
		if sc.Drift.Enabled {
			next := time.Now()
			if c.LastCheck != nil {
				every := time.Duration(sc.Drift.EveryHours) * time.Hour
				next = c.LastCheck.Add(every + jitter(c.ID, every))
			}
			x.NextCheck = &next
		}
		sl = append(sl, x)
	}
	type connScan struct {
		Name     string     `json:"name"`
		LastScan *time.Time `json:"last_scan,omitempty"`
		Running  bool       `json:"running"`
	}
	cl := []connScan{}
	for _, c := range env.Connections {
		at, running, _ := s.store.LastScanStarted(r.Context(), c.ID)
		cl = append(cl, connScan{Name: c.Name, LastScan: at, Running: running})
	}
	q := sc.Quiet
	writeJSON(w, 200, map[string]any{"schedule": sc, "quiet_now": q.quiet(time.Now()), "stacks": sl, "connections": cl})
}

func (s *Server) visibleEnvironment(w http.ResponseWriter, r *http.Request) (*store.Environment, bool) {
	env, err := s.store.GetEnvironment(r.Context(), r.PathValue("id"))
	if err == nil && !user(r).CanViewEntity(env.Entity) {
		err = store.ErrNotFound
	}
	if err != nil {
		s.writeStoreErr(w, err, "")
		return nil, false
	}
	return env, true
}

func (s *Server) putSchedule(w http.ResponseWriter, r *http.Request) {
	p := user(r)
	env, ok := s.visibleEnvironment(w, r)
	if !ok {
		return
	}
	if !p.CanManageEnvironments(env.Entity) {
		writeErr(w, http.StatusForbidden, "scheduling checks needs tenant_admin, or admin of the entity")
		return
	}
	var sc envSchedule
	if !decode(w, r, &sc) {
		return
	}
	if probs := sc.validate(); len(probs) > 0 {
		writeErr(w, 422, "invalid schedule", probs...)
		return
	}
	raw, _ := json.Marshal(sc)
	if err := s.store.SetEnvironmentSchedule(r.Context(), env.ID, raw); err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.audit(r.Context(), p.Actor(), "environment.schedule", "environment/"+env.Entity+":"+env.Name, "", map[string]any{"before": json.RawMessage(env.Schedule), "after": sc})
	s.getSchedule(w, r)
}

// checkNow starts a drift check of every stack in the environment that can
// have one now (and a rescan of its connections when asked), ignoring the
// schedule. Like scheduled checks, it only reports.
func (s *Server) checkNow(w http.ResponseWriter, r *http.Request) {
	p := user(r)
	env, ok := s.visibleEnvironment(w, r)
	if !ok {
		return
	}
	var b struct {
		Inventory bool `json:"inventory"`
	}
	if r.ContentLength > 0 && !decode(w, r, &b) {
		return
	}
	cands, err := s.store.DriftCandidates(r.Context(), env.ID)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	started, skipped := []string{}, []string{}
	for _, c := range cands {
		if !p.CanChange(c.BU) {
			continue
		}
		if s.startDriftCheck(r.Context(), c.ID, p.Subject, "checked from environment "+env.Name) {
			started = append(started, c.Name)
		} else {
			skipped = append(skipped, c.Name)
		}
	}
	scans := []string{}
	if b.Inventory && p.ManagesTenant() {
		for _, c := range env.Connections {
			if s.startScheduledScan(r.Context(), c.ID, p.Subject) {
				scans = append(scans, c.Name)
			}
		}
	}
	s.audit(r.Context(), p.Actor(), "environment.check_now", "environment/"+env.Entity+":"+env.Name, "", map[string]any{"drift": started, "scans": scans})
	writeJSON(w, 202, map[string]any{"drift_checks": started, "skipped": skipped, "scans": scans})
}

// startDriftCheck queues a refresh-only run of a stack.
func (s *Server) startDriftCheck(ctx context.Context, stackID, by, reason string) bool {
	st, err := s.store.GetStack(ctx, stackID)
	if err != nil || st.DeletedAt != nil {
		return false
	}
	env, err := s.stackEnv(ctx, st)
	if err != nil {
		return false
	}
	gen, _, probs := s.build(ctx, st.Name, st.BU, env, st.Spec)
	if probs != nil {
		return false
	}
	run, err := s.store.CreateRun(ctx, st.ID, "drift", by, gen.Hash)
	if err != nil {
		return false
	}
	s.audit(ctx, by, "run.create", "run/"+run.ID, st.BU, map[string]string{"stack": st.Name, "operation": "drift", "reason": reason})
	s.runCreated(ctx, run.ID)
	return true
}

// startScheduledScan starts an inventory scan of a connection that supports one.
func (s *Server) startScheduledScan(ctx context.Context, connID, by string) bool {
	conn, err := s.store.GetConnection(ctx, connID)
	if err != nil {
		return false
	}
	cl, err := spec.DecodeCloud(conn.Cloud)
	if err != nil || cl.Provider == "" || cl.Provider == "none" || (cl.Auth != "oidc" && cl.Auth != "vault") {
		return false
	}
	scan, err := s.store.StartScan(ctx, conn.ID, by)
	if err != nil {
		return false // one is running
	}
	s.audit(ctx, by, "inventory.scan", "connection/"+conn.Name, "", map[string]any{"scan": scan.ID, "subject": discoverySubject(conn.Name), "scheduled": by == scheduleActor})
	go s.runScan(conn, cl, scan.ID)
	return true
}

const scheduleActor = "system:schedule"

// scheduler runs due scheduled checks every minute on one replica.
func (s *Server) scheduler(ctx context.Context) {
	every := s.cfg.ScheduleEvery
	if every <= 0 {
		every = time.Minute
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s.store.TryLock(ctx, scheduleLock, s.runSchedules)
	}
}

func (s *Server) runSchedules(ctx context.Context) {
	envs, err := s.store.ScheduledEnvironments(ctx)
	if err != nil {
		s.log.Warn("loading schedules failed", "err", err)
		return
	}
	now := time.Now()
	budget := maxChecksPerTick
	for _, env := range envs {
		sc := parseSchedule(env.Schedule)
		if sc.Quiet.quiet(now) {
			continue
		}
		if sc.Drift.Enabled && budget > 0 {
			every := time.Duration(sc.Drift.EveryHours) * time.Hour
			cands, _ := s.store.DriftCandidates(ctx, env.ID)
			n := 0
			for _, c := range cands {
				if n >= maxDriftPerTick || budget <= 0 {
					break
				}
				if c.LastCheck != nil && now.Before(c.LastCheck.Add(every+jitter(c.ID, every))) {
					continue
				}
				if s.startDriftCheck(ctx, c.ID, scheduleActor, fmt.Sprintf("scheduled drift check (every %dh)", sc.Drift.EveryHours)) {
					n++
					budget--
				}
			}
		}
		if sc.Inventory.Enabled && budget > 0 {
			every := time.Duration(sc.Inventory.EveryHours) * time.Hour
			for _, c := range env.Connections {
				at, running, _ := s.store.LastScanStarted(ctx, c.ID)
				if running || (at != nil && now.Before(at.Add(every+jitter(c.ID, every)))) {
					continue
				}
				if budget > 0 && s.startScheduledScan(ctx, c.ID, scheduleActor) {
					budget--
				}
			}
		}
	}
}
