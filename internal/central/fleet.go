package central

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/itsPavanFeed/srustiops-backend/internal/httpx"
	"github.com/itsPavanFeed/srustiops-backend/internal/store"
)

// ---- the fleet: versions and staged rollouts (Platform → Fleet) ----
//
// Central learns which version every workspace's plane runs (its /healthz)
// and rolls a new version out in waves: canary workspaces first, then a share
// of the rest, then everyone. When a wave starts, central tells each of its
// workspaces the version to run; `srustiops updater` beside each plane
// applies it. A wave is done when all its workspaces report the version and
// stay healthy for the soak time; then the next starts. A wave that does not
// finish within a day pauses the rollout and raises an alert.

var fleetVersionRe = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$`)

type fleetWave struct {
	Name    string   `json:"name"`
	Tenants []string `json:"tenants,omitempty"` // named workspaces (a canary)
	Percent int      `json:"percent,omitempty"` // a share of all active workspaces (cumulative)
}

type Rollout struct {
	ID            string      `json:"id"`
	Version       string      `json:"version"`
	Waves         []fleetWave `json:"waves"`
	SoakMinutes   int         `json:"soak_minutes"`
	Status        string      `json:"status"`
	CurrentWave   int         `json:"current_wave"`
	WaveStartedAt time.Time   `json:"wave_started_at"`
	WaveDoneAt    *time.Time  `json:"wave_done_at,omitempty"`
	Detail        string      `json:"detail"`
	CreatedBy     string      `json:"created_by"`
	CreatedAt     time.Time   `json:"created_at"`
}

const rolloutCols = `id, version, waves, soak_minutes, status, current_wave, wave_started_at, wave_done_at, detail, created_by, created_at`

func scanRollout(r pgx.Row) (*Rollout, error) {
	var x Rollout
	var waves []byte
	err := r.Scan(&x.ID, &x.Version, &waves, &x.SoakMinutes, &x.Status, &x.CurrentWave, &x.WaveStartedAt, &x.WaveDoneAt, &x.Detail, &x.CreatedBy, &x.CreatedAt)
	json.Unmarshal(waves, &x.Waves)
	return &x, store.NotFound(err)
}

func (s *Store) ActiveRollout(ctx context.Context) (*Rollout, error) {
	return scanRollout(s.Pool().QueryRow(ctx, `SELECT `+rolloutCols+` FROM fleet_rollouts WHERE status IN ('running', 'paused')`))
}

func (s *Store) Rollouts(ctx context.Context) ([]*Rollout, error) {
	rows, err := s.Pool().Query(ctx, `SELECT `+rolloutCols+` FROM fleet_rollouts ORDER BY created_at DESC LIMIT 20`)
	if err != nil {
		return nil, err
	}
	return store.Collect(rows, scanRollout)
}

func (s *Store) updateRollout(ctx context.Context, r *Rollout) error {
	_, err := s.Pool().Exec(ctx, `UPDATE fleet_rollouts SET status = $2, current_wave = $3, wave_started_at = $4, wave_done_at = $5, detail = $6, updated_at = now() WHERE id = $1`,
		r.ID, r.Status, r.CurrentWave, r.WaveStartedAt, r.WaveDoneAt, r.Detail)
	return err
}

type fleetMember struct {
	Slug, Version, Desired string
	SeenAt                 *time.Time
}

func (s *Store) fleetMembers(ctx context.Context) ([]fleetMember, error) {
	rows, err := s.Pool().Query(ctx, `SELECT slug, plane_version, desired_version, version_seen_at FROM tenants WHERE status = 'active' ORDER BY slug`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []fleetMember
	for rows.Next() {
		var m fleetMember
		if rows.Scan(&m.Slug, &m.Version, &m.Desired, &m.SeenAt) == nil {
			out = append(out, m)
		}
	}
	return out, rows.Err()
}

// waveOf assigns every workspace to the first wave that takes it: named
// tenants, then by a stable hash for percentages (cumulative), and anything
// left to the last wave.
func waveOf(waves []fleetWave, slugs []string) map[string]int {
	out := map[string]int{}
	for i, w := range waves {
		for _, t := range w.Tenants {
			if _, ok := out[t]; !ok {
				out[t] = i
			}
		}
	}
	rest := []string{}
	for _, s := range slugs {
		if _, ok := out[s]; !ok {
			rest = append(rest, s)
		}
	}
	h := func(s string) uint32 { f := fnv.New32a(); f.Write([]byte(s)); return f.Sum32() }
	sort.Slice(rest, func(i, j int) bool { return h(rest[i]) < h(rest[j]) })
	taken := 0
	for i, w := range waves {
		if w.Percent <= 0 {
			continue
		}
		upTo := (len(rest)*w.Percent + 99) / 100
		for ; taken < upTo && taken < len(rest); taken++ {
			out[rest[taken]] = i
		}
	}
	for ; taken < len(rest); taken++ {
		out[rest[taken]] = len(waves) - 1
	}
	return out
}

// rolloutStep advances a running rollout given the fleet now; it returns
// the desired version per workspace that changed. It is pure (tested alone).
func rolloutStep(r *Rollout, members []fleetMember, now time.Time) map[string]string {
	desired := map[string]string{}
	if r.Status != "running" {
		return desired
	}
	slugs := make([]string, 0, len(members))
	for _, m := range members {
		slugs = append(slugs, m.Slug)
	}
	wave := waveOf(r.Waves, slugs)
	for {
		done, total := 0, 0
		for _, m := range members {
			if wave[m.Slug] <= r.CurrentWave {
				if m.Desired != r.Version {
					desired[m.Slug] = r.Version
				}
				if wave[m.Slug] == r.CurrentWave {
					total++
					if m.Version == r.Version {
						done++
					}
				}
			}
		}
		if done < total {
			r.WaveDoneAt = nil
			if now.Sub(r.WaveStartedAt) > 24*time.Hour {
				r.Status = "paused"
				r.Detail = fmt.Sprintf("wave %s: %d of %d workspaces run %s after a day; paused", r.Waves[r.CurrentWave].Name, done, total, r.Version)
			} else {
				r.Detail = fmt.Sprintf("wave %s: %d of %d workspaces run %s", r.Waves[r.CurrentWave].Name, done, total, r.Version)
			}
			return desired
		}
		if r.WaveDoneAt == nil {
			t := now
			r.WaveDoneAt = &t
		}
		if now.Sub(*r.WaveDoneAt) < time.Duration(r.SoakMinutes)*time.Minute {
			r.Detail = fmt.Sprintf("wave %s done (%d workspaces); soaking until %s", r.Waves[r.CurrentWave].Name, total, r.WaveDoneAt.Add(time.Duration(r.SoakMinutes)*time.Minute).Format(time.RFC3339))
			return desired
		}
		if r.CurrentWave == len(r.Waves)-1 {
			r.Status, r.Detail = "done", fmt.Sprintf("every workspace runs %s", r.Version)
			return desired
		}
		r.CurrentWave++
		r.WaveStartedAt, r.WaveDoneAt = now, nil
	}
}

// fleetLoop learns versions and drives the rollout on one replica.
func (s *Server) fleetLoop(ctx context.Context) {
	every := 5 * time.Minute
	if s.cfg.InviteSweep > 0 && s.cfg.InviteSweep < time.Minute {
		every = s.cfg.InviteSweep // the tests' short timers
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		conn, err := s.store.Pool().Acquire(ctx)
		if err != nil {
			continue
		}
		var got bool
		if conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(7206)`).Scan(&got); got {
			s.fleetTick(ctx)
			conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock(7206)`)
		}
		conn.Release()
	}
}

func (s *Server) fleetTick(ctx context.Context) {
	tenants, err := s.store.ListTenants(ctx)
	if err != nil {
		return
	}
	forEachTenant(ctx, tenants, func(ctx context.Context, t *Tenant) {
		if t.Status != "active" {
			return
		}
		if v, ok := s.planeVersion(ctx, t); ok {
			s.store.Pool().Exec(ctx, `UPDATE tenants SET plane_version = $2, version_seen_at = now() WHERE id = $1`, t.ID, v)
		}
	})
	r, err := s.store.ActiveRollout(ctx)
	if err != nil {
		return
	}
	members, err := s.store.fleetMembers(ctx)
	if err != nil {
		return
	}
	before := *r
	changes := rolloutStep(r, members, time.Now())
	for slug, v := range changes {
		t, err := s.store.Tenant(ctx, slug)
		if err != nil {
			continue
		}
		code, body, err := s.callTenantAs(ctx, t, s.system(t), http.MethodPost, "/api/v1/fleet/target",
			map[string]string{"version": v, "rollout": r.ID, "wave": r.Waves[min(r.CurrentWave, len(r.Waves)-1)].Name})
		if err != nil || code != 200 {
			s.log.Warn("telling a workspace its target version failed", "tenant", slug, "code", code, "err", err, "body", trim(string(body), 200))
			continue
		}
		s.store.Pool().Exec(ctx, `UPDATE tenants SET desired_version = $2 WHERE slug = $1`, slug, v)
	}
	if r.Status != before.Status || r.CurrentWave != before.CurrentWave || r.Detail != before.Detail || (r.WaveDoneAt == nil) != (before.WaveDoneAt == nil) {
		s.store.updateRollout(ctx, r)
		if r.CurrentWave != before.CurrentWave {
			s.audit(ctx, "system:fleet", "fleet.wave", "rollout/"+r.ID, "", map[string]any{"version": r.Version, "wave": r.Waves[r.CurrentWave].Name})
		}
		if r.Status != before.Status {
			s.audit(ctx, "system:fleet", "fleet.rollout_"+r.Status, "rollout/"+r.ID, "", map[string]any{"version": r.Version, "detail": r.Detail})
		}
	}
}

// planeVersion asks a workspace's plane which version it runs.
func (s *Server) planeVersion(ctx context.Context, t *Tenant) (string, bool) {
	rt, err := s.transport(t)
	if err != nil {
		return "", false
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, t.BackendURL+"/healthz", nil)
	resp, err := (&http.Client{Transport: rt}).Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	var h struct{ Status, Tenant, Version string }
	if json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&h) != nil || resp.StatusCode != 200 || h.Tenant != t.Slug {
		return "", false
	}
	if h.Version == "" {
		h.Version = "unknown"
	}
	return h.Version, true
}

// ---- API (platform admins) ----

func (s *Server) getFleet(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(w, r) {
		return
	}
	members, err := s.store.fleetMembers(r.Context())
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	counts := map[string]int{}
	type row struct {
		Slug    string     `json:"slug"`
		Version string     `json:"version"`
		Desired string     `json:"desired,omitempty"`
		SeenAt  *time.Time `json:"seen_at,omitempty"`
		Wave    string     `json:"wave,omitempty"`
	}
	rows := []row{}
	active, _ := s.store.ActiveRollout(r.Context())
	var wave map[string]int
	if active != nil && active.ID != "" {
		slugs := []string{}
		for _, m := range members {
			slugs = append(slugs, m.Slug)
		}
		wave = waveOf(active.Waves, slugs)
	}
	for _, m := range members {
		x := row{Slug: m.Slug, Version: m.Version, Desired: m.Desired, SeenAt: m.SeenAt}
		if wave != nil {
			x.Wave = active.Waves[wave[m.Slug]].Name
		}
		if x.Version == "" {
			x.Version = "unknown"
		}
		counts[x.Version]++
		rows = append(rows, x)
	}
	rs, _ := s.store.Rollouts(r.Context())
	if rs == nil {
		rs = []*Rollout{}
	}
	httpx.WriteJSON(w, 200, map[string]any{"central_version": s.cfg.Version, "workspaces": rows, "versions": counts, "rollouts": rs})
}

func (s *Server) startRollout(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(w, r) {
		return
	}
	var b struct {
		Version     string      `json:"version"`
		Waves       []fleetWave `json:"waves"`
		SoakMinutes *int        `json:"soak_minutes"`
	}
	if !httpx.Decode(w, r, &b) {
		return
	}
	var probs []string
	if !fleetVersionRe.MatchString(b.Version) {
		probs = append(probs, "version must be an image tag, e.g. 0.4.0")
	}
	if len(b.Waves) == 0 {
		b.Waves = []fleetWave{{Name: "everyone", Percent: 100}}
	}
	if len(b.Waves) > 10 {
		probs = append(probs, "at most 10 waves")
	}
	prev := 0
	for i, wv := range b.Waves {
		if strings.TrimSpace(wv.Name) == "" {
			b.Waves[i].Name = fmt.Sprintf("wave %d", i+1)
		}
		if (len(wv.Tenants) == 0) == (wv.Percent == 0) {
			probs = append(probs, fmt.Sprintf("wave %d names workspaces or a percentage, not both", i+1))
		}
		if wv.Percent != 0 && (wv.Percent < prev || wv.Percent > 100) {
			probs = append(probs, "percentages grow from wave to wave, up to 100")
		}
		if wv.Percent > 0 {
			prev = wv.Percent
		}
		for _, t := range wv.Tenants {
			if _, err := s.store.Tenant(r.Context(), t); err != nil {
				probs = append(probs, "unknown workspace "+t)
			}
		}
	}
	soak := 60
	if b.SoakMinutes != nil {
		soak = *b.SoakMinutes
	}
	if soak < 0 || soak > 7*24*60 {
		probs = append(probs, "soak_minutes must be 0 to a week")
	}
	if len(probs) > 0 {
		httpx.WriteErr(w, 422, "invalid rollout", probs...)
		return
	}
	waves, _ := json.Marshal(b.Waves)
	var id string
	err := s.store.Pool().QueryRow(r.Context(), `INSERT INTO fleet_rollouts (version, waves, soak_minutes, created_by) VALUES ($1, $2, $3, $4) RETURNING id`,
		b.Version, waves, soak, current(r).Email).Scan(&id)
	if store.IsUnique(err) {
		httpx.WriteErr(w, http.StatusConflict, "a rollout is in progress; finish, or abort, it first")
		return
	}
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	s.audit(r.Context(), current(r).Email, "fleet.rollout_start", "rollout/"+id, "", map[string]any{"version": b.Version, "waves": b.Waves, "soak_minutes": soak})
	go s.fleetTick(context.WithoutCancel(r.Context()))
	s.getFleet(w, r)
}

// controlRollout pauses, resumes or aborts the rollout in progress.
func (s *Server) controlRollout(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(w, r) {
		return
	}
	ro, err := s.store.ActiveRollout(r.Context())
	if err != nil {
		httpx.WriteErr(w, http.StatusConflict, "no rollout is in progress")
		return
	}
	switch a := r.PathValue("action"); a {
	case "pause":
		ro.Status, ro.Detail = "paused", "paused by "+current(r).Email
	case "resume":
		ro.Status = "running"
		ro.WaveStartedAt = time.Now() // a fresh day for the wave
	case "abort":
		ro.Status, ro.Detail = "aborted", "aborted by "+current(r).Email+"; workspaces keep the version they run"
		// Workspaces told to upgrade that have not yet are told to stay where they are.
		if ms, err := s.store.fleetMembers(r.Context()); err == nil {
			for _, m := range ms {
				if m.Desired != ro.Version || m.Version == ro.Version || m.Version == "" || m.Version == "unknown" {
					continue
				}
				if t, err := s.store.Tenant(r.Context(), m.Slug); err == nil {
					if code, _, err := s.callTenantAs(r.Context(), t, s.system(t), http.MethodPost, "/api/v1/fleet/target",
						map[string]string{"version": m.Version, "rollout": ro.ID, "wave": "aborted"}); err == nil && code == 200 {
						s.store.Pool().Exec(r.Context(), `UPDATE tenants SET desired_version = $2 WHERE slug = $1`, m.Slug, m.Version)
					}
				}
			}
		}
	default:
		httpx.WriteErr(w, 404, "unknown action "+a)
		return
	}
	if err := s.store.updateRollout(r.Context(), ro); err != nil {
		s.storeErr(w, err, "")
		return
	}
	s.audit(r.Context(), current(r).Email, "fleet.rollout_"+r.PathValue("action"), "rollout/"+ro.ID, "", map[string]string{"version": ro.Version})
	s.getFleet(w, r)
}
