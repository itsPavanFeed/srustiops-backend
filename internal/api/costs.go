package api

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/identity"
	"github.com/itsPavanFeed/srustiops-backend/internal/spec"
	"github.com/itsPavanFeed/srustiops-backend/internal/store"
)

// ---- actual cost and budgets per BU (Costs) ----
//
// Plans carry an estimate; this is what the clouds billed. Once enabled,
// each connection's billing API is read on a schedule (AWS Cost Explorer,
// Azure Cost Management, GCP's billing export in BigQuery) for this month
// and last, grouped by the srustiops-bu and srustiops-stack tags SrustiOps
// puts on everything it creates. FinOps sets a monthly budget per BU; when
// a BU's spend passes an alert threshold, FinOps is notified once, and
// policies see input.budget so a plan can be held when the BU is over.

const (
	costSettingsKey = "cost_settings"
	costLock        = 7307
)

type costSettings struct {
	Enabled    bool              `json:"enabled"`
	EveryHours int               `json:"every_hours"`
	GCPTables  map[string]string `json:"gcp_billing_tables,omitempty"` // connection -> project.dataset.table
}

func (s *Server) costSettings(ctx context.Context) costSettings {
	c := costSettings{EveryHours: 24}
	s.store.Setting(ctx, costSettingsKey, &c)
	if c.EveryHours < 1 {
		c.EveryHours = 24
	}
	return c
}

var monthRe = regexp.MustCompile(`^\d{4}-(0[1-9]|1[0-2])$`)

func thisMonth(t time.Time) string { return t.UTC().Format("2006-01") }

// fetchCosts reads every connection's billing for last month and this one.
func (s *Server) fetchCosts(ctx context.Context) {
	cs := s.costSettings(ctx)
	conns, err := s.store.ListConnections(ctx)
	if err != nil {
		return
	}
	now := time.Now().UTC()
	from := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, -1, 0)
	months := []string{thisMonth(from), thisMonth(now)}
	for _, conn := range conns {
		cl, err := spec.DecodeCloud(conn.Cloud)
		if err != nil || cl.Provider == "" || cl.Provider == "none" {
			continue
		}
		if cl.Auth != "oidc" && cl.Auth != "vault" {
			s.store.CostFetchFailed(ctx, conn.ID, "billing is read with OIDC or vault credentials; this connection uses "+cl.Auth)
			continue
		}
		c, err := s.discoveryClient(ctx, conn.Name, cl)
		if err != nil {
			s.store.CostFetchFailed(ctx, conn.ID, err.Error())
			continue
		}
		pick := func(apply, plan string) string {
			if plan != "" {
				return plan
			}
			return apply
		}
		var lines []store.CostLine
		add := func(m, bu, stack string, amt float64, cur string) {
			if cur == "" {
				cur = "USD"
			}
			lines = append(lines, store.CostLine{Month: m, BU: bu, Stack: stack, Amount: amt, Currency: cur})
		}
		switch cl.Provider {
		case "aws":
			ls, ferr := c.AWSCost(ctx, pick(cl.AWS.RoleARN, cl.AWS.PlanRoleARN), from, now)
			err = ferr
			for _, l := range ls {
				add(l.Month, l.BU, l.Stack, l.Amount, l.Currency)
			}
		case "azure":
			ls, ferr := c.AzureCost(ctx, cl.Azure.TenantID, pick(cl.Azure.ClientID, cl.Azure.PlanClientID), cl.Azure.SubscriptionID, from, now)
			err = ferr
			for _, l := range ls {
				add(l.Month, l.BU, l.Stack, l.Amount, l.Currency)
			}
		case "gcp":
			table := cs.GCPTables[conn.Name]
			if table == "" {
				err = fmt.Errorf("GCP actual cost comes from the Cloud Billing export to BigQuery: set this connection's export table under Costs → Settings")
				break
			}
			ls, ferr := c.GCPCost(ctx, cl.GCP.WorkloadIdentityProvider, pick(cl.GCP.ServiceAccountEmail, cl.GCP.PlanServiceAccountEmail), cl.GCP.ProjectID, table, from, now)
			err = ferr
			for _, l := range ls {
				add(l.Month, l.BU, l.Stack, l.Amount, l.Currency)
			}
		default:
			continue
		}
		if err == nil {
			err = s.store.ReplaceCosts(ctx, conn.ID, months, lines)
		}
		if err != nil {
			s.log.Warn("reading actual cost failed", "connection", conn.Name, "err", err)
			s.store.CostFetchFailed(ctx, conn.ID, trimTo(err.Error(), 500))
		}
	}
	s.checkBudgets(ctx, thisMonth(now))
}

func trimTo(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// checkBudgets notifies FinOps once per BU, month and threshold passed.
func (s *Server) checkBudgets(ctx context.Context, month string) {
	bs, err := s.store.Budgets(ctx)
	if err != nil {
		return
	}
	for _, b := range bs {
		spent := s.store.BUSpend(ctx, b.BU, month)
		pct := spent / b.Monthly * 100
		th := append([]int32(nil), b.AlertAt...)
		sort.Slice(th, func(i, j int) bool { return th[i] > th[j] })
		for _, t := range th { // only the highest threshold passed is announced
			if pct < float64(t) {
				continue
			}
			if s.store.ClaimBudgetAlert(ctx, b.BU, month, int(t), spent) {
				sev := "warning"
				if t >= 100 {
					sev = "error"
				}
				s.notifyEvent(ctx, store.Notification{Kind: "budget.threshold", Severity: sev, BU: b.BU, Steps: []string{identity.StepFinOps},
					Title: fmt.Sprintf("%s has used %.0f%% of its budget", b.BU, pct),
					Body:  fmt.Sprintf("%.2f of %.2f this month (%s), past the %d%% alert.", spent, b.Monthly, month, t), Link: "costs"})
				s.audit(ctx, "system:costs", "budget.alert", "bu/"+b.BU, b.BU, map[string]any{"month": month, "threshold": t, "spent": spent, "budget": b.Monthly})
			}
			break
		}
	}
}

func (s *Server) costLoop(ctx context.Context) {
	every := min(s.cfg.ScheduleEvery, time.Minute)
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
		cs := s.costSettings(ctx)
		if !cs.Enabled {
			continue
		}
		if last := s.store.LastCostFetch(ctx); last != nil && time.Since(*last) < time.Duration(cs.EveryHours)*time.Hour {
			continue
		}
		s.store.TryLock(ctx, costLock, s.fetchCosts)
	}
}

// budgetInput is input.budget for a run's BU (nil without a budget).
func (s *Server) budgetInput(ctx context.Context, bu string) map[string]any {
	b, err := s.store.Budget(ctx, bu)
	if err != nil {
		return nil
	}
	now := time.Now()
	month := thisMonth(now)
	spent := s.store.BUSpend(ctx, bu, month)
	fc := forecast(spent, now)
	return map[string]any{"monthly": b.Monthly, "month": month, "spent": spent, "remaining": b.Monthly - spent, "used_pct": spent / b.Monthly * 100,
		"forecast": fc, "forecast_pct": fc / b.Monthly * 100}
}

// forecast projects this month's spend to its end at the pace so far
// (billing lags about a day, so the elapsed part counts from yesterday).
func forecast(spent float64, now time.Time) float64 {
	now = now.UTC()
	start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	days := float64(start.AddDate(0, 1, 0).Sub(start) / (24 * time.Hour))
	elapsed := max(now.Sub(start).Hours()/24-1, 1)
	if elapsed >= days {
		return spent
	}
	return spent / elapsed * days
}

// ---- API ----

func canFinOps(p *identity.Principal) bool {
	return p.ManagesTenant() || p.HasTenantRole(identity.FinOps)
}

type buCost struct {
	BU       string             `json:"bu"`
	Actual   float64            `json:"actual"`
	Currency string             `json:"currency"`
	Other    map[string]float64 `json:"other_currencies,omitempty"` // spend in other currencies, not in actual
	Budget   *store.Budget      `json:"budget,omitempty"`
	UsedPct  *float64           `json:"used_pct,omitempty"`
	Forecast *float64           `json:"forecast,omitempty"` // this month's spend at the pace so far (current month only)
	Stacks   []store.CostLine   `json:"stacks"`
}

func (s *Server) getCosts(w http.ResponseWriter, r *http.Request) {
	p := user(r)
	ctx := r.Context()
	month := r.URL.Query().Get("month")
	if month == "" {
		month = thisMonth(time.Now())
	}
	if !monthRe.MatchString(month) {
		writeErr(w, 422, "month is YYYY-MM")
		return
	}
	lines, err := s.store.Costs(ctx, month)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	budgets, _ := s.store.Budgets(ctx)
	by := map[string]*buCost{}
	get := func(bu string) *buCost {
		if by[bu] == nil {
			by[bu] = &buCost{BU: bu, Currency: "USD", Stacks: []store.CostLine{}}
		}
		return by[bu]
	}
	var untagged float64
	for _, l := range lines {
		if l.BU == "" {
			untagged += l.Amount
			continue
		}
		if !p.CanView(l.BU) {
			continue
		}
		c := get(l.BU)
		c.Stacks = append(c.Stacks, l)
		if c.Other == nil {
			c.Other = map[string]float64{}
		}
		c.Other[l.Currency] += l.Amount
	}
	// Each BU's actual is in the currency it spent most in; the rest stays
	// apart, never added to it.
	for _, c := range by {
		best := ""
		for cur, v := range c.Other {
			if best == "" || v > c.Other[best] {
				best = cur
			}
		}
		if best != "" {
			c.Currency, c.Actual = best, c.Other[best]
			delete(c.Other, best)
		}
		if len(c.Other) == 0 {
			c.Other = nil
		}
	}
	for i := range budgets {
		b := budgets[i]
		if !p.CanView(b.BU) {
			continue
		}
		c := get(b.BU)
		c.Budget = &b
		pct := c.Actual / b.Monthly * 100
		c.UsedPct = &pct
	}
	if month == thisMonth(time.Now()) {
		for _, c := range by {
			f := forecast(c.Actual, time.Now())
			c.Forecast = &f
		}
	}
	out := []*buCost{}
	for _, c := range by {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].BU < out[j].BU })
	resp := map[string]any{"month": month, "bus": out, "can_edit": canFinOps(p)}
	if p.SeesAllBUs() {
		fetches, _ := s.store.CostFetches(ctx)
		resp["untagged"], resp["fetches"], resp["settings"] = untagged, fetches, s.costSettings(ctx)
	}
	writeJSON(w, 200, resp)
}

func (s *Server) putCostSettings(w http.ResponseWriter, r *http.Request) {
	p := user(r)
	if !canFinOps(p) {
		writeErr(w, http.StatusForbidden, "this needs the finops, tenant_admin or devops role")
		return
	}
	var b costSettings
	if !decode(w, r, &b) {
		return
	}
	if b.EveryHours < 1 || b.EveryHours > 24*7 {
		writeErr(w, 422, "every_hours must be 1-168")
		return
	}
	for conn, t := range b.GCPTables {
		if t != "" && strings.Count(t, ".") != 2 {
			writeErr(w, 422, "the billing export table of "+conn+" must be project.dataset.table")
			return
		}
	}
	if err := s.store.PutSetting(r.Context(), costSettingsKey, b, p.Subject); err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.audit(r.Context(), p.Actor(), "costs.settings", "costs", "", b)
	writeJSON(w, 200, b)
}

func (s *Server) refreshCosts(w http.ResponseWriter, r *http.Request) {
	p := user(r)
	if !canFinOps(p) {
		writeErr(w, http.StatusForbidden, "this needs the finops, tenant_admin or devops role")
		return
	}
	ran := false
	s.store.TryLock(r.Context(), costLock, func(ctx context.Context) { ran = true; s.fetchCosts(ctx) })
	if !ran {
		writeErr(w, http.StatusConflict, "costs are being read right now; try again in a moment")
		return
	}
	s.audit(r.Context(), p.Actor(), "costs.refresh", "costs", "", nil)
	s.getCosts(w, r)
}

func (s *Server) putBudget(w http.ResponseWriter, r *http.Request) {
	p := user(r)
	if !canFinOps(p) {
		writeErr(w, http.StatusForbidden, "budgets are set by FinOps (or a tenant admin)")
		return
	}
	bu := r.PathValue("bu")
	var b struct {
		Monthly float64 `json:"monthly"`
		AlertAt []int32 `json:"alert_at"`
	}
	if !decode(w, r, &b) {
		return
	}
	if bu == "" || len(bu) > 64 || b.Monthly <= 0 || b.Monthly > 1e10 {
		writeErr(w, 422, "a budget is a positive monthly amount for a BU")
		return
	}
	if len(b.AlertAt) == 0 {
		b.AlertAt = []int32{80, 100}
	}
	for _, a := range b.AlertAt {
		if a < 1 || a > 1000 {
			writeErr(w, 422, "alert thresholds are percentages, 1-1000")
			return
		}
	}
	bg := &store.Budget{BU: bu, Monthly: b.Monthly, AlertAt: b.AlertAt, UpdatedBy: p.Subject}
	if err := s.store.PutBudget(r.Context(), bg); err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.audit(r.Context(), p.Actor(), "budget.set", "bu/"+bu, bu, map[string]any{"monthly": b.Monthly, "alert_at": b.AlertAt})
	s.checkBudgets(r.Context(), thisMonth(time.Now()))
	writeJSON(w, 200, bg)
}

func (s *Server) deleteBudget(w http.ResponseWriter, r *http.Request) {
	p := user(r)
	if !canFinOps(p) {
		writeErr(w, http.StatusForbidden, "budgets are set by FinOps (or a tenant admin)")
		return
	}
	bu := r.PathValue("bu")
	if err := s.store.DeleteBudget(r.Context(), bu); err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.audit(r.Context(), p.Actor(), "budget.delete", "bu/"+bu, bu, nil)
	w.WriteHeader(http.StatusNoContent)
}
