package store

import (
	"context"
	"fmt"
	"time"
)

// ---- plan limits ----
//
// Central gives each workspace a plan; its limits are kept here (setting
// plan_limits) and checked when something countable is created, on every
// path that creates it (the API, contracts, imports, schedules). Zero means
// no limit. The count and the insert are not one transaction, so concurrent
// creates can pass a limit by a few: limits are a commercial guard, not a
// security boundary.

const PlanLimitsSetting = "plan_limits"

type Limits struct {
	Plan         string    `json:"plan"`
	Stacks       int       `json:"stacks,omitempty"`
	Environments int       `json:"environments,omitempty"`
	Connections  int       `json:"connections,omitempty"`
	Runners      int       `json:"runners,omitempty"`
	RunsPerMonth int       `json:"runs_per_month,omitempty"`
	People       int       `json:"people,omitempty"` // enforced by central, shown here
	SetAt        time.Time `json:"set_at"`
}

// LimitError is returned when a create would pass the plan's limit.
type LimitError struct {
	What  string
	Limit int
	Plan  string
}

func (e *LimitError) Error() string {
	return fmt.Sprintf("the %s plan allows %d %s; remove some, or ask the platform team for a bigger plan", e.Plan, e.Limit, e.What)
}

// Usage is what a workspace uses of each limited thing.
type Usage struct {
	Stacks       int `json:"stacks"`
	Environments int `json:"environments"`
	Connections  int `json:"connections"`
	Runners      int `json:"runners"`
	RunsPerMonth int `json:"runs_per_month"` // this calendar month (UTC), drift checks excluded
}

var usageSQL = map[string]string{
	"stacks":         `SELECT count(*) FROM stacks WHERE deleted_at IS NULL`,
	"environments":   `SELECT count(*) FROM environments`,
	"connections":    `SELECT count(*) FROM cloud_connections`,
	"runners":        `SELECT count(*) FROM runners WHERE revoked_at IS NULL`,
	"runs_per_month": `SELECT count(*) FROM runs WHERE operation <> 'drift' AND created_at >= date_trunc('month', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'`,
}

func (s *Store) Usage(ctx context.Context) (*Usage, error) {
	var u Usage
	for k, dst := range map[string]*int{"stacks": &u.Stacks, "environments": &u.Environments, "connections": &u.Connections, "runners": &u.Runners, "runs_per_month": &u.RunsPerMonth} {
		if err := s.db.QueryRow(ctx, usageSQL[k]).Scan(dst); err != nil {
			return nil, err
		}
	}
	return &u, nil
}

func (s *Store) PlanLimits(ctx context.Context) Limits {
	var l Limits
	s.Setting(ctx, PlanLimitsSetting, &l)
	return l
}

// checkLimit refuses one more of what when the plan's limit is reached.
func (s *Store) checkLimit(ctx context.Context, what string) error {
	l := s.PlanLimits(ctx)
	max := map[string]int{"stacks": l.Stacks, "environments": l.Environments, "connections": l.Connections, "runners": l.Runners, "runs_per_month": l.RunsPerMonth}[what]
	if max <= 0 {
		return nil
	}
	var n int
	if err := s.db.QueryRow(ctx, usageSQL[what]).Scan(&n); err != nil {
		return err
	}
	if n >= max {
		label := map[string]string{"stacks": "stacks", "environments": "environments", "connections": "cloud connections", "runners": "runners", "runs_per_month": "runs a month"}[what]
		return &LimitError{What: label, Limit: max, Plan: l.Plan}
	}
	return nil
}
