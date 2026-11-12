package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestPlanLimits(t *testing.T) {
	ctx := context.Background()
	st := open(t, freshDB(t, "limits"))
	env, err := st.CreateEnvironment(ctx, &Environment{Name: "dev", Entity: "retail", Tier: "nonprod", RunnerPool: "default", CreatedBy: "t"})
	if err != nil {
		t.Fatal(err)
	}
	st.PutSetting(ctx, PlanLimitsSetting, Limits{Plan: "trial", Stacks: 1, Environments: 1, RunsPerMonth: 2}, "central")
	var le *LimitError
	if _, err := st.CreateEnvironment(ctx, &Environment{Name: "prod", Entity: "retail", Tier: "prod", RunnerPool: "default", CreatedBy: "t"}); !errors.As(err, &le) || le.Limit != 1 {
		t.Fatalf("second environment: %v", err)
	}
	s1, err := st.CreateStack(ctx, "a", "payments", "retail", env.ID, nil, []byte(`{}`), "t")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateStack(ctx, "b", "payments", "retail", env.ID, nil, []byte(`{}`), "t"); !errors.As(err, &le) {
		t.Fatalf("second stack: %v", err)
	}
	for i := 0; i < 2; i++ {
		r, err := st.CreateRun(ctx, s1.ID, "apply", "t", "h")
		if err != nil {
			t.Fatal(err)
		}
		st.db.Exec(ctx, `UPDATE runs SET status = 'no_changes', finished_at = now() WHERE id = $1`, r.ID)
	}
	if _, err := st.CreateRun(ctx, s1.ID, "apply", "t", "h"); !errors.As(err, &le) || le.What != "runs a month" {
		t.Fatalf("third run: %v", err)
	}
	// Drift checks and destroys still run over the limit.
	for _, op := range []string{"drift", "destroy"} {
		r, err := st.CreateRun(ctx, s1.ID, op, "t", "h")
		if err != nil {
			t.Fatalf("%s over the limit: %v", op, err)
		}
		st.db.Exec(ctx, `UPDATE runs SET status = 'no_changes', finished_at = now() WHERE id = $1`, r.ID)
	}
	u, err := st.Usage(ctx)
	if err != nil || u.Stacks != 1 || u.Environments != 1 || u.RunsPerMonth != 3 {
		t.Fatalf("usage: %+v %v", u, err)
	}
	// No limits: anything goes.
	st.PutSetting(ctx, PlanLimitsSetting, Limits{Plan: "enterprise"}, "central")
	if _, err := st.CreateStack(ctx, "b", "payments", "retail", env.ID, nil, []byte(`{}`), "t"); err != nil {
		t.Fatal(err)
	}
}

func TestStackSummaries(t *testing.T) {
	ctx := context.Background()
	st := open(t, freshDB(t, "summ"))
	env, _ := st.CreateEnvironment(ctx, &Environment{Name: "dev", Entity: "retail", Tier: "nonprod", RunnerPool: "default", CreatedBy: "t"})
	for _, n := range []string{"a", "b", "c"} {
		if _, err := st.CreateStack(ctx, n, "payments", "retail", env.ID, nil, []byte(`{"modules":[{"name":"n","kind":"Naming","module":"x","inputs":{"big":"`+strings.Repeat("v", 5000)+`"}}],"imports":[{"to":"module.n.x","id":"i"}]}`), "t"); err != nil {
			t.Fatal(err)
		}
	}
	page, total, err := st.ListStackSummaries(ctx, nil, 2, 1)
	if err != nil || total != 3 || len(page) != 2 || page[0].Name != "b" {
		t.Fatalf("page: %d %d %v", len(page), total, err)
	}
	if strings.Contains(string(page[0].Spec), "vvvv") || !strings.Contains(string(page[0].Spec), `"kind": "Naming"`) || page[0].ImportsPending != 1 || page[0].Resources != nil {
		t.Fatalf("summary spec: %s %d", page[0].Spec, page[0].ImportsPending)
	}
}

func TestFairClaim(t *testing.T) {
	ctx := context.Background()
	st := open(t, freshDB(t, "fair"))
	env, _ := st.CreateEnvironment(ctx, &Environment{Name: "dev", Entity: "retail", Tier: "nonprod", RunnerPool: "default", CreatedBy: "t"})
	mk := func(name, bu string) string {
		s, err := st.CreateStack(ctx, name, bu, "retail", env.ID, nil, []byte(`{}`), "t")
		if err != nil {
			t.Fatal(err)
		}
		r, err := st.CreateRun(ctx, s.ID, "apply", "t", "h")
		if err != nil {
			t.Fatal(err)
		}
		return r.ID
	}
	// payments queues three first (a burst), data one after.
	p1, _, _ := mk("p1", "payments"), mk("p2", "payments"), mk("p3", "payments")
	d1 := mk("d1", "data")
	rn, err := st.CreateRunner(ctx, "r1", "default", []byte("h"))
	if err != nil {
		t.Fatal(err)
	}
	claim := func() string {
		r, err := st.ClaimRun(ctx, rn.ID, "default", []byte(fmt.Sprint(time.Now().UnixNano())), time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return r.ID
	}
	if got := claim(); got != p1 {
		t.Fatalf("first claim %s, want the oldest", got)
	}
	// payments now has one in progress, data none: data goes next.
	if got := claim(); got != d1 {
		t.Fatalf("second claim %s, want data's run before payments' second", got)
	}
}

func TestPrune(t *testing.T) {
	ctx := context.Background()
	st := open(t, freshDB(t, "prune"))
	env, _ := st.CreateEnvironment(ctx, &Environment{Name: "dev", Entity: "retail", Tier: "nonprod", RunnerPool: "default", CreatedBy: "t"})
	s1, _ := st.CreateStack(ctx, "a", "payments", "retail", env.ID, nil, []byte(`{}`), "t")
	run, _ := st.CreateRun(ctx, s1.ID, "apply", "t", "h")
	for i := 0; i < 8; i++ {
		key := fmt.Sprintf("state/a/%d", i%3) // content-addressed: keys repeat
		if _, err := st.PutState(ctx, s1.ID, run.ID, nil, key, "sha"); err != nil {
			t.Fatal(err)
		}
	}
	st.AddNotification(ctx, &Notification{Kind: "x", Severity: "info", Title: "old", BU: "payments"})
	st.db.Exec(ctx, `UPDATE notifications SET created_at = now() - interval '100 days'`)
	st.AddNotification(ctx, &Notification{Kind: "x", Severity: "info", Title: "new", BU: "payments"})
	n, objects, err := st.Prune(ctx, Retention{NotificationsDays: 90, StateVersionsKeep: 5})
	if err != nil || n["notifications"] != 1 || n["state_versions"] != 3 {
		t.Fatalf("pruned %v %v", n, err)
	}
	// The three deleted versions' keys are all still used by kept versions.
	if len(objects) != 0 {
		t.Fatalf("objects still in use were freed: %v", objects)
	}
	if ref, _ := st.LatestState(ctx, s1.ID); ref.Serial != 8 {
		t.Fatalf("latest state serial %d", ref.Serial)
	}
}

func TestEnvironmentConcurrencyCap(t *testing.T) {
	ctx := context.Background()
	st := open(t, freshDB(t, "cap"))
	env, _ := st.CreateEnvironment(ctx, &Environment{Name: "prod", Entity: "retail", Tier: "prod", RunnerPool: "default", MaxRunning: 1, CreatedBy: "t"})
	for _, n := range []string{"a", "b"} {
		s, _ := st.CreateStack(ctx, n, "payments", "retail", env.ID, nil, []byte(`{}`), "t")
		if _, err := st.CreateRun(ctx, s.ID, "apply", "t", "h"); err != nil {
			t.Fatal(err)
		}
	}
	rn, _ := st.CreateRunner(ctx, "r1", "default", []byte("h"))
	if _, err := st.ClaimRun(ctx, rn.ID, "default", []byte("t1"), time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ClaimRun(ctx, rn.ID, "default", []byte("t2"), time.Hour); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a second run started in an environment capped at one: %v", err)
	}
}
