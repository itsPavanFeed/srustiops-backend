package store

import (
	"context"
	"testing"
)

func TestCostsAndBudgets(t *testing.T) {
	ctx := context.Background()
	st := open(t, freshDB(t, "costs"))
	env, _ := st.CreateEnvironment(ctx, &Environment{Name: "dev", Entity: "retail", Tier: "nonprod", RunnerPool: "default", CreatedBy: "t"})
	if _, err := st.CreateStack(ctx, "pay-net", "payments", "retail", env.ID, nil, []byte(`{}`), "t"); err != nil {
		t.Fatal(err)
	}
	conn, err := st.CreateConnection(ctx, &Connection{Name: "aws", Cloud: []byte(`{"provider":"aws"}`), Entities: []string{}, CreatedBy: "t"})
	if err != nil {
		t.Fatal(err)
	}
	// The stack's own BU wins over a stale tag; two lines that end up the same are added.
	lines := []CostLine{{Month: "2026-11", BU: "old-bu", Stack: "pay-net", Amount: 10, Currency: "USD"}, {Month: "2026-11", BU: "payments", Stack: "pay-net", Amount: 5, Currency: "USD"},
		{Month: "2026-11", BU: "data", Stack: "gone-stack", Amount: 2, Currency: "USD"}, {Month: "2026-11", Amount: 1, Currency: "USD"}}
	if err := st.ReplaceCosts(ctx, conn.ID, []string{"2026-10", "2026-11"}, lines); err != nil {
		t.Fatal(err)
	}
	if got := st.BUSpend(ctx, "payments", "2026-11"); got != 15 {
		t.Fatalf("payments spent %v", got)
	}
	if got := st.BUSpend(ctx, "data", "2026-11"); got != 2 {
		t.Fatalf("data spent %v", got)
	}
	// A refetch replaces the month.
	st.ReplaceCosts(ctx, conn.ID, []string{"2026-11"}, lines[:1])
	if got := st.BUSpend(ctx, "payments", "2026-11"); got != 10 {
		t.Fatalf("after refetch %v", got)
	}
	cs, _ := st.Costs(ctx, "2026-11")
	if len(cs) != 1 {
		t.Fatalf("lines %+v", cs)
	}
	if err := st.PutBudget(ctx, &Budget{BU: "payments", Monthly: 100, AlertAt: []int32{80, 100}, UpdatedBy: "t"}); err != nil {
		t.Fatal(err)
	}
	if b, err := st.Budget(ctx, "payments"); err != nil || b.Monthly != 100 || len(b.AlertAt) != 2 {
		t.Fatalf("budget %+v %v", b, err)
	}
	if !st.ClaimBudgetAlert(ctx, "payments", "2026-11", 80, 85) || st.ClaimBudgetAlert(ctx, "payments", "2026-11", 80, 90) {
		t.Fatal("an alert is claimed exactly once")
	}
	if fs, _ := st.CostFetches(ctx); len(fs) != 1 || !fs[0].OK {
		t.Fatalf("fetches %+v", fs)
	}
}
