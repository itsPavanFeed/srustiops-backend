package central

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/identity"
	"github.com/itsPavanFeed/srustiops-backend/internal/store"
)

func TestPeopleLimit(t *testing.T) {
	_, st, _ := testServer(t, "")
	ctx := context.Background()
	suffix := fmt.Sprint(time.Now().UnixNano())
	tn, err := st.CreateTenant(ctx, &Tenant{Slug: "pl" + suffix[len(suffix)-8:], Name: "P", BackendURL: "https://p.example", CreatedBy: "test"})
	if err != nil {
		t.Fatal(err)
	}
	plan := "pt" + suffix[len(suffix)-8:]
	st.Pool().Exec(ctx, `INSERT INTO plans (name, limits, created_by) VALUES ($1, '{"people": 2}', 'test')`, plan)
	t.Cleanup(func() {
		st.Pool().Exec(context.Background(), `UPDATE tenants SET plan = NULL WHERE id = $1`, tn.ID)
		st.Pool().Exec(context.Background(), `DELETE FROM plans WHERE name = $1`, plan)
	})
	st.Pool().Exec(ctx, `UPDATE tenants SET plan = $2 WHERE id = $1`, tn.ID, plan)
	var ids []string
	for _, n := range []string{"a", "b", "c"} {
		u, err := st.EnsureUser(ctx, n+suffix+"@x.test", "", false, "test")
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, u.ID)
	}
	if _, err := st.AddMembership(ctx, ids[0], tn.ID, nil, nil, identity.TenantAdmin, "t"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddMembership(ctx, ids[1], tn.ID, nil, nil, "auditor", "t"); err != nil {
		t.Fatal(err)
	}
	// Someone already in may get another role; a third person may not join.
	if _, err := st.AddMembership(ctx, ids[0], tn.ID, nil, nil, "auditor", "t"); err != nil {
		t.Fatalf("a second role for a member: %v", err)
	}
	var le *store.LimitError
	if _, err := st.AddMembership(ctx, ids[2], tn.ID, nil, nil, "auditor", "t"); !errors.As(err, &le) || le.Limit != 2 {
		t.Fatalf("third person: %v", err)
	}
	if _, err := st.SaveTeam(ctx, tn.ID, &Team{Slug: "ops", Name: "Ops"}, []string{ids[1], ids[2]}, nil, "t", true); !errors.As(err, &le) {
		t.Fatalf("a team bringing a third person: %v", err)
	}
	if _, err := st.SaveTeam(ctx, tn.ID, &Team{Slug: "ops", Name: "Ops"}, []string{ids[0], ids[1]}, nil, "t", true); err != nil {
		t.Fatalf("a team of members: %v", err)
	}
}
