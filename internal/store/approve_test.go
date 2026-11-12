package store

import (
	"context"
	"errors"
	"testing"
)

// The author of a pull request's change, as its proposer or by a linked
// host login, cannot approve its plan; others can.
func TestApprovePRSeparationOfDuties(t *testing.T) {
	ctx := context.Background()
	st := open(t, freshDB(t, "sod"))
	st.SetPRScope("gitlab", "acme/contracts")
	env, _ := st.CreateEnvironment(ctx, &Environment{Name: "dev", Entity: "retail", Tier: "nonprod", RunnerPool: "default", CreatedBy: "t"})
	mk := func(name string, pr int) string {
		s, err := st.CreateStack(ctx, name, "payments", "retail", env.ID, nil, []byte(`{}`), "t")
		if err != nil {
			t.Fatal(err)
		}
		r, err := st.CreatePRRun(ctx, s.ID, "git:pr#1:alice", "h", []byte(`{}`), pr, "sha", false, nil)
		if err != nil {
			t.Fatal(err)
		}
		st.db.Exec(ctx, `UPDATE runs SET status = 'planned', required_approvals = '{manager}' WHERE id = $1`, r.ID)
		return r.ID
	}
	// Proposed in the console by mike (recorded after the plan started).
	r1 := mk("a", 1)
	st.SetPRProposer(ctx, 1, "mike@x.test")
	if _, err := st.Approve(ctx, r1, "manager", "mike@x.test", ""); !errors.Is(err, ErrSelfApproval) {
		t.Fatalf("proposer approved: %v", err)
	}
	// Opened on the host by login alice, linked to ann.
	r2 := mk("b", 2)
	st.PutGitIdentity(ctx, &GitIdentity{Provider: "gitlab", Login: "Alice", Subject: "ann@x.test", CreatedBy: "admin"})
	if _, err := st.Approve(ctx, r2, "manager", "ann@x.test", ""); !errors.Is(err, ErrSelfApproval) {
		t.Fatalf("linked author approved: %v", err)
	}
	if done, err := st.Approve(ctx, r2, "manager", "bob@x.test", ""); err != nil || !done {
		t.Fatalf("someone else: %v %v", done, err)
	}
	// Same number on another repository is another pull request.
	st.SetPRScope("github", "acme/contracts")
	if runs, _ := st.PRRuns(ctx, 1); len(runs) != 0 {
		t.Fatal("runs of a gitlab PR seen under github")
	}
}
