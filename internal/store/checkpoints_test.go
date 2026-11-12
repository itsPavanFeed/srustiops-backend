package store

import (
	"bytes"
	"context"
	"testing"

	"github.com/itsPavanFeed/srustiops-backend/internal/audit"
	"github.com/itsPavanFeed/srustiops-backend/internal/secure"
)

func TestAuditCheckpoints(t *testing.T) {
	ctx := context.Background()
	st := open(t, freshDB(t, "ckpt"))
	cs, _ := secure.NewSealer(bytes.Repeat([]byte{3}, 32))
	for i := 0; i < 5; i++ {
		st.AppendAudit(ctx, "a", "x.y", "t", "payments", map[string]int{"i": i})
	}
	v, err := st.VerifyAuditFast(ctx, cs, false)
	if err != nil || v.FirstBrokenID != 0 || v.Checked != 5 || v.FromCheckpoint != 0 {
		t.Fatalf("first verify %+v %v", v, err)
	}
	st.AppendAudit(ctx, "a", "x.y", "t", "payments", nil)
	v, _ = st.VerifyAuditFast(ctx, cs, false)
	if v.FirstBrokenID != 0 || v.Checked != 1 || v.FromCheckpoint == 0 {
		t.Fatalf("second verify starts at the checkpoint: %+v", v)
	}
	// Rewrite the whole chain consistently (what a plain hash chain cannot
	// detect): the sealed checkpoint no longer matches.
	st.db.Exec(ctx, `ALTER TABLE audit_events DISABLE TRIGGER audit_events_no_update`)
	evs, _ := st.AuditAfter(ctx, 0, 100)
	prev := audit.Genesis
	for _, e := range evs {
		e.Actor = "mallory"
		h := audit.Hash(prev, e)
		st.db.Exec(ctx, `UPDATE audit_events SET actor = 'mallory', prev_hash = $2, hash = $3 WHERE id = $1`, e.ID, prev, h)
		prev = h
	}
	if _, broken, _ := st.VerifyAudit(ctx); broken != 0 {
		t.Fatal("the plain verify was expected to miss a consistent rewrite")
	}
	if v, _ := st.VerifyAuditFast(ctx, cs, false); v.FirstBrokenID == 0 {
		t.Fatal("a rewritten chain passed the checkpoint")
	}
}
