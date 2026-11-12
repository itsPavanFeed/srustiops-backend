package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/itsPavanFeed/srustiops-backend/internal/audit"
	"github.com/jackc/pgx/v5"
)

// CheckpointSealer seals and opens audit checkpoints (the master key).
type CheckpointSealer interface {
	Seal(plaintext, aad []byte) ([]byte, error)
	Open(sealed, aad []byte) ([]byte, error)
}

var checkpointAAD = []byte("srustiops-audit-checkpoint")

type checkpoint struct {
	ID   int64  `json:"id"`
	Hash string `json:"hash"`
}

// AuditVerification is what a verification found.
type AuditVerification struct {
	Checked        int   `json:"checked"`
	FirstBrokenID  int64 `json:"first_broken_id"`
	FromCheckpoint int64 `json:"from_checkpoint,omitempty"` // events up to it were vouched for by a sealed checkpoint
}

// VerifyAuditFast verifies the chain from the newest checkpoint that opens
// (all of it with full, or when none opens), then records a checkpoint at
// its end. A checkpoint whose event no longer has the sealed hash means the
// chain was rewritten: that event is reported broken.
func (b *Base) VerifyAuditFast(ctx context.Context, cs CheckpointSealer, full bool) (AuditVerification, error) {
	var v AuditVerification
	prev, after := audit.Genesis, int64(0)
	if !full && cs != nil {
		var sealed []byte
		err := b.db.QueryRow(ctx, `SELECT sealed FROM audit_checkpoints ORDER BY id DESC LIMIT 1`).Scan(&sealed)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return v, err
		}
		var cp checkpoint
		if plain, oerr := openCheckpoint(cs, sealed); err == nil && oerr == nil && json.Unmarshal(plain, &cp) == nil {
			var h string
			if err := b.db.QueryRow(ctx, `SELECT hash FROM audit_events WHERE id = $1`, cp.ID).Scan(&h); err != nil || h != cp.Hash {
				v.FirstBrokenID = cp.ID
				return v, nil
			}
			prev, after, v.FromCheckpoint = cp.Hash, cp.ID, cp.ID
		}
	}
	for {
		rows, err := b.db.Query(ctx, `SELECT id, ts, actor, action, target, `+b.scopeCol+`, payload::text, prev_hash, hash FROM audit_events WHERE id > $1 ORDER BY id LIMIT 5000`, after)
		if err != nil {
			return v, err
		}
		evs, err := scanAudit(rows)
		if err != nil {
			return v, err
		}
		if len(evs) == 0 {
			break
		}
		if broken := audit.Verify(evs, prev); broken != 0 {
			v.FirstBrokenID = broken
			return v, nil
		}
		v.Checked += len(evs)
		prev, after = evs[len(evs)-1].Hash, evs[len(evs)-1].ID
	}
	if cs != nil && after > v.FromCheckpoint {
		p, _ := json.Marshal(checkpoint{ID: after, Hash: prev})
		if sealed, err := cs.Seal(p, checkpointAAD); err == nil {
			b.db.Exec(ctx, `INSERT INTO audit_checkpoints (id, sealed) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING`, after, sealed)
		}
	}
	return v, nil
}

func openCheckpoint(cs CheckpointSealer, sealed []byte) ([]byte, error) {
	if len(sealed) == 0 {
		return nil, fmt.Errorf("no checkpoint")
	}
	return cs.Open(sealed, checkpointAAD)
}
