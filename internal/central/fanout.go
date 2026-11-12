package central

import (
	"context"
	"sync"
)

// fanout is how many workspaces central talks to at once in its background
// loops: one slow or offline workspace must not hold up the others.
const fanout = 16

// forEachTenant runs fn for every tenant, fanout at a time, and returns
// when all are done.
func forEachTenant(ctx context.Context, ts []*Tenant, fn func(context.Context, *Tenant)) {
	sem := make(chan struct{}, fanout)
	var wg sync.WaitGroup
	for _, t := range ts {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(t *Tenant) {
			defer func() { <-sem; wg.Done() }()
			fn(ctx, t)
		}(t)
	}
	wg.Wait()
}

// onePlatformReplica runs fn on the central replica that holds the
// advisory lock key; the others skip this round.
func (s *Server) onePlatformReplica(ctx context.Context, key int64, fn func(context.Context)) {
	conn, err := s.store.Pool().Acquire(ctx)
	if err != nil {
		return
	}
	defer conn.Release()
	var got bool
	if conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&got); !got {
		return
	}
	defer conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, key)
	fn(ctx)
}
