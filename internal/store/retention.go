package store

import (
	"context"
	"fmt"
)

// Retention: how long this plane keeps what grows with use. Zero keeps
// everything. The audit log is append-only and never pruned here (export it
// to a SIEM); run records, approvals and the latest state are always kept.
type Retention struct {
	NotificationsDays     int `json:"notifications_days"`
	CloudEventsDays       int `json:"cloud_events_days"`
	WebhookDeliveriesDays int `json:"webhook_deliveries_days"`
	InventoryScansKeep    int `json:"inventory_scans_keep"` // per connection
	RunLogsDays           int `json:"run_logs_days"`        // logs kept in the database (no bucket)
	StateVersionsKeep     int `json:"state_versions_keep"`  // per stack, newest first
}

func DefaultRetention() Retention {
	return Retention{NotificationsDays: 90, CloudEventsDays: 90, WebhookDeliveriesDays: 30, InventoryScansKeep: 20, RunLogsDays: 180, StateVersionsKeep: 100}
}

// Prune deletes what is past retention, a batch at a time, and returns how
// many rows went per kind and the bucket objects of deleted state versions
// (for the caller to delete).
func (s *Store) Prune(ctx context.Context, r Retention) (map[string]int64, []string, error) {
	out := map[string]int64{}
	days := func(n int) string { return fmt.Sprintf("%d days", n) }
	run := func(kind, q string, args ...any) error {
		tag, err := s.db.Exec(ctx, q, args...)
		if err != nil {
			return fmt.Errorf("pruning %s: %w", kind, err)
		}
		out[kind] += tag.RowsAffected()
		return nil
	}
	if r.NotificationsDays > 0 {
		if err := run("notifications", `DELETE FROM notifications WHERE id IN (SELECT id FROM notifications WHERE created_at < now() - $1::interval LIMIT 50000)`, days(r.NotificationsDays)); err != nil {
			return out, nil, err
		}
	}
	if r.CloudEventsDays > 0 {
		if err := run("cloud_events", `DELETE FROM cloud_events WHERE id IN (SELECT id FROM cloud_events WHERE received_at < now() - $1::interval LIMIT 50000)`, days(r.CloudEventsDays)); err != nil {
			return out, nil, err
		}
	}
	if r.WebhookDeliveriesDays > 0 {
		if err := run("webhook_deliveries", `DELETE FROM webhook_deliveries WHERE id IN (SELECT id FROM webhook_deliveries WHERE received_at < now() - $1::interval LIMIT 50000)`, days(r.WebhookDeliveriesDays)); err != nil {
			return out, nil, err
		}
	}
	if r.InventoryScansKeep > 0 {
		if err := run("inventory_scans", `DELETE FROM inventory_scans WHERE id IN (SELECT id FROM (SELECT id, status,
			row_number() OVER (PARTITION BY connection_id ORDER BY started_at DESC) AS n FROM inventory_scans) x WHERE n > $1 AND status <> 'running')`, r.InventoryScansKeep); err != nil {
			return out, nil, err
		}
	}
	if r.RunLogsDays > 0 {
		if err := run("run_logs", `DELETE FROM run_logs WHERE run_id IN (SELECT id FROM runs WHERE NOT logs_archived AND finished_at < now() - $1::interval LIMIT 5000)`, days(r.RunLogsDays)); err != nil {
			return out, nil, err
		}
	}
	var objects []string
	if r.StateVersionsKeep > 0 {
		rows, err := s.db.Query(ctx, `DELETE FROM state_versions v USING (SELECT stack_id, serial FROM (SELECT stack_id, serial,
			row_number() OVER (PARTITION BY stack_id ORDER BY serial DESC) AS n FROM state_versions) x WHERE n > $1 LIMIT 5000) old
			WHERE v.stack_id = old.stack_id AND v.serial = old.serial RETURNING COALESCE(v.object_key, '')`, r.StateVersionsKeep)
		if err != nil {
			return out, nil, fmt.Errorf("pruning state versions: %w", err)
		}
		for rows.Next() {
			var k string
			rows.Scan(&k)
			out["state_versions"]++
			if k != "" {
				objects = append(objects, k)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return out, nil, err
		}
		// Objects are content-addressed: one still used by a kept version stays.
		if len(objects) > 0 {
			kept := map[string]bool{}
			r2, err := s.db.Query(ctx, `SELECT object_key FROM state_versions WHERE object_key = ANY($1)`, objects)
			if err == nil {
				for r2.Next() {
					var k string
					r2.Scan(&k)
					kept[k] = true
				}
				r2.Close()
			}
			free := objects[:0]
			for _, k := range objects {
				if !kept[k] {
					free = append(free, k)
				}
			}
			objects = free
		}
	}
	return out, objects, nil
}
