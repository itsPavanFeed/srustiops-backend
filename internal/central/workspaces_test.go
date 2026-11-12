package central

import (
	"testing"
	"time"
)

func TestStaleWorkspaces(t *testing.T) {
	old, recent := time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour)
	cases := []struct {
		name   string
		t      Tenant
		online bool
		want   bool
	}{
		{"never connected for two days", Tenant{Connectivity: "tunnel", CreatedAt: old}, false, true},
		{"just created", Tenant{Connectivity: "tunnel", CreatedAt: recent}, false, false},
		{"offline an hour", Tenant{Connectivity: "tunnel", CreatedAt: old, LinkSeenAt: &recent}, false, false},
		{"offline two days", Tenant{Connectivity: "tunnel", CreatedAt: old, LinkSeenAt: &old}, false, true},
		{"online", Tenant{Connectivity: "tunnel", CreatedAt: old, LinkSeenAt: &old}, true, false},
		{"direct", Tenant{Connectivity: "direct", CreatedAt: old}, false, false},
	}
	for _, c := range cases {
		if got := stale(&c.t, c.online); got != c.want {
			t.Errorf("%s: stale = %v, want %v", c.name, got, c.want)
		}
	}
}
