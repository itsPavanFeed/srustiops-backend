package central

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestWaveOf(t *testing.T) {
	slugs := []string{}
	for i := 0; i < 20; i++ {
		slugs = append(slugs, fmt.Sprintf("w%02d", i))
	}
	w := waveOf([]fleetWave{{Name: "canary", Tenants: []string{"w07"}}, {Name: "a quarter", Percent: 25}, {Name: "rest", Percent: 100}}, slugs)
	count := map[int]int{}
	for _, s := range slugs {
		count[w[s]]++
	}
	if w["w07"] != 0 || count[0] != 1 || count[1] != 5 || count[2] != 14 {
		t.Fatalf("waves: %v", count)
	}
	again := waveOf([]fleetWave{{Name: "canary", Tenants: []string{"w07"}}, {Name: "a quarter", Percent: 25}, {Name: "rest", Percent: 100}}, slugs)
	for _, s := range slugs {
		if again[s] != w[s] {
			t.Fatal("wave assignment is not stable")
		}
	}
}

func TestRolloutStep(t *testing.T) {
	now := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	r := &Rollout{ID: "r", Version: "0.4.0", Status: "running", SoakMinutes: 30, WaveStartedAt: now,
		Waves: []fleetWave{{Name: "canary", Tenants: []string{"acme"}}, {Name: "everyone", Percent: 100}}}
	ms := []fleetMember{{Slug: "acme", Version: "0.3.0"}, {Slug: "globex", Version: "0.3.0"}, {Slug: "initech", Version: "0.3.0"}}
	set := func(ch map[string]string) {
		for i := range ms {
			if v, ok := ch[ms[i].Slug]; ok {
				ms[i].Desired = v
			}
		}
	}
	ch := rolloutStep(r, ms, now)
	if len(ch) != 1 || ch["acme"] != "0.4.0" || r.CurrentWave != 0 {
		t.Fatalf("canary first: %v wave %d", ch, r.CurrentWave)
	}
	set(ch)
	if ch := rolloutStep(r, ms, now.Add(time.Minute)); len(ch) != 0 || !strings.Contains(r.Detail, "0 of 1") {
		t.Fatalf("waiting for the canary: %v %q", ch, r.Detail)
	}
	ms[0].Version = "0.4.0" // the canary upgraded
	rolloutStep(r, ms, now.Add(2*time.Minute))
	if r.WaveDoneAt == nil || r.CurrentWave != 0 || !strings.Contains(r.Detail, "soaking") {
		t.Fatalf("soak: %+v", r)
	}
	ch = rolloutStep(r, ms, now.Add(33*time.Minute))
	if r.CurrentWave != 1 || len(ch) != 2 || ch["globex"] != "0.4.0" {
		t.Fatalf("next wave after the soak: wave %d %v", r.CurrentWave, ch)
	}
	set(ch)
	// The next wave stalls a day: the rollout pauses.
	rolloutStep(r, ms, now.Add(33*time.Minute+25*time.Hour))
	if r.Status != "paused" || !strings.Contains(r.Detail, "after a day") {
		t.Fatalf("stall: %+v", r)
	}
	if ch := rolloutStep(r, ms, now.Add(26*time.Hour)); len(ch) != 0 {
		t.Fatal("a paused rollout changes nothing")
	}
	r.Status, r.WaveStartedAt = "running", now.Add(26*time.Hour)
	ms[1].Version, ms[2].Version = "0.4.0", "0.4.0"
	rolloutStep(r, ms, now.Add(27*time.Hour))
	rolloutStep(r, ms, now.Add(28*time.Hour))
	if r.Status != "done" {
		t.Fatalf("done: %+v", r)
	}
}
