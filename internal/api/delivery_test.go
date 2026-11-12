package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/opapolicy"
	"github.com/itsPavanFeed/srustiops-backend/internal/store"
)

func TestPolicyLibraryCompilesAndFires(t *testing.T) {
	input := func(res ...map[string]any) map[string]any {
		rs := []any{}
		for _, r := range res {
			rs = append(rs, r)
		}
		return map[string]any{
			"run":     map[string]any{"environment": "prod", "tier": "prod", "region": "us-east-1"},
			"summary": map[string]any{"resources": rs},
			"cost":    map[string]any{"monthly_delta_usd": 900.0},
		}
	}
	cases := map[string]struct {
		in   map[string]any
		want string // substring of a violation; "" = none
	}{
		"required-tags": {input(map[string]any{"address": "module.b.aws_s3_bucket.this", "type": "aws_s3_bucket", "actions": []any{"create"},
			"after": map[string]any{"tags": map[string]any{"owner": "x"}, "tags_all": map[string]any{"owner": "x"}}}), "cost-center"},
		"encryption-at-rest": {input(map[string]any{"address": "v", "type": "aws_ebs_volume", "actions": []any{"create"}, "after": map[string]any{"encrypted": false}}), "must be encrypted"},
		"no-public-access": {input(map[string]any{"address": "sg", "type": "aws_security_group", "actions": []any{"create"},
			"after": map[string]any{"ingress": []any{map[string]any{"from_port": 22, "to_port": 22, "cidr_blocks": []any{"0.0.0.0/0"}}}}}), "22-22"},
		"allowed-regions":        {input(), "us-east-1"},
		"allowed-instance-types": {input(map[string]any{"address": "i", "type": "aws_instance", "actions": []any{"create"}, "after": map[string]any{"instance_type": "m5.24xlarge"}}), "m5.24xlarge"},
		"no-destroy-in-prod":     {input(map[string]any{"address": "d", "type": "aws_sqs_queue", "actions": []any{"delete"}, "after": nil}), "deleted in production"},
		"monthly-cost-limit":     {input(), "adds about $900 a month, above the $500 limit"},
		"bu-budget": {func() map[string]any {
			in := input()
			in["run"].(map[string]any)["bu"] = "payments"
			in["budget"] = map[string]any{"monthly": 1000.0, "spent": 400.0, "used_pct": 40.0, "forecast": 600.0}
			return in
		}(), "payments is heading for 150% of its 1000 budget this month (400 spent so far)"},
	}
	if len(cases) != len(policyLibrary) {
		t.Fatalf("test every library policy: %d cases, %d policies", len(cases), len(policyLibrary))
	}
	for _, p := range policyLibrary {
		m, probs := renderLibPolicy(p, nil)
		if len(probs) > 0 {
			t.Fatalf("%s: %v", p.ID, probs)
		}
		if err := opapolicy.Compile(m); err != nil {
			t.Fatalf("%s does not compile: %v\n%s", p.ID, err, m)
		}
		c := cases[p.ID]
		vs := opapolicy.Evaluate(context.Background(), []opapolicy.Set{{Name: p.ID, Level: "hard", Module: m}}, c.in)
		var msgs []string
		for _, v := range vs {
			msgs = append(msgs, v.Message)
		}
		if !strings.Contains(strings.Join(msgs, "\n"), c.want) {
			t.Errorf("%s: want a violation with %q, got %v", p.ID, c.want, msgs)
		}
		// A clean plan passes.
		if vs := opapolicy.Evaluate(context.Background(), []opapolicy.Set{{Name: p.ID, Level: "hard", Module: m}},
			map[string]any{"run": map[string]any{"tier": "nonprod", "region": "eu-west-1"}, "summary": map[string]any{"resources": []any{}}, "cost": map[string]any{"monthly_delta_usd": 0.0}}); len(vs) > 0 {
			t.Errorf("%s fails an empty plan: %v", p.ID, vs)
		}
	}
}

func TestQuietHours(t *testing.T) {
	q := &quietHours{Start: "22:00", End: "06:00", Timezone: "UTC"}
	at := func(h, m int) time.Time { return time.Date(2026, 11, 11, h, m, 0, 0, time.UTC) }
	for _, c := range []struct {
		t    time.Time
		want bool
	}{{at(23, 0), true}, {at(5, 59), true}, {at(6, 0), false}, {at(12, 0), false}, {at(22, 0), true}} {
		if got := q.quiet(c.t); got != c.want {
			t.Errorf("%s: quiet=%v, want %v", c.t.Format("15:04"), got, c.want)
		}
	}
	day := &quietHours{Start: "09:00", End: "17:00", Timezone: "Asia/Kolkata"}
	if !day.quiet(time.Date(2026, 11, 11, 6, 0, 0, 0, time.UTC)) { // 11:30 IST
		t.Error("11:30 in Kolkata is within 09:00-17:00")
	}
	var none *quietHours
	if none.quiet(time.Now()) {
		t.Error("no quiet hours is never quiet")
	}
	sc := envSchedule{Drift: scheduleItem{Enabled: true}, Quiet: &quietHours{Start: "25:00", End: "06:00", Timezone: "Nowhere/City"}}
	if probs := sc.validate(); len(probs) != 2 || sc.Drift.EveryHours != 24 {
		t.Errorf("validate: %v (every %d)", probs, sc.Drift.EveryHours)
	}
	if j := jitter("abc", 24*time.Hour); j < 0 || j >= 24*time.Hour/10 {
		t.Errorf("jitter out of range: %s", j)
	}
}

func TestPortableAndRetarget(t *testing.T) {
	src := []byte(`{"modules":[{"name":"q","kind":"SQS","inputs":{"vpc":"stack/net-dev/vpc.vpc_id"},"baseline_gaps":{"policy":false}}],"imports":[{"to":"module.q.aws_sqs_queue.this","id":"https://q"}]}`)
	p, err := portableSpec(src)
	if err != nil || strings.Contains(string(p), "imports") || strings.Contains(string(p), "baseline_gaps") {
		t.Fatalf("portable: %s %v", p, err)
	}
	devID, prodID := "d", "p"
	all := []*store.Stack{
		{ID: "n1", Name: "net-dev", EnvironmentID: devID},
		{ID: "n2", Name: "net-prod", EnvironmentID: prodID, ClonedFrom: ptr("n1")},
		{ID: "x", Name: "other-dev", EnvironmentID: devID},
	}
	out, unmapped := retarget(p, all, prodID)
	if !strings.Contains(string(out), `stack/net-prod/vpc.vpc_id`) || len(unmapped) != 0 {
		t.Errorf("retarget: %s %v", out, unmapped)
	}
	out, unmapped = retarget([]byte(`{"a":"stack/other-dev/x.y"}`), all, prodID)
	if string(out) != `{"a":"stack/other-dev/x.y"}` || len(unmapped) != 1 {
		t.Errorf("unmapped refs stay: %s %v", out, unmapped)
	}
	// Promotion keeps the target's own imports and gaps.
	target := []byte(`{"modules":[{"name":"q","baseline_gaps":{"policy":false}}],"imports":[{"to":"module.q.aws_sqs_queue.this","id":"prod-q"},{"to":"module.gone.x.y","id":"z"}]}`)
	kept := keepLocal(p, target)
	var m map[string]any
	json.Unmarshal(kept, &m)
	if ims := m["imports"].([]any); len(ims) != 1 || !strings.Contains(string(kept), "prod-q") || !strings.Contains(string(kept), "baseline_gaps") {
		t.Errorf("keepLocal: %s", kept)
	}
}
