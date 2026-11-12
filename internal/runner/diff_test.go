package runner

import "testing"

func TestSummarizeDiffs(t *testing.T) {
	plan := []byte(`{
	  "resource_changes": [
	    {"address": "module.b.aws_s3_bucket.this[0]", "type": "aws_s3_bucket", "mode": "managed",
	     "change": {"actions": ["update"], "importing": {"id": "b"},
	       "before": {"bucket": "b", "tags": {"team": "ops"}, "force_destroy": false, "arn": "arn:x", "policy": "secret"},
	       "before_sensitive": {"policy": true},
	       "after": {"bucket": "b", "tags": {"team": "payments"}, "force_destroy": false, "policy": "other"},
	       "after_sensitive": {"policy": true}, "after_unknown": {"arn": true}}}
	  ],
	  "resource_drift": [
	    {"address": "module.b.aws_s3_bucket.this[0]", "type": "aws_s3_bucket", "mode": "managed",
	     "change": {"actions": ["update"], "before": {"tags": {"team": "payments"}}, "after": {"tags": {"team": "ops"}}}}
	  ]
	}`)
	s, err := Summarize(plan)
	if err != nil {
		t.Fatal(err)
	}
	d := map[string][2]any{}
	for _, x := range s.Resources[0].Diff {
		d[x.Path] = [2]any{x.Live, x.Code}
	}
	if len(d) != 3 || d["tags"][0].(map[string]any)["team"] != "ops" || d["policy"][0] != "(sensitive)" || d["arn"][1] != "(known after apply)" {
		t.Fatalf("diff = %+v", s.Resources[0].Diff)
	}
	if _, same := d["bucket"]; same {
		t.Fatal("unchanged attributes must not be listed")
	}
	dr := s.Drift[0].Diff
	if len(dr) != 1 || dr[0].Live.(map[string]any)["team"] != "ops" || dr[0].Code.(map[string]any)["team"] != "payments" {
		t.Fatalf("drift diff must show the refreshed value as live: %+v", dr)
	}
}
