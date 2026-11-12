package policy

import "testing"

// A contract matched to the live resources (live -> code) is held to the
// zero-diff gate even when nothing is imported, e.g. to resolve drift.
func TestZeroDiffGateForLiveToCodeCandidates(t *testing.T) {
	changed := Summary{Change: 1, Resources: []ResourceChange{{Address: "module.logs.aws_s3_bucket.this[0]", Type: "aws_s3_bucket", Actions: []string{"update"},
		Diff: []AttrDiff{{Path: "tags", Live: map[string]any{"team": "a"}, Code: map[string]any{"team": "b"}}}}}}
	if r := Evaluate(changed, Limits{}); !r.Passed {
		t.Fatalf("an ordinary change was blocked: %+v", r.Violations)
	}
	r := Evaluate(changed, Limits{ZeroDiff: true})
	if r.Passed || len(r.Violations) == 0 || r.Violations[0].Rule != "import-zero-diff" {
		t.Fatalf("a live -> code candidate that still changes something passed: %+v", r)
	}
	if r := Evaluate(Summary{Resources: []ResourceChange{}}, Limits{ZeroDiff: true}); !r.Passed {
		t.Fatalf("a matching candidate was blocked: %+v", r.Violations)
	}
}
