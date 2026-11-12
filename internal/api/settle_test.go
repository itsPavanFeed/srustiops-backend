package api

import (
	"encoding/json"
	"testing"

	"github.com/itsPavanFeed/srustiops-backend/internal/policy"
)

// Imports a plan did not perform are already in state: they leave the
// contract, so the stack no longer shows them as pending.
func TestWithoutSettledImports(t *testing.T) {
	raw := json.RawMessage(`{"modules":[{"name":"b","kind":"S3Bucket"}],"imports":[
		{"to":"module.b.aws_s3_bucket.this[0]","id":"x"},{"to":"module.b.aws_s3_bucket_versioning.this[0]","id":"x"}]}`)
	sum := &policy.Summary{Resources: []policy.ResourceChange{{Address: "module.b.aws_s3_bucket.this[0]", Importing: true, Actions: []string{"import"}}}}
	out, removed := withoutSettledImports(raw, sum)
	if len(removed) != 1 || removed[0] != "module.b.aws_s3_bucket_versioning.this[0]" {
		t.Fatalf("removed: %v", removed)
	}
	var v struct{ Imports []map[string]string }
	json.Unmarshal(out, &v)
	if len(v.Imports) != 1 || v.Imports[0]["to"] != "module.b.aws_s3_bucket.this[0]" {
		t.Fatalf("kept: %s", out)
	}
	// Nothing imported any more: the imports key goes.
	out, _ = withoutSettledImports(raw, &policy.Summary{})
	var w map[string]json.RawMessage
	json.Unmarshal(out, &w)
	if _, ok := w["imports"]; ok {
		t.Fatalf("imports kept: %s", out)
	}
}
