package api

import (
	"encoding/json"
	"testing"

	"github.com/itsPavanFeed/srustiops-backend/internal/catalog"
)

// The S3 live rules turn the live settings of an imported bucket (as the plan
// reports them) into the module arguments that reproduce them.
func TestS3LiveRulesReproduceTheBucket(t *testing.T) {
	cat, err := catalog.Load("../../../srustiops-modules/catalog")
	if err != nil {
		t.Skipf("modules repo not available: %v", err)
	}
	rules := cat.Kind("S3Bucket").Adopt.Live
	var sse, ver catalog.LiveRule
	for _, r := range rules {
		switch {
		case r.Resource == "aws_s3_bucket_server_side_encryption_configuration.this[0]":
			sse = r
		case r.Resource == "aws_s3_bucket_versioning.this[0]" && r.DropImport:
			ver = r
		}
	}
	var live map[string]any
	json.Unmarshal([]byte(`{"rule":[{"blocked_encryption_types":["SSE-C"],"bucket_key_enabled":true,
		"apply_server_side_encryption_by_default":[{"kms_master_key_id":"","sse_algorithm":"AES256"}]}]}`), &live)
	got, ok := fillLive(sse.Gaps, live)
	b, _ := json.Marshal(got)
	want := `{"server_side_encryption_configuration":{"rule":{"apply_server_side_encryption_by_default":{"kms_master_key_id":"","sse_algorithm":"AES256"},"blocked_encryption_types":["SSE-C"],"bucket_key_enabled":true}}}`
	if !ok || string(b) != want {
		t.Fatalf("encryption gaps:\n got  %s\n want %s", b, want)
	}

	json.Unmarshal([]byte(`{"versioning_configuration":[{"mfa_delete":"Disabled","status":"Disabled"}]}`), &live)
	if !liveMatches(live, ver.When) || !ver.DropImport {
		t.Fatal("never-versioned bucket: the versioning import must be dropped")
	}
	json.Unmarshal([]byte(`{"versioning_configuration":[{"status":"Suspended"}]}`), &live)
	if liveMatches(live, ver.When) {
		t.Fatal("suspended versioning is expressible and must stay imported")
	}
	// Hidden live values are never guessed.
	if _, ok := fillLive(sse.Gaps, map[string]any{"rule": "(sensitive)"}); ok {
		t.Fatal("filled a gap from a sensitive value")
	}
}
