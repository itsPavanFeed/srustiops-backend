package runner

import (
	"reflect"
	"testing"
)

func TestMissingImportsFromPlanOutput(t *testing.T) {
	out := `
Error: Cannot import non-existent remote object

While attempting to import an existing object to
"module.iac_resources_srustiops.aws_s3_bucket_policy.this[0]", the provider
detected that no object exists with the given id or identity.

Error: Cannot import non-existent remote object

While attempting to import an existing object to
"module.iac_resources_srustiops.aws_s3_bucket_versioning.this[0]", the provider
detected that no object exists with the given id or identity.
`
	want := []string{"module.iac_resources_srustiops.aws_s3_bucket_policy.this[0]", "module.iac_resources_srustiops.aws_s3_bucket_versioning.this[0]"}
	if got := missingImports(out); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
	if got := missingImports("Error: Invalid provider configuration"); len(got) != 0 {
		t.Fatalf("other errors: %v", got)
	}
}

// OpenTofu mirrors a value's shape in before_sensitive ({} or [{}]) even when
// nothing is sensitive: such values must reach the gate as they are.
func TestDiffShowsValuesWithMirroredSensitivity(t *testing.T) {
	live := map[string]any{"tags_all": map[string]any{}, "rule": []any{map[string]any{"bucket_key_enabled": true, "secret": "x"}}}
	liveSens := map[string]any{"tags_all": map[string]any{}, "rule": []any{map[string]any{"secret": true}}}
	code := map[string]any{"tags_all": map[string]any{"managed-by": "srustiops"}, "rule": []any{map[string]any{"bucket_key_enabled": false}}}
	diffs := attrDiffs(live, liveSens, code, map[string]any{}, map[string]any{})
	got := map[string]any{}
	for _, d := range diffs {
		got[d.Path] = d.Live
	}
	if !reflect.DeepEqual(got["tags_all"], map[string]any{}) {
		t.Fatalf("tags_all hidden: %v", got["tags_all"])
	}
	if !reflect.DeepEqual(got["rule"], []any{map[string]any{"bucket_key_enabled": true}}) {
		t.Fatalf("rule: want the non-sensitive part only, got %v", got["rule"])
	}
}
