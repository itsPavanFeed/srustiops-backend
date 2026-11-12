package spec

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/itsPavanFeed/srustiops-backend/internal/catalog"
)

// An adopted bucket without a policy or versioning keeps its baseline gaps in
// the contract, and the generated module stops creating those parts; only
// the gaps the kind declares are accepted.
func TestBaselineGapsOfAdoptedBucket(t *testing.T) {
	cat, err := catalog.Load("../../../srustiops-modules/catalog")
	if err != nil {
		t.Skipf("modules repo not available: %v", err)
	}
	stack := func(gaps string) *Stack {
		var st Stack
		raw := `{"modules":[{"name":"logs","kind":"S3Bucket","inputs":{"bucket":"acme-logs-dev"},"baseline_gaps":` + gaps + `}]}`
		if err := json.Unmarshal([]byte(raw), &st); err != nil {
			t.Fatal(err)
		}
		return &st
	}
	ok := stack(`{"attach_deny_insecure_transport_policy":false,"attach_require_latest_tls_policy":false,"versioning":{}}`)
	if err := ok.Validate(cat, "aws"); err != nil {
		t.Fatalf("declared gaps refused: %v", err)
	}
	g, err := ok.Generate(cat, GenerateInput{StackName: "s", Environment: "e", Cloud: awsOIDC, TofuVersion: "1.13.2"})
	if err != nil {
		t.Fatal(err)
	}
	code := string(g.Files["main.tf"])
	for _, want := range []string{"attach_deny_insecure_transport_policy = false", "attach_require_latest_tls_policy      = false", "baseline gaps (adopted as they exist)"} {
		if !strings.Contains(code, want) {
			t.Errorf("generated code lacks %q:\n%s", want, code)
		}
	}
	for _, bad := range []string{
		`{"attach_deny_insecure_transport_policy":"no"}`, // a value the kind does not declare
		`{"object_lock_enabled":false}`,                  // no rule of the kind sets it
		`{"sse_algorithm":"AES256"}`,
	} {
		if err := stack(bad).Validate(cat, "aws"); err == nil || !strings.Contains(err.Error(), "baseline gap") {
			t.Errorf("gap %s accepted: %v", bad, err)
		}
	}
}
