package spec

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestStackRefs(t *testing.T) {
	raw := []byte(`{"modules":[{"name":"db","kind":"RDSDatabase","inputs":{
		"vpc_security_group_ids":[{"$ref":"stack/app-sg/sg.id"},"sg-0123456789abcdef0"],
		"subnet_ids":{"$ref":"stack/network/vpc.private_subnets"},
		"engine":"postgres"}},
		{"name":"logs","kind":"S3Bucket","baseline_gaps":{"server_side_encryption_configuration":{"rule":{"apply_server_side_encryption_by_default":{"sse_algorithm":"aws:kms","kms_master_key_id":{"$ref":"stack/keys/key.key_arn"}}}}}}]}`)
	refs, err := StackRefs(raw)
	if err != nil || len(refs) != 3 {
		t.Fatalf("refs: %v %v", refs, err)
	}
	if got := strings.Join(DependsOn(raw), ","); got != "app-sg,keys,network" {
		t.Fatalf("depends on: %s", got)
	}
	values := map[string]string{"stack/app-sg/sg.id": `"sg-0aaaaaaaaaaaaaaaa"`, "stack/network/vpc.private_subnets": `["subnet-01","subnet-02"]`}
	out, errs := ResolveStackRefs(raw, func(r StackRef) (json.RawMessage, error) {
		if v, ok := values[r.String()]; ok {
			return json.RawMessage(v), nil
		}
		return nil, errors.New("not applied yet")
	})
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "stack/keys/key.key_arn") {
		t.Fatalf("unresolved: %v", errs)
	}
	s := string(out)
	for _, want := range []string{`"sg-0aaaaaaaaaaaaaaaa","sg-0123456789abcdef0"`, `"subnet_ids":["subnet-01","subnet-02"]`, `"stack/keys/key.key_arn"`} {
		if !strings.Contains(s, want) {
			t.Fatalf("resolved spec lacks %s:\n%s", want, s)
		}
	}
}
