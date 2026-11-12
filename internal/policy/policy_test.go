package policy

import "testing"

func TestPolicy(t *testing.T) {
	lim := Limits{MaxDestroys: 1}
	ok := Evaluate(Summary{Add: 1, Resources: []ResourceChange{{Address: "random_string.x", Type: "random_string", Actions: []string{"create"}}}}, lim)
	if !ok.Passed {
		t.Fatal(ok)
	}
	cases := map[string]Summary{
		"too many destroys": {Destroy: 2},
		"static key":        {Add: 1, Resources: []ResourceChange{{Type: "aws_iam_access_key", Actions: []string{"create"}}}},
		"open ingress":      {Add: 1, Resources: []ResourceChange{{Type: "aws_vpc_security_group_ingress_rule", Actions: []string{"create"}, After: map[string]any{"cidr_ipv4": "0.0.0.0/0"}}}},
		"public bucket":     {Add: 1, Resources: []ResourceChange{{Type: "aws_s3_bucket_public_access_block", Actions: []string{"create"}, After: map[string]any{"block_public_acls": false}}}},
		"gcs public":        {Add: 1, Resources: []ResourceChange{{Type: "google_storage_bucket", Actions: []string{"create"}, After: map[string]any{"public_access_prevention": "inherited"}}}},
	}
	for name, s := range cases {
		if Evaluate(s, lim).Passed {
			t.Errorf("%s: expected a hard violation", name)
		}
	}
	if Evaluate(Summary{Destroy: 5}, Limits{Destroying: true, AllowDestroy: true}).Passed != true {
		t.Error("allowed destroy runs are not subject to the per-run limit")
	}
	if Evaluate(Summary{Destroy: 5}, Limits{Destroying: true}).Passed {
		t.Error("destroy must be blocked when the environment disallows it")
	}
}

func TestImportThatDestroys(t *testing.T) {
	r := Evaluate(Summary{Replace: 1, Imports: 1, Resources: []ResourceChange{{Address: "a", Type: "random_string", Actions: []string{"delete", "create"}, Importing: true}}}, Limits{MaxDestroys: 10})
	if r.Passed || r.Violations[0].Rule != "import-zero-diff" {
		t.Fatalf("an import that destroys the adopted resource must be blocked: %+v", r)
	}
}

func TestCreateAndImportLimits(t *testing.T) {
	s := Summary{Add: 5, Imports: 3}
	if r := Evaluate(s, Limits{MaxCreates: 4, MaxImports: 3}); r.Passed || len(r.Violations) != 1 || r.Violations[0].Rule != "create-limit" {
		t.Fatalf("%+v", r)
	}
	if r := Evaluate(s, Limits{MaxImports: 2}); r.Passed || r.Violations[0].Rule != "import-limit" {
		t.Fatalf("%+v", r)
	}
	if r := Evaluate(s, Limits{}); !r.Passed {
		t.Fatalf("0 means no limit: %+v", r)
	}
}

func TestZeroDiffGate(t *testing.T) {
	clean := Summary{Imports: 2, Resources: []ResourceChange{
		{Address: "module.b.aws_s3_bucket.this[0]", Type: "aws_s3_bucket", Actions: []string{"import"}, Importing: true},
		{Address: "module.b.aws_s3_bucket_versioning.this[0]", Type: "aws_s3_bucket_versioning", Actions: []string{"import"}, Importing: true},
	}}
	if r := Evaluate(clean, Limits{MaxDestroys: 5}); !r.Passed {
		t.Fatalf("a pure import must pass: %+v", r.Violations)
	}
	for name, extra := range map[string]ResourceChange{
		"update on import": {Address: "module.b.aws_s3_bucket.this[0]", Actions: []string{"update"}, Importing: true, Diff: []AttrDiff{{Path: "tags", Live: map[string]any{}, Code: map[string]any{"team": "x"}}}},
		"replace":          {Address: "module.b.random_string.main", Actions: []string{"delete", "create"}, Importing: true},
		"extra create":     {Address: "module.b.aws_s3_bucket_policy.this[0]", Actions: []string{"create"}},
	} {
		s := clean
		s.Resources = append(append([]ResourceChange{}, clean.Resources...), extra)
		r := Evaluate(s, Limits{MaxDestroys: 5})
		found := false
		for _, v := range r.Violations {
			found = found || v.Rule == "import-zero-diff" && v.Level == "hard" && v.Address == extra.Address
		}
		if r.Passed || !found {
			t.Errorf("%s: the zero-diff gate did not block: %+v", name, r.Violations)
		}
	}
	// Without imports the gate does not apply.
	if r := Evaluate(Summary{Change: 1, Resources: []ResourceChange{{Address: "a.b", Actions: []string{"update"}}}}, Limits{MaxDestroys: 5}); !r.Passed {
		t.Fatalf("ordinary update blocked: %+v", r.Violations)
	}
}

func TestZeroDiffGateOwnershipLabels(t *testing.T) {
	gate := func(diff []AttrDiff, actions ...string) int {
		s := Summary{Imports: 1, Resources: []ResourceChange{{Address: "module.b.aws_s3_bucket.this[0]", Type: "aws_s3_bucket", Actions: actions, Importing: true, Diff: diff}}}
		n := 0
		for _, v := range Evaluate(s, Limits{}).Violations {
			if v.Rule == "import-zero-diff" {
				n++
			}
		}
		return n
	}
	owner := []AttrDiff{{Path: "tags_all", Live: map[string]any{"team": "a"}, Code: map[string]any{"team": "a", "managed-by": "srustiops", "srustiops-stack": "s"}}}
	if n := gate(owner, "update"); n != 0 {
		t.Fatalf("adding ownership labels on import must pass the gate, got %d violations", n)
	}
	other := []AttrDiff{{Path: "tags", Live: map[string]any{"team": "a"}, Code: map[string]any{"team": "b", "managed-by": "srustiops"}}}
	if n := gate(other, "update"); n != 1 {
		t.Fatalf("a changed user tag must be blocked")
	}
	mixed := append(owner, AttrDiff{Path: "force_destroy", Live: false, Code: true})
	if n := gate(mixed, "update"); n != 1 {
		t.Fatalf("other attributes must be blocked")
	}
	unknown := []AttrDiff{{Path: "tags_all", Live: map[string]any{}, Code: "(known after apply)"}}
	if n := gate(unknown, "update"); n != 1 {
		t.Fatalf("unknown labels must be blocked")
	}
	if n := gate(owner, "delete", "create"); n != 1 {
		t.Fatalf("a replacement is never allowed")
	}
}
