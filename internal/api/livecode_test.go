package api

import "testing"

func TestAddrMatches(t *testing.T) {
	for _, c := range []struct {
		pattern, addr string
		want          bool
	}{
		{"aws_s3_bucket.this[0]", "aws_s3_bucket.this[0]", true},
		{"aws_s3_bucket.this[0]", "aws_s3_bucket.this[1]", false},
		{`google_storage_bucket.buckets["{{name}}"]`, `google_storage_bucket.buckets["logs"]`, true},
		{`google_storage_bucket.buckets["{{name}}"]`, `google_storage_bucket.other["logs"]`, false},
		{`google_storage_bucket.buckets["{{name}}"]`, `google_storage_bucket.buckets["a"].x`, false},
	} {
		if got := addrMatches(c.pattern, c.addr); got != c.want {
			t.Errorf("addrMatches(%q, %q) = %v", c.pattern, c.addr, got)
		}
	}
	if i, in, ok := splitModuleAddr("module.orders.aws_s3_bucket.this[0]"); !ok || i != "orders" || in != "aws_s3_bucket.this[0]" {
		t.Fatalf("split: %q %q %v", i, in, ok)
	}
}
