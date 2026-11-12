package cloudapi

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// AWS's published SigV4 test suite, case "get-vanilla".
func TestSigV4MatchesAWSTestSuite(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.amazonaws.com/", nil)
	now, _ := time.Parse("20060102T150405Z", "20150830T123600Z")
	sigv4(req, nil, &awsCreds{AccessKey: "AKIDEXAMPLE", Secret: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}, "us-east-1", "service", now)
	want := "Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
	if got := req.Header.Get("Authorization"); !strings.HasSuffix(got, want) {
		t.Fatalf("authorization:\n got  %s\n want ...%s", got, want)
	}
}
