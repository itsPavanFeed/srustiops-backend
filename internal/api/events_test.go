package api

import (
	"encoding/base64"
	"testing"

	"github.com/itsPavanFeed/srustiops-backend/internal/spec"
)

func TestParseAWSEvent(t *testing.T) {
	body := []byte(`{"detail-type":"AWS API Call via CloudTrail","time":"2026-10-25T10:00:00Z","resources":[],
	  "detail":{"eventName":"PutBucketTagging","eventSource":"s3.amazonaws.com","readOnly":false,
	    "userIdentity":{"arn":"arn:aws:sts::123456789012:assumed-role/ops-admin/jane"},"requestParameters":{"bucketName":"acme-logs"}}}`)
	evs, err := parseAWS(body)
	if err != nil || len(evs) != 1 || evs[0].Action != "update" || evs[0].Resources[0] != "arn:aws:s3:::acme-logs" || evs[0].Actor == "" {
		t.Fatalf("%+v %v", evs, err)
	}
	for _, ro := range []string{`{"detail":{"eventName":"GetBucketTagging","eventSource":"s3.amazonaws.com","requestParameters":{"bucketName":"x"}}}`,
		`{"detail":{"eventName":"PutBucketTagging","readOnly":true,"requestParameters":{"bucketName":"x"}}}`,
		`{"detail":{"eventName":"PutBucketTagging","errorCode":"AccessDenied","requestParameters":{"bucketName":"x"}}}`} {
		if evs, _ := parseAWS([]byte(ro)); len(evs) != 0 {
			t.Fatalf("read-only or failed calls are not changes: %s", ro)
		}
	}
	c := &spec.Cloud{Provider: "aws", AWS: &spec.AWSCloud{RoleARN: "arn:aws:iam::123456789012:role/srustiops-deployer", PlanRoleARN: "arn:aws:iam::123456789012:role/srustiops-reader"}}
	if !platformActor(c, "arn:aws:sts::123456789012:assumed-role/srustiops-deployer/srustiops-apply-x", nil) || platformActor(c, "arn:aws:sts::123456789012:assumed-role/ops-admin/jane", nil) {
		t.Fatal("only the connection's own roles are the platform")
	}
}

func TestParseGCPEvent(t *testing.T) {
	entry := `{"timestamp":"2026-10-25T10:00:00Z","protoPayload":{"serviceName":"storage.googleapis.com","methodName":"storage.buckets.update","resourceName":"projects/_/buckets/b1","authenticationInfo":{"principalEmail":"jane@acme.test"}}}`
	body := []byte(`{"message":{"data":"` + base64.StdEncoding.EncodeToString([]byte(entry)) + `"},"subscription":"s"}`)
	evs, err := parseGCP(body)
	if err != nil || len(evs) != 1 || evs[0].Resources[0] != "//storage.googleapis.com/projects/_/buckets/b1" || evs[0].Action != "update" {
		t.Fatalf("%+v %v", evs, err)
	}
}

func TestParseAzureEvent(t *testing.T) {
	evs, hs, err := parseAzure([]byte(`[{"eventType":"Microsoft.EventGrid.SubscriptionValidationEvent","data":{"validationCode":"abc"}}]`))
	if err != nil || hs.(map[string]string)["validationResponse"] != "abc" || evs != nil {
		t.Fatalf("handshake: %v %v", hs, err)
	}
	evs, _, err = parseAzure([]byte(`[{"eventType":"Microsoft.Resources.ResourceDeleteSuccess","subject":"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/st","data":{"resourceUri":"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/st","operationName":"Microsoft.Storage/storageAccounts/delete","claims":{"appid":"app-1"}}}]`))
	if err != nil || len(evs) != 1 || evs[0].Action != "delete" || evs[0].Actor != "app-1" {
		t.Fatalf("%+v %v", evs, err)
	}
}
