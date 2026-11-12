package cloudapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestCostReaders(t *testing.T) {
	srv := fake(t, map[string]func(http.ResponseWriter, *http.Request, []byte){
		"sts.amazonaws.com/": func(w http.ResponseWriter, r *http.Request, b []byte) {
			io.WriteString(w, `<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>AK</AccessKeyId><SecretAccessKey>SK</SecretAccessKey><SessionToken>ST</SessionToken></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`)
		},
		"ce.us-east-1.amazonaws.com/": func(w http.ResponseWriter, r *http.Request, b []byte) {
			if r.Header.Get("X-Amz-Target") != "AWSInsightsIndexService.GetCostAndUsage" || !strings.Contains(r.Header.Get("Authorization"), "/us-east-1/ce/aws4_request") {
				t.Errorf("ce call: %v", r.Header)
			}
			var in map[string]any
			json.Unmarshal(b, &in)
			if tp := in["TimePeriod"].(map[string]any); tp["Start"] != "2026-10-01" || tp["End"] != "2026-12-01" {
				t.Errorf("period %v", tp)
			}
			io.WriteString(w, `{"ResultsByTime":[{"TimePeriod":{"Start":"2026-10-01"},"Groups":[
				{"Keys":["srustiops-bu$payments","srustiops-stack$pay-net"],"Metrics":{"UnblendedCost":{"Amount":"12.5","Unit":"USD"}}},
				{"Keys":["srustiops-bu$","srustiops-stack$"],"Metrics":{"UnblendedCost":{"Amount":"3","Unit":"USD"}}}]}]}`)
		},
		"login.microsoftonline.com/t1/oauth2/v2.0/token": func(w http.ResponseWriter, r *http.Request, b []byte) {
			io.WriteString(w, `{"access_token":"arm"}`)
		},
		"management.azure.com/subscriptions/s1/providers/Microsoft.CostManagement/query": func(w http.ResponseWriter, r *http.Request, b []byte) {
			if !strings.Contains(string(b), `"name":"srustiops-stack"`) {
				t.Errorf("azure body %s", b)
			}
			io.WriteString(w, `{"properties":{"columns":[{"name":"Cost"},{"name":"BillingMonth"},{"name":"TagKey"},{"name":"TagValue"},{"name":"Currency"}],
				"rows":[[7.25,"2026-11-01T00:00:00","srustiops-stack","az-st","EUR"],[1.0,"2026-11-01T00:00:00","","","EUR"]]}}`)
		},
		"sts.googleapis.com/v1/token":    func(w http.ResponseWriter, r *http.Request, b []byte) { io.WriteString(w, `{"access_token":"fed"}`) },
		"iamcredentials.googleapis.com/": func(w http.ResponseWriter, r *http.Request, b []byte) { io.WriteString(w, `{"accessToken":"sa"}`) },
		"bigquery.googleapis.com/bigquery/v2/projects/bill-proj/queries": func(w http.ResponseWriter, r *http.Request, b []byte) {
			if !strings.Contains(string(b), "`bill-proj.billing.gcp_billing_export_v1_X`") || !strings.Contains(string(b), `"value":"acme-1"`) {
				t.Errorf("bq body %s", b)
			}
			io.WriteString(w, `{"jobComplete":true,"rows":[{"f":[{"v":"202611"},{"v":"data"},{"v":"gcp-net"},{"v":"4.5"},{"v":"USD"}]}]}`)
		},
	})
	defer srv.Close()
	c := &Client{Base: srv.URL, Tokens: func(aud string) (string, error) { return "tok-" + aud, nil }}
	from, to := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	ls, err := c.AWSCost(context.Background(), "arn:aws:iam::1:role/read", from, to)
	if err != nil || len(ls) != 2 || ls[0] != (CostLine{Month: "2026-10", BU: "payments", Stack: "pay-net", Amount: 12.5, Currency: "USD"}) || ls[1].BU != "" || ls[1].Amount != 3 {
		t.Fatalf("aws %+v %v", ls, err)
	}
	ls, err = c.AzureCost(context.Background(), "t1", "c1", "s1", from, to)
	if err != nil || len(ls) != 2 || ls[0] != (CostLine{Month: "2026-11", Stack: "az-st", Amount: 7.25, Currency: "EUR"}) || ls[1].Stack != "" {
		t.Fatalf("azure %+v %v", ls, err)
	}
	ls, err = c.GCPCost(context.Background(), "projects/1/locations/global/workloadIdentityPools/p/providers/x", "read@p.iam.gserviceaccount.com", "acme-1", "bill-proj.billing.gcp_billing_export_v1_X", from, to)
	if err != nil || len(ls) != 1 || ls[0] != (CostLine{Month: "2026-11", BU: "data", Stack: "gcp-net", Amount: 4.5, Currency: "USD"}) {
		t.Fatalf("gcp %+v %v", ls, err)
	}
	if _, err := c.GCPCost(context.Background(), "p", "s", "acme-1", "x`; DROP", from, to); err == nil {
		t.Fatal("a bad table name was used in a query")
	}
}
