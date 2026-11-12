package spec

import (
	"strings"
	"testing"
)

func TestVaultModeCredentials(t *testing.T) {
	ok := []string{
		`{"provider":"aws","auth":"vault","aws":{"region":"eu-west-1"},"credentials":{"access_key_id":"vault://kv/c#a","secret_access_key":"vault://kv/c#s"}}`,
		`{"provider":"aws","auth":"vault","aws":{"region":"eu-west-1","role_arn":"arn:aws:iam::123456789012:role/d","external_id":"x-1"},"credentials":{"access_key_id":"vault://kv/c#a","secret_access_key":"vault://kv/c#s"}}`,
		`{"provider":"gcp","auth":"vault","gcp":{"project_id":"acme-prod-1234","region":"europe-west1","service_account_email":""},"credentials":{"service_account_key":"vault://kv/g#key.json"}}`,
		`{"provider":"azure","auth":"vault","azure":{"tenant_id":"00000000-0000-0000-0000-000000000001","subscription_id":"00000000-0000-0000-0000-000000000002","client_id":"00000000-0000-0000-0000-000000000003"},"credentials":{"client_secret":"vault://kv/a#secret"}}`,
	}
	for _, c := range ok {
		if _, err := DecodeCloud([]byte(c)); err != nil {
			t.Errorf("%s: %v", c, err)
		}
	}
	bad := map[string]string{
		"pasted key":           `{"provider":"aws","auth":"vault","aws":{"region":"eu-west-1"},"credentials":{"access_key_id":"AKIAIOSFODNN7EXAMPLE","secret_access_key":"vault://kv/c#s"}}`,
		"missing secret":       `{"provider":"aws","auth":"vault","aws":{"region":"eu-west-1"},"credentials":{"access_key_id":"vault://kv/c#a"}}`,
		"credentials in oidc":  `{"provider":"aws","auth":"oidc","aws":{"region":"eu-west-1","role_arn":"arn:aws:iam::123456789012:role/d"},"credentials":{"access_key_id":"vault://kv/c#a","secret_access_key":"vault://kv/c#s"}}`,
		"wrong cloud's secret": `{"provider":"gcp","auth":"vault","gcp":{"project_id":"acme-prod-1234","region":"europe-west1","service_account_email":""},"credentials":{"service_account_key":"vault://kv/g#k","client_secret":"vault://kv/a#s"}}`,
		"unknown field":        `{"provider":"aws","auth":"vault","aws":{"region":"eu-west-1"},"credentials":{"password":"x"}}`,
	}
	for name, c := range bad {
		if _, err := DecodeCloud([]byte(c)); err == nil {
			t.Errorf("%s must be refused", name)
		}
	}
	c, _ := DecodeCloud([]byte(ok[1]))
	env := c.SecretEnv()
	if env["AWS_ACCESS_KEY_ID"] != "vault://kv/c#a" || len(env) != 2 {
		t.Fatalf("secret env: %v", env)
	}
	for k := range env {
		if !SecretEnvAllowed[k] {
			t.Fatalf("%s is not allowlisted", k)
		}
	}
	if pe, _ := c.PhaseCredentials("s", "plan"); len(pe) != 0 {
		t.Fatalf("vault mode passes no identity through the control plane: %v", pe)
	}
	if strings.Contains(strings.Join(func() []string {
		var v []string
		for _, x := range env {
			v = append(v, x)
		}
		return v
	}(), " "), "AKIA") {
		t.Fatal("references only")
	}
}
