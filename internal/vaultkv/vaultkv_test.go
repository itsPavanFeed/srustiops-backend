package vaultkv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/itsPavanFeed/srustiops-backend/internal/spec"
)

func TestLoginAndRead(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/jwt/login":
			var b map[string]string
			json.NewDecoder(r.Body).Decode(&b)
			if b["role"] != "srustiops" || b["jwt"] != "run-jwt" {
				w.WriteHeader(403)
				json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied"}})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"auth": map[string]string{"client_token": "s.tok"}})
		case "/v1/kv/data/aws/prod":
			if r.Header.Get("X-Vault-Token") != "s.tok" {
				w.WriteHeader(403)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": map[string]any{
				"access_key_id": "AKIAEXAMPLE", "sa": map[string]string{"type": "service_account"}}}})
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	store := &spec.Vault{Address: srv.URL, Role: "srustiops"}
	c := &Client{Store: store, HC: srv.Client()}
	if err := c.Login(context.Background(), "wrong"); err == nil {
		t.Fatal("a wrong token must not log in")
	}
	if err := c.Login(context.Background(), "run-jwt"); err != nil {
		t.Fatal(err)
	}
	if v, err := c.Read(context.Background(), "vault://kv/aws/prod#access_key_id"); err != nil || v != "AKIAEXAMPLE" {
		t.Fatalf("read: %q %v", v, err)
	}
	if v, err := c.Read(context.Background(), "vault://kv/aws/prod#sa"); err != nil || v != `{"type":"service_account"}` {
		t.Fatalf("json value: %q %v", v, err)
	}
	if _, err := c.Read(context.Background(), "vault://kv/aws/prod#missing"); err == nil {
		t.Fatal("a missing key must fail")
	}
}
