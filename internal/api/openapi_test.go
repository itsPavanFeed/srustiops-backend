package api

import (
	"os"
	"slices"
	"testing"

	"github.com/itsPavanFeed/srustiops-backend/internal/openapi"
)

// The committed openapi.json matches the routes (UPDATE_OPENAPI=1 rewrites it).
func TestOpenAPIUpToDate(t *testing.T) {
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	want := openapi.Generate(string(src), openAPITitle, "1", openAPIDescription)
	if os.Getenv("UPDATE_OPENAPI") == "1" {
		os.WriteFile("openapi.json", want, 0o644)
	}
	if got, _ := os.ReadFile("openapi.json"); string(got) != string(want) {
		t.Fatal("openapi.json is out of date: run UPDATE_OPENAPI=1 go test ./internal/api -run TestOpenAPIUpToDate")
	}
	if ps := openapi.Paths(want); len(ps) < 50 || !slices.Contains(ps, openAPIProbe) {
		t.Fatalf("paths: %d, %v", len(ps), ps[:5])
	}
}
