package api

import (
	_ "embed"
	"net/http"
)

const (
	openAPITitle       = "SrustiOps tenant plane API"
	openAPIDescription = "A workspace's API, reached through central at /api/v1/t/{tenant}/... with a SrustiOps token. Paths below are relative to that prefix's /api/v1. Lists that can be long take ?limit= (and ?offset= or a cursor)."
	openAPIProbe       = "/api/v1/stacks/{id}/runs"
)

//go:embed openapi.json
var openAPIDoc []byte

func (s *Server) openAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(openAPIDoc)
}
