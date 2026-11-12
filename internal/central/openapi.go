package central

import (
	_ "embed"
	"net/http"
)

const (
	openAPITitle       = "SrustiOps central API"
	openAPIDescription = "Central: sign-in, workspaces, people and roles, the platform, and the wrapper /api/v1/t/{tenant}/... to each workspace's API (see that workspace's /api/v1/openapi.json)."
	openAPIProbe       = "/api/v1/tenants/{tenant}/members"
)

//go:embed openapi.json
var openAPIDoc []byte

func (s *Server) openAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(openAPIDoc)
}
