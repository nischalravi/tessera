package api

import (
	_ "embed"
	"net/http"
)

// The deployment-readiness routes are documented in their own OpenAPI
// document: /openapi.json is the FastAPI document served verbatim (and
// parity-tested), so it is left unchanged.

//go:embed openapi_readiness.json
var readinessOpenAPIDoc []byte

func (s *Server) readinessOpenAPI(w http.ResponseWriter, _ *http.Request, _ *params) (any, error) {
	return rawJSON(readinessOpenAPIDoc), nil
}
