package api

import (
	"net/http"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/health"
	"github.com/nischalravi/tessera/mvp/server/internal/obs"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
)

// Operational monitoring routes (issue #303).
//
// GET /livez and GET /readyz are orchestrator probes. They are served by
// probes, ahead of the API pipeline, and are not part of the route table,
// the OpenAPI document or the public allow-list (which lists API routes):
//
//   - not audited: they carry no tenant data, are polled every few seconds by
//     every load balancer and kubelet, and would otherwise bury the ledger
//     (audit.IsProbePath, pinned by test; every /api/* request stays audited,
//     except GET /api/health as before);
//   - not rate limited, not session-authenticated, no CORS, no tenant;
//   - constant-shape JSON: a fixed set of keys whose values are "ok" or
//     "fail". No error text, host, path or tenant data ever appears;
//   - counted in tessera_http_requests_total like any request.
//
// GET /metrics is NOT served here. It lives on the separate internal listener
// TESSERA_METRICS_ADDR (cmd/tessera), so it is never reachable through the
// public listener or its proxy; on this listener /metrics is an ordinary
// unknown route (401/404, audited).
//
// GET /api/admin/platform-health is the authenticated summary of the same
// signals for Admin -> Platform health (admin.read, audited as any /api/*).

func (s *Server) registerOpsRoutes() {
	s.handle(http.MethodGet, "/api/admin/platform-health", noTenant, need(auth.PermAdminRead), s.adminPlatformHealth)
}

// probes answers GET/HEAD /livez and /readyz and passes everything else on.
func (s *Server) probes(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !audit.IsProbePath(r.URL.Path) || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
			next.ServeHTTP(w, r)
			return
		}
		obs.SetRoute(r.Context(), "GET "+r.URL.Path)
		status := http.StatusOK
		var body any = health.Live()
		if r.URL.Path == "/readyz" {
			res := s.cfg.Health.Ready(r.Context())
			body = res
			if !res.Ready() {
				status = http.StatusServiceUnavailable
			}
		}
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		if r.Method == http.MethodHead {
			h.Set("Content-Type", "application/json")
			w.WriteHeader(status)
			return
		}
		writeJSON(w, status, body)
	})
}

func (s *Server) adminPlatformHealth(_ http.ResponseWriter, r *http.Request, _ *params) (any, error) {
	b, err := ojson.Marshal(s.cfg.Health.Summary(r.Context()))
	if err != nil {
		return nil, err
	}
	return rawJSON(b), nil
}
