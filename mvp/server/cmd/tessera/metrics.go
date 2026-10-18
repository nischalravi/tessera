package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/obs"
)

// metricsServer is the internal listener for GET /metrics (issue #303,
// TESSERA_METRICS_ADDR). It is a separate http.Server on a separate socket:
// the public listener never serves /metrics, so a reverse proxy or load
// balancer in front of the API cannot expose it, and the audit middleware
// (which wraps the public API only) never sees scrapes. It serves nothing but
// /metrics; every other path is 404.
type metricsServer struct {
	srv *http.Server
	ln  net.Listener
}

// newMetricsServer binds cfg.MetricsAddr. It returns (nil, nil) when metrics
// are off. A bind failure is fatal when the operator chose the address and a
// logged warning for the dev default (several dev instances share a machine).
func newMetricsServer(cfg *config.Config, apiAddr string, reg *obs.Registry, logger *slog.Logger) (*metricsServer, error) {
	if cfg.MetricsAddr == "" {
		return nil, nil
	}
	if sameListenAddr(cfg.MetricsAddr, apiAddr) {
		return nil, fmt.Errorf("TESSERA_METRICS_ADDR %s is the API listen address: /metrics needs its own listener", cfg.MetricsAddr)
	}
	ln, err := net.Listen("tcp", cfg.MetricsAddr)
	if err != nil {
		if cfg.MetricsAddrDefault {
			logger.Warn("metrics listener disabled: default address unavailable (set TESSERA_METRICS_ADDR or off)",
				"addr", cfg.MetricsAddr, "err", err)
			return nil, nil
		}
		return nil, fmt.Errorf("TESSERA_METRICS_ADDR: %w", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", reg.Handler())
	return &metricsServer{ln: ln, srv: &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}}, nil
}

func (m *metricsServer) serve(logger *slog.Logger) {
	logger.Info("tessera metrics listening", "addr", m.ln.Addr().String())
	if err := m.srv.Serve(m.ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("metrics listener stopped", "err", err)
	}
}

// sameListenAddr reports whether two host:port strings bind the same port on
// overlapping interfaces (a wildcard overlaps everything).
func sameListenAddr(a, b string) bool {
	ah, ap, err1 := net.SplitHostPort(a)
	bh, bp, err2 := net.SplitHostPort(b)
	if err1 != nil || err2 != nil || ap != bp {
		return false
	}
	wild := func(h string) bool { return h == "" || h == "0.0.0.0" || h == "::" }
	return ah == bh || wild(ah) || wild(bh)
}
