package main

import (
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/obs"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func TestMetricsServer_OffByDefaultInProd(t *testing.T) {
	cfg := &config.Config{Env: config.Prod}
	if m, err := newMetricsServer(cfg, "127.0.0.1:8000", obs.Default, quiet); m != nil || err != nil {
		t.Errorf("prod without TESSERA_METRICS_ADDR: %v %v", m, err)
	}
}

func TestMetricsServer_ServesOnlyMetrics(t *testing.T) {
	cfg := &config.Config{Env: config.Dev, MetricsAddr: freePort(t)}
	m, err := newMetricsServer(cfg, "127.0.0.1:8000", obs.Default, quiet)
	if err != nil || m == nil {
		t.Fatal(m, err)
	}
	go m.serve(quiet)
	defer m.srv.Close()
	base := "http://" + m.ln.Addr().String()
	resp, err := http.Get(base + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(b), "# TYPE tessera_http_requests_total counter") {
		t.Errorf("/metrics: %d %.200s", resp.StatusCode, b)
	}
	for _, p := range []string{"/", "/api/health", "/api/summary", "/livez"} {
		r, err := http.Get(base + p)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode != 404 {
			t.Errorf("%s on the metrics listener: %d, want 404", p, r.StatusCode)
		}
	}
}

func TestMetricsServer_BindFailure(t *testing.T) {
	busy := freePort(t)
	ln, err := newMetricsServer(&config.Config{MetricsAddr: busy}, "127.0.0.1:1", obs.Default, quiet)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.ln.Close()
	// explicit address that is taken: fatal
	if _, err := newMetricsServer(&config.Config{MetricsAddr: busy}, "127.0.0.1:1", obs.Default, quiet); err == nil {
		t.Error("explicit busy address accepted")
	}
	// the dev default that is taken: warning only
	if m, err := newMetricsServer(&config.Config{MetricsAddr: busy, MetricsAddrDefault: true}, "127.0.0.1:1", obs.Default, quiet); m != nil || err != nil {
		t.Errorf("busy default: %v %v", m, err)
	}
}

func TestMetricsServer_RefusesAPIAddress(t *testing.T) {
	if _, err := newMetricsServer(&config.Config{MetricsAddr: "127.0.0.1:8000"}, "127.0.0.1:8000", obs.Default, quiet); err == nil {
		t.Error("metrics on the API listener address accepted")
	}
	for a, b := range map[string]string{"127.0.0.1:8000": ":8000", "[::]:8000": "10.0.0.1:8000"} {
		if !sameListenAddr(a, b) {
			t.Errorf("%s and %s overlap", a, b)
		}
	}
	if sameListenAddr("127.0.0.1:8000", "127.0.0.1:8001") || sameListenAddr("127.0.0.1:8000", "10.0.0.1:8000") {
		t.Error("distinct listeners reported as overlapping")
	}
}
