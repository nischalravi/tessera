package obs

import (
	"bytes"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite testdata/metrics.golden")

// TestMetricContract_Golden pins every metric name, type and label set: the
// alert rules in deploy/prometheus and docs/operations/slo.md are written
// against them. A change needs a reviewed diff of testdata/metrics.golden and
// of the rules.
func TestMetricContract_Golden(t *testing.T) {
	var b strings.Builder
	for _, d := range Default.Descriptors() {
		fmt.Fprintf(&b, "%s %s {%s}\n", d.Name, d.Type, strings.Join(d.Labels, ","))
	}
	const path = "testdata/metrics.golden"
	if *update {
		if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != b.String() {
		t.Errorf("metric contract changed (go test ./internal/obs -update after review):\n got:\n%s\nwant:\n%s", b.String(), want)
	}
}

func TestExposition_Format(t *testing.T) {
	r := NewRegistry()
	c := r.NewCounter("x_total", "A counter.", "route", "class")
	h := r.NewHistogram("x_seconds", "A histogram.", []float64{0.1, 1}, "route")
	g := r.NewGauge("x_gauge", "A gauge.")
	r.NewCounterFunc("x_func_total", "Computed.", func() float64 { return 7 })
	c.Inc(`GET /a"b`, "2xx")
	c.Add(2, "GET /a", "5xx")
	h.Observe(0.05, "GET /a")
	h.Observe(0.5, "GET /a")
	h.Observe(5, "GET /a")
	g.Set(3)
	var buf bytes.Buffer
	if err := r.WriteText(&buf); err != nil {
		t.Fatal(err)
	}
	want := `# HELP x_func_total Computed.
# TYPE x_func_total counter
x_func_total 7
# HELP x_gauge A gauge.
# TYPE x_gauge gauge
x_gauge 3
# HELP x_seconds A histogram.
# TYPE x_seconds histogram
x_seconds_bucket{route="GET /a",le="0.1"} 1
x_seconds_bucket{route="GET /a",le="1"} 2
x_seconds_bucket{route="GET /a",le="+Inf"} 3
x_seconds_sum{route="GET /a"} 5.55
x_seconds_count{route="GET /a"} 3
# HELP x_total A counter.
# TYPE x_total counter
x_total{route="GET /a\"b",class="2xx"} 1
x_total{route="GET /a",class="5xx"} 2
`
	if buf.String() != want {
		t.Errorf("exposition:\n%s\nwant:\n%s", buf.String(), want)
	}
}

// Label cardinality is bounded: past MaxSeries, new label sets fold into one
// "other" series.
func TestCardinality_Bounded(t *testing.T) {
	r := NewRegistry()
	c := r.NewCounter("y_total", "y", "route")
	for i := 0; i < MaxSeries+500; i++ {
		c.Inc(fmt.Sprintf("route-%d", i))
	}
	n := 0
	var other float64
	c.Each(func(l []string, v float64) {
		n++
		if l[0] == Other {
			other = v
		}
	})
	if n != MaxSeries+1 || other != 500 {
		t.Errorf("series=%d other=%v, want %d and 500", n, other, MaxSeries+1)
	}
}

func TestQuantile(t *testing.T) {
	r := NewRegistry()
	h := r.NewHistogram("q_seconds", "q", []float64{1, 2, 4}, "route")
	if _, ok := h.Quantile(0.95, nil); ok {
		t.Error("quantile of nothing")
	}
	for i := 0; i < 100; i++ {
		h.Observe(0.5, "a")
	}
	h.Observe(3, "b")
	if v, _ := h.Quantile(0.5, nil); v <= 0 || v > 1 {
		t.Errorf("p50 = %v", v)
	}
	if v, _ := h.Quantile(0.999, func(l []string) bool { return l[0] == "b" }); v <= 2 || v > 4 {
		t.Errorf("p99.9 of b = %v", v)
	}
}

// HTTP series are keyed by the registered pattern: whatever raw paths arrive,
// an unrouted request is one "unmatched" series.
func TestInstrument_RouteLabelsAreBounded(t *testing.T) {
	var routed bool
	h := Instrument(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if routed {
			SetRoute(r.Context(), "GET /api/things/{id}")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	before := HTTPRequests.Value(Unmatched, "2xx")
	for i := 0; i < 50; i++ {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", fmt.Sprintf("/random/%d?x=1", i), nil))
	}
	routed = true
	b2 := HTTPRequests.Value("GET /api/things/{id}", "2xx")
	for i := 0; i < 50; i++ {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", fmt.Sprintf("/api/things/%d", i), nil))
	}
	if got := HTTPRequests.Value(Unmatched, "2xx") - before; got != 50 {
		t.Errorf("unmatched = %v, want 50", got)
	}
	if got := HTTPRequests.Value("GET /api/things/{id}", "2xx") - b2; got != 50 {
		t.Errorf("routed = %v, want 50", got)
	}
	HTTPRequests.Each(func(l []string, _ float64) {
		if strings.Contains(l[0], "/random/") || strings.Contains(l[0], "/api/things/1") {
			t.Errorf("raw path in a label: %q", l[0])
		}
	})
}

func TestStatusClass(t *testing.T) {
	for in, want := range map[int]string{200: "2xx", 204: "2xx", 302: "3xx", 404: "4xx", 503: "5xx", 0: Other, 700: Other} {
		if got := StatusClass(in); got != want {
			t.Errorf("StatusClass(%d) = %s, want %s", in, got, want)
		}
	}
}

func TestLoops_LagAndGating(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l := NewLoops(func() time.Time { return now })
	l.Register("fast", 30*time.Second, true)
	l.Register("daily", 24*time.Hour, false)
	now = now.Add(10 * time.Minute)
	// never ran: lag counts from registration; only the gated loop is reported
	if got := l.Lagging(5 * time.Minute); len(got) != 1 || got[0] != "fast" {
		t.Errorf("lagging = %v", got)
	}
	if err := l.Run("fast", func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if got := l.Lagging(5 * time.Minute); len(got) != 0 {
		t.Errorf("after a success: %v", got)
	}
	// failures do not refresh the success time
	now = now.Add(6 * time.Minute)
	_ = l.Run("fast", func() error { return fmt.Errorf("boom") })
	if got := l.Lagging(5 * time.Minute); len(got) != 1 {
		t.Errorf("failing loop must lag: %v", got)
	}
	var s LoopState
	for _, x := range l.Snapshot() {
		if x.Name == "fast" {
			s = x
		}
	}
	if s.Runs != 2 || s.Failures != 1 || s.LastOK.IsZero() {
		t.Errorf("state: %+v", s)
	}
	// an unregistered loop is ignored, never panics
	l.Done("nope", now, nil)
}

func TestHandler_MethodsAndHeaders(t *testing.T) {
	h := Default.Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if rec.Code != 200 || rec.Header().Get("Content-Type") != ContentType || !strings.Contains(rec.Body.String(), "tessera_http_requests_total") {
		t.Errorf("GET: %d %v", rec.Code, rec.Header())
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/metrics", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", rec.Code)
	}
}
