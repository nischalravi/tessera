// Package obs is Tessera's operational monitoring: a small in-house metrics
// registry that writes the Prometheus text exposition format (0.0.4), a
// tracker for background loops, and the handler for the internal /metrics
// listener (issue #303).
//
// It is separate from the audit ledger: metrics count and time things, they
// are not evidence, and they never carry tenant data. There is no tenant,
// user, identity or path label anywhere; HTTP series are keyed by the
// registered route pattern ("GET /api/identities/{identity_id}"), never by the
// raw URL. Every vector caps its number of series (MaxSeries); a label set
// beyond the cap is folded into one "other" series, so a bug or an attacker
// cannot grow memory without bound.
//
// obs imports nothing else of Tessera, so any package can record into it.
package obs

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// MaxSeries is the most label sets one metric keeps; more are folded into an
// "other" series.
const MaxSeries = 1000

// Other is the label value of the overflow series.
const Other = "other"

// DurationBuckets are the default histogram bounds, in seconds.
var DurationBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

type kind string

const (
	kindCounter   kind = "counter"
	kindGauge     kind = "gauge"
	kindHistogram kind = "histogram"
)

// Registry holds metrics and renders them. The zero value is not usable; use
// NewRegistry. Default is the process registry.
type Registry struct {
	mu      sync.Mutex
	metrics map[string]*metric
	hooks   []func()
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{metrics: map[string]*metric{}} }

// Default is the process-wide registry that the instrumented packages use.
var Default = NewRegistry()

type metric struct {
	name, help string
	kind       kind
	labels     []string
	buckets    []float64
	mu         sync.Mutex
	series     map[string]*series
	fn         func() float64 // counter/gauge computed at scrape (no labels)
}

type series struct {
	values []string
	val    atomic.Uint64 // counter/gauge: float64 bits
	// histogram
	counts []atomic.Uint64
	count  atomic.Uint64
	sum    atomic.Uint64 // float64 bits
}

func (r *Registry) register(m *metric) *metric {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.metrics[m.name]; dup {
		panic("obs: duplicate metric " + m.name)
	}
	m.series = map[string]*series{}
	r.metrics[m.name] = m
	return m
}

// OnScrape registers fn to run before every exposition; it refreshes gauges
// that are read from elsewhere (loop lag, pool statistics).
func (r *Registry) OnScrape(fn func()) {
	r.mu.Lock()
	r.hooks = append(r.hooks, fn)
	r.mu.Unlock()
}

// Counter is a monotonically increasing value family.
type Counter struct{ m *metric }

// Gauge is a value family that goes up and down.
type Gauge struct{ m *metric }

// Histogram is a distribution family with fixed buckets.
type Histogram struct{ m *metric }

// NewCounter registers a counter with the given label names.
func (r *Registry) NewCounter(name, help string, labels ...string) *Counter {
	return &Counter{r.register(&metric{name: name, help: help, kind: kindCounter, labels: labels})}
}

// NewGauge registers a gauge with the given label names.
func (r *Registry) NewGauge(name, help string, labels ...string) *Gauge {
	return &Gauge{r.register(&metric{name: name, help: help, kind: kindGauge, labels: labels})}
}

// NewHistogram registers a histogram (buckets nil: DurationBuckets).
func (r *Registry) NewHistogram(name, help string, buckets []float64, labels ...string) *Histogram {
	if buckets == nil {
		buckets = DurationBuckets
	}
	return &Histogram{r.register(&metric{name: name, help: help, kind: kindHistogram, labels: labels, buckets: buckets})}
}

// NewCounterFunc registers an unlabeled counter read from fn at scrape time.
func (r *Registry) NewCounterFunc(name, help string, fn func() float64) {
	r.register(&metric{name: name, help: help, kind: kindCounter, fn: fn})
}

// NewGaugeFunc registers an unlabeled gauge read from fn at scrape time.
func (r *Registry) NewGaugeFunc(name, help string, fn func() float64) {
	r.register(&metric{name: name, help: help, kind: kindGauge, fn: fn})
}

func (m *metric) get(values []string) *series {
	if len(values) != len(m.labels) {
		panic(fmt.Sprintf("obs: %s takes %d label values, got %d", m.name, len(m.labels), len(values)))
	}
	key := strings.Join(values, "\xff")
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.series[key]
	if ok {
		return s
	}
	if len(m.series) >= MaxSeries {
		values = make([]string, len(m.labels))
		for i := range values {
			values[i] = Other
		}
		key = strings.Join(values, "\xff")
		if s, ok = m.series[key]; ok {
			return s
		}
	}
	s = &series{values: append([]string(nil), values...)}
	if m.kind == kindHistogram {
		s.counts = make([]atomic.Uint64, len(m.buckets))
	}
	m.series[key] = s
	return s
}

func addFloat(u *atomic.Uint64, d float64) {
	for {
		old := u.Load()
		if u.CompareAndSwap(old, math.Float64bits(math.Float64frombits(old)+d)) {
			return
		}
	}
}

// Inc adds 1 to the series for the label values.
func (c *Counter) Inc(values ...string) { c.Add(1, values...) }

// Add adds d (ignored when negative) to the series for the label values.
func (c *Counter) Add(d float64, values ...string) {
	if d < 0 {
		return
	}
	addFloat(&c.m.get(values).val, d)
}

// Value returns the series' current value (tests and the admin summary).
func (c *Counter) Value(values ...string) float64 {
	return math.Float64frombits(c.m.get(values).val.Load())
}

// Set sets the series for the label values.
func (g *Gauge) Set(v float64, values ...string) { g.m.get(values).val.Store(math.Float64bits(v)) }

// Value returns the series' current value.
func (g *Gauge) Value(values ...string) float64 {
	return math.Float64frombits(g.m.get(values).val.Load())
}

// Observe records one value in the series for the label values.
func (h *Histogram) Observe(v float64, values ...string) {
	s := h.m.get(values)
	for i, b := range h.m.buckets {
		if v <= b {
			s.counts[i].Add(1)
			break
		}
	}
	s.count.Add(1)
	addFloat(&s.sum, v)
}

// Snapshot returns count and sum of the series (tests and the admin summary).
func (h *Histogram) Snapshot(values ...string) (count uint64, sum float64) {
	s := h.m.get(values)
	return s.count.Load(), math.Float64frombits(s.sum.Load())
}

// Total returns the sum of every series of a counter (the admin summary).
func (c *Counter) Total() float64 {
	c.m.mu.Lock()
	defer c.m.mu.Unlock()
	var t float64
	for _, s := range c.m.series {
		t += math.Float64frombits(s.val.Load())
	}
	return t
}

// Each calls fn for each series of the counter, in no particular order.
func (c *Counter) Each(fn func(labels []string, v float64)) {
	c.m.mu.Lock()
	defer c.m.mu.Unlock()
	for _, s := range c.m.series {
		fn(s.values, math.Float64frombits(s.val.Load()))
	}
}

// Quantile estimates the q quantile (0..1) over every series of the
// histogram that accept(labels) selects, by linear interpolation inside the
// bucket, as Prometheus' histogram_quantile does. ok is false with no data.
func (h *Histogram) Quantile(q float64, accept func(labels []string) bool) (v float64, ok bool) {
	m := h.m
	counts := make([]uint64, len(m.buckets))
	var total uint64
	m.mu.Lock()
	for _, s := range m.series {
		if accept != nil && !accept(s.values) {
			continue
		}
		for i := range counts {
			counts[i] += s.counts[i].Load()
		}
		total += s.count.Load()
	}
	m.mu.Unlock()
	if total == 0 {
		return 0, false
	}
	rank := q * float64(total)
	var cum uint64
	lower := 0.0
	for i, b := range m.buckets {
		prev := cum
		cum += counts[i]
		if float64(cum) >= rank {
			if counts[i] == 0 {
				return b, true
			}
			return lower + (b-lower)*(rank-float64(prev))/float64(counts[i]), true
		}
		lower = b
	}
	return m.buckets[len(m.buckets)-1], true // above the last bound
}

// ---------------------------------------------------------------- exposition

// ContentType is the exposition format's media type.
const ContentType = "text/plain; version=0.0.4; charset=utf-8"

// WriteText runs the scrape hooks and writes every metric in the Prometheus
// text format, sorted by metric name and label values so the output is stable.
func (r *Registry) WriteText(w io.Writer) error {
	r.mu.Lock()
	hooks := append([]func(){}, r.hooks...)
	names := make([]string, 0, len(r.metrics))
	for n := range r.metrics {
		names = append(names, n)
	}
	r.mu.Unlock()
	for _, h := range hooks {
		h()
	}
	sort.Strings(names)
	bw := bufio.NewWriter(w)
	for _, n := range names {
		r.mu.Lock()
		m := r.metrics[n]
		r.mu.Unlock()
		m.write(bw)
	}
	return bw.Flush()
}

func (m *metric) write(w *bufio.Writer) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", m.name, escapeHelp(m.help), m.name, m.kind)
	if m.fn != nil {
		fmt.Fprintf(w, "%s %s\n", m.name, fmtFloat(m.fn()))
		return
	}
	m.mu.Lock()
	keys := make([]string, 0, len(m.series))
	for k := range m.series {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	ss := make([]*series, len(keys))
	for i, k := range keys {
		ss[i] = m.series[k]
	}
	m.mu.Unlock()
	for _, s := range ss {
		switch m.kind {
		case kindHistogram:
			var cum uint64
			for i, b := range m.buckets {
				cum += s.counts[i].Load()
				fmt.Fprintf(w, "%s_bucket%s %d\n", m.name, labelText(m.labels, s.values, "le", fmtFloat(b)), cum)
			}
			cnt := s.count.Load()
			fmt.Fprintf(w, "%s_bucket%s %d\n", m.name, labelText(m.labels, s.values, "le", "+Inf"), cnt)
			fmt.Fprintf(w, "%s_sum%s %s\n", m.name, labelText(m.labels, s.values, "", ""), fmtFloat(math.Float64frombits(s.sum.Load())))
			fmt.Fprintf(w, "%s_count%s %d\n", m.name, labelText(m.labels, s.values, "", ""), cnt)
		default:
			fmt.Fprintf(w, "%s%s %s\n", m.name, labelText(m.labels, s.values, "", ""), fmtFloat(math.Float64frombits(s.val.Load())))
		}
	}
}

func labelText(names, values []string, extraName, extraValue string) string {
	if len(names) == 0 && extraName == "" {
		return ""
	}
	var b strings.Builder
	b.WriteByte('{')
	for i, n := range names {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(n + `="` + escapeLabel(values[i]) + `"`)
	}
	if extraName != "" {
		if len(names) > 0 {
			b.WriteByte(',')
		}
		b.WriteString(extraName + `="` + extraValue + `"`)
	}
	b.WriteByte('}')
	return b.String()
}

func fmtFloat(f float64) string {
	switch {
	case math.IsInf(f, 1):
		return "+Inf"
	case math.IsInf(f, -1):
		return "-Inf"
	case math.IsNaN(f):
		return "NaN"
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}

var (
	labelEscaper = strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`)
	helpEscaper  = strings.NewReplacer(`\`, `\\`, "\n", `\n`)
)

func escapeLabel(s string) string { return labelEscaper.Replace(s) }
func escapeHelp(s string) string  { return helpEscaper.Replace(s) }

// Handler serves the registry (GET and HEAD only).
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet && req.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", ContentType)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if req.Method == http.MethodHead {
			return
		}
		_ = r.WriteText(w)
	})
}

// Descriptor names a metric, its type and its label names: the stable
// contract that the golden test pins and the alert rules rely on.
type Descriptor struct {
	Name   string
	Type   string
	Labels []string
}

// Descriptors lists every registered metric, sorted by name.
func (r *Registry) Descriptors() []Descriptor {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Descriptor, 0, len(r.metrics))
	for _, m := range r.metrics {
		out = append(out, Descriptor{m.name, string(m.kind), append([]string{}, m.labels...)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
