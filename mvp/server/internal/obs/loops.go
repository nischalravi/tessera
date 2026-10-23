package obs

import (
	"sort"
	"sync"
	"time"
)

// Loop metrics: every background loop registers with the Loops tracker and
// reports each run, so a stalled or failing loop shows as lag.
var (
	loopLastRun = Default.NewGauge("tessera_loop_last_run_timestamp_seconds",
		"Unix time the loop last finished a run (ok or not).", "loop")
	loopLastOK = Default.NewGauge("tessera_loop_last_success_timestamp_seconds",
		"Unix time the loop last finished a successful run.", "loop")
	loopLag = Default.NewGauge("tessera_loop_lag_seconds",
		"Seconds since the loop last succeeded (since registration before its first success).", "loop")
	loopInterval = Default.NewGauge("tessera_loop_interval_seconds",
		"The loop's configured interval in seconds.", "loop")
	loopRuns = Default.NewCounter("tessera_loop_runs_total",
		"Loop runs by result (ok, error).", "loop", "result")
	loopDuration = Default.NewHistogram("tessera_loop_run_duration_seconds",
		"Duration of loop runs in seconds.", []float64{0.01, 0.05, 0.25, 1, 5, 30, 120}, "loop")
)

// LoopLeader is 1 while this replica holds the loop's leader lease (internal/leader), else 0.
var LoopLeader = Default.NewGauge("tessera_loop_leader",
	"1 when this replica leads the loop (holds its Postgres advisory-lock lease), 0 when it stands by.", "loop")

// LoopState is one loop's status.
type LoopState struct {
	Name       string
	Interval   time.Duration
	Gated      bool // counts toward /readyz
	Registered time.Time
	LastRun    time.Time // zero before the first run
	LastOK     time.Time // zero before the first success
	Runs       int64
	Failures   int64
}

// Lag is how long the loop has gone without a success, measured from its
// registration until it first succeeds.
func (s LoopState) Lag(now time.Time) time.Duration {
	base := s.LastOK
	if base.IsZero() {
		base = s.Registered
	}
	if d := now.Sub(base); d > 0 {
		return d
	}
	return 0
}

// Loops tracks background loops. Default's tracker is DefaultLoops.
type Loops struct {
	mu    sync.Mutex
	now   func() time.Time
	loops map[string]*LoopState
}

// NewLoops returns a tracker on the given clock (nil: the wall clock). The
// clock is real time, not TESSERA_NOW: freshness is about the process.
func NewLoops(now func() time.Time) *Loops {
	if now == nil {
		now = time.Now
	}
	return &Loops{now: now, loops: map[string]*LoopState{}}
}

// DefaultLoops is the tracker the server's loops report to; its gauges are
// refreshed at every scrape.
var DefaultLoops = func() *Loops {
	l := NewLoops(nil)
	Default.OnScrape(l.refresh)
	return l
}()

// Register declares a loop. gated loops make /readyz fail when they lag.
// Registering again resets the loop's baseline.
func (l *Loops) Register(name string, interval time.Duration, gated bool) {
	l.mu.Lock()
	l.loops[name] = &LoopState{Name: name, Interval: interval, Gated: gated, Registered: l.now()}
	l.mu.Unlock()
	loopInterval.Set(interval.Seconds(), name)
}

// Unregister drops loops from the tracker (a replica that stopped leading
// them must not report them as lagging).
func (l *Loops) Unregister(names ...string) {
	l.mu.Lock()
	for _, n := range names {
		delete(l.loops, n)
	}
	l.mu.Unlock()
}

// Done records the end of a run that began at start; err nil is a success.
func (l *Loops) Done(name string, start time.Time, err error) {
	l.mu.Lock()
	s, ok := l.loops[name]
	if !ok {
		l.mu.Unlock()
		return
	}
	now := l.now()
	s.LastRun = now
	s.Runs++
	res := "ok"
	if err != nil {
		s.Failures++
		res = "error"
	} else {
		s.LastOK = now
	}
	l.mu.Unlock()
	loopRuns.Inc(name, res)
	loopDuration.Observe(now.Sub(start).Seconds(), name)
}

// Run runs fn as one run of the loop and records it.
func (l *Loops) Run(name string, fn func() error) error {
	start := l.now()
	err := fn()
	l.Done(name, start, err)
	return err
}

// Snapshot lists the loops, sorted by name.
func (l *Loops) Snapshot() []LoopState {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]LoopState, 0, len(l.loops))
	for _, s := range l.loops {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Lagging lists the gated loops whose lag exceeds max.
func (l *Loops) Lagging(max time.Duration) []string {
	now := l.now()
	var out []string
	for _, s := range l.Snapshot() {
		if s.Gated && s.Lag(now) > max {
			out = append(out, s.Name)
		}
	}
	return out
}

func (l *Loops) refresh() {
	now := l.now()
	for _, s := range l.Snapshot() {
		if !s.LastRun.IsZero() {
			loopLastRun.Set(float64(s.LastRun.Unix()), s.Name)
		}
		if !s.LastOK.IsZero() {
			loopLastOK.Set(float64(s.LastOK.Unix()), s.Name)
		}
		loopLag.Set(s.Lag(now).Seconds(), s.Name)
	}
}

// Now is the tracker's clock.
func (l *Loops) Now() time.Time { return l.now() }
