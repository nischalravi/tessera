package worker

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Per-target limits and circuit breakers (issue #302).
//
// A target is one connection of one tenant. Every call a worker makes to a
// customer's system (a connector's Discover, a provisioning Apply or Verify)
// goes through Guard.Do, which enforces, in this order:
//
//   - the circuit breaker: after BreakerThreshold failed calls in a row the
//     breaker opens and calls are refused at once (BreakerOpenError, which
//     carries when to try again) for BreakerCooldown; then one probe call is
//     let through (half open), and its outcome closes or re-opens the breaker.
//     A call that was cancelled or refused by the target as a bad request
//     (a permanent target error) is not a failure of the target;
//   - the rate limit (a token bucket of RatePerMin with Burst tokens): a call
//     waits for its token, up to MaxRateWait, and is refused after that;
//   - the concurrency limit: at most MaxConcurrency calls in flight, the rest wait.
//
// The limits come from the connection's connection_limits row (0 in any field
// means the worker's Defaults) and are re-read every ConfigTTL. They are per
// worker process: N workers allow N times the rate and concurrency, which the
// README says (a cluster-wide limit would need a shared counter in the
// database on every call, a cost the worker avoids).

// Limits are the effective limits of one target.
type Limits struct {
	MaxConcurrency   int           // calls in flight at once; <= 0 means no limit
	RatePerMin       int           // calls per minute; <= 0 means no limit
	Burst            int           // bucket size; <= 0 means RatePerMin/60, at least 1
	BreakerThreshold int           // consecutive failures that open the breaker; <= 0 disables it
	BreakerCooldown  time.Duration // how long it stays open
}

// DefaultLimits are used when neither the worker's flags nor the connection
// say otherwise: modest concurrency, no rate limit, a breaker that opens after
// five failures in a row for thirty seconds.
var DefaultLimits = Limits{MaxConcurrency: 4, BreakerThreshold: 5, BreakerCooldown: 30 * time.Second}

// merge returns l with every non-zero field of the connection's row applied.
func (l Limits) merge(c *store.ConnectionLimits) Limits {
	if c == nil {
		return l
	}
	if c.MaxConcurrency > 0 {
		l.MaxConcurrency = c.MaxConcurrency
	}
	if c.RatePerMin > 0 {
		l.RatePerMin = c.RatePerMin
	}
	if c.Burst > 0 {
		l.Burst = c.Burst
	}
	if c.BreakerThreshold > 0 {
		l.BreakerThreshold = c.BreakerThreshold
	}
	if c.BreakerCooldownSecs > 0 {
		l.BreakerCooldown = time.Duration(c.BreakerCooldownSecs) * time.Second
	}
	return l
}

func (l Limits) burst() float64 {
	if l.Burst > 0 {
		return float64(l.Burst)
	}
	return max(1, float64(l.RatePerMin)/60)
}

// Errors of Guard.Do.
var (
	// ErrBreakerOpen: the target's breaker is open (errors.Is on a BreakerOpenError).
	ErrBreakerOpen = errors.New("worker: the target's circuit breaker is open")
	// ErrRateLimited: the call would wait longer than MaxRateWait for its token.
	ErrRateLimited = errors.New("worker: the target's rate limit is exhausted")
)

// BreakerOpenError is returned instead of a call while the breaker is open.
type BreakerOpenError struct {
	RetryAfter time.Duration
	LastError  string
}

// DeferFor is when to try again (provision.Deferred).
func (e *BreakerOpenError) DeferFor() time.Duration { return e.RetryAfter }

func (e *BreakerOpenError) Error() string {
	return fmt.Sprintf("the target's circuit breaker is open after repeated failures (next probe in %s)", e.RetryAfter.Round(time.Second))
}

// Is makes errors.Is(err, ErrBreakerOpen) true.
func (e *BreakerOpenError) Is(t error) bool { return t == ErrBreakerOpen }

// RateLimitedError is returned instead of a call that would wait longer than
// MaxRateWait for its rate-limit token.
type RateLimitedError struct{ RetryAfter time.Duration }

func (e *RateLimitedError) Error() string {
	return fmt.Sprintf("the target's rate limit is exhausted (a call is possible in %s)", e.RetryAfter.Round(time.Second))
}

// DeferFor is when to try again (provision.Deferred).
func (e *RateLimitedError) DeferFor() time.Duration { return e.RetryAfter }

// Is makes errors.Is(err, ErrRateLimited) true.
func (e *RateLimitedError) Is(t error) bool { return t == ErrRateLimited }

// Outcomes counted by Guard.OnCall.
const (
	OutcomeOK              = "ok"
	OutcomeError           = "error"
	OutcomeBreakerRejected = "breaker_rejected"
	OutcomeRateLimited     = "rate_limited"
)

// Guard enforces the limits of every target a worker process calls. The zero
// value (with a DB) uses DefaultLimits. It is safe for concurrent use.
type Guard struct {
	DB *store.DB
	// Defaults replace DefaultLimits for fields a connection does not set.
	Defaults *Limits
	Clock    func() time.Time
	// ConfigTTL is how long a connection's limits are cached (30 s).
	ConfigTTL time.Duration
	// MaxRateWait bounds the wait for a rate-limit token (30 s).
	MaxRateWait time.Duration
	// OnCall, when set, is told the outcome of every call (metrics).
	OnCall func(outcome string)

	mu      sync.Mutex
	targets map[tkey]*gtarget
	calls   atomic.Int64
}

type tkey struct {
	tenant tenancy.ID
	conn   string
}

func (g *Guard) now() time.Time {
	if g.Clock != nil {
		return g.Clock()
	}
	return time.Now().UTC()
}

func (g *Guard) defaults() Limits {
	if g.Defaults != nil {
		return *g.Defaults
	}
	return DefaultLimits
}

func (g *Guard) ttl() time.Duration {
	if g.ConfigTTL > 0 {
		return g.ConfigTTL
	}
	return 30 * time.Second
}

func (g *Guard) maxRateWait() time.Duration {
	if g.MaxRateWait > 0 {
		return g.MaxRateWait
	}
	return 30 * time.Second
}

func (g *Guard) target(t tenancy.ID, conn string) *gtarget {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.targets == nil {
		g.targets = map[tkey]*gtarget{}
	}
	k := tkey{t, conn}
	gt := g.targets[k]
	if gt == nil {
		gt = &gtarget{wake: make(chan struct{})}
		g.targets[k] = gt
	}
	return gt
}

// limits returns the target's effective limits, re-reading the connection's
// row when the cached copy is older than ConfigTTL. A database error keeps the
// previous limits (the defaults the first time): a call is never refused
// because the limits could not be read.
func (g *Guard) limits(ctx context.Context, t tenancy.ID, conn string, gt *gtarget) Limits {
	now := g.now()
	gt.mu.Lock()
	if gt.loaded && now.Sub(gt.loadedAt) < g.ttl() {
		l := gt.limits
		gt.mu.Unlock()
		return l
	}
	gt.mu.Unlock()
	l, ok := g.defaults(), false
	if g.DB != nil {
		var row *store.ConnectionLimits
		err := g.DB.ReadTenant(ctx, t, func(tx *store.TenantTx) error {
			var err error
			row, err = tx.ConnectionLimits(conn)
			if errors.Is(err, store.ErrNotFound) {
				row, err = nil, nil
			}
			return err
		})
		if err == nil {
			l, ok = l.merge(row), true
		}
	} else {
		ok = true
	}
	gt.mu.Lock()
	defer gt.mu.Unlock()
	if !ok && gt.loaded {
		return gt.limits
	}
	gt.limits, gt.loaded, gt.loadedAt = l, ok, now
	return l
}

// Do runs fn as one call to the target (tenant, conn) under its limits. It
// returns a *BreakerOpenError (without calling fn) while the breaker is open,
// ErrRateLimited when the rate limit would make it wait too long, ctx's error
// if ctx ends while it waits, and otherwise fn's error. fn is given ctx.
func (g *Guard) Do(ctx context.Context, t tenancy.ID, conn string, fn func(context.Context) error) error {
	gt := g.target(t, conn)
	l := g.limits(ctx, t, conn, gt)
	if err := gt.allow(g.now(), l); err != nil {
		g.report(OutcomeBreakerRejected)
		return err
	}
	if err := gt.takeToken(ctx, g.now, l, g.maxRateWait()); err != nil {
		gt.abandon()
		if errors.Is(err, ErrRateLimited) {
			g.report(OutcomeRateLimited)
		}
		return err
	}
	if err := gt.acquire(ctx, l); err != nil {
		gt.abandon()
		return err
	}
	err := fn(ctx)
	failed := isTargetFailure(ctx, err)
	gt.release()
	gt.finish(g.now(), l, err, failed, ctx.Err() != nil)
	if failed {
		g.report(OutcomeError)
	} else if err == nil {
		g.report(OutcomeOK)
	}
	return err
}

func (g *Guard) report(outcome string) {
	g.calls.Add(1)
	if g.OnCall != nil {
		g.OnCall(outcome)
	}
}

// isTargetFailure: a call that shows the target is unhealthy. A cancelled
// call and a permanent target error (the request was wrong, not the target)
// are not.
func isTargetFailure(ctx context.Context, err error) bool {
	if err == nil || ctx.Err() != nil || errors.Is(err, context.Canceled) {
		return false
	}
	var te *target.Error
	if errors.As(err, &te) && !te.Retryable {
		return false
	}
	return true
}

// gtarget is the state of one target: its cached limits, rate bucket,
// concurrency counter and breaker.
type gtarget struct {
	mu       sync.Mutex
	limits   Limits
	loaded   bool
	loadedAt time.Time

	tokens    float64
	refilled  time.Time
	hasBucket bool

	inFlight int
	wake     chan struct{}

	state    string
	failures int
	openTill time.Time
	probing  bool
	lastErr  string

	calls, failed, rejected int64
}

// allow is the breaker's gate.
func (gt *gtarget) allow(now time.Time, l Limits) error {
	gt.mu.Lock()
	defer gt.mu.Unlock()
	if l.BreakerThreshold <= 0 {
		gt.state, gt.probing = store.BreakerClosed, false
		return nil
	}
	switch gt.state {
	case "", store.BreakerClosed:
		return nil
	case store.BreakerOpen:
		if now.Before(gt.openTill) {
			gt.rejected++
			return &BreakerOpenError{RetryAfter: gt.openTill.Sub(now), LastError: gt.lastErr}
		}
		gt.state, gt.probing = store.BreakerHalfOpen, true
		return nil
	default: // half open: one probe at a time
		if gt.probing {
			gt.rejected++
			return &BreakerOpenError{RetryAfter: time.Second, LastError: gt.lastErr}
		}
		gt.probing = true
		return nil
	}
}

// abandon gives back a half-open probe slot taken by allow when the call
// never ran (it was cancelled or refused while waiting).
func (gt *gtarget) abandon() {
	gt.mu.Lock()
	gt.probing = false
	gt.mu.Unlock()
}

func (gt *gtarget) takeToken(ctx context.Context, clock func() time.Time, l Limits, maxWait time.Duration) error {
	if l.RatePerMin <= 0 {
		return nil
	}
	rate := float64(l.RatePerMin) / 60 // tokens per second
	gt.mu.Lock()
	now := clock()
	if !gt.hasBucket {
		gt.tokens, gt.refilled, gt.hasBucket = l.burst(), now, true
	}
	gt.tokens = min(l.burst(), gt.tokens+now.Sub(gt.refilled).Seconds()*rate)
	gt.refilled = now
	var wait time.Duration
	if gt.tokens < 1 {
		wait = time.Duration((1 - gt.tokens) / rate * float64(time.Second))
		if wait > maxWait {
			gt.rejected++
			gt.mu.Unlock()
			return &RateLimitedError{RetryAfter: wait}
		}
	}
	gt.tokens-- // a reservation: the waiter has its token when the wait ends
	gt.mu.Unlock()
	if wait <= 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		gt.mu.Lock()
		gt.tokens++ // never used
		gt.mu.Unlock()
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (gt *gtarget) acquire(ctx context.Context, l Limits) error {
	for {
		gt.mu.Lock()
		if l.MaxConcurrency <= 0 || gt.inFlight < l.MaxConcurrency {
			gt.inFlight++
			gt.calls++
			gt.mu.Unlock()
			return nil
		}
		wake := gt.wake
		gt.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-wake:
		}
	}
}

func (gt *gtarget) release() {
	gt.mu.Lock()
	gt.inFlight--
	close(gt.wake)
	gt.wake = make(chan struct{})
	gt.mu.Unlock()
}

// finish records the outcome of a call that ran and moves the breaker.
func (gt *gtarget) finish(now time.Time, l Limits, err error, failed, cancelled bool) {
	gt.mu.Lock()
	defer gt.mu.Unlock()
	gt.probing = false
	switch {
	case failed:
		gt.failed++
		gt.failures++
		gt.lastErr = shortError(err)
		if l.BreakerThreshold > 0 && (gt.state == store.BreakerHalfOpen || gt.failures >= l.BreakerThreshold) {
			gt.state = store.BreakerOpen
			gt.openTill = now.Add(l.BreakerCooldown)
		}
	case err == nil:
		gt.failures, gt.state, gt.lastErr = 0, store.BreakerClosed, ""
	case cancelled:
		// neither: a half-open breaker stays half open and probes again
	default:
		// a permanent target error: the target answered, so it is up
		gt.failures, gt.state = 0, store.BreakerClosed
	}
}

func shortError(err error) string {
	s := strings.Join(strings.Fields(err.Error()), " ")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// TargetState is a point-in-time view of one target for the worker's
// heartbeat and metrics.
type TargetState struct {
	Tenant tenancy.ID
	store.WorkerTargetState
}

// Snapshot returns the state of every target the worker has called or
// refused, by tenant then connection.
func (g *Guard) Snapshot() []TargetState {
	now := g.now()
	g.mu.Lock()
	keys := make([]tkey, 0, len(g.targets))
	for k := range g.targets {
		keys = append(keys, k)
	}
	ts := make(map[tkey]*gtarget, len(keys))
	for _, k := range keys {
		ts[k] = g.targets[k]
	}
	g.mu.Unlock()
	sort.Slice(keys, func(i, j int) bool {
		if a, b := keys[i].tenant.String(), keys[j].tenant.String(); a != b {
			return a < b
		}
		return keys[i].conn < keys[j].conn
	})
	out := make([]TargetState, 0, len(keys))
	for _, k := range keys {
		gt := ts[k]
		gt.mu.Lock()
		st := gt.state
		if st == "" {
			st = store.BreakerClosed
		}
		s := store.WorkerTargetState{ConnectionID: k.conn, State: st, ConsecutiveFailures: gt.failures, LastError: gt.lastErr,
			InFlight: gt.inFlight, Calls: gt.calls, Failures: gt.failed, Rejected: gt.rejected}
		if st == store.BreakerOpen {
			if until := gt.openTill; until.After(now) {
				s.OpenUntil = &until
			} else {
				s.State = store.BreakerHalfOpen // the cooldown is over: the next call probes
			}
		}
		gt.mu.Unlock()
		if s.Calls == 0 && s.Rejected == 0 && s.State == store.BreakerClosed {
			continue
		}
		out = append(out, TargetState{Tenant: k.tenant, WorkerTargetState: s})
	}
	return out
}
