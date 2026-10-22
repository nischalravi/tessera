package worker_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/jobs"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/worker"
)

var errDown = errors.New("target down")

// guard returns a Guard on the env's clock with small defaults.
func (e *env) guard(l worker.Limits) *worker.Guard {
	return &worker.Guard{DB: e.db, Clock: e.clk.Now, Defaults: &l}
}

func (e *env) connection(t *testing.T, tenant, name string) string {
	t.Helper()
	var id string
	if err := e.db.InTenant(t.Context(), tenantA, func(tx *store.TenantTx) error {
		now := e.clk.Now()
		c := &store.Connection{ID: store.NewID(), Name: name, ConnectorType: "ldap", System: name, Role: "account_source",
			CreatedAt: now, UpdatedAt: now}
		if err := tx.InsertConnection(c); err != nil {
			return err
		}
		id = c.ID
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

func fail(context.Context) error { return errDown }
func ok(context.Context) error   { return nil }

// The breaker opens after the threshold of failures in a row, refuses calls
// (without running them) for the cooldown, then lets one probe through whose
// outcome closes it or opens it again.
func TestGuard_BreakerLifecycle(t *testing.T) {
	e := newEnv(t)
	g := e.guard(worker.Limits{MaxConcurrency: 2, BreakerThreshold: 3, BreakerCooldown: time.Minute})
	conn := "c1"
	var outcomes []string
	g.OnCall = func(o string) { outcomes = append(outcomes, o) }
	for i := 0; i < 3; i++ {
		if err := g.Do(t.Context(), tenantA, conn, fail); !errors.Is(err, errDown) {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	ran := false
	err := g.Do(t.Context(), tenantA, conn, func(context.Context) error { ran = true; return nil })
	var open *worker.BreakerOpenError
	if !errors.Is(err, worker.ErrBreakerOpen) || !errors.As(err, &open) || ran {
		t.Fatalf("after 3 failures: err = %v, ran = %v", err, ran)
	}
	if open.RetryAfter != time.Minute || open.DeferFor() != time.Minute || open.LastError != "target down" {
		t.Errorf("open error = %+v", open)
	}
	// other targets, and other tenants' targets of the same id, are unaffected
	if err := g.Do(t.Context(), tenantA, "c2", ok); err != nil {
		t.Errorf("another connection: %v", err)
	}
	if err := g.Do(t.Context(), tenantB, conn, ok); err != nil {
		t.Errorf("another tenant: %v", err)
	}
	snap := g.Snapshot()
	var s0 worker.TargetState
	for _, s := range snap {
		if s.Tenant == tenantA && s.ConnectionID == conn {
			s0 = s
		}
	}
	if s0.State != store.BreakerOpen || s0.ConsecutiveFailures != 3 || s0.OpenUntil == nil || s0.Rejected != 1 ||
		s0.Calls != 3 || s0.Failures != 3 || s0.LastError != "target down" {
		t.Errorf("snapshot = %+v", s0)
	}
	// the cooldown ends: one probe; a failed probe re-opens at once
	e.clk.Add(time.Minute + time.Second)
	if err := g.Do(t.Context(), tenantA, conn, fail); !errors.Is(err, errDown) {
		t.Fatalf("probe: %v", err)
	}
	if err := g.Do(t.Context(), tenantA, conn, ok); !errors.Is(err, worker.ErrBreakerOpen) {
		t.Fatalf("after a failed probe: %v", err)
	}
	// the next probe succeeds: closed again, failures forgotten
	e.clk.Add(time.Minute + time.Second)
	if err := g.Do(t.Context(), tenantA, conn, ok); err != nil {
		t.Fatalf("probe: %v", err)
	}
	for i := 0; i < 2; i++ { // two failures are below the threshold again
		_ = g.Do(t.Context(), tenantA, conn, fail)
	}
	if err := g.Do(t.Context(), tenantA, conn, ok); err != nil {
		t.Errorf("the breaker re-opened below the threshold: %v", err)
	}
	counts := map[string]int{}
	for _, o := range outcomes {
		counts[o]++
	}
	if counts[worker.OutcomeBreakerRejected] != 2 || counts[worker.OutcomeError] != 6 || counts[worker.OutcomeOK] < 4 {
		t.Errorf("outcomes = %v", counts)
	}
}

// Only one probe is let through while the breaker is half open.
func TestGuard_HalfOpenAllowsOneProbe(t *testing.T) {
	e := newEnv(t)
	g := e.guard(worker.Limits{BreakerThreshold: 1, BreakerCooldown: time.Second})
	_ = g.Do(t.Context(), tenantA, "c", fail)
	e.clk.Add(2 * time.Second)
	started, release := make(chan struct{}), make(chan struct{})
	done := make(chan error)
	go func() {
		done <- g.Do(t.Context(), tenantA, "c", func(context.Context) error { close(started); <-release; return nil })
	}()
	<-started
	if err := g.Do(t.Context(), tenantA, "c", ok); !errors.Is(err, worker.ErrBreakerOpen) {
		t.Errorf("a second call during the probe: %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := g.Do(t.Context(), tenantA, "c", ok); err != nil {
		t.Errorf("after the probe closed it: %v", err)
	}
}

// A cancelled call and a permanent target error (a bad request) are not the
// target's failure; a retryable target error is.
func TestGuard_WhatCountsAsAFailure(t *testing.T) {
	e := newEnv(t)
	g := e.guard(worker.Limits{BreakerThreshold: 2, BreakerCooldown: time.Minute})
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	for i := 0; i < 5; i++ {
		_ = g.Do(t.Context(), tenantA, "perm", func(context.Context) error { return target.Permanent("no such group") })
		_ = g.Do(cancelled, tenantA, "cancel", func(ctx context.Context) error { return ctx.Err() })
	}
	for _, c := range []string{"perm", "cancel"} {
		if err := g.Do(t.Context(), tenantA, c, ok); err != nil {
			t.Errorf("%s opened the breaker: %v", c, err)
		}
	}
	for i := 0; i < 2; i++ {
		_ = g.Do(t.Context(), tenantA, "retryable", func(context.Context) error { return &target.Error{Msg: "503", Retryable: true} })
	}
	if err := g.Do(t.Context(), tenantA, "retryable", ok); !errors.Is(err, worker.ErrBreakerOpen) {
		t.Errorf("a retryable error did not open it: %v", err)
	}
	// a threshold of 0 disables the breaker
	off := e.guard(worker.Limits{})
	for i := 0; i < 20; i++ {
		_ = off.Do(t.Context(), tenantA, "x", fail)
	}
	if err := off.Do(t.Context(), tenantA, "x", ok); err != nil {
		t.Errorf("a disabled breaker refused: %v", err)
	}
}

// No more than MaxConcurrency calls are in flight to one target; another
// target is not held up by it.
func TestGuard_Concurrency(t *testing.T) {
	e := newEnv(t)
	g := e.guard(worker.Limits{MaxConcurrency: 2})
	var cur, peak atomic.Int32
	var wg sync.WaitGroup
	gate := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = g.Do(t.Context(), tenantA, "c", func(context.Context) error {
				n := cur.Add(1)
				for {
					p := peak.Load()
					if n <= p || peak.CompareAndSwap(p, n) {
						break
					}
				}
				<-gate
				cur.Add(-1)
				return nil
			})
		}()
	}
	for deadline := time.Now().Add(10 * time.Second); cur.Load() != 2; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("two calls never ran")
		}
	}
	// a third waits; another target runs at once
	if err := g.Do(t.Context(), tenantA, "other", ok); err != nil {
		t.Fatal(err)
	}
	if s := stateOf(g, "c"); s.InFlight != 2 {
		t.Errorf("in flight = %d", s.InFlight)
	}
	close(gate)
	wg.Wait()
	if peak.Load() != 2 {
		t.Errorf("peak concurrency = %d, want 2", peak.Load())
	}
	// a waiter gives up when its context ends
	g2 := e.guard(worker.Limits{MaxConcurrency: 1})
	hold, free := make(chan struct{}), make(chan struct{})
	go func() {
		_ = g2.Do(t.Context(), tenantA, "c", func(context.Context) error { close(hold); <-free; return nil })
	}()
	<-hold
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if err := g2.Do(ctx, tenantA, "c", ok); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("a waiter outlived its context: %v", err)
	}
	close(free)
}

func stateOf(g *worker.Guard, conn string) worker.TargetState {
	for _, s := range g.Snapshot() {
		if s.ConnectionID == conn {
			return s
		}
	}
	return worker.TargetState{}
}

// The rate limit spends the burst, then makes a call wait for a token; a call
// that would wait longer than MaxRateWait is refused with a deferral.
func TestGuard_RateLimit(t *testing.T) {
	e := newEnv(t)
	// 6000 a minute is 100 a second: one token per 10 ms
	g := e.guard(worker.Limits{RatePerMin: 6000, Burst: 2})
	start := time.Now()
	for i := 0; i < 2; i++ {
		if err := g.Do(t.Context(), tenantA, "c", ok); err != nil {
			t.Fatal(err)
		}
	}
	if time.Since(start) > 5*time.Millisecond {
		t.Errorf("the burst waited %s", time.Since(start))
	}
	// the clock is fake and does not move: the bucket stays empty, so each call reserves a later token
	g.MaxRateWait = 5 * time.Millisecond
	err := g.Do(t.Context(), tenantA, "c", ok)
	var rl *worker.RateLimitedError
	if !errors.Is(err, worker.ErrRateLimited) || !errors.As(err, &rl) || rl.DeferFor() <= 0 {
		t.Fatalf("an exhausted bucket: %v", err)
	}
	var outcome string
	g.OnCall = func(o string) { outcome = o }
	g.MaxRateWait = time.Second
	begin := time.Now()
	if err := g.Do(t.Context(), tenantA, "c", ok); err != nil {
		t.Fatal(err)
	}
	if w := time.Since(begin); w < 5*time.Millisecond || w > 500*time.Millisecond {
		t.Errorf("waited %s for a token, want about 10ms", w)
	}
	if outcome != worker.OutcomeOK {
		t.Errorf("outcome = %q", outcome)
	}
	// a refused call is counted and visible, and a rate-limited probe slot is given back
	if s := stateOf(g, "c"); s.Rejected != 1 || s.Calls != 3 {
		t.Errorf("state = %+v", s)
	}
}

// Limits come from the connection's own row over the defaults, and a change is
// picked up after the cache expires.
func TestGuard_LimitsFromTheConnection(t *testing.T) {
	e := newEnv(t)
	conn := e.connection(t, "a", "limited")
	g := e.guard(worker.Limits{MaxConcurrency: 4, BreakerThreshold: 100, BreakerCooldown: time.Hour})
	g.ConfigTTL = time.Minute
	put := func(l store.ConnectionLimits) {
		t.Helper()
		l.ConnectionID, l.UpdatedBy = conn, "test"
		if err := e.db.InTenant(t.Context(), tenantA, func(tx *store.TenantTx) error { return tx.PutConnectionLimits(&l, e.clk.Now()) }); err != nil {
			t.Fatal(err)
		}
	}
	// no row: the defaults (a breaker that needs 100 failures)
	for i := 0; i < 3; i++ {
		_ = g.Do(t.Context(), tenantA, conn, fail)
	}
	if err := g.Do(t.Context(), tenantA, conn, ok); err != nil {
		t.Fatalf("the default threshold is 100: %v", err)
	}
	// the row lowers the threshold; the guard still has the old limits until the TTL passes
	put(store.ConnectionLimits{BreakerThreshold: 2, BreakerCooldownSecs: 90})
	for i := 0; i < 3; i++ {
		_ = g.Do(t.Context(), tenantA, conn, fail)
	}
	if err := g.Do(t.Context(), tenantA, conn, ok); err != nil {
		t.Fatalf("the cached limits changed early: %v", err)
	}
	e.clk.Add(2 * time.Minute)
	_ = g.Do(t.Context(), tenantA, conn, ok) // reloads
	for i := 0; i < 2; i++ {
		_ = g.Do(t.Context(), tenantA, conn, fail)
	}
	var open *worker.BreakerOpenError
	if err := g.Do(t.Context(), tenantA, conn, ok); !errors.As(err, &open) || open.RetryAfter != 90*time.Second {
		t.Fatalf("the connection's own threshold and cooldown: %v", err)
	}
}

// flakyConnector reads nothing, and fails when it has an error.
type flakyConnector struct {
	connectors.Connector
	system string
	calls  *atomic.Int32
	err    error
}

func (c flakyConnector) System() string { return c.system }
func (c flakyConnector) Discover(context.Context) (*connectors.DiscoveryResult, error) {
	c.calls.Add(1)
	if c.err != nil {
		return nil, c.err
	}
	return &connectors.DiscoveryResult{}, nil
}

// A connector whose breaker is open is skipped by the sync (audited as
// connectors.sync_skipped) instead of failing the others; once the breaker closes it is read again.
func TestSync_SkipsAConnectorWhoseBreakerIsOpen(t *testing.T) {
	e := newEnv(t)
	bad, good := e.connection(t, "a", "bad-sys"), e.connection(t, "a", "good-sys")
	_, _ = bad, good
	g := e.guard(worker.Limits{BreakerThreshold: 2, BreakerCooldown: time.Minute})
	var badCalls, goodCalls atomic.Int32
	badErr := errors.New("source down")
	deps := &worker.Deps{Guard: g, Connectors: func(time.Time) ([]connectors.Connector, error) {
		return []connectors.Connector{
			flakyConnector{system: "bad-sys", calls: &badCalls, err: badErr}, flakyConnector{system: "good-sys", calls: &goodCalls}}, nil
	}}
	q := e.queue(t, "w", time.Minute, deps, jobs.ConnectorSync)
	run := func(key string) *store.QueueJob {
		t.Helper()
		e.enqueue(t, q, tenantA, jobs.ConnectorSync, key)
		if err := q.Tick(t.Context()); err != nil {
			t.Fatal(err)
		}
		q.Wait()
		var j *store.QueueJob
		_ = e.db.ReadTenant(t.Context(), tenantA, func(tx *store.TenantTx) error {
			js, err := tx.QueueJobs(store.QueueJobFilter{})
			for _, x := range js {
				if x.IdempotencyKey != nil && *x.IdempotencyKey == key {
					j = x
				}
			}
			return err
		})
		return j
	}
	// two failed attempts of one sync open the breaker (a failing source fails the whole sync, as before)
	e.enqueue(t, q, tenantA, jobs.ConnectorSync, "fail")
	for i := 0; i < 2; i++ {
		if err := q.Tick(t.Context()); err != nil {
			t.Fatal(err)
		}
		q.Wait()
		e.clk.Add(30 * time.Second)
	}
	if got := badCalls.Load(); got != 2 {
		t.Fatalf("the failing source was called %d times", got)
	}
	e.clk.Add(-20 * time.Second) // 40 s in: inside the minute's cooldown, before the third attempt is due
	before := badCalls.Load()
	j := run("skip")
	if j.Status != store.QueueSucceeded {
		t.Fatalf("the sync with an open breaker: %+v", j)
	}
	if badCalls.Load() != before {
		t.Error("the open breaker let a call through")
	}
	raw, _ := json.Marshal(e.audit(t, tenantA, "connectors.sync_skipped"))
	if !strings.Contains(string(raw), "bad-sys") || strings.Contains(string(raw), "good-sys") {
		t.Errorf("connectors.sync_skipped events = %s", raw)
	}
	if goodCalls.Load() == 0 {
		t.Error("the healthy connector was not read")
	}
}
