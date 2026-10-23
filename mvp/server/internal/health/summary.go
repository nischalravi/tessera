package health

import (
	"context"
	"sort"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/leader"
	"github.com/nischalravi/tessera/mvp/server/internal/obs"
)

// Summary is Admin -> Platform health: the signals /metrics exposes, rolled
// up for a person. It is process-wide, carries no tenant data and no secrets,
// and no error text.
type Summary struct {
	GeneratedAt string           `json:"generated_at"`
	Status      string           `json:"status"` // "ok" or "degraded"
	Checks      []CheckSummary   `json:"checks"`
	Loops       []LoopSummary    `json:"loops"`
	HTTP        HTTPSummary      `json:"http"`
	Audit       AuditSummary     `json:"audit"`
	Database    DatabaseSummary  `json:"database"`
	Logins      []LoginSummary   `json:"logins"`
	Connectors  []ConnectorStats `json:"connectors"`
	MaxLoopLag  int              `json:"max_loop_lag_seconds"`
	Leaders     []leader.Status  `json:"leaders"` // this replica's loop leases (empty without election)
}

// CheckSummary is one /readyz check.
type CheckSummary struct {
	Name string `json:"name"`
	OK   bool   `json:"ok"`
}

// LoopSummary is one background loop.
type LoopSummary struct {
	Name            string  `json:"name"`
	IntervalSeconds float64 `json:"interval_seconds"`
	Gated           bool    `json:"gated"`
	LastRunAt       *string `json:"last_run_at"`
	LastSuccessAt   *string `json:"last_success_at"`
	LagSeconds      float64 `json:"lag_seconds"`
	Runs            int64   `json:"runs"`
	Failures        int64   `json:"failures"`
	Healthy         bool    `json:"healthy"`
}

// HTTPSummary counts requests since the process started.
type HTTPSummary struct {
	Requests     int64    `json:"requests"`
	ServerErrors int64    `json:"server_errors"`
	P95Seconds   *float64 `json:"p95_seconds"`
}

// AuditSummary counts http.request event writes since the process started.
type AuditSummary struct {
	Writes        int64 `json:"writes"`
	WriteFailures int64 `json:"write_failures"`
}

// DatabaseSummary is the pool and transaction picture.
type DatabaseSummary struct {
	OpenConnections int      `json:"open_connections"`
	InUse           int      `json:"in_use"`
	Idle            int      `json:"idle"`
	PoolWaits       int64    `json:"pool_waits"`
	BusyErrors      int64    `json:"busy_errors"`
	TxP95Seconds    *float64 `json:"tx_p95_seconds"`
	LockWaitP95     *float64 `json:"lock_wait_p95_seconds"`
}

// LoginSummary is the sign-in outcome count of one method.
type LoginSummary struct {
	Method  string `json:"method"`
	Success int64  `json:"success"`
	Failure int64  `json:"failure"`
}

// ConnectorStats is the call count and error count of one external system.
type ConnectorStats struct {
	Connector string `json:"connector"`
	Op        string `json:"op"`
	Calls     int64  `json:"calls"`
	Errors    int64  `json:"errors"`
}

func ts(t time.Time) *string {
	if t.IsZero() {
		return nil
	}
	s := t.UTC().Format(time.RFC3339)
	return &s
}

func q95(h *obs.Histogram, accept func([]string) bool) *float64 {
	if v, ok := h.Quantile(0.95, accept); ok {
		return &v
	}
	return nil
}

// Summary evaluates readiness and reads the in-process counters.
func (c *Checker) Summary(ctx context.Context) Summary {
	res := c.Ready(ctx)
	now := c.now()
	s := Summary{GeneratedAt: now.UTC().Format(time.RFC3339), Status: "ok", MaxLoopLag: int(c.MaxLoopLag.Seconds()),
		Checks: []CheckSummary{}, Loops: []LoopSummary{}, Logins: []LoginSummary{}, Connectors: []ConnectorStats{}}
	if !res.Ready() {
		s.Status = "degraded"
	}
	s.Leaders = []leader.Status{}
	if c.Leaders != nil {
		s.Leaders = append(s.Leaders, c.Leaders()...)
	}
	for _, n := range checkNames {
		s.Checks = append(s.Checks, CheckSummary{Name: n, OK: res.OK(n)})
	}
	for _, l := range c.Loops.Snapshot() {
		lag := l.Lag(c.Loops.Now())
		s.Loops = append(s.Loops, LoopSummary{Name: l.Name, IntervalSeconds: l.Interval.Seconds(), Gated: l.Gated,
			LastRunAt: ts(l.LastRun), LastSuccessAt: ts(l.LastOK), LagSeconds: lag.Seconds(), Runs: l.Runs, Failures: l.Failures,
			Healthy: !l.Gated || lag <= c.MaxLoopLag})
	}
	obs.HTTPRequests.Each(func(l []string, v float64) {
		s.HTTP.Requests += int64(v)
		if l[1] == "5xx" {
			s.HTTP.ServerErrors += int64(v)
		}
	})
	s.HTTP.P95Seconds = q95(obs.HTTPDuration, nil)
	s.Audit = AuditSummary{Writes: int64(obs.AuditWrites.Total()), WriteFailures: int64(obs.AuditWriteFailures.Total())}
	p := obs.CurrentPoolStats()
	s.Database = DatabaseSummary{OpenConnections: p.Open, InUse: p.InUse, Idle: p.Idle, PoolWaits: p.WaitCount,
		BusyErrors: int64(obs.DBBusy.Total()), TxP95Seconds: q95(obs.DBTxDuration, nil), LockWaitP95: q95(obs.DBLockWait, nil)}
	logins := map[string]*LoginSummary{}
	obs.Logins.Each(func(l []string, v float64) {
		e := logins[l[0]]
		if e == nil {
			e = &LoginSummary{Method: l[0]}
			logins[l[0]] = e
		}
		if l[1] == "success" {
			e.Success += int64(v)
		} else {
			e.Failure += int64(v)
		}
	})
	for _, e := range logins {
		s.Logins = append(s.Logins, *e)
	}
	sort.Slice(s.Logins, func(i, j int) bool { return s.Logins[i].Method < s.Logins[j].Method })
	conns := map[[2]string]*ConnectorStats{}
	obs.ConnectorCalls.Each(func(l []string, v float64) {
		k := [2]string{l[0], l[1]}
		e := conns[k]
		if e == nil {
			e = &ConnectorStats{Connector: l[0], Op: l[1]}
			conns[k] = e
		}
		e.Calls += int64(v)
		if l[2] == "error" {
			e.Errors += int64(v)
		}
	})
	for _, e := range conns {
		s.Connectors = append(s.Connectors, *e)
	}
	sort.Slice(s.Connectors, func(i, j int) bool {
		if s.Connectors[i].Connector != s.Connectors[j].Connector {
			return s.Connectors[i].Connector < s.Connectors[j].Connector
		}
		return s.Connectors[i].Op < s.Connectors[j].Op
	})
	return s
}
