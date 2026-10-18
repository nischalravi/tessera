package store

import (
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/obs"
)

// Transaction metrics (issue #303): duration by kind and outcome, the wait
// for the single-writer lock, and SQLITE_BUSY / locked failures. No SQL text,
// tenant or error text is ever a label.

// lockWrite takes the write lock and records how long it waited.
func (d *DB) lockWrite() {
	start := time.Now()
	d.mu.Lock()
	obs.DBLockWait.Observe(time.Since(start).Seconds())
}

func observeTx(kind string, start time.Time, err error) {
	outcome := "ok"
	if err != nil {
		outcome = "error"
		if isBusy(err) {
			outcome = "busy"
			obs.DBBusy.Inc(kind)
		}
	}
	obs.DBTxDuration.Observe(time.Since(start).Seconds(), kind, outcome)
}

// isBusy reports whether err is SQLite's "database is locked" (SQLITE_BUSY
// or SQLITE_LOCKED); the driver words it "database is locked (5) (SQLITE_BUSY)".
func isBusy(err error) bool {
	s := err.Error()
	return strings.Contains(s, "SQLITE_BUSY") || strings.Contains(s, "SQLITE_LOCKED") || strings.Contains(s, "database is locked")
}

// PoolStats is the connection pool's current state, for the pool gauges.
func (d *DB) PoolStats() obs.PoolStats {
	s := d.sql.Stats()
	return obs.PoolStats{Open: s.OpenConnections, InUse: s.InUse, Idle: s.Idle, WaitCount: s.WaitCount, WaitDuration: s.WaitDuration}
}
