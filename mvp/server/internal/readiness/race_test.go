//go:build race

package readiness

// raceEnabled trims the state × action matrix under -race: the pure-Go
// SQLite driver runs about 30 times slower with the race detector, and the
// matrix tests logic, not concurrency (TestActivate_ConcurrentCAS does that).
const raceEnabled = true
