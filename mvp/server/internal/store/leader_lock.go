package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"sync"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/leader"
)

// Postgres leader leases (internal/leader): one session-level advisory lock
// per background loop, all held on one dedicated connection that is not part
// of the pool's traffic. A session lock is released by Postgres when the
// session ends, so a crashed or partitioned replica loses its leases without
// any cleanup. The keys are namespaced so they never meet pgLockTenant's.
const (
	pgTryLeader     = `SELECT pg_try_advisory_lock(hashtextextended($1, 0))`
	pgUnlockLeader  = `SELECT pg_advisory_unlock(hashtextextended($1, 0))`
	pgLeaderPing    = `SELECT 1`
	leaderKeyPrefix = "tessera/leader/"
	// LeaderPingEvery is how often the lock connection is checked; a failed
	// check ends every lease at once.
	LeaderPingEvery = 5 * time.Second
	leaderOpTimeout = 5 * time.Second
)

// LeaderLocker returns the database's leader-lease locker, or nil on SQLite
// (a single process needs no election).
func (d *DB) LeaderLocker() *LeaderLocker {
	if d.d != dialectPostgres {
		return nil
	}
	d.leaderOnce.Do(func() { d.leader = &LeaderLocker{db: d.sql, held: map[string]chan struct{}{}, every: LeaderPingEvery} })
	return d.leader
}

// LeaderLocker holds leader leases on one dedicated Postgres connection.
type LeaderLocker struct {
	db    *sql.DB
	every time.Duration

	mu      sync.Mutex
	conn    *sql.Conn
	held    map[string]chan struct{} // lease name -> closed when lost
	stop    chan struct{}
	closing bool
}

// TryLock takes the named lease if nobody holds it; (nil, nil) when held
// elsewhere (or already by this locker).
func (l *LeaderLocker) TryLock(ctx context.Context, name string) (leader.Lease, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closing {
		return nil, errors.New("store: leader locker closed")
	}
	if _, ok := l.held[name]; ok {
		return nil, nil
	}
	if l.conn == nil {
		c, err := l.db.Conn(ctx)
		if err != nil {
			return nil, err
		}
		l.conn = c
		l.stop = make(chan struct{})
		go l.keepAlive(l.conn, l.stop) // #nosec G118 -- the keepalive outlives the caller's context by design; it ends with the connection
	}
	octx, cancel := context.WithTimeout(ctx, leaderOpTimeout)
	defer cancel()
	var got bool
	if err := l.conn.QueryRowContext(octx, pgTryLeader, leaderKeyPrefix+name).Scan(&got); err != nil {
		l.dropLocked() // the session may hold a lock we never heard about
		return nil, err
	}
	if !got {
		return nil, nil
	}
	lost := make(chan struct{})
	l.held[name] = lost
	return &PGLease{l: l, name: name, lost: lost}, nil
}

// dropLocked discards the connection (ending its session, so Postgres
// releases every lock on it) and signals every lease lost.
func (l *LeaderLocker) dropLocked() {
	if l.conn != nil {
		// ErrBadConn makes database/sql close the connection instead of pooling it
		_ = l.conn.Raw(func(any) error { return driver.ErrBadConn })
		_ = l.conn.Close()
		l.conn = nil
		close(l.stop)
	}
	for n, ch := range l.held {
		close(ch)
		delete(l.held, n)
	}
}

func (l *LeaderLocker) keepAlive(c *sql.Conn, stop chan struct{}) {
	t := time.NewTicker(l.every)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		l.mu.Lock()
		if l.conn != c { // dropped meanwhile
			l.mu.Unlock()
			return
		}
		if len(l.held) > 0 {
			ctx, cancel := context.WithTimeout(context.Background(), leaderOpTimeout)
			_, err := c.ExecContext(ctx, pgLeaderPing)
			cancel()
			if err != nil {
				l.dropLocked()
				l.mu.Unlock()
				return
			}
		}
		l.mu.Unlock()
	}
}

func (l *LeaderLocker) release(name string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.held[name]; !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), leaderOpTimeout)
	defer cancel()
	var ok bool
	if err := l.conn.QueryRowContext(ctx, pgUnlockLeader, leaderKeyPrefix+name).Scan(&ok); err != nil || !ok {
		l.dropLocked() // cannot prove it is unlocked: end the session
		return
	}
	delete(l.held, name) // not closed: the holder released it on purpose
}

// Close ends the session, which releases every lease.
func (l *LeaderLocker) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closing = true
	l.dropLocked()
}

// PGLease is one held lease.
type PGLease struct {
	l    *LeaderLocker
	name string
	lost chan struct{}
}

// Lost is closed when the session behind the lease failed.
func (p *PGLease) Lost() <-chan struct{} { return p.lost }

// Release gives the lease up.
func (p *PGLease) Release() { p.l.release(p.name) }
