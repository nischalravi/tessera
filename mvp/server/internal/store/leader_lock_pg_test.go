package store

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/leader"
)

func openPGPair(t *testing.T) (*DB, *DB) {
	t.Helper()
	PostgresForTest(t)
	ctx := context.Background()
	a, err := Open(ctx, TestTarget(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	b, err := Open(ctx, TestTarget(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return a, b
}

func TestLeaderLocker_SQLiteHasNone(t *testing.T) {
	if openTest(t).LeaderLocker() != nil {
		t.Fatal("SQLite must not elect leaders")
	}
}

// Two stores on one Postgres: a lease is held by one at a time, released on
// request, and dropped when the holder's session dies.
func TestPG_LeaderLease(t *testing.T) {
	a, b := openPGPair(t)
	ctx := context.Background()
	la, lb := a.LeaderLocker(), b.LeaderLocker()
	la.every, lb.every = 50*time.Millisecond, 50*time.Millisecond
	name := "test-lease-" + time.Now().Format("150405.000000")

	l1, err := la.TryLock(ctx, name)
	if err != nil || l1 == nil {
		t.Fatalf("first lock: %v %v", l1, err)
	}
	if l, err := lb.TryLock(ctx, name); err != nil || l != nil {
		t.Fatalf("second replica took a held lease: %v %v", l, err)
	}
	if l, _ := la.TryLock(ctx, name); l != nil {
		t.Fatal("the same replica took its own lease twice")
	}
	l1.Release()
	l2, err := lb.TryLock(ctx, name)
	if err != nil || l2 == nil {
		t.Fatalf("lease not free after release: %v %v", l2, err)
	}
	// kill b's lock session from the server: the lease is lost and a can take it
	var pid int
	lb.mu.Lock()
	err = lb.conn.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid)
	lb.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.owner.ExecContext(ctx, `SELECT pg_terminate_backend($1)`, pid); err != nil {
		t.Fatal(err)
	}
	select {
	case <-l2.Lost():
	case <-time.After(5 * time.Second):
		t.Fatal("a killed session did not end the lease")
	}
	var l3 leader.Lease
	for i := 0; i < 50 && l3 == nil; i++ {
		if l3, err = la.TryLock(ctx, name); err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if l3 == nil {
		t.Fatal("lease not free after the holder's session died")
	}
	l3.Release()
}

// Two replicas (two stores, each with its own elector) on one Postgres never
// run the same loop at once, and one takes over when the other stops.
func TestPG_TwoReplicasNeverDoubleRunALoop(t *testing.T) {
	a, b := openPGPair(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	mk := func(d *DB) *leader.Elector {
		return &leader.Elector{Locker: d.LeaderLocker(), Retry: 10 * time.Millisecond, Log: log}
	}
	ea, eb := mk(a), mk(b)
	name := "test-loop-" + time.Now().Format("150405.000000")
	var inside, maxInside, runs atomic.Int32
	body := func(ctx context.Context) {
		n := inside.Add(1)
		if n > maxInside.Load() {
			maxInside.Store(n)
		}
		runs.Add(1)
		<-ctx.Done()
		inside.Add(-1)
	}
	ctxA, stopA := context.WithCancel(context.Background())
	ctxB, stopB := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); ea.Run(ctxA, name, nil, body) }()
	go func() { defer wg.Done(); eb.Run(ctxB, name, nil, body) }()
	wait := func(want int32) {
		for i := 0; i < 500 && runs.Load() < want; i++ {
			time.Sleep(10 * time.Millisecond)
		}
		if runs.Load() < want {
			t.Fatalf("runs %d, want %d", runs.Load(), want)
		}
	}
	wait(1)
	time.Sleep(200 * time.Millisecond)
	if runs.Load() != 1 || maxInside.Load() != 1 {
		t.Fatalf("double run: runs %d max %d", runs.Load(), maxInside.Load())
	}
	// stop whichever replica leads; the other must take over
	if ea.Status()[0].Leader {
		stopA()
	} else {
		stopB()
	}
	wait(2)
	stopA()
	stopB()
	wg.Wait()
	if maxInside.Load() != 1 {
		t.Fatalf("overlap: %d", maxInside.Load())
	}
}
