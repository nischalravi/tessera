package leader

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeCluster is a shared lock table: what Postgres advisory locks give two
// replicas.
type fakeCluster struct {
	mu      sync.Mutex
	holders map[string]*fakeLease
}

type fakeLease struct {
	c    *fakeCluster
	name string
	lost chan struct{}
	once sync.Once
}

func (l *fakeLease) Lost() <-chan struct{} { return l.lost }
func (l *fakeLease) Release() {
	l.c.mu.Lock()
	if l.c.holders[l.name] == l {
		delete(l.c.holders, l.name)
	}
	l.c.mu.Unlock()
}

// lose models a failed session: the holder is told, but the lock itself stays
// held until the holder releases it or it expires (expire).
func (l *fakeLease) lose()   { l.once.Do(func() { close(l.lost) }) }
func (l *fakeLease) expire() { l.lose(); l.Release() }

type fakeLocker struct{ c *fakeCluster }

func (f fakeLocker) TryLock(_ context.Context, name string) (Lease, error) {
	f.c.mu.Lock()
	defer f.c.mu.Unlock()
	if f.c.holders[name] != nil {
		return nil, nil
	}
	l := &fakeLease{c: f.c, name: name, lost: make(chan struct{})}
	f.c.holders[name] = l
	return l, nil
}

func newElector(c *fakeCluster) *Elector {
	return &Elector{Locker: fakeLocker{c}, Retry: 5 * time.Millisecond, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func eventually(t *testing.T, what string, f func() bool) {
	t.Helper()
	for i := 0; i < 400; i++ {
		if f() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out: %s", what)
}

// Two replicas, one loop: never in the loop at once; the standby takes over
// when the leader stops, and when the leader's lease is lost.
func TestElector_NeverRunsALoopTwice(t *testing.T) {
	c := &fakeCluster{holders: map[string]*fakeLease{}}
	var inside, maxInside atomic.Int32
	var runs [2]atomic.Int32
	body := func(i int) func(context.Context) {
		return func(ctx context.Context) {
			n := inside.Add(1)
			for {
				m := maxInside.Load()
				if n <= m || maxInside.CompareAndSwap(m, n) {
					break
				}
			}
			runs[i].Add(1)
			<-ctx.Done()
			inside.Add(-1)
		}
	}
	ctxA, stopA := context.WithCancel(context.Background())
	ctxB, stopB := context.WithCancel(context.Background())
	defer stopB()
	a, b := newElector(c), newElector(c)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); a.Run(ctxA, "siem", nil, body(0)) }()
	go func() { defer wg.Done(); b.Run(ctxB, "siem", nil, body(1)) }()

	eventually(t, "one replica leads", func() bool { return runs[0].Load()+runs[1].Load() == 1 })
	time.Sleep(50 * time.Millisecond)
	if runs[0].Load()+runs[1].Load() != 1 || maxInside.Load() != 1 {
		t.Fatalf("both replicas ran the loop: runs %d/%d max %d", runs[0].Load(), runs[1].Load(), maxInside.Load())
	}
	leaderIsA := runs[0].Load() == 1
	leads := func(e *Elector) bool { s := e.Status(); return len(s) == 1 && s[0].Leader }
	if leads(a) == leads(b) {
		t.Fatalf("exactly one replica must lead: a=%v b=%v", a.Status(), b.Status())
	}

	// the leader's lease is lost: it stops, the other takes over, never overlapping
	c.mu.Lock()
	cur := c.holders["siem"]
	c.mu.Unlock()
	cur.lose()
	_ = leaderIsA
	eventually(t, "someone leads again after a lost lease", func() bool { return runs[0].Load()+runs[1].Load() == 2 })
	if maxInside.Load() != 1 {
		t.Fatalf("overlap during failover: %d", maxInside.Load())
	}

	// a clean stop of replica A releases its lease for B
	stopA()
	eventually(t, "A returns", func() bool { return len(a.Status()) == 1 && !a.Status()[0].Leader })
	stopB()
	wg.Wait()
	if inside.Load() != 0 || maxInside.Load() != 1 {
		t.Fatalf("inside %d max %d", inside.Load(), maxInside.Load())
	}
}

// Different loops have different leases: one replica may lead several.
func TestElector_LoopsAreIndependent(t *testing.T) {
	c := &fakeCluster{holders: map[string]*fakeLease{}}
	a := newElector(c)
	ctx, stop := context.WithCancel(context.Background())
	var n atomic.Int32
	var wg sync.WaitGroup
	for _, name := range []string{"a", "b", "c"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.Run(ctx, name, nil, func(ctx context.Context) { n.Add(1); <-ctx.Done() })
		}()
	}
	eventually(t, "all three loops run", func() bool { return n.Load() == 3 })
	stop()
	wg.Wait()
}

// Without a Locker (SQLite) the loop just runs, and reports itself leader.
func TestElector_NoLockerRunsDirectly(t *testing.T) {
	e := &Elector{}
	ran := false
	e.Run(context.Background(), "x", nil, func(context.Context) { ran = true })
	if !ran {
		t.Fatal("loop did not run")
	}
	if e.Enabled() {
		t.Fatal("enabled without a locker")
	}
}

// A loop that ends by itself while leading is not restarted in a spin.
func TestElector_LoopThatEndsDoesNotSpin(t *testing.T) {
	c := &fakeCluster{holders: map[string]*fakeLease{}}
	e := newElector(c)
	var n int
	e.Run(context.Background(), "once", nil, func(context.Context) { n++ })
	if n != 1 {
		t.Fatalf("ran %d times", n)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.holders) != 0 {
		t.Fatal("lease not released")
	}
}

// A loop that ignores cancellation must not make the lease be released early,
// nor hold Run forever: Run reports it is no longer leader and leaves the lease
// to expire; the standby takes over only after it did, and the stuck loop is
// never run twice by its own replica.
func TestElector_StuckLoopLeavesLeaseToExpire(t *testing.T) {
	c := &fakeCluster{holders: map[string]*fakeLease{}}
	a := newElector(c)
	a.StopGrace = 30 * time.Millisecond
	release := make(chan struct{})
	var aRuns atomic.Int32
	ctx, stop := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		a.Run(ctx, "siem", nil, func(context.Context) { aRuns.Add(1); <-release })
	}()
	eventually(t, "A leads", func() bool { return aRuns.Load() == 1 })
	c.mu.Lock()
	cur := c.holders["siem"]
	c.mu.Unlock()
	cur.lose()
	eventually(t, "A stops claiming leadership", func() bool { s := a.Status(); return len(s) == 1 && !s[0].Leader })
	time.Sleep(50 * time.Millisecond)
	c.mu.Lock()
	still := c.holders["siem"] == cur
	c.mu.Unlock()
	if !still {
		t.Fatal("lease released while the old loop was still running")
	}
	if aRuns.Load() != 1 {
		t.Fatalf("stuck loop restarted on its own replica: %d runs", aRuns.Load())
	}
	cur.expire()
	close(release)
	stop()
	wg.Wait()
}
