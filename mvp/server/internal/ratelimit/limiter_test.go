package ratelimit_test

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ratelimit"
)

var t0 = time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)

func TestLimiter(t *testing.T) {
	cases := []struct {
		name  string
		every time.Duration
		burst int
		calls []time.Duration // offsets from t0
		want  []bool
	}{
		{"burst then deny", time.Second, 3, []time.Duration{0, 0, 0, 0}, []bool{true, true, true, false}},
		{"refills over time", time.Second, 1, []time.Duration{0, 0, time.Second, time.Second}, []bool{true, false, true, false}},
		{"partial refill is not enough", 5 * time.Second, 1, []time.Duration{0, 4 * time.Second, 5 * time.Second}, []bool{true, false, true}},
		{"burst refills fully after a pause", time.Second, 2, []time.Duration{0, 0, 0, 10 * time.Second, 10 * time.Second, 10 * time.Second},
			[]bool{true, true, false, true, true, false}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l := ratelimit.New(c.every, c.burst, 10)
			for i, off := range c.calls {
				if got := l.AllowAt("1.2.3.4", t0.Add(off)); got != c.want[i] {
					t.Errorf("call %d at +%v = %t, want %t", i, off, got, c.want[i])
				}
			}
		})
	}
}

func TestKeysAreIndependent(t *testing.T) {
	l := ratelimit.New(time.Minute, 1, 10)
	if !l.AllowAt("a", t0) || l.AllowAt("a", t0) {
		t.Fatal("a")
	}
	if !l.AllowAt("b", t0) {
		t.Error("key b limited by key a")
	}
}

func TestBoundedKeys(t *testing.T) {
	l := ratelimit.New(time.Minute, 1, 3)
	for i := range 100 {
		l.AllowAt(fmt.Sprint("k", i), t0)
	}
	if l.Len() != 3 {
		t.Fatalf("tracking %d keys, want at most 3", l.Len())
	}
	// least recently used is evicted: touch k97, add a new key, k98 goes
	l.AllowAt("k97", t0)
	l.AllowAt("new", t0)
	if l.AllowAt("k97", t0) {
		t.Error("k97 was evicted although recently used")
	}
	if !l.AllowAt("k98", t0) {
		t.Error("k98 should have been evicted (fresh bucket)")
	}
}

func TestConcurrent(t *testing.T) {
	l := ratelimit.New(time.Hour, 50, 1000)
	var allowed atomic.Int32
	var wg sync.WaitGroup
	for range 200 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if l.Allow("shared") {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()
	if n := allowed.Load(); n != 50 {
		t.Errorf("%d events allowed, want exactly the burst of 50", n)
	}
}

func TestNewValidates(t *testing.T) {
	for _, args := range [][3]int{{0, 1, 1}, {1, 0, 1}, {1, 1, 0}} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("New%v did not panic", args)
				}
			}()
			ratelimit.New(time.Duration(args[0]), args[1], args[2])
		}()
	}
}

func TestExhausted(t *testing.T) {
	l := ratelimit.New(time.Second, 2, 10)
	if l.ExhaustedAt("k", t0) || l.Len() != 0 {
		t.Fatal("an untracked key is exhausted or got tracked")
	}
	l.AllowAt("k", t0)
	if l.ExhaustedAt("k", t0) {
		t.Fatal("exhausted with a token left")
	}
	l.AllowAt("k", t0)
	if !l.ExhaustedAt("k", t0) || !l.ExhaustedAt("k", t0) {
		t.Fatal("not exhausted after the burst (or peeking took a token)")
	}
	if l.ExhaustedAt("k", t0.Add(time.Second)) {
		t.Fatal("still exhausted after a refill")
	}
}
