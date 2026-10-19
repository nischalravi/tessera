package ratelimit_test

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ratelimit"
)

var t0 = time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)

func ip(s string) ratelimit.Key { return ratelimit.IPKey(netip.MustParseAddr(s)) }

func ipN(i int) ratelimit.Key {
	return ratelimit.IPKey(netip.AddrFrom4([4]byte{198, 51, byte(i >> 8), byte(i)}))
}

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
			l := ratelimit.New(ratelimit.ClassIP, c.every, c.burst, 10)
			for i, off := range c.calls {
				if got := l.AllowAt(ip("1.2.3.4"), t0.Add(off)); got != c.want[i] {
					t.Errorf("call %d at +%v = %t, want %t", i, off, got, c.want[i])
				}
			}
		})
	}
}

func TestKeysAreIndependent(t *testing.T) {
	l := ratelimit.New(ratelimit.ClassIP, time.Minute, 1, 10)
	if !l.AllowAt(ip("192.0.2.1"), t0) || l.AllowAt(ip("192.0.2.1"), t0) {
		t.Fatal("a")
	}
	if !l.AllowAt(ip("192.0.2.2"), t0) {
		t.Error("key b limited by key a")
	}
}

func TestBoundedKeys(t *testing.T) {
	l := ratelimit.New(ratelimit.ClassIP, time.Minute, 1, 3)
	for i := range 100 {
		l.AllowAt(ipN(i), t0)
	}
	if l.Len() != 3 {
		t.Fatalf("tracking %d keys, want at most 3", l.Len())
	}
	// least recently used is evicted: touch 97, add a new key, 98 goes
	l.AllowAt(ipN(97), t0)
	l.AllowAt(ipN(1000), t0)
	if l.AllowAt(ipN(97), t0) {
		t.Error("97 was evicted although recently used")
	}
	if !l.AllowAt(ipN(98), t0) {
		t.Error("98 should have been evicted (fresh bucket)")
	}
}

func TestConcurrent(t *testing.T) {
	l := ratelimit.New(ratelimit.ClassIP, time.Hour, 50, 1000)
	var allowed atomic.Int32
	var wg sync.WaitGroup
	for range 200 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if l.Allow(ip("203.0.113.7")) {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()
	if n := allowed.Load(); n != 50 {
		t.Errorf("%d events allowed, want exactly the burst of 50", n)
	}
}

func mustPanic(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Errorf("%s did not panic", name)
		}
	}()
	fn()
}

func TestNewValidates(t *testing.T) {
	for _, args := range [][3]int{{0, 1, 1}, {1, 0, 1}, {1, 1, 0}} {
		mustPanic(t, fmt.Sprint("New", args), func() {
			ratelimit.New(ratelimit.ClassIP, time.Duration(args[0]), args[1], args[2])
		})
	}
	mustPanic(t, "New(class 0)", func() { ratelimit.New(0, time.Second, 1, 1) })
	mustPanic(t, "New(class 99)", func() { ratelimit.New(99, time.Second, 1, 1) })
}

func TestExhausted(t *testing.T) {
	l := ratelimit.New(ratelimit.ClassIP, time.Second, 2, 10)
	k := ip("192.0.2.9")
	if l.ExhaustedAt(k, t0) || l.Len() != 0 {
		t.Fatal("an untracked key is exhausted or got tracked")
	}
	l.AllowAt(k, t0)
	if l.ExhaustedAt(k, t0) {
		t.Fatal("exhausted with a token left")
	}
	l.AllowAt(k, t0)
	if !l.ExhaustedAt(k, t0) || !l.ExhaustedAt(k, t0) {
		t.Fatal("not exhausted after the burst (or peeking took a token)")
	}
	if l.ExhaustedAt(k, t0.Add(time.Second)) {
		t.Fatal("still exhausted after a refill")
	}
}

// TestIPKey (L7): IPv6 clients share their /64's bucket (zone dropped);
// IPv4-mapped addresses are their IPv4 address; another /64 is another key.
func TestIPKey(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.1":                  "192.0.2.1",
		"::ffff:192.0.2.1":           "192.0.2.1",
		"2001:db8:1:2::7":            "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff:ffff:0:1": "2001:db8:1:2::/64",
		"2001:db8:1:3::7":            "2001:db8:1:3::/64",
		"fe80::1%eth0":               "fe80::/64",
		"::1":                        "::/64",
	} {
		k := ratelimit.IPKey(netip.MustParseAddr(in))
		if k.String() != want || k.Class() != ratelimit.ClassIP {
			t.Errorf("IPKey(%s) = %s (%s), want %s", in, k, k.Class(), want)
		}
	}
	if k := ratelimit.IPKey(netip.Addr{}); k.String() != "invalid" {
		t.Errorf("IPKey(invalid) = %s", k)
	}
	// rotating through a /64 does not earn fresh buckets
	l := ratelimit.New(ratelimit.ClassIP, time.Hour, 2, 100)
	allowed := 0
	for i := range 50 {
		if l.AllowAt(ip(fmt.Sprintf("2001:db8:aa:bb::%x", i+1)), t0) {
			allowed++
		}
	}
	if allowed != 2 || l.Len() != 1 {
		t.Errorf("50 addresses of one /64: %d allowed over %d buckets, want 2 over 1", allowed, l.Len())
	}
	if !l.AllowAt(ip("2001:db8:aa:bc::1"), t0) {
		t.Error("the neighbouring /64 was limited")
	}
}

// TestKeyClassesAreSeparate (L7): a limiter takes keys of its own class
// only, so a flood of user codes fills the (smaller) user-code LRU and never
// evicts a per-IP bucket; session ids and user codes are not kept in clear.
func TestKeyClassesAreSeparate(t *testing.T) {
	if !(ratelimit.ClassUserCode.DefaultMaxKeys() < ratelimit.ClassIP.DefaultMaxKeys() &&
		ratelimit.ClassSession.DefaultMaxKeys() < ratelimit.ClassIP.DefaultMaxKeys()) {
		t.Error("the session and user-code LRUs are not smaller than the IP LRU")
	}
	ips := ratelimit.New(ratelimit.ClassIP, time.Hour, 1, ratelimit.ClassIP.DefaultMaxKeys())
	codes := ratelimit.New(ratelimit.ClassUserCode, time.Hour, 1, ratelimit.ClassUserCode.DefaultMaxKeys())
	victim := ip("198.51.100.10")
	if !ips.AllowAt(victim, t0) || ips.AllowAt(victim, t0) {
		t.Fatal("victim bucket")
	}
	for i := range 5 * ratelimit.ClassUserCode.DefaultMaxKeys() {
		codes.AllowAt(ratelimit.UserCodeKey(fmt.Sprintf("WDJB-%04d", i)), t0)
	}
	if codes.Len() != ratelimit.ClassUserCode.DefaultMaxKeys() {
		t.Errorf("user-code LRU holds %d keys", codes.Len())
	}
	if ips.AllowAt(victim, t0) || ips.Len() != 1 {
		t.Error("user-code attempts reset the victim's per-IP bucket")
	}
	for name, fn := range map[string]func(){
		"user code in the IP limiter": func() { ips.AllowAt(ratelimit.UserCodeKey("WDJB-MJHT"), t0) },
		"IP in the user-code limiter": func() { codes.AllowAt(victim, t0) },
		"session in the IP limiter":   func() { ips.Exhausted(ratelimit.SessionKey("s")) },
		"zero key":                    func() { ips.Allow(ratelimit.Key{}) },
	} {
		mustPanic(t, name, fn)
	}
	if k := ratelimit.UserCodeKey("WDJB-MJHT"); strings.Contains(k.String(), "WDJB") || k.Class() != ratelimit.ClassUserCode {
		t.Errorf("user code key %s (%s)", k, k.Class())
	}
	if k := ratelimit.SessionKey("secret-session-id"); strings.Contains(k.String(), "secret") || k.Class() != ratelimit.ClassSession {
		t.Errorf("session key %s (%s)", k, k.Class())
	}
}
