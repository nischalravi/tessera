// Package ratelimit is an in-process, keyed token-bucket limiter on
// golang.org/x/time/rate (design docs/design/phase-0-platform-security.md §6,
// threats D1 and I4). Keys are per IP, per session or per user code; the
// number of keys is bounded by evicting the least recently used one, so a
// flood of distinct keys cannot exhaust memory. An evicted key starts again
// with a full bucket, which is the accepted trade-off of a bounded
// in-process limiter; a shared store (Valkey) replaces it in production (§21).
//
// The callers (the /token, /device_authorization and device-verify
// endpoints, home-realm discovery) arrive in PR6 and PR10.
package ratelimit

import (
	"container/list"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Limiter limits events per key. It is safe for concurrent use.
type Limiter struct {
	limit   rate.Limit
	burst   int
	maxKeys int

	mu   sync.Mutex
	lru  *list.List // front = most recently used
	keys map[string]*list.Element
}

type entry struct {
	key string
	lim *rate.Limiter
}

// New returns a limiter allowing every bucket `every` refill interval per
// event with a burst of burst, tracking at most maxKeys keys.
func New(every time.Duration, burst, maxKeys int) *Limiter {
	if every <= 0 || burst < 1 || maxKeys < 1 {
		panic("ratelimit: New needs every > 0, burst >= 1 and maxKeys >= 1")
	}
	return &Limiter{limit: rate.Every(every), burst: burst, maxKeys: maxKeys, lru: list.New(),
		keys: make(map[string]*list.Element)}
}

// Allow reports whether one event for key may happen now.
func (l *Limiter) Allow(key string) bool { return l.AllowAt(key, time.Now()) }

// AllowAt reports whether one event for key may happen at now.
func (l *Limiter) AllowAt(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	var lim *rate.Limiter
	if el, ok := l.keys[key]; ok {
		l.lru.MoveToFront(el)
		lim = el.Value.(*entry).lim
	} else {
		lim = rate.NewLimiter(l.limit, l.burst)
		l.keys[key] = l.lru.PushFront(&entry{key: key, lim: lim})
		for l.lru.Len() > l.maxKeys {
			oldest := l.lru.Back()
			l.lru.Remove(oldest)
			delete(l.keys, oldest.Value.(*entry).key)
		}
	}
	return lim.AllowN(now, 1)
}

// Len returns the number of tracked keys.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lru.Len()
}
