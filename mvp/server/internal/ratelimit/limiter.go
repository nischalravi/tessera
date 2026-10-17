// Package ratelimit is an in-process, keyed token-bucket limiter on
// golang.org/x/time/rate (design docs/design/phase-0-platform-security.md §6,
// threats D1 and I4). Keys are per IP, per session or per user code; the
// number of keys is bounded by evicting the least recently used one, so a
// flood of distinct keys cannot exhaust memory. An evicted key starts again
// with a full bucket, which is the accepted trade-off of a bounded
// in-process limiter; a shared store (Valkey) replaces it in production (§21).
//
// Every Limiter serves one key Class and has its own LRU, sized for that
// class, and refuses (panics on) a key of another class. So a flood of one
// kind of key (made-up user codes, say) can only evict keys of its own kind
// and never resets the per-IP buckets. Keys are built only by IPKey,
// SessionKey and UserCodeKey: IPv6 clients are keyed by their /64 (one
// host usually controls a whole /64), and session ids and user codes are
// kept only as a truncated SHA-256.
//
// The API limits anonymous and /api/auth/* requests per IP before they reach
// the audit ledger (internal/api ratelimit.go); the /token,
// /device_authorization and device-verify limits arrive in PR10.
package ratelimit

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Class is the kind of thing a key identifies.
type Class uint8

// Key classes.
const (
	ClassIP Class = iota + 1
	ClassSession
	ClassUserCode
)

func (c Class) String() string {
	switch c {
	case ClassIP:
		return "ip"
	case ClassSession:
		return "session"
	case ClassUserCode:
		return "user_code"
	}
	return fmt.Sprintf("class(%d)", uint8(c))
}

// DefaultMaxKeys is the LRU size for a class: many client addresses, fewer
// live sessions, and few user codes in flight at once.
func (c Class) DefaultMaxKeys() int {
	switch c {
	case ClassIP:
		return 10000
	case ClassSession:
		return 4096
	case ClassUserCode:
		return 1024
	}
	return 0
}

// IPv6Prefix is the prefix length IPv6 clients are keyed by.
const IPv6Prefix = 64

// Key identifies one bucket. The zero Key is invalid.
type Key struct {
	class Class
	id    string
}

// Class returns the key's class.
func (k Key) Class() Class { return k.class }

// String returns the key's identifier (an address or prefix, or a hash).
func (k Key) String() string { return k.id }

// IPKey is the key of a client address: an IPv4 address (IPv4-mapped IPv6
// unmapped first), or the /64 of an IPv6 address, without any zone. An
// invalid address maps to one shared "invalid" bucket.
func IPKey(a netip.Addr) Key {
	a = a.WithZone("").Unmap()
	switch {
	case !a.IsValid():
		return Key{ClassIP, "invalid"}
	case a.Is6():
		p, err := a.Prefix(IPv6Prefix)
		if err != nil {
			return Key{ClassIP, "invalid"}
		}
		return Key{ClassIP, p.String()}
	}
	return Key{ClassIP, a.String()}
}

// SessionKey is the key of a session id (kept only as a hash).
func SessionKey(id string) Key { return Key{ClassSession, digest(id)} }

// UserCodeKey is the key of a device-flow user code (kept only as a hash).
func UserCodeKey(code string) Key { return Key{ClassUserCode, digest(code)} }

func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:16])
}

// Limiter limits events per key of one class. It is safe for concurrent use.
type Limiter struct {
	class   Class
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

// New returns a limiter for keys of class, allowing every bucket `every`
// refill interval per event with a burst of burst, tracking at most maxKeys
// keys (class.DefaultMaxKeys() is the usual size).
func New(class Class, every time.Duration, burst, maxKeys int) *Limiter {
	if class.DefaultMaxKeys() == 0 || every <= 0 || burst < 1 || maxKeys < 1 {
		panic("ratelimit: New needs a known class, every > 0, burst >= 1 and maxKeys >= 1")
	}
	return &Limiter{class: class, limit: rate.Every(every), burst: burst, maxKeys: maxKeys, lru: list.New(),
		keys: make(map[string]*list.Element)}
}

// Class returns the class of keys l accepts.
func (l *Limiter) Class() Class { return l.class }

// check panics on a key of another class (or the zero Key): mixing classes
// in one LRU is a programming error.
func (l *Limiter) check(k Key) {
	if k.class != l.class {
		panic(fmt.Sprintf("ratelimit: a %s key used with a %s limiter", k.class, l.class))
	}
}

// Allow reports whether one event for k may happen now.
func (l *Limiter) Allow(k Key) bool { return l.AllowAt(k, time.Now()) }

// AllowAt reports whether one event for k may happen at now.
func (l *Limiter) AllowAt(k Key, now time.Time) bool {
	l.check(k)
	l.mu.Lock()
	defer l.mu.Unlock()
	var lim *rate.Limiter
	if el, ok := l.keys[k.id]; ok {
		l.lru.MoveToFront(el)
		lim = el.Value.(*entry).lim
	} else {
		lim = rate.NewLimiter(l.limit, l.burst)
		l.keys[k.id] = l.lru.PushFront(&entry{key: k.id, lim: lim})
		for l.lru.Len() > l.maxKeys {
			oldest := l.lru.Back()
			l.lru.Remove(oldest)
			delete(l.keys, oldest.Value.(*entry).key)
		}
	}
	return lim.AllowN(now, 1)
}

// Exhausted reports whether k's bucket is empty now (no event would be
// allowed), without taking a token. An untracked key is not exhausted.
func (l *Limiter) Exhausted(k Key) bool { return l.ExhaustedAt(k, time.Now()) }

// ExhaustedAt is Exhausted at now.
func (l *Limiter) ExhaustedAt(k Key, now time.Time) bool {
	l.check(k)
	l.mu.Lock()
	defer l.mu.Unlock()
	el, ok := l.keys[k.id]
	if !ok {
		return false
	}
	return el.Value.(*entry).lim.TokensAt(now) < 1
}

// Len returns the number of tracked keys.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lru.Len()
}
