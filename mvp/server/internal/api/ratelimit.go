package api

import (
	"context"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/ratelimit"
)

// Per-IP limits on unauthenticated traffic (threats D1, I4). They run before
// the audit middleware, so a flood is refused before it writes to the ledger
// or reaches the database:
//
//   - every /api/auth/* request (sign-in, session, logout) takes a token from
//     the IP's auth bucket;
//   - a request without a session cookie takes a token from the IP's
//     anonymous bucket;
//   - a request with a session cookie passes unless that bucket is empty, and
//     takes a token from it afterwards if the cookie did not authenticate, so
//     made-up cookies cannot bypass the limit.
//
// The key is the client address: the TCP peer, or, when the peer is one of
// TrustedProxies (TESSERA_TRUSTED_PROXIES), the rightmost X-Forwarded-For
// entry that is not a trusted proxy, keyed by ratelimit.IPKey (an IPv6
// client by its /64). Both buckets are per-IP limiters with their own LRU;
// other key classes (sessions, user codes) get their own limiters, so they
// cannot evict these. Refusals are 429 rate_limited with Retry-After.

// RateLimit is one token bucket per IP: Burst requests at once, refilled at
// one per Every.
type RateLimit struct {
	Every time.Duration
	Burst int
}

// RateLimits configures the per-IP limits. The zero value is the defaults.
type RateLimits struct {
	Anonymous RateLimit // default 1 per 500 ms, burst 120
	Auth      RateLimit // default 1 per 2 s, burst 30
	MaxKeys   int       // IPs tracked per bucket (LRU), default 10000
}

const (
	defaultAnonEvery = 500 * time.Millisecond
	defaultAnonBurst = 120
	defaultAuthEvery = 2 * time.Second
	defaultAuthBurst = 30
)

func (rl RateLimit) orDefault(every time.Duration, burst int) RateLimit {
	if rl.Every <= 0 {
		rl.Every = every
	}
	if rl.Burst <= 0 {
		rl.Burst = burst
	}
	return rl
}

type limiters struct {
	anon, auth *ratelimit.Limiter
	anonEvery  time.Duration
	authEvery  time.Duration
}

func newLimiters(c RateLimits) *limiters {
	keys := c.MaxKeys
	if keys <= 0 {
		keys = ratelimit.ClassIP.DefaultMaxKeys()
	}
	anon := c.Anonymous.orDefault(defaultAnonEvery, defaultAnonBurst)
	au := c.Auth.orDefault(defaultAuthEvery, defaultAuthBurst)
	return &limiters{anon: ratelimit.New(ratelimit.ClassIP, anon.Every, anon.Burst, keys),
		auth:      ratelimit.New(ratelimit.ClassIP, au.Every, au.Burst, keys),
		anonEvery: anon.Every, authEvery: au.Every}
}

// Where a client address came from (condaccess.Input.IPVia).
const (
	ipViaPeer = "peer"
	ipViaXFF  = "x_forwarded_for"
	// ipViaUnresolved: a trusted proxy did not say who the client is.
	ipViaUnresolved = "unresolved"
)

// walkClient resolves the request's client. The peer is the client unless it
// is one of TrustedProxies, and then the rightmost X-Forwarded-For entry that
// is not itself a trusted proxy. A header sent by any other peer is ignored,
// so a client cannot name its own address. resolved is false when the peer is
// a trusted proxy and no client could be found: the header is missing or
// malformed (the walk stops at a malformed hop), or every hop is a trusted
// proxy. addr is then the last address the walk could trust, the proxy's own.
// The zero Addr means the peer address could not be parsed (also unresolved).
func (s *Server) walkClient(r *http.Request) (addr netip.Addr, via string, resolved bool) {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, "", false
	}
	a, via := ap.Addr().Unmap(), ipViaPeer
	if !s.trustedProxy(a) {
		return a, via, true
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		h, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break // a malformed hop: keep the last address we could trust
		}
		a, via = h.Unmap(), ipViaXFF
		if !s.trustedProxy(a) {
			return a, via, true
		}
	}
	return a, via, false
}

// clientIP is the client address for rate limiting. When the client cannot be
// resolved it falls back to the last trusted address (the proxy's own), which
// is a fine limiter key but must never be used for an access decision: see
// accessClientIP.
func (s *Server) clientIP(r *http.Request) (netip.Addr, string) {
	a, via, _ := s.walkClient(r)
	return a, via
}

// accessClientIP is the client address for conditional access, and fails
// closed: when the client is unresolved it returns the zero Addr and via
// ipViaUnresolved, never the trusted proxy's address (which may sit in a
// corporate range and so make an external client look internal).
func (s *Server) accessClientIP(r *http.Request) (netip.Addr, string, bool) {
	a, via, ok := s.walkClient(r)
	if !ok {
		return netip.Addr{}, ipViaUnresolved, false
	}
	return a, via, true
}

// rateKey is the limiter key of the request's client. A peer address that
// does not parse (not TCP) shares one "invalid" bucket.
func (s *Server) rateKey(r *http.Request) ratelimit.Key {
	a, _ := s.clientIP(r)
	return ratelimit.IPKey(a)
}

func (s *Server) trustedProxy(a netip.Addr) bool {
	for _, p := range s.cfg.TrustedProxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// authenticatedKey marks, for the rate limiter, that the request's session
// authenticated (authorize sets it).
type authenticatedKey struct{}

func markAuthenticated(ctx context.Context) {
	if b, ok := ctx.Value(authenticatedKey{}).(*bool); ok {
		*b = true
	}
}

// rateLimit applies the per-IP limits (see above).
func (s *Server) rateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := s.rateKey(r)
		if authAttempt(r) {
			if !s.limits.auth.Allow(key) {
				tooMany(w, s.limits.authEvery)
				return
			}
		}
		if _, err := r.Cookie(s.authn.Cookies.Name()); err != nil {
			if !s.limits.anon.Allow(key) {
				tooMany(w, s.limits.anonEvery)
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		if s.limits.anon.Exhausted(key) {
			tooMany(w, s.limits.anonEvery)
			return
		}
		authenticated := false
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), authenticatedKey{}, &authenticated)))
		if !authenticated {
			s.limits.anon.Allow(key)
		}
	})
}

// authAttempt reports whether a request counts against the sign-in limit. Every /api/auth/*
// request does, except a signed-in browser reading its own session or session list: the UI
// fetches those on every page load, and counting them locked active users out (UAT #308).
// Those reads still pass the authenticated path, so a bad cookie costs the anonymous budget.
func authAttempt(r *http.Request) bool {
	p := r.URL.Path
	if p != "/api/auth" && !strings.HasPrefix(p, "/api/auth/") {
		return false
	}
	if r.Method == http.MethodGet && (p == "/api/auth/session" || p == "/api/auth/sessions") {
		return false
	}
	return true
}

func tooMany(w http.ResponseWriter, every time.Duration) {
	secs := int((every + time.Second - 1) / time.Second)
	w.Header().Set("Retry-After", strconv.Itoa(max(secs, 1)))
	writeJSON(w, http.StatusTooManyRequests, ojson.Object{{Key: "error", Value: "rate_limited"}})
}
