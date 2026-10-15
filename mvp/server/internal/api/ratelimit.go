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
// entry that is not a trusted proxy. An IPv6 client is keyed by its /64.
// Refusals are 429 rate_limited with Retry-After.

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
	defaultRateKeys  = 10000
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
		keys = defaultRateKeys
	}
	anon := c.Anonymous.orDefault(defaultAnonEvery, defaultAnonBurst)
	au := c.Auth.orDefault(defaultAuthEvery, defaultAuthBurst)
	return &limiters{anon: ratelimit.New(anon.Every, anon.Burst, keys), auth: ratelimit.New(au.Every, au.Burst, keys),
		anonEvery: anon.Every, authEvery: au.Every}
}

// rateKey is the limiter key of the request's client.
func (s *Server) rateKey(r *http.Request) string {
	a, ok := s.clientIP(r)
	if !ok {
		return r.RemoteAddr
	}
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.String()
	}
	return a.String()
}

// requestIP is the client address as text (the OAuth server records it and
// keys its limiter by it).
func (s *Server) requestIP(r *http.Request) string {
	if a, ok := s.clientIP(r); ok {
		return a.String()
	}
	return r.RemoteAddr
}

// clientIP is the client address: the TCP peer, or, when the peer is a
// trusted proxy, the rightmost X-Forwarded-For entry that is not one.
func (s *Server) clientIP(r *http.Request) (netip.Addr, bool) {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, false
	}
	a := ap.Addr().Unmap()
	if s.trustedProxy(a) {
		hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
		for i := len(hops) - 1; i >= 0; i-- {
			h, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
			if err != nil {
				break // a malformed hop: keep the last address we could trust
			}
			a = h.Unmap()
			if !s.trustedProxy(a) {
				break
			}
		}
	}
	return a, true
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
		if r.URL.Path == "/api/auth" || strings.HasPrefix(r.URL.Path, "/api/auth/") {
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

func tooMany(w http.ResponseWriter, every time.Duration) {
	secs := int((every + time.Second - 1) / time.Second)
	w.Header().Set("Retry-After", strconv.Itoa(max(secs, 1)))
	writeJSON(w, http.StatusTooManyRequests, ojson.Object{{Key: "error", Value: "rate_limited"}})
}
