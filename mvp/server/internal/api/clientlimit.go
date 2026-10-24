package api

import (
	"container/list"
	"context"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/obs"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Per-machine-client rate limits (issue #587). Every request of an OAuth
// client (a token principal, authenticated by authorize) takes a token from
// the bucket of its tenant and client: Burst requests at once, refilled at
// PerMinute a minute. The default is ClientRate (TESSERA_API_CLIENT_RATE_*); a
// client's own row in api_client_limits replaces it (POST
// /api/admin/api-clients/{client_id}/rate-limit).
//
// Answers carry the draft-ietf-httpapi-ratelimit-headers fields: RateLimit-Limit
// (the burst), RateLimit-Remaining, RateLimit-Reset (seconds until the bucket
// is full) and RateLimit-Policy (`<per minute>;w=60`). A refused request is 429
// rate_limited with Retry-After. It is audited like any other request (its
// http.request event has status 429, outcome failure, and names the client)
// and counted in tessera_api_client_rate_limited_total.
//
// The buckets live in this process (an LRU of clientBucketKeys entries), like
// the per-IP buckets; so does a 30 second cache of the per-client overrides.

// ClientRate is the default bucket of a machine client. The zero value means
// 120 requests at once and 600 a minute; PerMinute 0 with a Burst turns the
// limit off.
type ClientRate struct {
	Burst, PerMinute int
}

const (
	defaultClientBurst     = 120
	defaultClientPerMinute = 600
	clientBucketKeys       = 10000
	clientLimitCacheTTL    = 30 * time.Second
)

func (c ClientRate) orDefault() ClientRate {
	if c.Burst <= 0 {
		return ClientRate{defaultClientBurst, defaultClientPerMinute}
	}
	return c
}

// rateLimitedTotal counts requests refused by a client's limit. No client or
// tenant label: those are unbounded (the audit log names the client).
var rateLimitedTotal = obs.Default.NewCounter("tessera_api_client_rate_limited_total",
	"Requests of machine clients refused with 429 by their rate limit.")

type bucketKey struct {
	tenant tenancy.ID
	client string
}

type clientBucket struct {
	key bucketKey
	lim *rate.Limiter
	cfg ClientRate
}

type cachedLimit struct {
	cfg   ClientRate
	until time.Time
}

type clientLimiter struct {
	mu    sync.Mutex
	def   ClientRate
	lru   *list.List // of *clientBucket, front = most recent
	items map[bucketKey]*list.Element
	cache map[bucketKey]cachedLimit
}

func newClientLimiter(def ClientRate) *clientLimiter {
	return &clientLimiter{def: def.orDefault(), lru: list.New(), items: map[bucketKey]*list.Element{}, cache: map[bucketKey]cachedLimit{}}
}

// clientDecision is the outcome of one request against its bucket.
type clientDecision struct {
	Allowed    bool
	Burst      int
	PerMinute  int
	Remaining  int
	ResetSecs  int
	RetryAfter int
}

// limitOf is the client's bucket configuration: its override, else the default.
func (l *clientLimiter) limitOf(ctx context.Context, db *store.DB, now time.Time, k bucketKey) (ClientRate, error) {
	l.mu.Lock()
	if c, ok := l.cache[k]; ok && now.Before(c.until) {
		l.mu.Unlock()
		return c.cfg, nil
	}
	l.mu.Unlock()
	cfg := l.def
	err := db.ReadTenant(ctx, k.tenant, func(tx *store.TenantTx) error {
		o, err := tx.APIClientLimit(k.client)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		cfg = ClientRate{o.Burst, o.PerMinute}
		return nil
	})
	if err != nil {
		return ClientRate{}, err
	}
	l.mu.Lock()
	if len(l.cache) >= clientBucketKeys {
		clear(l.cache)
	}
	l.cache[k] = cachedLimit{cfg, now.Add(clientLimitCacheTTL)}
	l.mu.Unlock()
	return cfg, nil
}

// forget drops the cached override of a client (after it is changed).
func (l *clientLimiter) forget(k bucketKey) {
	l.mu.Lock()
	delete(l.cache, k)
	l.mu.Unlock()
}

// take spends one token of the client's bucket.
func (l *clientLimiter) take(now time.Time, k bucketKey, cfg ClientRate) clientDecision {
	l.mu.Lock()
	defer l.mu.Unlock()
	var b *clientBucket
	if el, ok := l.items[k]; ok {
		l.lru.MoveToFront(el)
		b = el.Value.(*clientBucket)
		if b.cfg != cfg { // the client's limit was changed
			b.lim.SetLimitAt(now, perMinute(cfg))
			b.lim.SetBurstAt(now, cfg.Burst)
			b.cfg = cfg
		}
	} else {
		b = &clientBucket{key: k, lim: rate.NewLimiter(perMinute(cfg), cfg.Burst), cfg: cfg}
		l.items[k] = l.lru.PushFront(b)
		for l.lru.Len() > clientBucketKeys {
			oldest := l.lru.Back()
			l.lru.Remove(oldest)
			delete(l.items, oldest.Value.(*clientBucket).key)
		}
	}
	d := clientDecision{Burst: cfg.Burst, PerMinute: cfg.PerMinute}
	res := b.lim.ReserveN(now, 1)
	if delay := res.DelayFrom(now); !res.OK() || delay > 0 {
		res.CancelAt(now)
		d.RetryAfter = max(int((delay+time.Second-1)/time.Second), 1)
		if !res.OK() {
			d.RetryAfter = 1
		}
		d.ResetSecs = int((float64(cfg.Burst)*60 + float64(cfg.PerMinute) - 1) / float64(cfg.PerMinute)) // an empty bucket refilling
		return d
	}
	tokens := b.lim.TokensAt(now)
	d.Allowed = true
	d.Remaining = max(int(tokens), 0)
	d.ResetSecs = int((float64(cfg.Burst) - tokens) * 60 / float64(cfg.PerMinute))
	return d
}

func perMinute(c ClientRate) rate.Limit { return rate.Limit(float64(c.PerMinute) / 60) }

// limitClient applies the principal's rate limit and sets the RateLimit-*
// headers. It reports false when the request was refused (and answered).
func (s *Server) limitClient(w http.ResponseWriter, r *http.Request, p *auth.Principal) bool {
	if p.Kind != auth.KindAPIClient || s.clientLimits.def.PerMinute <= 0 {
		return true
	}
	now := s.clock()
	k := bucketKey{p.TenantID, p.ClientID}
	cfg, err := s.clientLimits.limitOf(r.Context(), s.store, now, k)
	if err != nil {
		if clientCanceled(r, err) {
			return true // the client hung up; nothing is answered
		}
		s.log.Error("client rate limit lookup failed", "method", r.Method, "err", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return false
	}
	d := s.clientLimits.take(now, k, cfg)
	h := w.Header()
	h.Set("RateLimit-Limit", strconv.Itoa(d.Burst))
	h.Set("RateLimit-Remaining", strconv.Itoa(d.Remaining))
	h.Set("RateLimit-Reset", strconv.Itoa(d.ResetSecs))
	h.Set("RateLimit-Policy", strconv.Itoa(d.PerMinute)+";w=60")
	if d.Allowed {
		return true
	}
	h.Set("Retry-After", strconv.Itoa(d.RetryAfter))
	rateLimitedTotal.Inc()
	writeJSON(w, http.StatusTooManyRequests, ojson.Object{{Key: "error", Value: "rate_limited"},
		{Key: "detail", Value: "The client's request rate limit is exhausted"}})
	return false
}
