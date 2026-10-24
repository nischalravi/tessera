package restgen

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

type exchangeKey struct{}

// IsAuthExchange reports whether r is the request that fetches an OAuth token.
// A dry run (provision.DryRun) holds back every write but lets this POST
// through, or an OAuth target could show nothing after its first step. The mark
// is on the request's context, so it is never sent to the token endpoint.
func IsAuthExchange(r *http.Request) bool {
	v, _ := r.Context().Value(exchangeKey{}).(bool)
	return v
}

// ErrTooLarge is returned when a response is longer than limits.max_response_bytes.
var ErrTooLarge = errors.New("restgen: response is larger than the configured limit")

// Secrets are the sealed half of the authentication. Which one is used follows
// Auth.Type; the others stay empty.
type Secrets struct {
	ClientSecret connsync.Secret // oauth2_client_credentials
	APIKey       connsync.Secret // api_key
	Password     connsync.Secret // basic
	Token        connsync.Secret // bearer
}

// ParseSecrets reads the credential stored sealed with a connection: a JSON
// object with client_secret, api_key, password or token, or for convenience
// the bare secret, which is taken as the one the auth type uses.
func ParseSecrets(authType, raw string) (Secrets, error) {
	var s Secrets
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return s, errors.New("the credential is empty")
	}
	if raw[0] == '{' {
		var in struct {
			ClientSecret string `json:"client_secret"`
			APIKey       string `json:"api_key"`
			Password     string `json:"password"`
			Token        string `json:"token"`
		}
		dec := json.NewDecoder(strings.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&in); err != nil {
			return s, errors.New("the credential is not a JSON object of client_secret, api_key, password or token")
		}
		s = Secrets{connsync.NewSecret(in.ClientSecret), connsync.NewSecret(in.APIKey), connsync.NewSecret(in.Password), connsync.NewSecret(in.Token)}
	} else {
		v := connsync.NewSecret(raw)
		switch authType {
		case AuthOAuth2:
			s.ClientSecret = v
		case AuthAPIKey:
			s.APIKey = v
		case AuthBasic:
			s.Password = v
		case AuthBearer:
			s.Token = v
		}
	}
	return s, s.check(authType)
}

func (s Secrets) check(authType string) error {
	var v connsync.Secret
	var name string
	switch authType {
	case AuthOAuth2:
		v, name = s.ClientSecret, "client_secret"
	case AuthAPIKey:
		v, name = s.APIKey, "api_key"
	case AuthBasic:
		v, name = s.Password, "password"
	case AuthBearer:
		v, name = s.Token, "token"
	default:
		return fmt.Errorf("unknown auth type %q", authType)
	}
	if v.Empty() {
		return fmt.Errorf("the credential has no %s, which %s authentication needs", name, authType)
	}
	return nil
}

// bucket is a token bucket. A 429 empties it and holds it shut for the
// server's Retry-After.
type bucket struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	tokens  float64
	last    time.Time
	blocked time.Time
	now     func() time.Time
}

func newBucket(rate float64, burst int, now func() time.Time) *bucket {
	return &bucket{rate: rate, burst: float64(burst), tokens: float64(burst), last: now(), now: now}
}

// reserve takes one token and returns how long the caller must wait for it.
func (b *bucket) reserve() time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	b.tokens += now.Sub(b.last).Seconds() * b.rate
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	b.last = now
	var wait time.Duration
	if b.blocked.After(now) {
		wait = b.blocked.Sub(now)
	}
	b.tokens--
	if b.tokens < 0 {
		if w := time.Duration(-b.tokens / b.rate * float64(time.Second)); w > wait {
			wait = w
		}
	}
	return wait
}

// penalize holds the bucket shut for d.
func (b *bucket) penalize(d time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if until := b.now().Add(d); until.After(b.blocked) {
		b.blocked = until
	}
	b.tokens = 0
}

// Stats are what a Client has seen, for the readiness checks (counts only).
type Stats struct {
	Requests, Throttled, Retries int
	RetryAfterSeconds            int
	Limit, Remaining             int // from X-RateLimit-Limit/Remaining, when sent (-1: not sent)
}

// Client sends the requests of one Spec. It is safe for concurrent use.
type Client struct {
	spec    *Spec
	lim     Limits
	base    *url.URL
	hc      *http.Client
	secrets Secrets
	bucket  *bucket

	// Now and Sleep are the clock and the wait; tests replace them.
	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) error

	mu       sync.Mutex
	token    string
	tokenExp time.Time
	stats    Stats
}

// NewClient validates the spec's base URL and credential and returns a client.
// hc must come from internal/safehttp. It does not validate the whole Spec;
// Spec.Validate does, at save time.
func NewClient(spec *Spec, sec Secrets, rt connsync.Runtime, hc *http.Client) (*Client, error) {
	if hc == nil {
		return nil, errors.New("restgen: no outbound HTTP client")
	}
	base, err := connsync.ParseBaseURL(spec.BaseURL, rt)
	if err != nil {
		return nil, fmt.Errorf("restgen: %w", err)
	}
	if err := sec.check(spec.Auth.Type); err != nil {
		return nil, fmt.Errorf("restgen: %w", err)
	}
	if spec.Auth.Type == AuthOAuth2 {
		if _, err := connsync.ParseBaseURL(spec.Auth.TokenURL, rt); err != nil {
			return nil, fmt.Errorf("restgen: token_url: %w", err)
		}
	}
	lim := spec.Limits.norm()
	c := &Client{spec: spec, lim: lim, base: base, secrets: sec, Now: time.Now, Sleep: connsync.SleepCtx}
	c.stats.Limit, c.stats.Remaining = -1, -1
	// the ports the spec names explicitly (https://api.example.com:9443) are allowed for those hosts only
	hc = safehttp.WithConfiguredPorts(hc, spec.BaseURL, spec.Auth.TokenURL)
	cp := *hc
	cp.Timeout = time.Duration(lim.TimeoutSeconds) * time.Second
	c.hc = &cp
	c.bucket = newBucket(lim.RequestsPerSecond, lim.Burst, func() time.Time { return c.Now() })
	return c, nil
}

// Stats returns a copy of what the client has seen.
func (c *Client) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stats
}

// Response is a fully read, size-limited answer.
type Response struct {
	Status int
	Header http.Header
	Body   []byte
	// RetryAfter is the wait a 429 or 503 asked for, when it was too long to honour.
	RetryAfter time.Duration
	// TLS is the connection's handshake, nil for plain http.
	TLS *tls.ConnectionState
}

// JSON decodes the body, keeping numbers exact.
func (r *Response) JSON() (any, error) {
	dec := json.NewDecoder(bytes.NewReader(r.Body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, errors.New("the response is not JSON")
	}
	return normalize(v), nil
}

// normalize turns json.Number into float64-or-string-safe values: integers
// that float64 cannot hold exactly stay strings, so large ids survive mapping.
func normalize(v any) any {
	switch t := v.(type) {
	case json.Number:
		if i, err := t.Int64(); err == nil {
			if i > 1<<53 || i < -(1<<53) {
				return t.String()
			}
			return float64(i)
		}
		if f, err := t.Float64(); err == nil {
			return f
		}
		return t.String()
	case []any:
		for i := range t {
			t[i] = normalize(t[i])
		}
	case map[string]any:
		for k := range t {
			t[k] = normalize(t[k])
		}
	}
	return v
}

type request struct {
	method string
	u      *url.URL
	body   []byte
	key    string // Idempotency-Key
	// exchange marks the OAuth token request: sent without the Authorization of the API.
	exchange bool
	form     url.Values
	basic    [2]string
	// anon sends the request without the API credential (a reachability probe).
	anon bool
}

func (rq *request) idempotent() bool {
	return rq.method == http.MethodGet || rq.method == http.MethodHead || rq.method == http.MethodPut || rq.method == http.MethodDelete
}

// do sends one request, waiting for the token bucket first and retrying
// throttling (429, 503 with or without Retry-After) and, for idempotent
// methods, 502/504 and transport failures, within limits.max_attempts. The
// final answer is returned whatever its status; an error is a failure to get
// any answer.
func (c *Client) do(ctx context.Context, rq request) (*Response, error) {
	maxWait := time.Duration(c.lim.MaxRetryWaitSeconds) * time.Second
	reauthed := false
	for attempt := 0; ; attempt++ {
		if err := c.Sleep(ctx, c.bucket.reserve()); err != nil {
			return nil, err
		}
		resp, err := c.once(ctx, rq)
		c.mu.Lock()
		c.stats.Requests++
		c.mu.Unlock()
		last := attempt+1 >= c.lim.MaxAttempts
		if err != nil {
			if tooLarge(err) || ctx.Err() != nil || !rq.idempotent() || last {
				return nil, err
			}
			if err := c.Sleep(ctx, c.backoff(attempt, 0)); err != nil {
				return nil, err
			}
			c.count(func(s *Stats) { s.Retries++ })
			continue
		}
		c.observe(resp)
		switch {
		case resp.Status == http.StatusUnauthorized && !rq.exchange && c.spec.Auth.Type == AuthOAuth2 && !reauthed:
			reauthed = true
			c.mu.Lock()
			c.token = ""
			c.mu.Unlock()
			continue
		case resp.Status == http.StatusTooManyRequests || resp.Status == http.StatusServiceUnavailable ||
			(rq.idempotent() && (resp.Status == http.StatusBadGateway || resp.Status == http.StatusGatewayTimeout)):
			wait, ok := connsync.ParseRetryAfter(resp.Header.Get("Retry-After"), c.Now())
			if resp.Status == http.StatusTooManyRequests {
				c.count(func(s *Stats) {
					s.Throttled++
					if sec := int(wait.Round(time.Second) / time.Second); sec > s.RetryAfterSeconds {
						s.RetryAfterSeconds = sec
					}
				})
			}
			if ok && wait > maxWait {
				resp.RetryAfter = wait
				return resp, nil
			}
			if last {
				resp.RetryAfter = wait
				return resp, nil
			}
			d := c.backoff(attempt, wait)
			c.bucket.penalize(d)
			if err := c.Sleep(ctx, d); err != nil {
				return nil, err
			}
			c.count(func(s *Stats) { s.Retries++ })
			continue
		}
		return resp, nil
	}
}

func (c *Client) backoff(attempt int, serverWait time.Duration) time.Duration {
	return connsync.Backoff{Base: 500 * time.Millisecond, Max: time.Duration(c.lim.MaxRetryWaitSeconds) * time.Second}.Delay(attempt, serverWait)
}

func (c *Client) count(f func(*Stats)) {
	c.mu.Lock()
	f(&c.stats)
	c.mu.Unlock()
}

func (c *Client) observe(r *Response) {
	get := func(names ...string) (int, bool) {
		for _, n := range names {
			if v := r.Header.Get(n); v != "" {
				if i, err := strconv.Atoi(v); err == nil {
					return i, true
				}
			}
		}
		return 0, false
	}
	l, lok := get("X-RateLimit-Limit", "RateLimit-Limit")
	rem, rok := get("X-RateLimit-Remaining", "RateLimit-Remaining")
	c.mu.Lock()
	defer c.mu.Unlock()
	if lok {
		c.stats.Limit = l
	}
	if rok {
		c.stats.Remaining = rem
	}
}

func (c *Client) once(ctx context.Context, rq request) (*Response, error) {
	u := rq.u
	hdr := http.Header{"Accept": {"application/json"}}
	for k, v := range c.spec.Headers {
		hdr.Set(k, v)
	}
	var body []byte
	switch {
	case rq.exchange:
		body = []byte(rq.form.Encode())
		hdr.Set("Content-Type", "application/x-www-form-urlencoded")
		ctx = context.WithValue(ctx, exchangeKey{}, true)
	case rq.body != nil:
		body = rq.body
		hdr.Set("Content-Type", "application/json")
	}
	if rq.key != "" && rq.method != http.MethodGet {
		hdr.Set("Idempotency-Key", rq.key)
	}
	var basicUser, basicPass string
	var useBasic bool
	if rq.exchange {
		basicUser, basicPass, useBasic = rq.basic[0], rq.basic[1], rq.basic[0] != ""
	} else if !rq.anon {
		var err error
		if u, useBasic, basicUser, basicPass, err = c.authorize(ctx, rq.u, hdr); err != nil {
			return nil, err
		}
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, rq.method, u.String(), rd)
	if err != nil {
		return nil, errors.New("restgen: the request is not valid")
	}
	req.Header = hdr
	if useBasic {
		req.SetBasicAuth(basicUser, basicPass)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			// the URL may carry an API key in its query; keep the cause only
			return nil, fmt.Errorf("restgen: request failed: %w", ue.Err)
		}
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, c.lim.MaxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("restgen: reading the response failed: %w", err)
	}
	if int64(len(data)) > c.lim.MaxResponseBytes {
		return nil, ErrTooLarge
	}
	return &Response{Status: resp.StatusCode, Header: resp.Header, Body: data, TLS: resp.TLS}, nil
}

// authorize adds the credential to the request headers (or returns a URL with
// the API key in its query) and says whether to use HTTP basic.
func (c *Client) authorize(ctx context.Context, u *url.URL, hdr http.Header) (*url.URL, bool, string, string, error) {
	a := c.spec.Auth
	switch a.Type {
	case AuthBearer:
		hdr.Set("Authorization", "Bearer "+c.secrets.Token.Reveal())
	case AuthBasic:
		return u, true, a.Username, c.secrets.Password.Reveal(), nil
	case AuthAPIKey:
		if a.In == "header" {
			hdr.Set(a.Name, a.Prefix+c.secrets.APIKey.Reveal())
		} else {
			cp := *u
			q := cp.Query()
			q.Set(a.Name, c.secrets.APIKey.Reveal())
			cp.RawQuery = q.Encode()
			return &cp, false, "", "", nil
		}
	case AuthOAuth2:
		tok, err := c.accessToken(ctx)
		if err != nil {
			return nil, false, "", "", err
		}
		hdr.Set("Authorization", "Bearer "+tok)
	}
	return u, false, "", "", nil
}

// accessToken returns a cached OAuth token, fetching one when none is held or
// it is within a minute of expiry.
func (c *Client) accessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	if c.token != "" && c.Now().Before(c.tokenExp.Add(-time.Minute)) {
		t := c.token
		c.mu.Unlock()
		return t, nil
	}
	c.mu.Unlock()

	a := c.spec.Auth
	tu, err := url.Parse(a.TokenURL)
	if err != nil {
		return "", errors.New("restgen: token_url is not valid")
	}
	form := url.Values{"grant_type": {"client_credentials"}}
	if len(a.Scopes) > 0 {
		form.Set("scope", strings.Join(a.Scopes, " "))
	}
	rq := request{method: http.MethodPost, u: tu, exchange: true, form: form}
	if a.ClientAuth == "body" {
		form.Set("client_id", a.ClientID)
		form.Set("client_secret", c.secrets.ClientSecret.Reveal())
	} else {
		rq.basic = [2]string{url.QueryEscape(a.ClientID), url.QueryEscape(c.secrets.ClientSecret.Reveal())}
	}
	resp, err := c.do(ctx, rq)
	if err != nil {
		return "", fmt.Errorf("restgen: token request failed: %w", err)
	}
	if resp.Status < 200 || resp.Status > 299 {
		return "", &StatusError{Status: resp.Status, Op: "token request", Detail: errorDetail(resp.Body)}
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(resp.Body, &tr); err != nil || tr.AccessToken == "" {
		return "", errors.New("restgen: the token endpoint answered without an access_token")
	}
	if tr.TokenType != "" && !strings.EqualFold(tr.TokenType, "bearer") {
		return "", fmt.Errorf("restgen: the token endpoint issued a %q token, not a bearer token", tr.TokenType)
	}
	if tr.ExpiresIn <= 0 {
		tr.ExpiresIn = 300
	}
	if tr.ExpiresIn > 86400 {
		tr.ExpiresIn = 86400
	}
	c.mu.Lock()
	c.token, c.tokenExp = tr.AccessToken, c.Now().Add(time.Duration(tr.ExpiresIn)*time.Second)
	c.mu.Unlock()
	return tr.AccessToken, nil
}

// StatusError is an answer the connector did not accept.
type StatusError struct {
	Status     int
	Op         string
	Detail     string
	RetryAfter time.Duration
}

func (e *StatusError) Error() string {
	msg := fmt.Sprintf("%s: HTTP %d", e.Op, e.Status)
	switch e.Status {
	case http.StatusUnauthorized, http.StatusForbidden:
		msg = fmt.Sprintf("%s: the system refused the credential (HTTP %d)", e.Op, e.Status)
	case http.StatusTooManyRequests:
		msg = fmt.Sprintf("%s: rate limited (HTTP 429)", e.Op)
	}
	if e.Detail != "" {
		msg += ": " + e.Detail
	}
	return msg
}

// errorDetail is a short, single-line excerpt of an error body: the standard
// error fields when there are any, never the whole body.
func errorDetail(body []byte) string {
	var e struct {
		Error            any    `json:"error"`
		ErrorDescription string `json:"error_description"`
		Message          string `json:"message"`
		Detail           string `json:"detail"`
	}
	if json.Unmarshal(body, &e) != nil {
		return ""
	}
	parts := []string{}
	switch t := e.Error.(type) {
	case string:
		parts = append(parts, t)
	case map[string]any:
		if m, ok := t["message"].(string); ok {
			parts = append(parts, m)
		}
	}
	for _, s := range []string{e.ErrorDescription, e.Message, e.Detail} {
		if s != "" {
			parts = append(parts, s)
		}
	}
	out := strings.Join(strings.Fields(strings.Join(parts, ": ")), " ")
	if len(out) > 160 {
		out = out[:160] + "…"
	}
	return out
}

// tooLarge reports whether err is a response over the size limit, ours or the
// shared outbound client's. It is not retried: asking again returns the same.
func tooLarge(err error) bool {
	return errors.Is(err, ErrTooLarge) || errors.Is(err, safehttp.ErrTooLarge)
}
