package connsync

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

var (
	// ErrRateLimited: the source kept answering 429 after every allowed retry.
	ErrRateLimited = errors.New("connsync: rate limited")
	// ErrMalformed: a response body is not the JSON the connector expects.
	ErrMalformed = errors.New("connsync: malformed response")
)

// StatusError is a non-2xx answer. It carries the status and the provider's
// short error code, never the body: bodies can echo request data.
type StatusError struct {
	Method, Path string
	Status       int
	Code         string
}

func (e *StatusError) Error() string {
	s := fmt.Sprintf("%s %s: HTTP %d", e.Method, e.Path, e.Status)
	if e.Code != "" {
		s += " (" + e.Code + ")"
	}
	return s
}

// Unwrap lets errors.Is(err, ErrRateLimited) match an exhausted 429.
func (e *StatusError) Unwrap() error {
	if e.Status == http.StatusTooManyRequests {
		return ErrRateLimited
	}
	return nil
}

// Status returns the HTTP status of a *StatusError in err's chain, or 0.
func Status(err error) int {
	var se *StatusError
	if errors.As(err, &se) {
		return se.Status
	}
	return 0
}

// Backoff is a bounded wait between attempts.
type Backoff struct {
	Base        time.Duration // first exponential delay (default 500ms)
	Max         time.Duration // no wait is ever longer (default 60s)
	MaxAttempts int           // total tries per request (default 5)
	// Sleep waits d or until ctx ends. Tests replace it.
	Sleep func(ctx context.Context, d time.Duration) error
}

func (b Backoff) norm() Backoff {
	if b.Base <= 0 {
		b.Base = 500 * time.Millisecond
	}
	if b.Max <= 0 {
		b.Max = 60 * time.Second
	}
	if b.MaxAttempts <= 0 {
		b.MaxAttempts = 5
	}
	if b.Sleep == nil {
		b.Sleep = SleepCtx
	}
	return b
}

// Delay is the wait before retry number attempt (0 for the first retry).
// A server-supplied wait (Retry-After) wins over the exponential schedule;
// either way the result is bounded by Max.
func (b Backoff) Delay(attempt int, serverWait time.Duration) time.Duration {
	b = b.norm()
	d := serverWait
	if d <= 0 {
		d = b.Base
		for i := 0; i < attempt && d < b.Max; i++ {
			d *= 2
		}
	}
	if d > b.Max {
		d = b.Max
	}
	return d
}

// SleepCtx waits d or until ctx ends.
func SleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// ParseRetryAfter reads a Retry-After value: delta-seconds or an HTTP date.
func ParseRetryAfter(v string, now time.Time) (time.Duration, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		if n < 0 {
			return 0, false
		}
		if n > 1<<31 { // avoid overflow; Backoff caps it anyway
			n = 1 << 31
		}
		return time.Duration(n) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := t.Sub(now); d > 0 {
			return d, true
		}
		return 0, true
	}
	return 0, false
}

// parseResetEpoch reads an X-Rate-Limit-Reset value (Unix seconds).
func parseResetEpoch(v string, now time.Time) (time.Duration, bool) {
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil || n <= 0 {
		return 0, false
	}
	d := time.Unix(n, 0).Sub(now)
	if d < 0 {
		d = 0
	}
	return d, true
}

// Client is a retrying JSON client. HC must come from internal/safehttp.
type Client struct {
	HC      *http.Client
	Backoff Backoff
	// Header is added to every request (User-Agent, Accept).
	Header http.Header
	// Authorize, when set, returns the Authorization header value for a request.
	// It is called per attempt, so a refreshed token is used on retry.
	Authorize func(ctx context.Context) (string, error)
	// OnUnauthorized is called once after a 401; return nil to retry the request
	// once (for example after dropping a cached token).
	OnUnauthorized func()
	// Now is the clock (default time.Now).
	Now func() time.Time
}

// Response is a fully read, size-limited answer.
type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Do sends one request, retrying 429 and 502/503/504 within the Backoff
// bounds. The wait is the server's Retry-After (or Okta's X-Rate-Limit-Reset)
// when given. It also pauses before the next call once a response reports no
// remaining quota (X-Rate-Limit-Remaining: 0). A non-2xx final answer is a
// *StatusError.
func (c *Client) Do(ctx context.Context, method, rawURL string, hdr http.Header, body []byte) (*Response, error) {
	b := c.Backoff.norm()
	path := rawURL
	if u, err := url.Parse(rawURL); err == nil {
		path = u.Path
	}
	reauthed := false
	for attempt := 0; ; attempt++ {
		resp, err := c.once(ctx, method, rawURL, hdr, body)
		if err != nil {
			return nil, unwrapURL(err)
		}
		switch {
		case resp.Status >= 200 && resp.Status < 300:
			if rem := resp.Header.Get("X-Rate-Limit-Remaining"); rem == "0" {
				if d, ok := parseResetEpoch(resp.Header.Get("X-Rate-Limit-Reset"), c.now()); ok && d > 0 {
					if err := b.Sleep(ctx, b.Delay(0, d)); err != nil {
						return nil, err
					}
				}
			}
			return resp, nil
		case resp.Status == http.StatusUnauthorized && c.OnUnauthorized != nil && !reauthed:
			reauthed = true
			c.OnUnauthorized()
			continue
		case (resp.Status == http.StatusTooManyRequests || resp.Status == 502 || resp.Status == 503 || resp.Status == 504) &&
			attempt+1 < b.MaxAttempts:
			wait, ok := ParseRetryAfter(resp.Header.Get("Retry-After"), c.now())
			if !ok {
				if d, ok2 := parseResetEpoch(resp.Header.Get("X-Rate-Limit-Reset"), c.now()); ok2 && resp.Status == http.StatusTooManyRequests {
					wait = d + time.Second
				}
			}
			if err := b.Sleep(ctx, b.Delay(attempt, wait)); err != nil {
				return nil, err
			}
			continue
		}
		return nil, &StatusError{Method: method, Path: path, Status: resp.Status, Code: errorCode(resp.Body)}
	}
}

func (c *Client) once(ctx context.Context, method, rawURL string, hdr http.Header, body []byte) (*Response, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, rdr)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", safehttp.ErrURL, err)
	}
	for k, v := range c.Header {
		req.Header[k] = v
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	if c.Authorize != nil {
		a, err := c.Authorize(ctx)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", a)
	}
	resp, err := c.HC.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return &Response{Status: resp.StatusCode, Header: resp.Header, Body: data}, nil
}

// unwrapURL drops the URL net/http puts in its errors: filters in a query
// string can carry names and addresses, and none of it helps an operator.
func unwrapURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("connsync: request failed: %w", ue.Err)
	}
	return err
}

// errorCode extracts a short provider error code from an error body (Okta
// errorCode, Graph error.code, OAuth error), or "".
func errorCode(body []byte) string {
	var e struct {
		ErrorCode string `json:"errorCode"`
		Error     any    `json:"error"`
	}
	if len(body) > 1<<20 || json.Unmarshal(body, &e) != nil {
		return ""
	}
	code := e.ErrorCode
	switch v := e.Error.(type) {
	case string:
		code = v
	case map[string]any:
		if s, ok := v["code"].(string); ok {
			code = s
		}
	}
	if len(code) > 64 {
		code = code[:64]
	}
	for _, r := range code { // a code is a token, not free text
		if !(r == '_' || r == '.' || r == '-' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return ""
		}
	}
	return code
}

// GetJSON GETs rawURL and decodes the body into v (see DecodeJSON). It
// returns the response headers (pagination links, rate limits).
func (c *Client) GetJSON(ctx context.Context, rawURL string, hdr http.Header, v any) (http.Header, error) {
	resp, err := c.Do(ctx, http.MethodGet, rawURL, hdr, nil)
	if err != nil {
		return nil, err
	}
	if err := DecodeJSON(resp.Body, v); err != nil {
		return nil, err
	}
	return resp.Header, nil
}

// DecodeJSON decodes exactly one JSON value from body into v. An empty body,
// invalid JSON or trailing data is ErrMalformed. The error never quotes the
// body. The size is bounded by the client's safehttp limit before the body
// gets here (safehttp.ErrTooLarge).
func DecodeJSON(body []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: %s", ErrMalformed, shortJSONError(err))
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing data", ErrMalformed)
	}
	return nil
}

func shortJSONError(err error) string {
	var te *json.UnmarshalTypeError
	var se *json.SyntaxError
	switch {
	case errors.As(err, &te):
		return "unexpected type for field " + te.Field
	case errors.As(err, &se):
		return "invalid JSON at offset " + strconv.FormatInt(se.Offset, 10)
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "unexpected end of JSON"
	}
	return "invalid JSON"
}
