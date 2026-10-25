// Package awsorg is the read-only AWS connector (design
// docs/design/aws-effective-permission-evaluator.md §11.1). It collects one
// model.Snapshot of an AWS estate: Organizations (SCPs, RCPs, the tree), IAM
// (users, groups, roles, policies, boundaries, trust policies), and the
// resource policies of S3, KMS, SQS, SNS, Secrets Manager, Lambda, ECR and VPC
// endpoints, plus Identity Center permission sets.
//
// It uses no AWS SDK. Every call is an HTTPS request signed with the stdlib
// SigV4 signer (internal/aws/sigv4) and sent through a Doer, which in
// production is the safehttp SSRF-guarded client (NewHTTPClient). Only read
// actions are used; ReaderPolicy is the IAM policy the customer's role needs
// and is verified read-only against the action catalog in tests.
//
// Fail-closed contract (design §3.3): a stored policy that does not parse, a
// statement dropped as an ingest anomaly, and a read that fails are never
// skipped silently. Each is recorded as a Finding with the scope of decisions
// it could affect (Findings.Affects), and every such decision is UNSUPPORTED
// with POLICY_UNPARSEABLE.
package awsorg

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/sigv4"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// HTTP limits for the client. The safehttp defaults (5 s, 512 KiB) suit OIDC
// discovery, not IAM: a GetAccountAuthorizationDetails page can be megabytes.
// The SSRF guard itself is unchanged.
const (
	httpTimeout      = 2 * time.Minute
	httpMaxBodyBytes = 256 << 20
	// maxResponseBytes bounds one response the client reads.
	maxResponseBytes = 128 << 20
)

// NewHTTPClient returns the *http.Client the connector must use: safehttp's
// SSRF-guarded client (https only, every resolved address checked in the
// dialer, no proxies, no redirects off the host) with limits sized for AWS API
// responses. The environment and the loopback exception come from the
// validated configuration (safehttp.ForConfigLimits).
func NewHTTPClient(c *config.Config) (*http.Client, error) {
	return safehttp.ForConfigLimits(c, httpTimeout, httpMaxBodyBytes)
}

// Doer sends one request. *http.Client from NewHTTPClient is the production
// Doer; tests use awsreplay.Replay.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Client signs and sends AWS API requests, with backoff on throttling. The
// zero value is not usable: set HTTP. It holds no credentials; each call
// passes them.
type Client struct {
	HTTP Doer
	// Now is the signing clock (default time.Now).
	Now func() time.Time
	// Sleep waits between attempts, returning early with ctx's error (default:
	// a timer).
	Sleep func(ctx context.Context, d time.Duration) error
	// Jitter returns a duration in [0, max] (default: crypto/rand).
	Jitter func(max time.Duration) time.Duration
	// MaxAttempts is the number of tries per call, the first included
	// (default 6).
	MaxAttempts int
	// BaseDelay and MaxDelay bound the exponential backoff (defaults 200 ms,
	// 20 s).
	BaseDelay, MaxDelay time.Duration
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Client) attempts() int {
	if c.MaxAttempts > 0 {
		return c.MaxAttempts
	}
	return 6
}

// Error is an error response from AWS.
type Error struct {
	Service string // the signing name, e.g. "iam"
	Op      string
	Status  int
	Code    string // e.g. "AccessDenied", "NoSuchBucketPolicy"
	Message string

	retryAfter time.Duration // the Retry-After header, for the backoff
}

func (e *Error) Error() string {
	return fmt.Sprintf("aws: %s %s: %d %s: %s", e.Service, e.Op, e.Status, e.Code, e.Message)
}

// IsCode reports whether err is an *Error with one of the codes.
func IsCode(err error, codes ...string) bool {
	var ae *Error
	if !errors.As(err, &ae) {
		return false
	}
	for _, c := range codes {
		if ae.Code == c {
			return true
		}
	}
	return false
}

// IsAccessDenied reports an authorization failure (the account's role lacks a
// permission, or an SCP denies the call).
func IsAccessDenied(err error) bool {
	return IsCode(err, "AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "AuthFailure",
		"UnauthorizedAccess", "AWSOrganizationsNotInUseException")
}

// throttleCodes are the error codes AWS services use for throttling.
var throttleCodes = map[string]bool{
	"Throttling": true, "ThrottlingException": true, "ThrottledException": true, "RequestThrottled": true,
	"RequestThrottledException": true, "TooManyRequestsException": true, "RequestLimitExceeded": true,
	"SlowDown": true, "ProvisionedThroughputExceededException": true, "TransactionInProgressException": true,
	"BandwidthLimitExceeded": true, "EC2ThrottledException": true, "PriorRequestNotComplete": true,
	"ServiceUnavailable": true, "RequestTimeout": true, "RequestTimeoutException": true, "InternalError": true,
	"InternalFailure": true, "ServiceUnavailableException": true,
}

func retryable(status int, code string) bool {
	return throttleCodes[code] || status == http.StatusTooManyRequests || status == http.StatusBadGateway ||
		status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout || status == http.StatusInternalServerError
}

// call describes one request.
type call struct {
	Service string // signing name: iam, sts, organizations, s3, kms, ...
	Host    string
	Region  string // signing region
	Method  string
	Path    string
	Query   url.Values
	Header  http.Header
	Body    []byte
	Op      string // for errors, e.g. "GetAccountAuthorizationDetails"
	// MaxBytes bounds the response (default maxResponseBytes): a log file is
	// read with a limit of its own, far below what an IAM page can be.
	MaxBytes int
	// Unsigned sends the request without SigV4 (sts:AssumeRoleWithWebIdentity,
	// which authenticates by the token in its body).
	Unsigned bool
}

// do sends the call, retrying throttling and server errors with exponential
// backoff and full jitter, and returns the response body.
func (c *Client) do(ctx context.Context, creds sigv4.Credentials, cl call) ([]byte, http.Header, error) {
	var last error
	for attempt := 0; attempt < c.attempts(); attempt++ {
		if attempt > 0 {
			if err := c.sleep(ctx, c.backoff(attempt, last)); err != nil {
				return nil, nil, err
			}
		}
		body, hdr, err := c.once(ctx, creds, cl)
		if err == nil {
			return body, hdr, nil
		}
		last = err
		var ae *Error
		if errors.As(err, &ae) {
			if !retryable(ae.Status, ae.Code) {
				return nil, nil, err
			}
			continue
		}
		if ctx.Err() != nil {
			return nil, nil, err
		}
		// a transport error (reset, timeout): retry; a refusal by the SSRF guard is final
		if errors.Is(err, safehttp.ErrURL) || errors.Is(err, safehttp.ErrBlockedAddress) || errors.Is(err, safehttp.ErrRedirect) ||
			errors.Is(err, safehttp.ErrTooLarge) || errors.Is(err, errSigning) {
			return nil, nil, err
		}
	}
	return nil, nil, fmt.Errorf("aws: %s %s: gave up after %d attempts: %w", cl.Service, cl.Op, c.attempts(), last)
}

var errSigning = errors.New("aws: cannot sign request")

func (c *Client) once(ctx context.Context, creds sigv4.Credentials, cl call) ([]byte, http.Header, error) {
	u := url.URL{Scheme: "https", Host: cl.Host, Path: cl.Path, RawQuery: encodeQuery(cl.Query)}
	req, err := http.NewRequestWithContext(ctx, cl.Method, u.String(), bytes.NewReader(cl.Body))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", safehttp.ErrURL, err)
	}
	for k, vs := range cl.Header {
		req.Header[k] = append([]string(nil), vs...)
	}
	req.Header.Set("User-Agent", "tessera-aws-connector/1")
	if !cl.Unsigned {
		if err := sigv4.Sign(req, cl.Body, creds, cl.Region, cl.Service, c.now()); err != nil {
			return nil, nil, fmt.Errorf("%w: %v", errSigning, err)
		}
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	limit := maxResponseBytes
	if cl.MaxBytes > 0 && cl.MaxBytes < limit {
		limit = cl.MaxBytes
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	if err != nil {
		return nil, nil, err
	}
	if len(body) > limit {
		return nil, nil, safehttp.ErrTooLarge
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		ae := parseError(cl, resp, body)
		ae.retryAfter = retryAfter(resp.Header)
		return nil, nil, ae
	}
	return body, resp.Header, nil
}

// encodeQuery sorts and percent-encodes (with %20, never "+") what the signer
// signs, so the signed string is the one sent.
func encodeQuery(q url.Values) string {
	var pairs []string
	for k, vs := range q {
		if len(vs) == 0 {
			pairs = append(pairs, sigv4.Encode(k))
		}
		for _, v := range vs {
			if v == "" {
				pairs = append(pairs, sigv4.Encode(k))
				continue
			}
			pairs = append(pairs, sigv4.Encode(k)+"="+sigv4.Encode(v))
		}
	}
	sort.Strings(pairs)
	return strings.Join(pairs, "&")
}

func (c *Client) sleep(ctx context.Context, d time.Duration) error {
	if c.Sleep != nil {
		return c.Sleep(ctx, d)
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

// backoff is the wait before attempt n (n >= 1): full jitter over
// min(MaxDelay, BaseDelay * 2^(n-1)), and at least the server's Retry-After.
func (c *Client) backoff(n int, last error) time.Duration {
	base, maxD := c.BaseDelay, c.MaxDelay
	if base <= 0 {
		base = 200 * time.Millisecond
	}
	if maxD <= 0 {
		maxD = 20 * time.Second
	}
	d := base
	for i := 1; i < n && d < maxD; i++ {
		d *= 2
	}
	if d > maxD {
		d = maxD
	}
	var j time.Duration
	if c.Jitter != nil {
		j = c.Jitter(d)
	} else {
		j = cryptoJitter(d)
	}
	if j > d {
		j = d
	}
	var ae *Error
	if errors.As(last, &ae) && ae.retryAfter > j {
		j = ae.retryAfter
	}
	return j
}

func cryptoJitter(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return max
	}
	return time.Duration(binary.BigEndian.Uint64(b[:]) % uint64(max+1)) // #nosec G115 -- max is positive
}

// retryAfter reads a Retry-After header in seconds, capped at 30 s.
func retryAfter(h http.Header) time.Duration {
	n, err := strconv.Atoi(strings.TrimSpace(h.Get("Retry-After")))
	if err != nil || n <= 0 {
		return 0
	}
	return min(time.Duration(n)*time.Second, 30*time.Second)
}

// parseError reads an AWS error body: the query/REST-XML form
// (<Error><Code>..</Code><Message>..</Message></Error>, also inside
// <ErrorResponse>) or the JSON form ({"__type": "...#Code", "message": ".."},
// or the x-amzn-ErrorType header).
func parseError(cl call, resp *http.Response, body []byte) *Error {
	e := &Error{Service: cl.Service, Op: cl.Op, Status: resp.StatusCode}
	trim := bytes.TrimSpace(body)
	switch {
	case len(trim) > 0 && trim[0] == '{':
		var j struct {
			Type     string `json:"__type"`
			Code     string `json:"code"`
			Message  string `json:"message"`
			MessageU string `json:"Message"`
		}
		_ = json.Unmarshal(trim, &j)
		e.Code = firstNonEmpty(j.Type, j.Code)
		e.Message = firstNonEmpty(j.Message, j.MessageU)
	case len(trim) > 0 && trim[0] == '<':
		var x struct {
			Code    string `xml:"Code"`
			Message string `xml:"Message"`
			Error   struct {
				Code    string `xml:"Code"`
				Message string `xml:"Message"`
			} `xml:"Error"`
		}
		_ = xml.Unmarshal(trim, &x)
		e.Code = firstNonEmpty(x.Code, x.Error.Code)
		e.Message = firstNonEmpty(x.Message, x.Error.Message)
	}
	if h := resp.Header.Get("X-Amzn-Errortype"); h != "" && e.Code == "" {
		e.Code = h
	}
	// "com.amazonaws.kms#NotFoundException" and "NotFoundException:http://..." both mean NotFoundException
	if i := strings.LastIndex(e.Code, "#"); i >= 0 {
		e.Code = e.Code[i+1:]
	}
	if i := strings.Index(e.Code, ":"); i >= 0 {
		e.Code = e.Code[:i]
	}
	if e.Code == "" {
		e.Code = "HTTP" + strconv.Itoa(resp.StatusCode)
	}
	e.Message = clip(e.Message, 300)
	return e
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
