package ghapp

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// DefaultAPIBase is GitHub's API. A GitHub Enterprise Server base ("https://ghe.example.com/api/v3") is set by the
// operator (TESSERA_GITHUB_API_BASE).
const DefaultAPIBase = "https://api.github.com"

// Permissions are all an installation token is ever asked for: the check run and the pull request comment. The token
// is also limited to the one configured repository. (The check reads no repository files, so no contents permission.)
var Permissions = map[string]string{"checks": "write", "pull_requests": "write"}

// Limits.
const (
	// RefreshMargin: a cached token is replaced this long before its expires_at.
	RefreshMargin = 5 * time.Minute
	// MaxRetries bounds the waits on a rate limit per request.
	MaxRetries = 2
	// DefaultMaxWait is the longest a request sleeps for one rate-limit window; a longer one is reported instead.
	DefaultMaxWait = 30 * time.Second
	// MaxCommentBytes keeps under GitHub's 65,536 character limit for comments and check summaries.
	MaxCommentBytes = 60000
	maxTitleBytes   = 250
	maxReplyBytes   = 1 << 20
	maxCacheEntries = 256
	// CheckName is the name of the check run.
	CheckName = "Tessera policy check"
)

var (
	repoRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9_.-]{1,100}$`)
	shaRE   = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
	tokenRE = regexp.MustCompile(`^[A-Za-z0-9_\-.=+/]+$`)
)

// ValidRepo reports whether repo is "owner/name" with the characters GitHub allows and no dot segments.
func ValidRepo(repo string) bool {
	if !repoRE.MatchString(repo) {
		return false
	}
	for _, part := range strings.Split(repo, "/") {
		if part == "." || part == ".." {
			return false
		}
	}
	return true
}

// ValidSHA reports whether s is a full commit id (SHA-1 or SHA-256, lower-case hex).
func ValidSHA(s string) bool { return shaRE.MatchString(s) }

// Errors. None carries a response body.
var (
	// ErrAppAuth: GitHub refused the App's JWT (wrong App id, wrong or revoked key, or a clock that is off).
	ErrAppAuth = errors.New("ghapp: GitHub refused the App credentials")
	// ErrInstallationNotFound: the installation does not exist (wrong id, or the App was uninstalled).
	ErrInstallationNotFound = errors.New("ghapp: installation not found")
	// ErrInstallationScope: GitHub answered 422 to the token request, which it does when the repository is not one the
	// installation covers, or when the requested permissions exceed what the installation was granted (the App's
	// permissions changed and the installation has not accepted them yet).
	ErrInstallationScope = errors.New("ghapp: the installation does not cover the repository or the requested permissions")
	// ErrHeadMismatch: head_sha is not the head of the pull request now.
	ErrHeadMismatch = errors.New("ghapp: the commit is not the pull request's head")
	// ErrPullNotFound: the number is not a pull request of the repository (an issue, or none).
	ErrPullNotFound = errors.New("ghapp: pull request not found")
	// ErrBadInput: a value failed validation before any request was made.
	ErrBadInput = errors.New("ghapp: invalid repository, pull request, commit or text")
)

// StatusError is a non-2xx answer, as its status only.
type StatusError struct {
	Status int
	Op     string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("ghapp: GitHub answered %d to %s", e.Status, e.Op)
}

// RateLimitError is a rate limit that was not waited out. RetryAfter is zero when GitHub did not say how long.
type RateLimitError struct{ RetryAfter time.Duration }

func (e *RateLimitError) Error() string { return "ghapp: GitHub rate limit" }

// ErrCode is a short code for err, for the API's answer and audit event: never its text.
func ErrCode(err error) string {
	var se *StatusError
	var rl *RateLimitError
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrAppAuth):
		return "app_auth_failed"
	case errors.Is(err, ErrInstallationNotFound):
		return "installation_not_found"
	case errors.Is(err, ErrInstallationScope):
		return "installation_scope_mismatch"
	case errors.Is(err, ErrHeadMismatch):
		return "head_sha_mismatch"
	case errors.Is(err, ErrPullNotFound):
		return "pull_request_not_found"
	case errors.Is(err, ErrBadInput), errors.Is(err, ErrAppID), errors.Is(err, ErrKey):
		return "invalid_settings"
	case errors.As(err, &rl):
		return "rate_limited"
	case errors.As(err, &se):
		return "github_" + strconv.Itoa(se.Status)
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	}
	return "unreachable"
}

// Credentials identify the installation a request acts through.
type Credentials struct {
	AppID          string
	InstallationID int64
	// Repo is "owner/name": the one repository the installation token is limited to.
	Repo string
	Key  *rsa.PrivateKey
	// Scope and KeyID namespace the token cache: the tenant, and the key's Fingerprint, so a rotated key (or another
	// tenant with the same installation) never shares a token.
	Scope string
	KeyID string
}

func (cr *Credentials) cacheKey() string {
	return strings.Join([]string{cr.Scope, cr.AppID, strconv.FormatInt(cr.InstallationID, 10), cr.Repo, cr.KeyID}, "|")
}

// TokenCache holds installation tokens in memory until RefreshMargin before they expire. Tokens are never written
// anywhere else.
type TokenCache struct {
	mu sync.Mutex
	m  map[string]cachedToken
}

type cachedToken struct {
	token   string
	expires time.Time
}

// NewTokenCache returns an empty cache.
func NewTokenCache() *TokenCache { return &TokenCache{m: map[string]cachedToken{}} }

func (c *TokenCache) get(key string, now time.Time) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	t, ok := c.m[key]
	if !ok || !now.Before(t.expires.Add(-RefreshMargin)) {
		return "", false
	}
	return t.token, true
}

func (c *TokenCache) put(key, token string, expires, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= maxCacheEntries {
		for k, t := range c.m {
			if !now.Before(t.expires) {
				delete(c.m, k)
			}
		}
	}
	for k := range c.m {
		if len(c.m) < maxCacheEntries {
			break
		}
		delete(c.m, k)
	}
	c.m[key] = cachedToken{token: token, expires: expires}
}

func (c *TokenCache) invalidate(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, key)
}

// Len is the number of cached tokens (for tests).
func (c *TokenCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m)
}

// Client talks to the GitHub API. HTTP must be a client from internal/safehttp.
type Client struct {
	HTTP *http.Client
	// APIBase defaults to DefaultAPIBase.
	APIBase string
	Cache   *TokenCache
	// Now, Sleep and MaxWait default to the clock, a context-aware sleep and DefaultMaxWait; tests replace them.
	Now     func() time.Time
	Sleep   func(ctx context.Context, d time.Duration) error
	MaxWait time.Duration
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
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

func (c *Client) maxWait() time.Duration {
	if c.MaxWait > 0 {
		return c.MaxWait
	}
	return DefaultMaxWait
}

// ValidAPIBase reports whether base is usable as an API base: an http(s) URL with a host and no user info, query or
// fragment. Whether it may be plain http or name a private address is decided by internal/config and internal/safehttp.
func ValidAPIBase(base string) bool {
	u, err := url.Parse(base)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && !u.ForceQuery
}

func (c *Client) endpoint(path string) (string, error) {
	base := c.APIBase
	if base == "" {
		base = DefaultAPIBase
	}
	if !ValidAPIBase(base) {
		return "", errors.New("ghapp: bad API base")
	}
	return strings.TrimRight(base, "/") + path, nil
}

// reply is an answer with only the headers the client reads.
type reply struct {
	status int
	retry  string // Retry-After
	remain string // X-RateLimit-Remaining
	reset  string // X-RateLimit-Reset
	body   []byte
}

func (c *Client) roundTrip(ctx context.Context, method, path, bearer string, payload []byte) (*reply, error) {
	if c == nil || c.HTTP == nil {
		return nil, errors.New("ghapp: no outbound client")
	}
	u, err := c.endpoint(path)
	if err != nil {
		return nil, err
	}
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, errors.New("ghapp: bad request")
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "tessera-policy-check")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// A redirect (a renamed or transferred repository answers 301) would turn a POST or PATCH into a GET that succeeds
	// without doing anything: never follow one, so it surfaces as a status error. The copy shares the safehttp client's
	// transport, so the address and port rules still apply.
	hc := *c.HTTP
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := hc.Do(req) // #nosec G704 -- HTTP is an internal/safehttp client
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // drop the URL, which names the repository
		}
		return nil, fmt.Errorf("ghapp: request failed: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxReplyBytes))
	if err != nil {
		return nil, errors.New("ghapp: reading the answer failed")
	}
	return &reply{status: resp.StatusCode, retry: resp.Header.Get("Retry-After"), remain: resp.Header.Get("X-RateLimit-Remaining"),
		reset: resp.Header.Get("X-RateLimit-Reset"), body: raw}, nil
}

// rateLimited reports whether r is a rate limit answer and how long to wait: a negative wait means GitHub did not
// say (a secondary limit without Retry-After), so it is not retried.
func (c *Client) rateLimited(r *reply) (wait time.Duration, limited bool) {
	if r.status != http.StatusForbidden && r.status != http.StatusTooManyRequests {
		return 0, false
	}
	if n, err := strconv.ParseInt(strings.TrimSpace(r.retry), 10, 64); err == nil && n >= 0 {
		return time.Duration(n) * time.Second, true
	}
	if strings.TrimSpace(r.remain) == "0" {
		if epoch, err := strconv.ParseInt(strings.TrimSpace(r.reset), 10, 64); err == nil {
			d := time.Unix(epoch, 0).Sub(c.now())
			return max(d, time.Second), true
		}
	}
	if r.status == http.StatusTooManyRequests || bytes.Contains(bytes.ToLower(r.body), []byte("rate limit")) {
		return -1, true
	}
	return 0, false
}

// do sends one request and waits out rate limits (at most MaxRetries times, each at most maxWait). It sends nothing
// again after a non-rate-limit answer.
func (c *Client) do(ctx context.Context, method, path, bearer string, payload []byte) (*reply, error) {
	for tries := 0; ; tries++ {
		r, err := c.roundTrip(ctx, method, path, bearer, payload)
		if err != nil {
			return nil, err
		}
		wait, limited := c.rateLimited(r)
		if !limited {
			return r, nil
		}
		if wait < 0 || wait > c.maxWait() || tries >= MaxRetries {
			return nil, &RateLimitError{RetryAfter: max(wait, 0)}
		}
		if err := c.sleep(ctx, wait); err != nil {
			return nil, err
		}
	}
}

// installationToken returns a token for cr from the cache, or mints one:
// POST /app/installations/{id}/access_tokens, authenticated with a fresh App JWT, asking for Permissions and the one
// repository.
func (c *Client) installationToken(ctx context.Context, cr *Credentials) (string, error) {
	now := c.now()
	key := cr.cacheKey()
	if c.Cache != nil {
		if t, ok := c.Cache.get(key, now); ok {
			return t, nil
		}
	}
	if !ValidRepo(cr.Repo) || cr.InstallationID < 1 {
		return "", ErrBadInput
	}
	jwt, err := AppJWT(cr.AppID, cr.Key, now)
	if err != nil {
		return "", err
	}
	_, name, _ := strings.Cut(cr.Repo, "/")
	payload, err := json.Marshal(map[string]any{"repositories": []string{name}, "permissions": Permissions})
	if err != nil {
		return "", err
	}
	r, err := c.do(ctx, http.MethodPost, "/app/installations/"+strconv.FormatInt(cr.InstallationID, 10)+"/access_tokens", jwt, payload)
	if err != nil {
		return "", err
	}
	switch r.status {
	case http.StatusCreated:
	case http.StatusUnauthorized:
		return "", ErrAppAuth
	case http.StatusNotFound:
		return "", ErrInstallationNotFound
	case http.StatusUnprocessableEntity:
		return "", ErrInstallationScope
	default:
		return "", &StatusError{Status: r.status, Op: "the installation token request"}
	}
	var out struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}
	if json.Unmarshal(r.body, &out) != nil || out.Token == "" || len(out.Token) > 512 || !tokenRE.MatchString(out.Token) {
		return "", errors.New("ghapp: unreadable installation token answer")
	}
	exp, err := time.Parse(time.RFC3339, out.ExpiresAt)
	if err != nil || !exp.After(now) {
		return "", errors.New("ghapp: installation token answer has no usable expires_at")
	}
	if c.Cache != nil {
		c.Cache.put(key, out.Token, exp, now)
	}
	return out.Token, nil
}

// api sends an authenticated request as the installation. A 401 (the token expired or was revoked early) drops the
// cached token and retries once with a new one.
func (c *Client) api(ctx context.Context, cr *Credentials, method, path string, payload any, want int, op string) (*reply, error) {
	var raw []byte
	if payload != nil {
		var err error
		if raw, err = json.Marshal(payload); err != nil {
			return nil, err
		}
	}
	refreshed := false
	for {
		tok, err := c.installationToken(ctx, cr)
		if err != nil {
			return nil, err
		}
		r, err := c.do(ctx, method, path, tok, raw)
		if err != nil {
			return nil, err
		}
		if r.status == http.StatusUnauthorized && !refreshed {
			if c.Cache != nil {
				c.Cache.invalidate(cr.cacheKey())
			}
			refreshed = true
			continue
		}
		if r.status != want {
			return nil, &StatusError{Status: r.status, Op: op}
		}
		return r, nil
	}
}

// Check is the content of a check run. Conclusion is success, failure or neutral.
type Check struct {
	HeadSHA    string
	Conclusion string
	Title      string
	Summary    string
}

func (k *Check) valid() bool {
	return ValidSHA(k.HeadSHA) && (k.Conclusion == "success" || k.Conclusion == "failure" || k.Conclusion == "neutral") &&
		k.Title != "" && k.Summary != ""
}

func (k *Check) payload(now time.Time, create bool) map[string]any {
	title := k.Title
	if len(title) > maxTitleBytes {
		title = title[:maxTitleBytes]
	}
	m := map[string]any{"name": CheckName, "status": "completed", "conclusion": k.Conclusion,
		"completed_at": now.UTC().Format(time.RFC3339), "output": map[string]string{"title": title, "summary": clip(k.Summary)}}
	if create {
		m["head_sha"] = k.HeadSHA
	}
	return m
}

// clip cuts s to MaxCommentBytes on a rune boundary.
func clip(s string) string {
	if len(s) <= MaxCommentBytes {
		return s
	}
	s = s[:MaxCommentBytes]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s + "\n\n(cut)"
}

type created struct {
	ID      int64  `json:"id"`
	HTMLURL string `json:"html_url"`
}

func parseCreated(r *reply) (int64, string) {
	var o created
	_ = json.Unmarshal(r.body, &o) // a created object without a readable answer is still created
	u := ""
	if strings.HasPrefix(o.HTMLURL, "https://") && len(o.HTMLURL) <= 300 {
		u = o.HTMLURL
	}
	return o.ID, u
}

// CreateCheckRun creates a completed check run on the commit.
func (c *Client) CreateCheckRun(ctx context.Context, cr *Credentials, k Check) (id int64, htmlURL string, err error) {
	if !ValidRepo(cr.Repo) || !k.valid() {
		return 0, "", ErrBadInput
	}
	r, err := c.api(ctx, cr, http.MethodPost, "/repos/"+cr.Repo+"/check-runs", k.payload(c.now(), true), http.StatusCreated, "the check run create")
	if err != nil {
		return 0, "", err
	}
	if id, htmlURL = parseCreated(r); id < 1 {
		return 0, "", errors.New("ghapp: GitHub created the check run but returned no id")
	}
	return id, htmlURL, nil
}

// UpdateCheckRun replaces the content of check run id (same commit).
func (c *Client) UpdateCheckRun(ctx context.Context, cr *Credentials, id int64, k Check) error {
	if !ValidRepo(cr.Repo) || !k.valid() || id < 1 {
		return ErrBadInput
	}
	_, err := c.api(ctx, cr, http.MethodPatch, "/repos/"+cr.Repo+"/check-runs/"+strconv.FormatInt(id, 10), k.payload(c.now(), false), http.StatusOK, "the check run update")
	return err
}

// CreateComment adds a comment to pull request number (GitHub treats it as an issue for comments).
func (c *Client) CreateComment(ctx context.Context, cr *Credentials, number int, body string) (id int64, htmlURL string, err error) {
	if !ValidRepo(cr.Repo) || number < 1 || number > 1<<31-1 || body == "" {
		return 0, "", ErrBadInput
	}
	r, err := c.api(ctx, cr, http.MethodPost, "/repos/"+cr.Repo+"/issues/"+strconv.Itoa(number)+"/comments", map[string]string{"body": clip(body)}, http.StatusCreated, "the comment create")
	if err != nil {
		return 0, "", err
	}
	if id, htmlURL = parseCreated(r); id < 1 {
		return 0, "", errors.New("ghapp: GitHub created the comment but returned no id")
	}
	return id, htmlURL, nil
}

// UpdateComment replaces the text of comment id.
func (c *Client) UpdateComment(ctx context.Context, cr *Credentials, id int64, body string) (htmlURL string, err error) {
	if !ValidRepo(cr.Repo) || id < 1 || body == "" {
		return "", ErrBadInput
	}
	r, err := c.api(ctx, cr, http.MethodPatch, "/repos/"+cr.Repo+"/issues/comments/"+strconv.FormatInt(id, 10), map[string]string{"body": clip(body)}, http.StatusOK, "the comment update")
	if err != nil {
		return "", err
	}
	_, htmlURL = parseCreated(r)
	return htmlURL, nil
}

// VerifyHead checks that sha is the head of pull request number now (GET /repos/{repo}/pulls/{number}, which the
// pull_requests permission covers). It also proves the number is a pull request and not an issue. A check posted for an
// old commit, or for a commit that is not the pull request's, is refused (ErrHeadMismatch).
func (c *Client) VerifyHead(ctx context.Context, cr *Credentials, number int, sha string) error {
	if !ValidRepo(cr.Repo) || number < 1 || number > 1<<31-1 || !ValidSHA(sha) {
		return ErrBadInput
	}
	r, err := c.api(ctx, cr, http.MethodGet, "/repos/"+cr.Repo+"/pulls/"+strconv.Itoa(number), nil, http.StatusOK, "the pull request read")
	if err != nil {
		if IsStatus(err, http.StatusNotFound) {
			return ErrPullNotFound
		}
		return err
	}
	var out struct {
		Head struct {
			SHA string `json:"sha"`
		} `json:"head"`
	}
	if json.Unmarshal(r.body, &out) != nil || !strings.EqualFold(out.Head.SHA, sha) {
		return ErrHeadMismatch
	}
	return nil
}

// IsStatus reports whether err is a StatusError with the status.
func IsStatus(err error, status int) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Status == status
}

// Previous is what an earlier Publish for the same pull request left: the commit its check run is on, the check run
// and the comment. Zero values mean none.
type Previous struct {
	HeadSHA    string
	CheckRunID int64
	CommentID  int64
}

// Published is where the check and the comment are now.
type Published struct {
	HeadSHA    string
	CheckRunID int64
	CheckURL   string
	CommentID  int64
	CommentURL string
	// CheckCreated and CommentCreated are false when an existing one was updated in place.
	CheckCreated   bool
	CommentCreated bool
}

// Publish posts the check run and the pull request comment. The check run is updated when prev is on the same commit
// (and created for a new commit, which is how GitHub shows one check per commit); the comment is always updated in
// place when prev names one. A check run or comment that was deleted (404) is created again, once.
func (c *Client) Publish(ctx context.Context, cr *Credentials, number int, k Check, comment string, prev Previous) (*Published, error) {
	out := &Published{HeadSHA: k.HeadSHA}
	if prev.CheckRunID > 0 && prev.HeadSHA == k.HeadSHA {
		err := c.UpdateCheckRun(ctx, cr, prev.CheckRunID, k)
		switch {
		case err == nil:
			out.CheckRunID = prev.CheckRunID
		case IsStatus(err, http.StatusNotFound):
			prev.CheckRunID = 0
		default:
			return nil, err
		}
	} else {
		prev.CheckRunID = 0
	}
	if prev.CheckRunID == 0 {
		id, u, err := c.CreateCheckRun(ctx, cr, k)
		if err != nil {
			return nil, err
		}
		out.CheckRunID, out.CheckURL, out.CheckCreated = id, u, true
	}
	if prev.CommentID > 0 {
		u, err := c.UpdateComment(ctx, cr, prev.CommentID, comment)
		switch {
		case err == nil:
			out.CommentID, out.CommentURL = prev.CommentID, u
		case IsStatus(err, http.StatusNotFound):
			prev.CommentID = 0
		default:
			return out, err
		}
	}
	if prev.CommentID == 0 {
		id, u, err := c.CreateComment(ctx, cr, number, comment)
		if err != nil {
			return out, err
		}
		out.CommentID, out.CommentURL, out.CommentCreated = id, u, true
	}
	return out, nil
}
