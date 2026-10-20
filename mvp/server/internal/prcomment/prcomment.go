// Package prcomment posts the access-diff comment of the AWS evaluator to a
// GitHub pull request (design §11.3). It is the only outbound call of that
// feature, so it is small and strict: the host is fixed (api.github.com unless
// a test points it elsewhere), the repository and pull request number are
// validated before they reach a URL, the request goes through a client from
// internal/safehttp, and the token appears only in the Authorization header:
// never in an error, a log line or a returned value.
package prcomment

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// DefaultAPIBase is where comments are posted.
const DefaultAPIBase = "https://api.github.com"

// MaxBodyBytes is the largest comment posted (GitHub allows 65,536 characters).
const MaxBodyBytes = 65000

// MaxTokenBytes bounds a token (GitHub's are under 255 bytes).
const MaxTokenBytes = 512

var (
	repoRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9_.-]{1,100}$`)
	tokenRE = regexp.MustCompile(`^[A-Za-z0-9_\-.=+/]+$`)
)

// Errors.
var (
	ErrRepo   = errors.New("prcomment: repository must be owner/name")
	ErrNumber = errors.New("prcomment: pull request number must be a positive integer")
	ErrToken  = errors.New("prcomment: no usable token")
	ErrBody   = errors.New("prcomment: comment is empty or too large")
)

// StatusError is a non-2xx answer. It carries the status only: the body of an
// error response is not kept, since it can echo the request.
type StatusError struct{ Status int }

func (e *StatusError) Error() string { return fmt.Sprintf("prcomment: GitHub answered %d", e.Status) }

// ValidRepo reports whether repo is "owner/name" with the characters GitHub
// allows, and not a path that could leave the repository's issues.
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

// ValidToken reports whether token looks like a GitHub token: printable
// token characters only, so it cannot inject a header.
func ValidToken(token string) bool {
	return token != "" && len(token) <= MaxTokenBytes && tokenRE.MatchString(token)
}

// Poster posts comments through HTTP, which must be a client from
// internal/safehttp.
type Poster struct {
	HTTP *http.Client
	// APIBase defaults to DefaultAPIBase; tests point it at a local server.
	APIBase string
}

// Result is the comment GitHub created.
type Result struct {
	ID  int64
	URL string // the comment's html_url, if GitHub gave an https one
}

// Post adds a comment to pull request number of repo. GitHub treats a pull
// request as an issue for comments.
func (p *Poster) Post(ctx context.Context, token, repo string, number int, body string) (*Result, error) {
	switch {
	case p == nil || p.HTTP == nil:
		return nil, errors.New("prcomment: no outbound client")
	case !ValidRepo(repo):
		return nil, ErrRepo
	case number < 1 || number > 1<<31-1:
		return nil, ErrNumber
	case !ValidToken(token):
		return nil, ErrToken
	case body == "" || len(body) > MaxBodyBytes:
		return nil, ErrBody
	}
	base := p.APIBase
	if base == "" {
		base = DefaultAPIBase
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, errors.New("prcomment: bad API base")
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/repos/" + repo + "/issues/" + strconv.Itoa(number) + "/comments"
	payload, err := json.Marshal(map[string]string{"body": body})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(payload))
	if err != nil {
		return nil, errors.New("prcomment: bad request")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "tessera-access-diff")
	resp, err := p.HTTP.Do(req) // #nosec G704 -- HTTP is an internal/safehttp client
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // drop the URL, which names the repository
		}
		return nil, fmt.Errorf("prcomment: post failed: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, errors.New("prcomment: reading the answer failed")
	}
	if resp.StatusCode != http.StatusCreated {
		return nil, &StatusError{Status: resp.StatusCode}
	}
	var out struct {
		ID      int64  `json:"id"`
		HTMLURL string `json:"html_url"`
	}
	_ = json.Unmarshal(raw, &out) // a created comment without a readable answer is still created
	res := &Result{ID: out.ID}
	if strings.HasPrefix(out.HTMLURL, "https://") && len(out.HTMLURL) <= 300 {
		res.URL = out.HTMLURL
	}
	return res, nil
}
