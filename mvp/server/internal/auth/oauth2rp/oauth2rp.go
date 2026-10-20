// Package oauth2rp signs users in through providers that speak only OAuth
// 2.0 and issue no ID token, such as GitHub (issue #151). The authorization
// code flow uses PKCE S256 and state; the code is redeemed and the user API
// called only through the configured endpoints (pinned, never discovered),
// over the safehttp client.
//
// Nothing signed says who signed in: identity is the user API's answer to
// the access token, over TLS. The subject is an immutable provider id (the
// configured field: GitHub's numeric id), never a login name or email, and
// the result proves no factor and no freshness (internal/auth/normalize
// gives these sign-ins AAL1, never phishing resistance).
//
// Every refusal is an *Error with a machine-readable Reason for the
// auth.login.failure audit event.
package oauth2rp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"unicode"

	"golang.org/x/oauth2"

	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// Profiles (store.ProfileGitHub, store.ProfileGenericOAuth2).
const (
	GitHub  = "github"
	Generic = "generic_oauth2"
)

// GitHub's endpoints, the github profile's defaults.
const (
	GitHubAuthorizationURL = "https://github.com/login/oauth/authorize"
	GitHubTokenURL         = "https://github.com/login/oauth/access_token" // #nosec G101 -- a public endpoint URL, not a credential
	GitHubUserURL          = "https://api.github.com/user"
)

// MaxUserBytes caps a user API answer.
const MaxUserBytes = 64 << 10

// Failure reasons (auth.login.failure detail.reason).
const (
	ReasonConfig        = "oauth2_connection_misconfigured"
	ReasonTokenExchange = "token_exchange_failed"
	ReasonTokenType     = "oauth2_token_type_unsupported" // #nosec G101 -- an audit reason, not a credential
	ReasonUserAPI       = "oauth2_user_api_failed"
	ReasonSubject       = "subject_missing"
)

// Error is a refused sign-in step. Reason is safe to audit; Err is for logs.
type Error struct {
	Reason string
	Err    error
}

func (e *Error) Error() string {
	if e.Err == nil {
		return "oauth2rp: " + e.Reason
	}
	return "oauth2rp: " + e.Reason + ": " + e.Err.Error()
}

func (e *Error) Unwrap() error { return e.Err }

func fail(reason string, err error) error { return &Error{Reason: reason, Err: err} }

// ReasonOf returns the audit reason of err ("internal_error" for others).
func ReasonOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return "internal_error"
}

// Connection is one OAuth 2.0 connection, with its client secret opened.
type Connection struct {
	Profile                                 string
	AuthorizationURL, TokenURL, UserinfoURL string
	ClientID, ClientSecret                  string
	Scopes                                  []string
	// SubjectField is the user object's immutable id field ("id" for GitHub).
	SubjectField string
	// EmailsURL, for GitHub with the user:email scope, lists the user's
	// addresses; the primary verified one is the display email.
	EmailsURL string
}

// Defaults fills a github connection's unset endpoints and subject field.
func (c Connection) Defaults() Connection {
	if c.Profile == GitHub {
		if c.AuthorizationURL == "" {
			c.AuthorizationURL = GitHubAuthorizationURL
		}
		if c.TokenURL == "" {
			c.TokenURL = GitHubTokenURL
		}
		if c.UserinfoURL == "" {
			c.UserinfoURL = GitHubUserURL
		}
		if c.SubjectField == "" {
			c.SubjectField = "id"
		}
		if c.EmailsURL == "" && slices.Contains(c.Scopes, "user:email") {
			c.EmailsURL = strings.TrimSuffix(c.UserinfoURL, "/") + "/emails"
		}
	}
	return c
}

func (c Connection) check() error {
	if c.Profile != GitHub && c.Profile != Generic {
		return fail(ReasonConfig, fmt.Errorf("profile %q", c.Profile))
	}
	for _, u := range []string{c.AuthorizationURL, c.TokenURL, c.UserinfoURL} {
		if p, err := url.Parse(u); err != nil || p.Host == "" || (p.Scheme != "https" && p.Scheme != "http") {
			return fail(ReasonConfig, fmt.Errorf("endpoint %q", u))
		}
	}
	if c.ClientID == "" || c.SubjectField == "" {
		return fail(ReasonConfig, errors.New("no client_id or subject field"))
	}
	return nil
}

func (c Connection) oauth(redirectURI string) *oauth2.Config {
	style := oauth2.AuthStyleInHeader // client_secret_basic
	if c.Profile == GitHub {
		style = oauth2.AuthStyleInParams // GitHub's documented form
	}
	return &oauth2.Config{ClientID: c.ClientID, ClientSecret: c.ClientSecret, RedirectURL: redirectURI, Scopes: c.Scopes,
		Endpoint: oauth2.Endpoint{AuthURL: c.AuthorizationURL, TokenURL: c.TokenURL, AuthStyle: style}}
}

// RP redeems codes and calls user APIs through HTTP (a safehttp client).
type RP struct{ http *http.Client }

// New returns an RP; h must be the safehttp client.
func New(h *http.Client) (*RP, error) {
	if h == nil {
		return nil, errors.New("oauth2rp: an HTTP client is required (internal/safehttp)")
	}
	return &RP{http: h}, nil
}

// AuthRequest is one authorization request.
type AuthRequest struct {
	RedirectURI, State, Verifier string
}

// AuthURL returns the provider's authorization URL (PKCE S256).
func AuthURL(c Connection, r AuthRequest) (string, error) {
	c = c.Defaults()
	if err := c.check(); err != nil {
		return "", err
	}
	return c.oauth(r.RedirectURI).AuthCodeURL(r.State, oauth2.S256ChallengeOption(r.Verifier)), nil
}

// User is who the user API says signed in.
type User struct {
	Subject     string // the immutable id, as a string
	Login, Name string // display only
	Email       string // display only; never an identifier
	Raw         []byte // the user API answer (evidence; hashed)
}

// Exchange redeems the code (with the PKCE verifier) and asks the user API
// who signed in.
func (rp *RP) Exchange(ctx context.Context, c Connection, code, redirectURI, verifier string) (*User, error) {
	c = c.Defaults()
	if err := c.check(); err != nil {
		return nil, err
	}
	// the configured endpoints may name their own ports (safehttp allows
	// only 443 and 8443 otherwise)
	hc := safehttp.WithConfiguredPorts(rp.http, c.TokenURL, c.UserinfoURL, c.EmailsURL)
	tok, err := c.oauth(redirectURI).Exchange(context.WithValue(ctx, oauth2.HTTPClient, hc), code,
		oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, fail(ReasonTokenExchange, err)
	}
	if tok.AccessToken == "" {
		return nil, fail(ReasonTokenExchange, errors.New("no access_token"))
	}
	if t := strings.ToLower(tok.TokenType); t != "" && t != "bearer" {
		return nil, fail(ReasonTokenType, fmt.Errorf("token_type %q", tok.TokenType))
	}
	raw, err := get(ctx, hc, c.UserinfoURL, tok.AccessToken)
	if err != nil {
		return nil, err
	}
	var v map[string]any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&v); err != nil {
		return nil, fail(ReasonUserAPI, err)
	}
	sub, ok := subjectOf(v[c.SubjectField])
	if _, num := v[c.SubjectField].(json.Number); c.Profile == GitHub && c.SubjectField == "id" && !num {
		ok = false // GitHub's id is a number; a string there is not GitHub's id
	}
	if !ok {
		return nil, fail(ReasonSubject, fmt.Errorf("field %q", c.SubjectField))
	}
	u := &User{Subject: sub, Login: str(v["login"]), Name: str(v["name"]), Email: str(v["email"]), Raw: raw}
	if c.EmailsURL != "" {
		// best effort: display data only
		if b, err := get(ctx, hc, c.EmailsURL, tok.AccessToken); err == nil {
			var es []struct {
				Email             string `json:"email"`
				Primary, Verified bool
			}
			if json.Unmarshal(b, &es) == nil {
				u.Email = ""
				for _, e := range es {
					if e.Primary && e.Verified {
						u.Email = e.Email
					}
				}
			}
		}
	}
	return u, nil
}

func get(ctx context.Context, hc *http.Client, u, token string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fail(ReasonConfig, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fail(ReasonUserAPI, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxUserBytes+1))
	switch {
	case err != nil:
		return nil, fail(ReasonUserAPI, err)
	case resp.StatusCode != http.StatusOK:
		return nil, fail(ReasonUserAPI, fmt.Errorf("status %d", resp.StatusCode))
	case len(b) > MaxUserBytes:
		return nil, fail(ReasonUserAPI, errors.New("answer too large"))
	}
	return b, nil
}

// subjectOf accepts a non-negative integer (GitHub's id) or a non-empty
// string of printable characters, at most 255 bytes.
func subjectOf(v any) (string, bool) {
	switch x := v.(type) {
	case json.Number:
		s := x.String()
		if s == "" || strings.Trim(s, "0123456789") != "" {
			return "", false
		}
		return s, true
	case string:
		if x == "" || len(x) > 255 || strings.TrimSpace(x) != x || strings.IndexFunc(x, func(r rune) bool { return !unicode.IsPrint(r) }) >= 0 {
			return "", false
		}
		return x, true
	}
	return "", false
}

func str(v any) string {
	s, _ := v.(string)
	return s
}
