package cliauth

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/nischalravi/tessera/mvp/server/internal/oauth/dpop"
)

// Names the CLI uses with the server.
const (
	ClientID     = "tessera-cli"
	DefaultScope = "tessera:read tessera:write"

	grantDeviceCode = "urn:ietf:params:oauth:grant-type:device_code"
	grantRefresh    = "refresh_token"
)

// refreshSkew is how long before its expiry an access token is replaced.
const refreshSkew = 30 * time.Second

var slugRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,39}$`)

// Client talks to one Tessera server. HTTP must be an SSRF-guarded client
// (internal/safehttp); the CLI never builds its own.
type Client struct {
	HTTP  *http.Client
	Store *Store
	// Now is the clock of DPoP proofs and expiry checks (default time.Now).
	Now func() time.Time
	// Sleep waits between polls (default: a timer that honours ctx).
	Sleep func(ctx context.Context, d time.Duration) error
	// Out receives the sign-in instructions (default: discarded).
	Out io.Writer
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

func (c *Client) say(format string, a ...any) {
	if c.Out != nil {
		_, _ = fmt.Fprintf(c.Out, format, a...)
	}
}

// OAuthError is an RFC 6749 error response.
type OAuthError struct {
	Status      int
	Code        string
	Description string
}

func (e *OAuthError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("%s: %s", e.Code, printable(e.Description))
	}
	return e.Code
}

// StepUpError means the API wants a fresher or stronger sign-in than the
// session has (RFC 9470 insufficient_user_authentication, design §9.4).
type StepUpError struct {
	Reason string
	ACR    string
	MaxAge int
}

func (e *StepUpError) Error() string {
	r := e.Reason
	if r == "" {
		r = "this action needs a fresh sign-in"
	}
	return printable(r)
}

// printable drops control characters from text a server sent, so that it
// cannot rewrite the user's terminal.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}

// ---------------------------------------------------------------- DPoP

// proof builds a DPoP proof (RFC 9449 §4.2) for a request of method to rawURL:
// htu is the URL without query or fragment, ath binds it to accessToken.
func (c *Client) proof(key *ecdsa.PrivateKey, method, rawURL, accessToken, nonce string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	u.RawQuery, u.Fragment = "", ""
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{EmbedJWK: true}).WithType("dpop+jwt"))
	if err != nil {
		return "", err
	}
	jti := make([]byte, 16)
	_, _ = rand.Read(jti)
	claims := map[string]any{"jti": base64.RawURLEncoding.EncodeToString(jti), "htm": method, "htu": u.String(),
		"iat": c.now().Unix()}
	if accessToken != "" {
		claims["ath"] = dpop.AccessTokenHash(accessToken)
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	return jwt.Signed(signer).Claims(claims).Serialize()
}

// ---------------------------------------------------------------- HTTP

// roundTrip sends req and reads the (size-limited) body.
func (c *Client) roundTrip(req *http.Request) (*http.Response, []byte, error) {
	if c.HTTP == nil {
		return nil, nil, errors.New("cliauth: no HTTP client")
	}
	res, err := c.HTTP.Do(req) // #nosec G107 -- c.HTTP is a safehttp client
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = res.Body.Close() }()
	b, err := io.ReadAll(res.Body)
	return res, b, err
}

func (c *Client) getJSON(ctx context.Context, rawURL string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	res, body, err := c.roundTrip(req)
	if err != nil {
		return err
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered %d", rawURL, res.StatusCode)
	}
	return json.Unmarshal(body, v)
}

// postForm sends a form to an OAuth endpoint, with a DPoP proof when key is
// set. A use_dpop_nonce answer is retried once with the nonce it carries. The
// newest nonce is left in *nonce. A non-200 answer is an *OAuthError.
func (c *Client) postForm(ctx context.Context, endpoint string, form url.Values, key *ecdsa.PrivateKey, nonce *string) ([]byte, error) {
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json")
		if key != nil {
			n := ""
			if nonce != nil {
				n = *nonce
			}
			p, err := c.proof(key, http.MethodPost, endpoint, "", n)
			if err != nil {
				return nil, err
			}
			req.Header.Set("DPoP", p)
		}
		res, body, err := c.roundTrip(req)
		if err != nil {
			return nil, err
		}
		if n := res.Header.Get("DPoP-Nonce"); n != "" && nonce != nil {
			*nonce = n
		}
		if res.StatusCode == http.StatusOK {
			return body, nil
		}
		oe := &OAuthError{Status: res.StatusCode}
		var e struct{ Error, Description string }
		var raw map[string]any
		if json.Unmarshal(body, &raw) == nil {
			e.Error, _ = raw["error"].(string)
			e.Description, _ = raw["error_description"].(string)
		}
		oe.Code, oe.Description = e.Error, e.Description
		if oe.Code == "" {
			oe.Code = "http_" + strconv.Itoa(res.StatusCode)
		}
		if oe.Code == "use_dpop_nonce" && attempt == 0 && nonce != nil && *nonce != "" {
			continue
		}
		return nil, oe
	}
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

func (c *Client) tokenRequest(ctx context.Context, endpoint string, form url.Values, key *ecdsa.PrivateKey, nonce *string) (*tokenResponse, error) {
	body, err := c.postForm(ctx, endpoint, form, key, nonce)
	if err != nil {
		return nil, err
	}
	var t tokenResponse
	if err := json.Unmarshal(body, &t); err != nil {
		return nil, fmt.Errorf("the token response is not JSON: %w", err)
	}
	if !strings.EqualFold(t.TokenType, "DPoP") || t.AccessToken == "" || t.RefreshToken == "" || t.ExpiresIn <= 0 {
		return nil, errors.New("the token response is not a DPoP token response")
	}
	return &t, nil
}

// ---------------------------------------------------------------- login

// LoginOptions say who to sign in to and what to ask for.
type LoginOptions struct {
	Server string // the server's public URL
	Tenant string // tenant slug
	Scope  string // default DefaultScope
	// ACR and MaxAge are sent as acr_values and max_age (a step-up asks for
	// the stronger or fresher sign-in the API demanded).
	ACR    string
	MaxAge *int
}

// NormalizeServer validates a server URL: http or https, a host, no user
// info, query or fragment, and returns it without a trailing slash.
func NormalizeServer(s string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" ||
		u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", fmt.Errorf("%q is not a server URL (want https://host[:port])", s)
	}
	return u.Scheme + "://" + u.Host, nil
}

func sameOrigin(a, b string) bool {
	ua, err1 := url.Parse(a)
	ub, err2 := url.Parse(b)
	return err1 == nil && err2 == nil && ua.Scheme == ub.Scheme && ua.Host == ub.Host
}

type serverMetadata struct {
	Issuer                string   `json:"issuer"`
	TokenEndpoint         string   `json:"token_endpoint"`
	DeviceEndpoint        string   `json:"device_authorization_endpoint"`
	RevocationEndpoint    string   `json:"revocation_endpoint"`
	GrantTypesSupported   []string `json:"grant_types_supported"`
	DPoPAlgsSupported     []string `json:"dpop_signing_alg_values_supported"`
	TokenEndpointAuthMeth []string `json:"token_endpoint_auth_methods_supported"`
}

// discover reads and checks the issuer's RFC 8414 metadata: the issuer must
// be exactly the one asked for (RFC 8414 §3.3) and every endpoint must be on
// the server's own origin.
func (c *Client) discover(ctx context.Context, server, tenant string) (*serverMetadata, error) {
	issuer := server + "/t/" + tenant
	var m serverMetadata
	if err := c.getJSON(ctx, issuer+"/.well-known/oauth-authorization-server", &m); err != nil {
		return nil, fmt.Errorf("cannot read the sign-in metadata of %q at %s: %w", tenant, server, err)
	}
	if m.Issuer != issuer {
		return nil, fmt.Errorf("the server's issuer %q is not %q", printable(m.Issuer), issuer)
	}
	for _, e := range []string{m.TokenEndpoint, m.DeviceEndpoint, m.RevocationEndpoint} {
		if !sameOrigin(e, server) {
			return nil, fmt.Errorf("the server advertises an endpoint on another origin (%s)", printable(e))
		}
	}
	has := func(list []string, v string) bool {
		for _, x := range list {
			if x == v {
				return true
			}
		}
		return false
	}
	if !has(m.GrantTypesSupported, grantDeviceCode) || !has(m.DPoPAlgsSupported, "ES256") {
		return nil, errors.New("this server does not support command-line sign-in (device grant with DPoP ES256)")
	}
	return &m, nil
}

type deviceResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

// Login runs the device authorization grant (design §9.3): it asks for a
// device code, prints the user code and the page to enter it on, polls until
// the user decides, and stores the tokens and the DPoP key it generated.
func (c *Client) Login(ctx context.Context, o LoginOptions) (*Credentials, error) {
	server, err := NormalizeServer(o.Server)
	if err != nil {
		return nil, err
	}
	if !slugRE.MatchString(o.Tenant) {
		return nil, fmt.Errorf("%q is not a tenant name (lower-case letters, digits and dashes, 3 to 40 characters)", o.Tenant)
	}
	scope := strings.Join(strings.Fields(o.Scope), " ")
	if scope == "" {
		scope = DefaultScope
	}
	meta, err := c.discover(ctx, server, o.Tenant)
	if err != nil {
		return nil, err
	}
	key, jwk, err := NewKey()
	if err != nil {
		return nil, err
	}
	form := url.Values{"client_id": {ClientID}, "scope": {scope}}
	if o.ACR != "" {
		form.Set("acr_values", o.ACR)
	}
	if o.MaxAge != nil {
		form.Set("max_age", strconv.Itoa(*o.MaxAge))
	}
	body, err := c.postForm(ctx, meta.DeviceEndpoint, form, nil, nil)
	if err != nil {
		var oe *OAuthError
		if errors.As(err, &oe) {
			return nil, fmt.Errorf("the server refused to start a sign-in: %w", oe)
		}
		return nil, err
	}
	var d deviceResponse
	if err := json.Unmarshal(body, &d); err != nil || d.DeviceCode == "" || d.UserCode == "" || d.ExpiresIn <= 0 {
		return nil, errors.New("the device authorization response is not valid")
	}
	if d.Interval < 1 {
		d.Interval = 5
	}
	// Only the code and the page are shown: no pre-filled link and no QR code
	// (the user must type the code themselves), and a warning against being
	// talked into approving someone else's request.
	c.say("To sign in to %s, open\n\n    %s\n\nand enter the code\n\n    %s\n\n", o.Tenant, printable(d.VerificationURI), printable(d.UserCode))
	c.say("Only approve if you just ran this command yourself. Tessera staff will never ask you for this code.\n")
	c.say("Waiting for approval (the code works for %d minutes)...\n", (d.ExpiresIn+59)/60)

	deadline := c.now().Add(time.Duration(d.ExpiresIn) * time.Second)
	interval := time.Duration(d.Interval) * time.Second
	var nonce string
	transient := 0
	for {
		if err := c.sleep(ctx, interval); err != nil {
			return nil, err
		}
		if !c.now().Before(deadline) {
			return nil, errors.New("the code expired before it was approved; run the command again")
		}
		t, err := c.tokenRequest(ctx, meta.TokenEndpoint, url.Values{"grant_type": {grantDeviceCode}, "client_id": {ClientID},
			"device_code": {d.DeviceCode}}, key, &nonce)
		var oe *OAuthError
		switch {
		case err == nil:
			cr := &Credentials{Server: server, Tenant: o.Tenant, Issuer: meta.Issuer, ClientID: ClientID, Scope: t.Scope,
				DPoPKey: jwk, RefreshToken: t.RefreshToken, AccessToken: t.AccessToken,
				AccessExpiresAt: c.now().Add(time.Duration(t.ExpiresIn) * time.Second), Nonce: nonce, SignedInAt: c.now().UTC()}
			if err := c.Store.Save(cr); err != nil {
				return nil, fmt.Errorf("signed in, but the credentials could not be saved: %w", err)
			}
			return cr, nil
		case errors.As(err, &oe):
			switch oe.Code {
			case "authorization_pending":
			case "slow_down":
				interval += 5 * time.Second
			case "access_denied":
				return nil, errors.New("the sign-in was denied (or device sign-in is turned off for this organization)")
			case "expired_token":
				return nil, errors.New("the code expired before it was approved; run the command again")
			default:
				return nil, fmt.Errorf("the server refused the sign-in: %w", oe)
			}
			transient = 0
		default:
			if transient++; transient > 3 || ctx.Err() != nil {
				return nil, err
			}
		}
	}
}

// ---------------------------------------------------------------- tokens

// ErrSessionEnded means the server no longer accepts the refresh token: the
// session was revoked, expired or its token was reused.
var ErrSessionEnded = errors.New("the session has ended: run `tessera-cli login`")

// refresh exchanges the refresh token for new tokens and saves them, under
// the credentials lock so that two processes never present the same token. If
// another process already refreshed, its access token is used.
func (c *Client) refresh(ctx context.Context, force bool) (*Credentials, error) {
	unlock, err := c.Store.Lock(15*time.Second, 2*time.Minute)
	if err != nil {
		return nil, err
	}
	defer unlock()
	cr, err := c.Store.Load()
	if err != nil {
		return nil, err
	}
	if !force && cr.AccessToken != "" && c.now().Add(refreshSkew).Before(cr.AccessExpiresAt) {
		return cr, nil
	}
	key, err := cr.Key()
	if err != nil {
		return nil, err
	}
	nonce := cr.Nonce
	t, err := c.tokenRequest(ctx, cr.Issuer+"/oauth/token", url.Values{"grant_type": {grantRefresh}, "client_id": {cr.ClientID},
		"refresh_token": {cr.RefreshToken}}, key, &nonce)
	var oe *OAuthError
	if errors.As(err, &oe) && (oe.Code == "invalid_grant" || oe.Code == "invalid_client") {
		_ = c.Store.Delete() // nothing in it works any more
		return nil, fmt.Errorf("%w (%s)", ErrSessionEnded, printable(oe.Description))
	}
	if err != nil {
		return nil, err
	}
	cr.RefreshToken, cr.AccessToken, cr.Nonce = t.RefreshToken, t.AccessToken, nonce
	cr.AccessExpiresAt = c.now().Add(time.Duration(t.ExpiresIn) * time.Second)
	if t.Scope != "" {
		cr.Scope = t.Scope
	}
	// the rotated token must reach the disk before anything else happens
	if err := c.Store.Save(cr); err != nil {
		return nil, fmt.Errorf("refreshed, but the credentials could not be saved (sign in again): %w", err)
	}
	return cr, nil
}

// credentials returns credentials with an access token that is valid for a
// while, refreshing when needed.
func (c *Client) credentials(ctx context.Context) (*Credentials, error) {
	cr, err := c.Store.Load()
	if err != nil {
		return nil, err
	}
	if cr.AccessToken != "" && c.now().Add(refreshSkew).Before(cr.AccessExpiresAt) {
		return cr, nil
	}
	return c.refresh(ctx, false)
}

// ---------------------------------------------------------------- API calls

// Response is an API response.
type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

// parseChallenge reads the auth-params of a WWW-Authenticate value.
func parseChallenge(h string) (scheme string, params map[string]string) {
	params = map[string]string{}
	scheme, rest, _ := strings.Cut(strings.TrimSpace(h), " ")
	for rest = strings.TrimSpace(rest); rest != ""; {
		eq := strings.IndexByte(rest, '=')
		if eq < 0 {
			break
		}
		name := strings.ToLower(strings.TrimSpace(rest[:eq]))
		rest = strings.TrimSpace(rest[eq+1:])
		var val string
		if strings.HasPrefix(rest, `"`) {
			var sb strings.Builder
			i := 1
			for ; i < len(rest) && rest[i] != '"'; i++ {
				if rest[i] == '\\' && i+1 < len(rest) {
					i++
				}
				sb.WriteByte(rest[i])
			}
			val = sb.String()
			if i < len(rest) {
				i++
			}
			rest = rest[i:]
		} else {
			end := strings.IndexByte(rest, ',')
			if end < 0 {
				end = len(rest)
			}
			val = strings.TrimSpace(rest[:end])
			rest = rest[end:]
		}
		params[name] = val
		rest = strings.TrimLeft(rest, ", ")
	}
	return scheme, params
}

// Do calls the API at path (a path on the signed-in server, never a URL: the
// token is only ever sent there) with a DPoP-bound access token. A 401 with
// the RFC 9470 challenge returns *StepUpError; a stale token is refreshed
// once and a server nonce is adopted, each with one retry.
func (c *Client) Do(ctx context.Context, method, path string, body []byte) (*Response, error) {
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.ContainsAny(path, "\\\r\n") {
		return nil, fmt.Errorf("%q is not an API path (want /api/...)", path)
	}
	if u, err := url.Parse(path); err != nil || u.Scheme != "" || u.Host != "" {
		return nil, fmt.Errorf("%q is not an API path (want /api/...)", path)
	}
	cr, err := c.credentials(ctx)
	if err != nil {
		return nil, err
	}
	key, err := cr.Key()
	if err != nil {
		return nil, err
	}
	nonce := cr.Nonce
	refreshed, noncesTried := false, false
	for {
		req, err := http.NewRequestWithContext(ctx, method, cr.Server+path, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		p, err := c.proof(key, method, req.URL.String(), cr.AccessToken, nonce)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "DPoP "+cr.AccessToken)
		req.Header.Set("DPoP", p)
		req.Header.Set("Accept", "application/json")
		if len(body) > 0 {
			req.Header.Set("Content-Type", "application/json")
		}
		res, b, err := c.roundTrip(req)
		if err != nil {
			return nil, err
		}
		out := &Response{Status: res.StatusCode, Header: res.Header, Body: b}
		if res.StatusCode != http.StatusUnauthorized {
			return out, nil
		}
		_, ch := parseChallenge(res.Header.Get("WWW-Authenticate"))
		switch ch["error"] {
		case "insufficient_user_authentication":
			se := &StepUpError{Reason: ch["error_description"], ACR: ch["acr_values"]}
			se.MaxAge, _ = strconv.Atoi(ch["max_age"])
			return out, se
		case "use_dpop_nonce":
			if n := res.Header.Get("DPoP-Nonce"); n != "" && !noncesTried {
				nonce, noncesTried = n, true
				continue
			}
		case "invalid_token", "invalid_dpop_proof":
			if !refreshed { // an expired or revoked token: one refresh says which
				refreshed = true
				if cr, err = c.refresh(ctx, true); err != nil {
					return out, err
				}
				nonce = cr.Nonce
				continue
			}
		}
		return out, nil
	}
}

// Whoami asks the API who the CLI session is (GET /api/auth/session).
func (c *Client) Whoami(ctx context.Context) (*Response, error) {
	return c.Do(ctx, http.MethodGet, "/api/auth/session", nil)
}

// Revoke tells the server to revoke cr's refresh token, its family and its CLI
// session (RFC 7009). The local file is not touched.
func (c *Client) Revoke(ctx context.Context, cr *Credentials) error {
	_, err := c.postForm(ctx, cr.Issuer+"/oauth/revoke", url.Values{"token": {cr.RefreshToken}, "client_id": {cr.ClientID}}, nil, nil)
	return err
}

// Logout revokes the session at the server (RFC 7009: the refresh token, its
// family and the CLI session) and deletes the local credentials. The local
// credentials are deleted even if the server cannot be reached; the returned
// error then says so, because the session is still live there until it
// expires.
func (c *Client) Logout(ctx context.Context) error {
	unlock, err := c.Store.Lock(15*time.Second, 2*time.Minute)
	if err != nil {
		return err
	}
	defer unlock()
	cr, err := c.Store.Load()
	if err != nil {
		return err
	}
	revokeErr := c.Revoke(ctx, cr)
	if err := c.Store.Delete(); err != nil {
		return err
	}
	if revokeErr != nil {
		return fmt.Errorf("signed out locally, but the server could not be told (the session stays valid there until it expires): %w", revokeErr)
	}
	return nil
}
