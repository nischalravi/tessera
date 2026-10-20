package helpdesk

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
	"strings"
	"sync"
)

// Executor systems.
const (
	SystemOkta      = "okta"
	SystemEntra     = "entra"
	SystemSimulated = "simulated"
)

// Target is the account a reset runs against.
type Target struct {
	System   string
	UserID   string // the provider's user id
	Username string
	Kind     string // KindPassword or KindMFA
}

// Result is what a reset did. Steps are for the audit trail and the case
// panel and carry no secret. TemporaryAccessPass is the one secret a reset can
// produce (Entra): it is returned to the caller once and never stored,
// audited or logged.
type Result struct {
	Steps               []string `json:"steps"`
	TemporaryAccessPass string   `json:"-"`
}

// ResetExecutor runs a reset at an IdP. An error means the reset did not
// complete; the case stays retryable and nothing is reported as done.
type ResetExecutor interface {
	Reset(ctx context.Context, t Target) (Result, error)
}

var userIDRE = regexp.MustCompile(`^[A-Za-z0-9._@+:-]{1,254}$`)

// ErrBadTarget: the provider user id is not a plausible id.
var ErrBadTarget = errors.New("helpdesk: the account has no usable provider user id")

func (t Target) check() error {
	if !userIDRE.MatchString(t.UserID) {
		return ErrBadTarget
	}
	return nil
}

// ---------------------------------------------------------------- fakes

// FakeExecutor records its calls and fails on demand (tests).
type FakeExecutor struct {
	mu    sync.Mutex
	calls []Target
	// Err, when set, is returned by every Reset.
	Err error
	// TAP, when set, is returned as the temporary access pass.
	TAP string
}

// Reset implements ResetExecutor.
func (f *FakeExecutor) Reset(_ context.Context, t Target) (Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, t)
	if f.Err != nil {
		return Result{}, f.Err
	}
	return Result{Steps: []string{"fake " + t.Kind + " reset"}, TemporaryAccessPass: f.TAP}, nil
}

// Calls returns the targets Reset was called with.
func (f *FakeExecutor) Calls() []Target {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Target(nil), f.calls...)
}

// SimulatedExecutor pretends to reset at an IdP, for demos and the dev and
// test instances: it calls nothing and says so in its steps. The service
// refuses it in production.
type SimulatedExecutor struct{}

// Reset implements ResetExecutor.
func (SimulatedExecutor) Reset(_ context.Context, t Target) (Result, error) {
	steps := []string{"simulated: no IdP was called"}
	if t.Kind == KindMFA {
		steps = append(steps, "simulated: factors reset for "+t.Username)
	} else {
		steps = append(steps, "simulated: password reset for "+t.Username)
	}
	return Result{Steps: steps}, nil
}

// ---------------------------------------------------------------- client

// maxBody caps an IdP answer.
const maxBody = 1 << 20

// client is a small JSON client for one provider. hc must come from
// internal/safehttp.
type client struct {
	hc   *http.Client
	base *url.URL
	auth string
}

func newClient(hc *http.Client, baseURL, def, scheme, token string) (*client, error) {
	if hc == nil {
		return nil, errors.New("helpdesk: outbound HTTP is not configured")
	}
	if baseURL == "" {
		baseURL = def
	}
	u, err := url.Parse(baseURL)
	if err != nil || baseURL == "" || u.Host == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("helpdesk: base_url is not a valid URL")
	}
	u.RawQuery, u.Fragment = "", ""
	if token == "" {
		return nil, errors.New("helpdesk: no token configured for this provider")
	}
	return &client{hc: hc, base: u, auth: scheme + " " + token}, nil
}

// StatusError is a non-2xx answer; it carries the method, path and status only.
type StatusError struct {
	Method, Path string
	Status       int
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("%s %s: status %d", e.Method, e.Path, e.Status)
}

// do sends one request. path must already be escaped. A 2xx body is decoded
// into out when out is non-nil. Error text never carries the URL query, the
// token or the body.
func (c *client) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	u := *c.base
	u.Path = strings.TrimRight(u.Path, "/") + path
	u.RawPath = ""
	if q != nil {
		u.RawQuery = q.Encode()
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", c.auth)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req) // #nosec G704 -- hc is an internal/safehttp client
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return fmt.Errorf("%s %s: unreadable answer", method, path)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &StatusError{method, path, resp.StatusCode}
	}
	if out != nil && len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("%s %s: unreadable answer", method, path)
		}
	}
	return nil
}

func esc(s string) string { return url.PathEscape(s) }

// ---------------------------------------------------------------- Okta

// OktaExecutor resets at Okta with an API token (scope okta.users.manage).
type OktaExecutor struct{ c *client }

// NewOkta returns the Okta executor. baseURL is the org URL
// (https://example.okta.com); hc must come from internal/safehttp.
func NewOkta(hc *http.Client, baseURL, token string) (*OktaExecutor, error) {
	c, err := newClient(hc, baseURL, "", "SSWS", token)
	if err != nil {
		return nil, err
	}
	return &OktaExecutor{c}, nil
}

// Reset implements ResetExecutor. An MFA reset is Okta's reset_factors. A
// password reset is reset_password with sendEmail=true: Okta emails the
// reset link to the user, so the link (a secret) never reaches Tessera.
func (o *OktaExecutor) Reset(ctx context.Context, t Target) (Result, error) {
	if err := t.check(); err != nil {
		return Result{}, err
	}
	base := "/api/v1/users/" + esc(t.UserID) + "/lifecycle/"
	if t.Kind == KindMFA {
		if err := o.c.do(ctx, http.MethodPost, base+"reset_factors", nil, nil, nil); err != nil {
			return Result{}, err
		}
		return Result{Steps: []string{"okta: reset all enrolled factors"}}, nil
	}
	q := url.Values{"sendEmail": {"true"}}
	if err := o.c.do(ctx, http.MethodPost, base+"reset_password", q, nil, nil); err != nil {
		return Result{}, err
	}
	return Result{Steps: []string{"okta: password reset link emailed to the user"}}, nil
}

// ---------------------------------------------------------------- Entra

// EntraExecutor resets at Microsoft Entra through Graph with a bearer token
// (UserAuthenticationMethod.ReadWrite.All).
type EntraExecutor struct{ c *client }

// NewEntra returns the Entra executor. baseURL defaults to Graph v1.0.
func NewEntra(hc *http.Client, baseURL, token string) (*EntraExecutor, error) {
	c, err := newClient(hc, baseURL, "https://graph.microsoft.com", "Bearer", token)
	if err != nil {
		return nil, err
	}
	return &EntraExecutor{c}, nil
}

// entraMethodPaths maps a Graph authentication method type to its delete
// endpoint segment. The password method cannot be deleted and is skipped.
var entraMethodPaths = map[string]string{
	"#microsoft.graph.phoneAuthenticationMethod":                   "phoneMethods",
	"#microsoft.graph.microsoftAuthenticatorAuthenticationMethod":  "microsoftAuthenticatorMethods",
	"#microsoft.graph.fido2AuthenticationMethod":                   "fido2Methods",
	"#microsoft.graph.softwareOathAuthenticationMethod":            "softwareOathMethods",
	"#microsoft.graph.windowsHelloForBusinessAuthenticationMethod": "windowsHelloForBusinessMethods",
	"#microsoft.graph.emailAuthenticationMethod":                   "emailMethods",
	"#microsoft.graph.temporaryAccessPassAuthenticationMethod":     "temporaryAccessPassMethods",
}

// tapMinutes is the lifetime of an issued temporary access pass; it is
// single-use.
const tapMinutes = 60

// Reset implements ResetExecutor. An MFA reset deletes every deletable
// authentication method, then issues a single-use temporary access pass so the
// user can register new ones. A password reset issues the pass only: the user
// signs in with it and sets a new password through self-service. A method that
// cannot be deleted, or an unknown method type, fails the reset: it is never
// reported as done.
func (e *EntraExecutor) Reset(ctx context.Context, t Target) (Result, error) {
	if err := t.check(); err != nil {
		return Result{}, err
	}
	base := "/v1.0/users/" + esc(t.UserID) + "/authentication/"
	var res Result
	if t.Kind == KindMFA {
		var list struct {
			Value []struct {
				Type string `json:"@odata.type"`
				ID   string `json:"id"`
			} `json:"value"`
		}
		if err := e.c.do(ctx, http.MethodGet, base+"methods", nil, nil, &list); err != nil {
			return Result{}, err
		}
		deleted := 0
		for _, m := range list.Value {
			if m.Type == "#microsoft.graph.passwordAuthenticationMethod" {
				continue
			}
			seg, ok := entraMethodPaths[m.Type]
			if !ok || !userIDRE.MatchString(m.ID) {
				return Result{}, fmt.Errorf("helpdesk: entra method %q cannot be deleted by Tessera; remove it by hand", m.Type)
			}
			if err := e.c.do(ctx, http.MethodDelete, base+seg+"/"+esc(m.ID), nil, nil, nil); err != nil {
				return Result{}, err
			}
			deleted++
		}
		res.Steps = append(res.Steps, fmt.Sprintf("entra: deleted %d authentication method(s)", deleted))
	}
	var tap struct {
		Pass string `json:"temporaryAccessPass"`
	}
	body := map[string]any{"lifetimeInMinutes": tapMinutes, "isUsableOnce": true}
	if err := e.c.do(ctx, http.MethodPost, base+"temporaryAccessPassMethods", nil, body, &tap); err != nil {
		return Result{}, err
	}
	if tap.Pass == "" {
		return Result{}, errors.New("helpdesk: entra issued no temporary access pass")
	}
	res.TemporaryAccessPass = tap.Pass
	res.Steps = append(res.Steps, fmt.Sprintf("entra: issued a single-use temporary access pass (%d minutes)", tapMinutes))
	return res, nil
}
