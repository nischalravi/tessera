// Package casclient signs users in through a CAS 3.0 server (Apereo CAS,
// issue #152): the /login redirect with an exact service URL, and service
// ticket validation at /p3/serviceValidate through the safehttp client.
//
// Only service tickets (ST-) are accepted: no proxy tickets, no proxy
// granting (pgtUrl is never sent) and a response that lists proxies is
// refused. The XML answer is size-capped and checked for encoding/xml
// round-trip safety; it must carry exactly one cas:user, and any markup
// inside the user or an attribute value (a comment splitting
// "adm<!---->in", a nested element) is refused rather than flattened.
//
// Every refusal is an *Error with a machine-readable Reason for the
// auth.login.failure audit event.
package casclient

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	xrv "github.com/mattermost/xml-roundtrip-validator"
)

// NS is the CAS protocol namespace.
const NS = "http://www.yale.edu/tp/cas"

// Limits.
const (
	MaxResponseBytes = 64 << 10
	MaxTicketBytes   = 256
)

// Failure reasons (auth.login.failure detail.reason).
const (
	ReasonConfig     = "cas_connection_misconfigured"
	ReasonTicket     = "cas_ticket_invalid"
	ReasonValidation = "cas_validation_unavailable"
	ReasonFailure    = "cas_authentication_failure"
	ReasonMalformed  = "cas_response_malformed"
	ReasonRoundTrip  = "cas_xml_roundtrip"
	ReasonUser       = "cas_user_invalid"
	ReasonProxied    = "cas_proxied_ticket"
)

// Error is a refused sign-in step. Reason is safe to audit; Err is for logs.
type Error struct {
	Reason string
	Err    error
}

func (e *Error) Error() string {
	if e.Err == nil {
		return "casclient: " + e.Reason
	}
	return "casclient: " + e.Reason + ": " + e.Err.Error()
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

// Client validates tickets through HTTP (the safehttp client).
type Client struct{ http *http.Client }

// New returns a Client; h must be the safehttp client.
func New(h *http.Client) (*Client, error) {
	if h == nil {
		return nil, errors.New("casclient: an HTTP client is required (internal/safehttp)")
	}
	return &Client{http: h}, nil
}

func serverURL(s string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimRight(s, "/"))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.RawQuery != "" || u.Fragment != "" {
		return nil, fail(ReasonConfig, fmt.Errorf("CAS server URL %q", s))
	}
	return u, nil
}

// LoginURL is the CAS /login URL for service; renew forces the user to
// authenticate again (step-up).
func LoginURL(server, service string, renew bool) (string, error) {
	u, err := serverURL(server)
	if err != nil {
		return "", err
	}
	u.Path += "/login"
	v := url.Values{"service": {service}}
	if renew {
		v.Set("renew", "true")
	}
	u.RawQuery = v.Encode()
	return u.String(), nil
}

// Ticket is a validated service ticket's content.
type Ticket struct {
	User       string
	Attributes map[string][]string
	// AuthenticationDate is the server's authenticationDate attribute (zero
	// when not released); NewLogin its isFromNewLogin (nil when absent).
	AuthenticationDate time.Time
	NewLogin           *bool
	Raw                []byte
}

type serviceResponse struct {
	XMLName xml.Name `xml:"http://www.yale.edu/tp/cas serviceResponse"`
	Success *struct {
		Users      []value `xml:"http://www.yale.edu/tp/cas user"`
		Attributes *struct {
			Values []value `xml:",any"`
		} `xml:"http://www.yale.edu/tp/cas attributes"`
		Proxies *struct{} `xml:"http://www.yale.edu/tp/cas proxies"`
		PGT     *struct{} `xml:"http://www.yale.edu/tp/cas proxyGrantingTicket"`
	} `xml:"http://www.yale.edu/tp/cas authenticationSuccess"`
	Failure *struct {
		Code string `xml:"code,attr"`
	} `xml:"http://www.yale.edu/tp/cas authenticationFailure"`
}

type value struct {
	XMLName xml.Name
	Inner   string `xml:",innerxml"`
}

// text is the value's text, refusing any markup inside it.
func (v value) text() (string, bool) {
	if strings.ContainsAny(v.Inner, "<>") {
		return "", false
	}
	var s string
	if err := xml.Unmarshal([]byte("<v>"+v.Inner+"</v>"), &s); err != nil {
		return "", false
	}
	return s, true
}

// Validate redeems ticket for service at the CAS server (renew when the
// sign-in had to be a new authentication).
func (c *Client) Validate(ctx context.Context, server, service, ticket string, renew bool) (*Ticket, error) {
	u, err := serverURL(server)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(ticket, "ST-") || len(ticket) > MaxTicketBytes ||
		strings.IndexFunc(ticket, func(r rune) bool { return r > unicode.MaxASCII || !unicode.IsPrint(r) || r == ' ' }) >= 0 {
		return nil, fail(ReasonTicket, nil) // only service tickets; PT- proxy tickets are refused
	}
	u.Path += "/p3/serviceValidate"
	v := url.Values{"service": {service}, "ticket": {ticket}}
	if renew {
		v.Set("renew", "true")
	}
	u.RawQuery = v.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fail(ReasonConfig, err)
	}
	req.Header.Set("Accept", "application/xml")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fail(ReasonValidation, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	switch {
	case err != nil:
		return nil, fail(ReasonValidation, err)
	case resp.StatusCode != http.StatusOK:
		return nil, fail(ReasonValidation, fmt.Errorf("status %d", resp.StatusCode))
	case len(raw) > MaxResponseBytes:
		return nil, fail(ReasonMalformed, errors.New("response too large"))
	}
	return Parse(raw)
}

// Parse checks and decodes a serviceValidate answer.
func Parse(raw []byte) (*Ticket, error) {
	if err := xrv.Validate(bytes.NewReader(raw)); err != nil {
		return nil, fail(ReasonRoundTrip, err)
	}
	var r serviceResponse
	if err := xml.Unmarshal(raw, &r); err != nil {
		return nil, fail(ReasonMalformed, err)
	}
	switch {
	case r.Failure != nil && r.Success == nil:
		return nil, fail(ReasonFailure, fmt.Errorf("code %q", r.Failure.Code))
	case r.Success == nil || r.Failure != nil:
		return nil, fail(ReasonMalformed, errors.New("not exactly one of authenticationSuccess and authenticationFailure"))
	case r.Success.Proxies != nil || r.Success.PGT != nil:
		return nil, fail(ReasonProxied, nil)
	case len(r.Success.Users) != 1:
		return nil, fail(ReasonUser, fmt.Errorf("%d cas:user elements", len(r.Success.Users)))
	}
	user, ok := r.Success.Users[0].text()
	if !ok || user == "" || strings.TrimSpace(user) != user || len(user) > 255 ||
		strings.IndexFunc(user, func(r rune) bool { return !unicode.IsPrint(r) }) >= 0 {
		return nil, fail(ReasonUser, nil)
	}
	t := &Ticket{User: user, Attributes: map[string][]string{}, Raw: raw}
	if r.Success.Attributes != nil {
		for _, a := range r.Success.Attributes.Values {
			if a.XMLName.Space != NS {
				continue
			}
			s, ok := a.text()
			if !ok {
				return nil, fail(ReasonMalformed, fmt.Errorf("markup inside attribute %s", a.XMLName.Local))
			}
			t.Attributes[a.XMLName.Local] = append(t.Attributes[a.XMLName.Local], strings.TrimSpace(s))
		}
	}
	if d := t.Attributes["authenticationDate"]; len(d) == 1 {
		t.AuthenticationDate = parseDate(d[0])
	}
	if n := t.Attributes["isFromNewLogin"]; len(n) == 1 {
		b := n[0] == "true"
		t.NewLogin = &b
	}
	return t, nil
}

// parseDate reads an ISO-8601 date as CAS prints it (Java ZonedDateTime may
// append the zone id in brackets: "2026-10-11T09:30:00Z[UTC]").
func parseDate(s string) time.Time {
	if i := strings.IndexByte(s, '['); i > 0 {
		s = s[:i]
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}
