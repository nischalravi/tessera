package ssf

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Outbound calls (keys, discovery, poll, verification) all use s.HTTP, an
// internal/safehttp client. Error text names the operation and the status,
// never the URL (it can carry a token) or the response body.

// ErrKeysUnavailable: the transmitter's keys could not be fetched. The SET is
// neither accepted nor refused as invalid: the transmitter should try again.
var ErrKeysUnavailable = errors.New("the transmitter's signing keys are unavailable")

// jwksTTL is how long fetched keys are used; a SET signed by an unknown key
// forces one refresh, at most every jwksMinRefresh.
const (
	jwksTTL        = 10 * time.Minute
	jwksMinRefresh = 30 * time.Second
)

type jwksEntry struct {
	keys    []Key
	fetched time.Time
	url     string
}

func scrubErr(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// outboundSyntax is the exact syntax of a URL Tessera calls a transmitter
// at: http(s), an ASCII DNS name or a bracketed IP literal, an optional port,
// and a path and query of RFC 3986 characters. No user info or fragment can
// match. do checks it on the very string the request is built from, after
// outboundURL; the safehttp client still applies its address, port and
// redirect rules at dial time.
var outboundSyntax = regexp.MustCompile(`^https?://(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*|\[[0-9A-Fa-f:.]+\])(?::[0-9]{1,5})?(?:/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*)?(?:\?[A-Za-z0-9._~!$&'()*+,;=:@%/?-]*)?$`)

// outboundURL checks a transmitter-configured URL before any request is built:
// https (http only with Dev), a host, no user info, and no IP literal in a
// private, loopback or link-local range (loopback literals only with Dev). The
// safehttp client repeats these checks at dial time, after DNS resolution.
func (s *Service) outboundURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("the URL is not valid")
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && s.Dev:
	default:
		return nil, errors.New("the URL must use https")
	}
	if u.Hostname() == "" {
		return nil, errors.New("the URL has no host")
	}
	if u.User != nil {
		return nil, errors.New("the URL must not carry user info")
	}
	if a, err := netip.ParseAddr(u.Hostname()); err == nil {
		if a.Zone() != "" {
			return nil, errors.New("the URL host is not allowed")
		}
		if !(s.Dev && a.Unmap().IsLoopback()) && safehttp.Blocked(a) {
			return nil, errors.New("the URL host is not allowed")
		}
	}
	return u, nil
}

// do sends a request and returns the status and body (at most maxBody bytes).
func (s *Service) do(ctx context.Context, method, rawURL, bearer string, body any, maxBody int64) (int, []byte, error) {
	if s.HTTP == nil {
		return 0, nil, errors.New("outbound HTTP is not configured")
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rd = bytes.NewReader(b)
	}
	u, err := s.outboundURL(rawURL)
	if err != nil {
		return 0, nil, err
	}
	target := u.String()
	if !outboundSyntax.MatchString(target) {
		return 0, nil, errors.New("the URL is not allowed")
	}
	req, err := http.NewRequestWithContext(ctx, method, target, rd)
	if err != nil {
		return 0, nil, errors.New("the URL is not valid")
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := s.HTTP.Do(req) // #nosec G704 -- HTTP is an internal/safehttp client
	if err != nil {
		return 0, nil, scrubErr(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return 0, nil, scrubErr(err)
	}
	return resp.StatusCode, raw, nil
}

// keys returns the transmitter's signing keys: its inline JWKS, or the JWKS
// at its URL (cached; refresh forces a re-fetch when the cache is old enough).
func (s *Service) keys(ctx context.Context, tr *store.SSFTransmitter, refresh bool) ([]Key, error) {
	if tr.JWKSInline != "" {
		return ParseJWKS([]byte(tr.JWKSInline))
	}
	s.jwksMu.Lock()
	e, ok := s.jwks[tr.ID]
	s.jwksMu.Unlock()
	age := s.now().Sub(e.fetched)
	if ok && e.url == tr.JWKSURL && age < jwksTTL && (!refresh || age < jwksMinRefresh) {
		return e.keys, nil
	}
	status, raw, err := s.do(ctx, http.MethodGet, tr.JWKSURL, "", nil, 1<<20)
	if err == nil && status != http.StatusOK {
		err = fmt.Errorf("the JWKS endpoint answered %d", status)
	}
	var keys []Key
	if err == nil {
		keys, err = ParseJWKS(raw)
	}
	if err != nil {
		if ok && e.url == tr.JWKSURL && refresh {
			return e.keys, nil // keep using the cached keys; the SET is judged by them
		}
		return nil, fmt.Errorf("%w: %v", ErrKeysUnavailable, err)
	}
	s.jwksMu.Lock()
	if s.jwks == nil {
		s.jwks = map[string]jwksEntry{}
	}
	s.jwks[tr.ID] = jwksEntry{keys: keys, fetched: s.now(), url: tr.JWKSURL}
	s.jwksMu.Unlock()
	return keys, nil
}

// Metadata is what /.well-known/ssf-configuration tells (SSF 1.0 section 7.2).
type Metadata struct {
	Issuer                string   `json:"issuer"`
	JWKSURI               string   `json:"jwks_uri"`
	DeliveryMethods       []string `json:"delivery_methods_supported"`
	ConfigurationEndpoint string   `json:"configuration_endpoint"`
	VerificationEndpoint  string   `json:"verification_endpoint"`
}

// DiscoveryURL is the transmitter metadata URL of an issuer: the well-known
// path goes between the host and the issuer's own path.
func DiscoveryURL(issuer string) (string, error) {
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return "", errors.New("the issuer is not a URL")
	}
	u.RawQuery, u.Fragment = "", ""
	u.Path = "/.well-known/ssf-configuration" + strings.TrimRight(u.Path, "/")
	return u.String(), nil
}

// Discover fetches the transmitter metadata of issuer and checks its issuer.
func (s *Service) Discover(ctx context.Context, issuer string) (*Metadata, error) {
	u, err := DiscoveryURL(issuer)
	if err != nil {
		return nil, err
	}
	status, raw, err := s.do(ctx, http.MethodGet, u, "", nil, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("fetching /.well-known/ssf-configuration failed: %w", err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("/.well-known/ssf-configuration answered %d", status)
	}
	var m Metadata
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, errors.New("/.well-known/ssf-configuration is not valid JSON")
	}
	if m.Issuer != issuer {
		return nil, errors.New("the metadata's issuer is not the configured issuer")
	}
	for _, v := range []string{m.JWKSURI, m.VerificationEndpoint} {
		if err := checkURL("a metadata URL", v); err != nil {
			return nil, errors.New("the metadata holds an invalid URL")
		}
	}
	return &m, nil
}

// ApplyDiscovery fills the blank JWKS URL and verification endpoint of in from m.
func ApplyDiscovery(in *TransmitterInput, m *Metadata) {
	if in.JWKSURL == "" && len(in.JWKS) == 0 {
		in.JWKSURL = m.JWKSURI
	}
	if in.VerificationURL == "" {
		in.VerificationURL = m.VerificationEndpoint
	}
}
