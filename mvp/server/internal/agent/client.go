package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Client is the agent's end of the channel to Tessera. It pins Tessera's CA:
// only certificates that chain to the CA file the customer installed are
// trusted (the system roots are not consulted), and it presents the agent's
// own client certificate. It is an outbound-only client of the customer's own
// Tessera; the server's SSRF guard (safehttp) does not apply to it.
type Client struct {
	base string
	http *http.Client
}

// StatusError is a non-2xx answer from Tessera.
type StatusError struct {
	Status int
	Code   string
}

func (e *StatusError) Error() string { return fmt.Sprintf("tessera answered %d %s", e.Status, e.Code) }

// IsUnauthorized reports a 401: the agent was revoked or is not enrolled.
func IsUnauthorized(err error) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Status == http.StatusUnauthorized
}

// NewClient returns a Client for serverURL (https only). caPEM is the pinned
// CA bundle, cert the agent's client certificate.
func NewClient(serverURL string, caPEM []byte, cert tls.Certificate) (*Client, error) {
	u, err := url.Parse(serverURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") ||
		u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("agent: server_url must be an https URL of the form https://host[:port]")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("agent: the CA file holds no certificate")
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			RootCAs:      pool,
			Certificates: []tls.Certificate{cert},
		},
		ResponseHeaderTimeout: PollWait + 15*time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		IdleConnTimeout:       60 * time.Second,
		// no proxy: the pinned CA is the trust anchor and a proxy would add a
		// party the customer did not configure
		Proxy: nil,
	}
	return &Client{base: "https://" + u.Host, http: &http.Client{Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (c *Client) post(ctx context.Context, path string, in, out any, limit int64) (int, error) {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return 0, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, body)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return resp.StatusCode, err
	}
	if int64(len(raw)) > limit {
		return resp.StatusCode, errors.New("agent: the response is too large")
	}
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		return resp.StatusCode, &StatusError{Status: resp.StatusCode, Code: e.Error}
	}
	if out != nil && resp.StatusCode != http.StatusNoContent {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(out); err != nil {
			return resp.StatusCode, fmt.Errorf("agent: malformed response: %w", err)
		}
	}
	return resp.StatusCode, nil
}

// Enrol presents the single-use code and the agent's key (through the TLS
// handshake).
func (c *Client) Enrol(ctx context.Context, code string, t Telemetry) (*EnrolResponse, error) {
	var out EnrolResponse
	_, err := c.post(ctx, PathEnrol, EnrolRequest{Code: code, ProtocolVersion: ProtocolVersion, Telemetry: t}, &out, MaxRequestBytes)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// Heartbeat reports liveness, version and the allowlist hash.
func (c *Client) Heartbeat(ctx context.Context, t Telemetry) error {
	var out struct {
		OK         bool   `json:"ok"`
		MinVersion string `json:"min_version"`
	}
	_, err := c.post(ctx, PathHeartbeat, HeartbeatRequest{ProtocolVersion: ProtocolVersion, Telemetry: t}, &out, MaxRequestBytes)
	return err
}

// Poll waits for the next job. It returns (nil, nil) when none arrived. The
// job is decoded strictly: a field this agent does not know is refused.
func (c *Client) Poll(ctx context.Context) (*Job, error) {
	var j Job
	status, err := c.post(ctx, PathPoll, nil, &j, MaxRequestBytes)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNoContent {
		return nil, nil
	}
	return &j, nil
}

// Claim waits for the next pulled job (a sync). It returns (nil, nil) when
// none arrived. The job is decoded strictly.
func (c *Client) Claim(ctx context.Context) (*PulledJob, error) {
	var j PulledJob
	status, err := c.post(ctx, PathClaim, nil, &j, MaxRequestBytes)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNoContent {
		return nil, nil
	}
	return &j, nil
}

// Report returns a pulled job's result or error.
func (c *Client) Report(ctx context.Context, r PullResult) error {
	var out struct {
		OK bool `json:"ok"`
	}
	_, err := c.post(ctx, PathReport, r, &out, MaxRequestBytes)
	return err
}

// SendResult returns a job's result.
func (c *Client) SendResult(ctx context.Context, r Result) error {
	var out struct {
		OK bool `json:"ok"`
	}
	_, err := c.post(ctx, PathResult, r, &out, MaxRequestBytes)
	return err
}
