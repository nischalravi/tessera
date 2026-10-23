package safehttp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The cloud metadata services are the one place Tessera must reach a
// link-local address: a workload gets its credentials from them (AWS IMDSv2,
// Azure managed identity, GCP metadata server). Every other safehttp client
// refuses these addresses (SSRF: a request that reaches 169.254.169.254 leaks
// the node's credentials). MetadataClient is the narrow exception:
//
//   - it reaches only the fixed addresses below, on port 80, over plain http
//     (the services offer nothing else); no DNS lookup happens, and a host
//     name, another address or another port is refused before any socket;
//   - it follows no redirects and reads at most 64 KiB;
//   - it has no URL input of its own: the only caller is internal/cloudcred,
//     which builds the paths itself, never from a request, a tenant setting
//     or a configured URL (internal/archtest pins the single caller).
const (
	metadataTimeout  = 3 * time.Second
	metadataMaxBytes = 64 << 10
)

// metadataAddrs are the only hosts MetadataClient reaches.
var metadataAddrs = map[string]string{
	"169.254.169.254": "169.254.169.254:80", // AWS IMDS, Azure IMDS, GCP metadata server
	"169.254.170.2":   "169.254.170.2:80",   // ECS/Fargate container credentials
	"[fd00:ec2::254]": "[fd00:ec2::254]:80", // AWS IMDS over IPv6
}

// ErrMetadataTarget: the request is not for one of the fixed metadata addresses.
var ErrMetadataTarget = errors.New("safehttp: not a cloud metadata address")

// MetadataClient returns the client for credential fetches from the cloud
// metadata services. See the package comment of this file for its limits.
func MetadataClient() *http.Client { return newMetadataClient(nil) }

// NewMetadataClientForTest is MetadataClient with every dial redirected to
// target (a local test server). The request URL is still checked against the
// fixed addresses. Tests only.
func NewMetadataClientForTest(tb testing.TB, target string) *http.Client {
	if tb == nil || !testing.Testing() {
		panic("safehttp: NewMetadataClientForTest is for tests only")
	}
	tb.Helper()
	return newMetadataClient(func(string) string { return target })
}

func newMetadataClient(redirect func(string) string) *http.Client {
	d := net.Dialer{Timeout: metadataTimeout}
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			addr, ok := metadataDialTarget(address)
			if !ok {
				return nil, fmt.Errorf("%w: %s", ErrMetadataTarget, address)
			}
			if redirect != nil {
				addr = redirect(addr)
			}
			return d.DialContext(ctx, "tcp", addr)
		},
		ResponseHeaderTimeout:  metadataTimeout,
		MaxResponseHeaderBytes: 16 << 10,
		DisableKeepAlives:      true,
	}
	return &http.Client{
		Transport: &metadataGuard{next: tr},
		Timeout:   metadataTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // a redirect is an answer, not a hop
		},
	}
}

// metadataDialTarget maps a request's host:port to the fixed dial address.
func metadataDialTarget(address string) (string, bool) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port != "80" {
		return "", false
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	t, ok := metadataAddrs[host]
	return t, ok && t != ""
}

type metadataGuard struct{ next http.RoundTripper }

func (g *metadataGuard) RoundTrip(req *http.Request) (*http.Response, error) {
	closeBody := func() {
		if req.Body != nil {
			_ = req.Body.Close()
		}
	}
	u := req.URL
	if u.Scheme != "http" || u.User != nil || u.Fragment != "" {
		closeBody()
		return nil, fmt.Errorf("%w: %q", ErrMetadataTarget, u.Redacted())
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(strings.Trim(u.Hostname(), "[]"), "80")
	}
	if _, ok := metadataDialTarget(host); !ok {
		closeBody()
		return nil, fmt.Errorf("%w: %s", ErrMetadataTarget, u.Host)
	}
	resp, err := g.next.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Body = &limitedBody{rc: resp.Body, left: metadataMaxBytes}
	return resp, nil
}
