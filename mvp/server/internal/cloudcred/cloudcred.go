// Package cloudcred fetches short-lived credentials for the three clouds from
// the workload's own identity, so Tessera needs no static cloud key:
//
//   - AWS: the standard environment keys, then web identity (IRSA, the
//     AWS_WEB_IDENTITY_TOKEN_FILE of EKS), then ECS container credentials,
//     then the EC2 instance role through IMDSv2;
//   - Azure: workload identity federation (AKS: AZURE_FEDERATED_TOKEN_FILE),
//     then the managed identity endpoint of the VM or scale set;
//   - GCP: a service-account key file (GOOGLE_APPLICATION_CREDENTIALS), then
//     the metadata server (GKE workload identity, GCE).
//
// Network rules. Token exchanges with public endpoints (STS, Microsoft Entra,
// Google OAuth) use the SSRF-guarded client of internal/safehttp. The link-local
// metadata services are reached only through safehttp.MetadataClient, whose
// fixed addresses and port are the only metadata access Tessera has. Every
// URL here is built from constants and from the environment of the process
// (not from tenant, request or stored configuration), and no secret reaches
// an error message or a log.
package cloudcred

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
)

// maxResponse bounds every credential response.
const maxResponse = 64 << 10

// refreshEarly renews a credential this long before it expires.
const refreshEarly = 5 * time.Minute

// Env is the process environment and file system, replaceable in tests.
type Env struct {
	Getenv   func(string) string
	ReadFile func(string) ([]byte, error)
	Now      func() time.Time
}

func (e Env) get(k string) string {
	if e.Getenv != nil {
		return e.Getenv(k)
	}
	return os.Getenv(k)
}

func (e Env) read(p string) ([]byte, error) {
	if e.ReadFile != nil {
		return e.ReadFile(p)
	}
	return os.ReadFile(p) // #nosec G304 -- the path comes from the process's own environment
}

func (e Env) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// do sends req and returns the body of a 2xx answer (at most maxResponse).
// The error carries the status and, never, the body: a token response must not
// reach a log.
func do(c *http.Client, req *http.Request, what string) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("cloudcred: %s: no HTTP client", what)
	}
	resp, err := c.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // the URL is not needed in the message
		}
		return nil, fmt.Errorf("cloudcred: %s: %w", what, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return nil, fmt.Errorf("cloudcred: %s: %w", what, err)
	}
	if len(b) > maxResponse {
		return nil, fmt.Errorf("cloudcred: %s: response too large", what)
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("cloudcred: %s: %s", what, resp.Status)
	}
	return b, nil
}

// cached holds one credential until shortly before it expires.
type cached[T any] struct {
	mu  sync.Mutex
	val T
	exp time.Time
}

func (c *cached[T]) get(now time.Time, fetch func() (T, time.Time, error)) (T, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.exp.IsZero() && now.Before(c.exp.Add(-refreshEarly)) {
		return c.val, nil
	}
	v, exp, err := fetch()
	if err != nil {
		var zero T
		return zero, err
	}
	c.val, c.exp = v, exp
	return v, nil
}

// ErrNoCredentials: no source of credentials is available to this process.
var ErrNoCredentials = errors.New("cloudcred: no workload credentials found")
