// Package connsynctest holds the test helpers the connector packages share: a
// TLS server on loopback that replays recorded fixtures, and the safehttp
// client and Runtime that reach it. Import it only from tests.
package connsynctest

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// Req is one request the server saw.
type Req struct {
	Method, Path, Query, Authorization string
}

// Server is a recorded-fixture server.
type Server struct {
	*httptest.Server
	mu   sync.Mutex
	reqs []Req
}

// New starts a TLS server on loopback that records every request and then
// calls h. It is closed when the test ends.
func New(t testing.TB, h http.Handler) *Server {
	t.Helper()
	s := &Server{}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.reqs = append(s.reqs, Req{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Get("Authorization")})
		s.mu.Unlock()
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(s.Close)
	return s
}

// Requests returns the requests seen so far.
func (s *Server) Requests() []Req {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Req(nil), s.reqs...)
}

// Count returns how many requests had a path starting with prefix.
func (s *Server) Count(prefix string) int {
	n := 0
	for _, r := range s.Requests() {
		if strings.HasPrefix(r.Path, prefix) {
			n++
		}
	}
	return n
}

// Runtime is a dev runtime with the loopback exception, which is how tests
// reach the server.
var Runtime = connsync.Runtime{Env: config.Dev, AllowLoopback: true}

// Options returns safehttp options for a client that trusts the server's
// certificate, reads at most maxBody bytes per response (0: the safehttp
// default) and reaches the loopback server (the dev loopback exception).
// Tests pass them to safehttp.NewForTest, which only a _test.go file may call.
func (s *Server) Options(maxBody int64) safehttp.Options {
	pool := x509.NewCertPool()
	pool.AddCert(s.Certificate())
	return safehttp.Options{Env: config.Dev, AllowLoopback: true, RootCAs: pool, MaxBodyBytes: maxBody, Timeout: 10 * time.Second}
}

// Fixture reads testdata/<name> (relative to the calling test's package) and
// replaces {{BASE}} with base, so recorded pages can link to the server.
func Fixture(t testing.TB, name, base string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name)) // #nosec G304 -- a fixed testdata directory and a name from the test itself
	if err != nil {
		t.Fatal(err)
	}
	return []byte(strings.ReplaceAll(string(b), "{{BASE}}", base))
}

// NoSleep replaces Backoff.Sleep: it records the requested waits and returns
// immediately.
type NoSleep struct {
	mu    sync.Mutex
	Waits []time.Duration
}

// Sleep implements the Backoff.Sleep signature.
func (n *NoSleep) Sleep(ctx context.Context, d time.Duration) error {
	n.mu.Lock()
	n.Waits = append(n.Waits, d)
	n.mu.Unlock()
	return ctx.Err()
}
