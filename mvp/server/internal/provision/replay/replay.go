// Package replay serves recorded HTTP exchanges ("cassettes") to a client
// under test, so connector tests run against what real targets answered
// without any network.
//
// A cassette is JSON: {"interactions":[{"request":{"method","path","query" (a map of
// parameters the request must carry), "body_contains"},"response":{"status","headers","body"}}]}. A request
// matches the first unused interaction with the same method, path and (when
// given) query; body_contains lists substrings the request body must hold
// (they pin PATCH semantics). A request nothing matches is answered 599 and
// recorded in Unmatched; interactions never used are in Unused.
package replay

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
)

// Interaction is one recorded request and its response.
type Interaction struct {
	Request struct {
		Method       string            `json:"method"`
		Path         string            `json:"path"`
		Query        map[string]string `json:"query"`
		BodyContains []string          `json:"body_contains"`
	} `json:"request"`
	Response struct {
		Status  int               `json:"status"`
		Headers map[string]string `json:"headers"`
		Body    json.RawMessage   `json:"body"`
	} `json:"response"`
	used bool
}

// Cassette is a set of interactions.
type Cassette struct {
	Name         string         `json:"name"`
	Interactions []*Interaction `json:"interactions"`

	mu        sync.Mutex
	unmatched []string
	requests  []string
}

// Load reads a cassette file.
func Load(path string) (*Cassette, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- test fixture paths
	if err != nil {
		return nil, err
	}
	var c Cassette
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("replay: %s: %w", path, err)
	}
	return &c, nil
}

// Handler serves the cassette. BaseURL is replaced in headers and bodies:
// the literal "{{base}}" becomes base, so a Link header can name the test server.
func (c *Cassette) Handler(base func() string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		defer c.mu.Unlock()
		c.requests = append(c.requests, r.Method+" "+r.URL.RequestURI())
		for _, in := range c.Interactions {
			if in.used || !in.matches(r, string(body)) {
				continue
			}
			in.used = true
			for k, v := range in.Response.Headers {
				w.Header().Set(k, strings.ReplaceAll(v, "{{base}}", base()))
			}
			if w.Header().Get("Content-Type") == "" {
				w.Header().Set("Content-Type", "application/json")
			}
			w.WriteHeader(in.Response.Status)
			if len(in.Response.Body) > 0 {
				_, _ = w.Write([]byte(strings.ReplaceAll(string(in.Response.Body), "{{base}}", base())))
			}
			return
		}
		c.unmatched = append(c.unmatched, r.Method+" "+r.URL.RequestURI()+" "+string(body))
		w.WriteHeader(599)
	})
}

func (in *Interaction) matches(r *http.Request, body string) bool {
	q := in.Request
	if q.Method != r.Method || q.Path != r.URL.Path {
		return false
	}
	for k, v := range q.Query {
		if r.URL.Query().Get(k) != v {
			return false
		}
	}
	for _, s := range q.BodyContains {
		if !strings.Contains(body, s) {
			return false
		}
	}
	return true
}

// Unmatched lists requests no interaction answered.
func (c *Cassette) Unmatched() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.unmatched...)
}

// Unused lists interactions no request used.
func (c *Cassette) Unused() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, in := range c.Interactions {
		if !in.used {
			out = append(out, in.Request.Method+" "+in.Request.Path)
		}
	}
	return out
}

// Requests lists the requests received, "METHOD uri".
func (c *Cassette) Requests() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.requests...)
}
