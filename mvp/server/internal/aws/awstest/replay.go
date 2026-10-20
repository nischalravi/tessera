// Package awstest records and replays AWS API traffic at the SDK's HTTP layer
// (design §13.1, §11.1). A Replay is an aws.HTTPClient: hand it to an SDK
// client and every request is answered from a cassette, with no network and no
// credentials. In record mode it forwards to an inner client and stores the
// answers.
//
// A cassette entry is keyed by a canonical hash of the request (method, host,
// path, query and form parameters, sorted) plus the fixture version, so a
// request made against another fixture never matches. An entry holds a list of
// responses, served in order; this is how pagination (each page has its own
// Marker, so its own key) and retries (the same key answered first with a
// throttle, then with success) are recorded. Asking for more responses than
// were recorded is an error, never a repeat, so a retry loop that does not
// terminate fails the test instead of hanging.
//
// Nothing here signs a request or stores a header other than a small allowlist
// of response headers, so a cassette never holds credentials.
package awstest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
)

// Errors returned by Replay.Do.
var (
	ErrNoRecording       = errors.New("awstest: no recording for request")
	ErrCassetteExhausted = errors.New("awstest: cassette has no more responses for request")
	ErrReadOnly          = errors.New("awstest: replay cannot record without an inner client")
)

// Response is one recorded HTTP response.
type Response struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body"`
}

// Entry is every response recorded for one canonical request.
type Entry struct {
	Key       string     `json:"key"`
	Request   string     `json:"request"` // canonical text, for review; the key is its hash
	Responses []Response `json:"responses"`
}

// Cassette is a set of recorded entries for one fixture version.
type Cassette struct {
	FixtureVersion string  `json:"fixture_version"`
	Entries        []Entry `json:"entries"`
}

// HTTPDoer is the inner client of record mode (aws.HTTPClient). The caller
// supplies it so every outbound call goes through internal/safehttp.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// keptHeaders are the only response headers a cassette stores.
var keptHeaders = []string{"Content-Type", "Retry-After", "X-Amzn-Requestid", "X-Amzn-Errortype"}

// Replay serves a cassette. The zero value is not usable; call NewReplay or
// NewRecorder.
type Replay struct {
	mu       sync.Mutex
	cassette *Cassette
	index    map[string]int // key to entry position
	served   map[string]int // key to responses served so far
	inner    HTTPDoer       // non-nil in record mode
}

// NewReplay serves c and nothing else.
func NewReplay(c *Cassette) *Replay {
	r := &Replay{cassette: c, index: map[string]int{}, served: map[string]int{}}
	for i, e := range c.Entries {
		r.index[e.Key] = i
	}
	return r
}

// NewRecorder forwards to inner and records every answer into a new cassette
// for fixtureVersion.
func NewRecorder(inner HTTPDoer, fixtureVersion string) (*Replay, error) {
	if inner == nil {
		return nil, ErrReadOnly
	}
	r := NewReplay(&Cassette{FixtureVersion: fixtureVersion})
	r.inner = inner
	return r, nil
}

// Load reads a cassette file.
func Load(path string) (*Cassette, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- the harness reads its own testdata path
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse decodes cassette JSON strictly.
func Parse(b []byte) (*Cassette, error) {
	var c Cassette
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("awstest: cassette: %w", err)
	}
	if c.FixtureVersion == "" {
		return nil, errors.New("awstest: cassette has no fixture_version")
	}
	seen := map[string]bool{}
	for _, e := range c.Entries {
		if e.Key == "" || seen[e.Key] {
			return nil, fmt.Errorf("awstest: cassette entry key %q is empty or repeated", e.Key)
		}
		seen[e.Key] = true
		if len(e.Responses) == 0 {
			return nil, fmt.Errorf("awstest: cassette entry %q has no responses", e.Key)
		}
	}
	return &c, nil
}

// Cassette returns the cassette, including anything recorded so far.
func (r *Replay) Cassette() *Cassette {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cassette
}

// Save writes the cassette to path with entries sorted by key.
func (r *Replay) Save(path string) error {
	r.mu.Lock()
	c := *r.cassette
	c.Entries = append([]Entry(nil), c.Entries...)
	r.mu.Unlock()
	sort.Slice(c.Entries, func(i, j int) bool { return c.Entries[i].Key < c.Entries[j].Key })
	b, err := json.MarshalIndent(&c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

// Canonical returns the canonical text of a request and its body: method, host,
// path, then the sorted query and form parameters one per line. A body that is
// not a form is represented by its SHA-256.
func Canonical(req *http.Request, body []byte) string {
	var sb strings.Builder
	sb.WriteString(req.Method + " " + strings.ToLower(req.URL.Host) + req.URL.Path + "\n")
	params := url.Values{}
	for k, vs := range req.URL.Query() {
		params[k] = append(params[k], vs...)
	}
	if len(body) > 0 {
		if strings.HasPrefix(req.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
			if form, err := url.ParseQuery(string(body)); err == nil {
				for k, vs := range form {
					params[k] = append(params[k], vs...)
				}
			} else {
				fmt.Fprintf(&sb, "body-sha256=%x\n", sha256.Sum256(body))
			}
		} else {
			fmt.Fprintf(&sb, "body-sha256=%x\n", sha256.Sum256(body))
		}
	}
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		vs := append([]string(nil), params[k]...)
		sort.Strings(vs)
		for _, v := range vs {
			sb.WriteString(k + "=" + v + "\n")
		}
	}
	return sb.String()
}

// Key is the cassette key of a canonical request under a fixture version.
func Key(fixtureVersion, canonical string) string {
	sum := sha256.Sum256([]byte(fixtureVersion + "\n" + canonical))
	return hex.EncodeToString(sum[:])
}

// Do implements aws.HTTPClient.
func (r *Replay) Do(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		b, err := io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return nil, err
		}
		body = b
	}
	canon := Canonical(req, body)
	key := Key(r.cassette.FixtureVersion, canon)

	if r.inner != nil {
		return r.record(req, body, canon, key)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	i, ok := r.index[key]
	if !ok {
		return nil, fmt.Errorf("%w:\n%s", ErrNoRecording, canon)
	}
	n := r.served[key]
	e := r.cassette.Entries[i]
	if n >= len(e.Responses) {
		return nil, fmt.Errorf("%w (%d recorded):\n%s", ErrCassetteExhausted, len(e.Responses), canon)
	}
	r.served[key] = n + 1
	return toHTTP(req, e.Responses[n]), nil
}

func (r *Replay) record(req *http.Request, body []byte, canon, key string) (*http.Response, error) {
	fwd := req.Clone(req.Context())
	fwd.Body = io.NopCloser(bytes.NewReader(body))
	fwd.ContentLength = int64(len(body))
	resp, err := r.inner.Do(fwd)
	if err != nil {
		return nil, err
	}
	rb, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	rec := Response{Status: resp.StatusCode, Body: string(rb), Headers: map[string]string{}}
	for _, h := range keptHeaders {
		if v := resp.Header.Get(h); v != "" {
			rec.Headers[h] = v
		}
	}
	r.mu.Lock()
	if i, ok := r.index[key]; ok {
		r.cassette.Entries[i].Responses = append(r.cassette.Entries[i].Responses, rec)
	} else {
		r.index[key] = len(r.cassette.Entries)
		r.cassette.Entries = append(r.cassette.Entries, Entry{Key: key, Request: canon, Responses: []Response{rec}})
	}
	r.mu.Unlock()
	resp.Body = io.NopCloser(bytes.NewReader(rb))
	return resp, nil
}

func toHTTP(req *http.Request, rs Response) *http.Response {
	h := http.Header{}
	for k, v := range rs.Headers {
		h.Set(k, v)
	}
	return &http.Response{
		Status:        fmt.Sprintf("%d %s", rs.Status, http.StatusText(rs.Status)),
		StatusCode:    rs.Status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        h,
		Body:          io.NopCloser(strings.NewReader(rs.Body)),
		ContentLength: int64(len(rs.Body)),
		Request:       req,
	}
}
