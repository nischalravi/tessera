// Package awsreplay is the test double of the AWS connector's HTTP layer
// (design docs/design/aws-effective-permission-evaluator.md §11.1, PR-7). It is
// test-only: the server binary never imports it.
//
// Replay stands in for the safehttp client. It serves recorded response bodies,
// so the connector's real request builders, SigV4 signer, XML and JSON decoders
// and retry loop run, while no network is touched. Like moto before it, it does
// not enforce IAM: these are collection tests only. Evaluation correctness is
// the golden corpus's and the harness's job.
//
// Recorded fixtures live in a tree
//
//	<service>/<operation>/<n>.xml | <n>.json | <n>.txt           HTTP 200
//	<service>/<operation>/<n>.<status>.xml | .json | .txt        that HTTP status
//
// with n counting from 1 per operation, in call order. The service is the
// SigV4 signing name taken from the request's Authorization header ("iam",
// "organizations", "s3", ...); the operation is worked out from the request
// itself (the Action of a query request, the X-Amz-Target of a JSON request,
// the method, path and sub-resource of a REST request), so a fixture exists
// only if the connector asked AWS for exactly that. Recorded bodies in this
// repository are synthetic: fake account ids, no real ARNs.
package awsreplay

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/sigv4"
)

// Response is one canned response.
type Response struct {
	Status int // 0 means 200
	Body   string
	Header http.Header
}

// Request is what Replay saw, minus the Authorization header.
type Request struct {
	Service, Operation string
	Method, Host, Path string
	Region             string
	AccessKeyID        string
	SessionToken       string
	Query              url.Values // the URL query
	Form               url.Values // the body of a form (query-protocol) request
	JSON               string     // the body of a JSON request
}

// Replay is an http.Client stand-in. The zero value is not usable: use NewReplay.
type Replay struct {
	// RepeatLast serves the highest-numbered recorded response again when a
	// call has none of its own (the same STS reply for every account). Off by
	// default: a call with no recording is then reported by Unrecorded.
	RepeatLast bool

	fsys fs.FS

	mu         sync.Mutex
	counters   map[string]int
	queues     map[string][]Response
	requests   []Request
	unrecorded []string
	secrets    map[string]string
	badSigs    []string
}

// NewReplay serves recorded responses from fsys (for example
// os.DirFS("testdata/http")); fsys may be nil when a test only enqueues.
func NewReplay(fsys fs.FS) *Replay {
	return &Replay{fsys: fsys, counters: map[string]int{}, queues: map[string][]Response{}, secrets: map[string]string{}}
}

// Enqueue appends canned responses for one operation ("<service>/<operation>").
// An operation with queued responses is served from the queue and never from
// files: use it for throttling, errors and other control-flow cases.
func (r *Replay) Enqueue(operation string, resp ...Response) *Replay {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.queues[operation] = append(r.queues[operation], resp...)
	return r
}

// Verify makes Replay check the SigV4 signature of every request signed with
// accessKeyID against secret, by signing a copy of the request again. A wrong
// signature is returned to the connector as 403 SignatureDoesNotMatch and
// listed by BadSignatures.
func (r *Replay) Verify(accessKeyID, secret string) *Replay {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.secrets[accessKeyID] = secret
	return r
}

// Requests returns what Replay has served, in order.
func (r *Replay) Requests() []Request {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Request(nil), r.requests...)
}

// Calls counts the requests of one operation ("<service>/<operation>").
func (r *Replay) Calls(operation string) int {
	n := 0
	for _, q := range r.Requests() {
		if q.Service+"/"+q.Operation == operation {
			n++
		}
	}
	return n
}

// Unrecorded lists the operations that were called with no response left to
// serve. A test that expects none asserts this is empty.
func (r *Replay) Unrecorded() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.unrecorded...)
}

// BadSignatures lists the requests whose signature did not verify.
func (r *Replay) BadSignatures() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.badSigs...)
}

var credentialRE = regexp.MustCompile(`Credential=([^/,\s]+)/(\d{8})/([^/]+)/([^/]+)/aws4_request`)

// Do implements the connector's Doer.
func (r *Replay) Do(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" || !strings.HasSuffix(req.URL.Hostname(), ".amazonaws.com") {
		return nil, fmt.Errorf("awsreplay: request to %s is not an https amazonaws.com URL", req.URL.Redacted())
	}
	var body []byte
	if req.Body != nil {
		var err error
		if body, err = io.ReadAll(req.Body); err != nil {
			return nil, err
		}
		_ = req.Body.Close()
	}
	m := credentialRE.FindStringSubmatch(req.Header.Get("Authorization"))
	if m == nil {
		return nil, errors.New("awsreplay: request is not signed")
	}
	accessKey, region, service := m[1], m[3], m[4]
	op := Operation(req, body)
	key := service + "/" + op

	rec := Request{Service: service, Operation: op, Method: req.Method, Host: req.URL.Host, Path: req.URL.Path,
		Region: region, AccessKeyID: accessKey, SessionToken: req.Header.Get("X-Amz-Security-Token"), Query: req.URL.Query()}
	if strings.HasPrefix(req.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		rec.Form, _ = url.ParseQuery(string(body))
	} else if len(body) > 0 {
		rec.JSON = string(body)
	}
	r.mu.Lock()
	r.requests = append(r.requests, rec)
	secret, verify := r.secrets[accessKey]
	r.counters[key]++
	n := r.counters[key]
	var resp Response
	var ok bool
	if q, queued := r.queues[key]; queued {
		if n <= len(q) {
			resp, ok = q[n-1], true
		}
	} else if r.fsys != nil {
		for i := n; i >= 1 && !ok; i-- {
			if resp, ok = r.fromFiles(service, op, i); !r.RepeatLast {
				break
			}
		}
	}
	if !ok {
		r.unrecorded = append(r.unrecorded, fmt.Sprintf("%s #%d", key, n))
	}
	r.mu.Unlock()

	if verify {
		if err := verifySignature(req, body, accessKey, secret, region, service); err != nil {
			r.mu.Lock()
			r.badSigs = append(r.badSigs, key+": "+err.Error())
			r.mu.Unlock()
			return respond(req, Response{Status: http.StatusForbidden, Body: errorXML("SignatureDoesNotMatch", err.Error())}), nil
		}
	}
	if !ok {
		return respond(req, Response{Status: http.StatusBadRequest, Body: errorXML("UnrecordedCall", key+" #"+strconv.Itoa(n))}), nil
	}
	return respond(req, resp), nil
}

func errorXML(code, msg string) string {
	return "<Error><Code>" + code + "</Code><Message>" + msg + "</Message></Error>"
}

func (r *Replay) fromFiles(service, op string, n int) (Response, bool) {
	dir := path.Join(service, op)
	entries, err := fs.ReadDir(r.fsys, dir)
	if err != nil {
		return Response{}, false
	}
	prefix := strconv.Itoa(n) + "."
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, prefix) {
			continue
		}
		parts := strings.Split(strings.TrimPrefix(name, prefix), ".") // [ext] or [status, ext]
		status := http.StatusOK
		if len(parts) == 2 {
			s, err := strconv.Atoi(parts[0])
			if err != nil {
				continue
			}
			status = s
		}
		b, err := fs.ReadFile(r.fsys, path.Join(dir, name))
		if err != nil {
			return Response{}, false
		}
		h := http.Header{}
		if parts[len(parts)-1] == "json" {
			h.Set("Content-Type", "application/x-amz-json-1.1")
		}
		return Response{Status: status, Body: string(b), Header: h}, true
	}
	return Response{}, false
}

func respond(req *http.Request, r Response) *http.Response {
	status := r.Status
	if status == 0 {
		status = http.StatusOK
	}
	h := http.Header{}
	for k, v := range r.Header {
		h[k] = append([]string(nil), v...)
	}
	return &http.Response{StatusCode: status, Status: strconv.Itoa(status) + " " + http.StatusText(status), Header: h,
		Body: io.NopCloser(strings.NewReader(r.Body)), ContentLength: int64(len(r.Body)), Request: req, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1}
}

// verifySignature signs a copy of req the way the connector should have and
// compares the Authorization headers.
func verifySignature(req *http.Request, body []byte, accessKey, secret, region, service string) error {
	date, err := time.Parse(sigv4.TimeLayout, req.Header.Get("X-Amz-Date"))
	if err != nil {
		return errors.New("missing or bad X-Amz-Date")
	}
	cp := req.Clone(req.Context())
	cp.Header = http.Header{}
	for k, v := range req.Header {
		switch http.CanonicalHeaderKey(k) {
		case "Authorization", "X-Amz-Date", "X-Amz-Security-Token", "X-Amz-Content-Sha256", "User-Agent":
		default:
			cp.Header[k] = v
		}
	}
	c := sigv4.Credentials{AccessKeyID: accessKey, SecretAccessKey: secret, SessionToken: req.Header.Get("X-Amz-Security-Token")}
	if err := sigv4.Sign(cp, body, c, region, service, date); err != nil {
		return err
	}
	if got, want := req.Header.Get("Authorization"), cp.Header.Get("Authorization"); got != want {
		return fmt.Errorf("signature mismatch: got %s, want %s", got, want)
	}
	return nil
}

// Operation names the AWS operation a request calls.
func Operation(req *http.Request, body []byte) string {
	if t := req.Header.Get("X-Amz-Target"); t != "" {
		return t[strings.LastIndex(t, ".")+1:]
	}
	if req.Method == http.MethodPost && strings.HasPrefix(req.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		if v, err := url.ParseQuery(string(body)); err == nil && v.Get("Action") != "" {
			return v.Get("Action")
		}
	}
	host, p, q := req.URL.Hostname(), req.URL.Path, req.URL.Query()
	switch {
	case strings.Contains(host, ".s3-control."):
		switch {
		case p == "/v20180820/configuration/publicAccessBlock":
			return "GetPublicAccessBlock"
		case p == "/v20180820/accesspoint":
			return "ListAccessPoints"
		case strings.HasPrefix(p, "/v20180820/accesspoint/") && strings.HasSuffix(p, "/policy"):
			return "GetAccessPointPolicy"
		}
	case strings.HasPrefix(host, "lambda."):
		switch {
		case p == "/2015-03-31/functions":
			return "ListFunctions"
		case strings.HasPrefix(p, "/2015-03-31/functions/") && strings.HasSuffix(p, "/policy"):
			return "GetPolicy"
		}
	case host == "s3.amazonaws.com" || strings.Contains(host, ".s3.") || strings.HasPrefix(host, "s3."):
		for sub, op := range map[string]string{"policy": "GetBucketPolicy", "acl": "GetBucketAcl",
			"ownershipControls": "GetBucketOwnershipControls", "publicAccessBlock": "GetBucketPublicAccessBlock"} {
			if _, ok := q[sub]; ok {
				return op
			}
		}
		if p == "/" && strings.HasPrefix(host, "s3.") {
			return "ListAllMyBuckets"
		}
	}
	return "Unknown"
}

// compile-time check: Replay has the Do method of the connector's Doer.
var _ interface {
	Do(*http.Request) (*http.Response, error)
} = (*Replay)(nil)
