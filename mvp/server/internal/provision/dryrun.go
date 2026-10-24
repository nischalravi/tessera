package provision

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/restgen"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// A dry run shows what a change would send to a target before write-back is
// switched on: the connector runs against the real target with a transport that
// lets reads (GET, HEAD) through, since every connector reads before it writes,
// and records every other request instead of sending it. The recorded write
// gets a synthetic empty success, so the connector carries on and the steps
// after it show too; a connector that needs the real answer (the id of a user
// it just created) may stop early, which the result says.

// DryRunStep is one request a change makes.
type DryRunStep struct {
	Method string `json:"method"`
	URL    string `json:"url"`
	// Sent is true for a read that went to the target, false for a write that was held back.
	Sent bool `json:"sent"`
	// Status is the target's answer to a read (0 for a held-back write).
	Status int `json:"status"`
	// Body is the request body of a held-back write (credentials never appear in it), cut at 4 KiB.
	Body string `json:"body,omitempty"`
}

// DryRunResult is what a dry run found.
type DryRunResult struct {
	Steps []DryRunStep `json:"steps"`
	// Error is why the change stopped before its last step, if it did.
	Error string `json:"error,omitempty"`
}

// Writes are the steps that would change the target.
func (r *DryRunResult) Writes() int {
	n := 0
	for _, s := range r.Steps {
		if !s.Sent {
			n++
		}
	}
	return n
}

const (
	dryRunBodyLimit = 4 << 10
	dryRunMaxSteps  = 50
)

// dryRunKinds are the target kinds a dry run can show. A vault or ERP target
// signs in with a POST that must really happen, and an agent-reached target is
// not called by the server at all.
var dryRunKinds = map[string]bool{KindSCIM: true, KindFake: true, KindOkta: true, KindREST: true}

type recorder struct {
	inner http.RoundTripper
	mu    sync.Mutex
	steps []DryRunStep
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	// the OAuth token request of a REST target must really happen, or no later step could show
	if req.Method == http.MethodGet || req.Method == http.MethodHead || restgen.IsAuthExchange(req) {
		resp, err := r.inner.RoundTrip(req)
		st := DryRunStep{Method: req.Method, URL: safehttp.RedactURL(req.URL.String()), Sent: true}
		if resp != nil {
			st.Status = resp.StatusCode
		}
		r.add(st)
		return resp, err
	}
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(io.LimitReader(req.Body, dryRunBodyLimit+1))
		_ = req.Body.Close()
	}
	b := string(body)
	if len(body) > dryRunBodyLimit {
		b = string(body[:dryRunBodyLimit]) + "…"
	}
	r.add(DryRunStep{Method: req.Method, URL: safehttp.RedactURL(req.URL.String()), Body: b})
	// An empty answer that every connector reads as "done": SCIM and Okta writes
	// answer 200/204 with an optional body.
	return &http.Response{StatusCode: http.StatusNoContent, Status: "204 No Content", Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{restgen.DryRunHeader: {"1"}}, Body: io.NopCloser(bytes.NewReader(nil)), ContentLength: 0, Request: req}, nil
}

func (r *recorder) add(s DryRunStep) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.steps) < dryRunMaxSteps {
		r.steps = append(r.steps, s)
	}
}

// DryRun applies req to the target of connection connID without changing the
// target, and returns the requests the change makes. Nothing is stored.
func (e *Engine) DryRun(ctx context.Context, t tenancy.ID, connID string, req target.Request) (*DryRunResult, error) {
	if e.HTTP == nil || e.Build != nil {
		// a replaced connector would really send what the dry run must hold back
		return nil, &Error{503, "dry_run_unavailable", "a dry run needs the outbound client of the server"}
	}
	var pt *store.ProvTarget
	err := e.DB.ReadTenant(ctx, t, func(tx *store.TenantTx) error {
		var err error
		pt, err = tx.ProvTarget(connID)
		return err
	})
	if errors.Is(err, store.ErrNotFound) {
		return nil, &Error{404, "not_found", "the connection has no provisioning target"}
	}
	if err != nil {
		return nil, err
	}
	var s Settings
	if err := json.Unmarshal([]byte(pt.Settings), &s); err != nil {
		return nil, &Error{422, "target_unreadable", "the target's settings are unreadable"}
	}
	if s.AgentID != "" {
		return nil, &Error{422, "dry_run_unavailable", "this target is reached through a Directory Agent; the server cannot call it, so it cannot show a dry run"}
	}
	if !dryRunKinds[pt.Kind] {
		return nil, &Error{422, "dry_run_unavailable", "a dry run is available for SCIM, Okta and REST targets"}
	}
	token, err := e.openToken(t, pt)
	if err != nil {
		return nil, &Error{422, "credential_unavailable", "the target's credential cannot be opened"}
	}
	hc, err := e.httpFor(ctx, t, connID)
	if err != nil {
		return nil, &Error{422, "mtls_unavailable", err.Error()}
	}
	rec := &recorder{inner: hc.Transport}
	if rec.inner == nil {
		return nil, &Error{503, "dry_run_unavailable", "the outbound client has no transport"}
	}
	clone := *e
	clone.HTTP = &http.Client{Transport: rec, CheckRedirect: hc.CheckRedirect, Timeout: hc.Timeout}
	conn, err := clone.build(pt, token)
	if err != nil {
		return nil, &Error{422, "target_unavailable", err.Error()}
	}
	cctx, cancel := e.call(ctx)
	defer cancel()
	res := &DryRunResult{}
	if err := conn.Apply(cctx, req); err != nil {
		res.Error = safehttp.ScrubError(err, pt.BaseURL)
	}
	rec.mu.Lock()
	res.Steps = append([]DryRunStep{}, rec.steps...)
	rec.mu.Unlock()
	for i := range res.Steps {
		res.Steps[i].URL = strings.TrimSpace(res.Steps[i].URL)
	}
	return res, nil
}
