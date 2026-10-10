package api

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Audit middleware and routes (design §13.4, §16.1, §20 E2.3–E2.5).

func ledger(t *testing.T, db *store.DB, tn tenancy.ID) []*store.AuditEvent {
	t.Helper()
	var out []*store.AuditEvent
	if err := db.ReadTenant(context.Background(), tn, func(tx *store.TenantTx) error {
		var err error
		out, err = tx.AuditLog(-1)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func httpEvents(evs []*store.AuditEvent) []*store.AuditEvent {
	var out []*store.AuditEvent
	for _, e := range evs {
		if e.Action == store.ActionHTTPRequest {
			out = append(out, e)
		}
	}
	return out
}

func latestEventID(t *testing.T, db *store.DB, tn tenancy.ID) string {
	t.Helper()
	evs := ledger(t, db, tn)
	if len(evs) == 0 {
		t.Fatal("tenant has no audit events")
	}
	return evs[0].ID.String()
}

type httpField struct {
	Method     string            `json:"method"`
	Route      *string           `json:"route"`
	PathParams map[string]string `json:"path_params"`
	QueryKeys  []string          `json:"query_keys"`
	Status     int               `json:"status"`
}

// TestAudit_EveryRequestOneEvent (E2.3): each call writes exactly one
// http.request event with the route template (never the raw path), the
// status, sorted query keys only, and the anonymous actor, whatever the
// client claims.
func TestAudit_EveryRequestOneEvent(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := isolationServer(f, f.B.ID).Handler()
	alice := fmt.Sprint(f.B.IDs["alice"])
	cases := []struct {
		method, path, body string
		hdr                []string
		route              any // nil: unmatched
		status             int
		outcome            string
		targetType         string
	}{
		{"GET", "/api/identities/" + alice + "?zeta=1&alpha=secret-value", "", nil, "/api/identities/{identity_id}", 200, "success", "identity"},
		{"GET", "/api/identities/" + fmt.Sprint(missingID), "", nil, "/api/identities/{identity_id}", 404, "failure", "identity"},
		{"GET", "/api/no-such-route", "", nil, nil, 404, "failure", ""},
		{"DELETE", "/api/identities", "", nil, nil, 405, "failure", ""},
		{"GET", "/api/audit?limit=abc", "", nil, "/api/audit", 422, "failure", ""},
		{"POST", "/api/jit/sweep", `{}`, []string{"X-Tessera-User", "mallory"}, "/api/jit/sweep", 200, "success", ""},
		{"POST", "/api/connections", `{"name":"Workday (audit test)","connector_type":"demo-workday"}`, []string{"X-Tessera-User", "Mallory Admin"}, "/api/connections", 201, "success", ""},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			before := httpEvents(ledger(t, f.DB, f.B.ID))
			rec := client{t, h}.do(tc.method, tc.path, tc.body, tc.hdr...)
			if rec.Code != tc.status {
				t.Fatalf("status %d, want %d: %.300s", rec.Code, tc.status, rec.Body.String())
			}
			after := httpEvents(ledger(t, f.DB, f.B.ID))
			if len(after) != len(before)+1 {
				t.Fatalf("%d http.request events written, want 1", len(after)-len(before))
			}
			e := after[0]
			if e.ActorType != store.ActorAnonymous || e.ActorID != nil || e.ActorDisplay != nil {
				t.Errorf("actor %s %v %v, want anonymous", e.ActorType, e.ActorID, e.ActorDisplay)
			}
			if e.Outcome != tc.outcome {
				t.Errorf("outcome %s, want %s", e.Outcome, tc.outcome)
			}
			var hf httpField
			if err := json.Unmarshal(e.HTTP, &hf); err != nil {
				t.Fatal(err)
			}
			switch r := tc.route.(type) {
			case nil:
				if hf.Route != nil {
					t.Errorf("route %q for an unmatched path", *hf.Route)
				}
			case string:
				if hf.Route == nil || *hf.Route != r {
					t.Errorf("route %v, want %s", hf.Route, r)
				}
			}
			if hf.Method != tc.method || hf.Status != tc.status {
				t.Errorf("http %+v", hf)
			}
			if strings.Contains(string(e.HTTP), "secret-value") || strings.Contains(string(e.Detail), "secret-value") {
				t.Error("a query value was recorded")
			}
			if strings.Contains(tc.path, "zeta") && strings.Join(hf.QueryKeys, ",") != "alpha,zeta" {
				t.Errorf("query keys %v", hf.QueryKeys)
			}
			if (e.TargetType == nil) != (tc.targetType == "") || (e.TargetType != nil && *e.TargetType != tc.targetType) {
				t.Errorf("target %v %v, want %s", e.TargetType, e.TargetID, tc.targetType)
			}
			if rec.Header().Get("X-Request-Id") == "" || e.RequestID == nil || *e.RequestID != rec.Header().Get("X-Request-Id") {
				t.Errorf("request id %v vs header %q", e.RequestID, rec.Header().Get("X-Request-Id"))
			}
		})
	}
	// The domain event of the connection create is attributed to the
	// anonymous request actor; the header's name is only a claim.
	for _, e := range ledger(t, f.DB, f.B.ID) {
		if e.Action == "connection.created" && strings.Contains(string(e.Detail), "Mallory Admin") {
			if e.ActorType != store.ActorAnonymous || e.ActorDisplay != nil {
				t.Errorf("connection.created actor %s %v", e.ActorType, e.ActorDisplay)
			}
			if !strings.Contains(string(e.Detail), `"claimed_actor":"Mallory Admin"`) {
				t.Errorf("claimed actor not kept: %s", e.Detail)
			}
			if e.RequestID == nil {
				t.Error("domain event lacks the request id")
			}
			return
		}
	}
	t.Error("no connection.created event with the claimed actor")
}

// TestAudit_HealthNotRecorded: the excluded public routes write nothing.
func TestAudit_HealthNotRecorded(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := isolationServer(f, f.B.ID).Handler()
	before := len(ledger(t, f.DB, f.B.ID)) + len(ledger(t, f.DB, tenancy.Platform))
	if rec := serveOnce(h, "GET", "/api/health", ""); rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	if n := len(ledger(t, f.DB, f.B.ID)) + len(ledger(t, f.DB, tenancy.Platform)); n != before {
		t.Errorf("GET /api/health wrote %d events", n-before)
	}
}

// TestAudit_ReadFailsClosed (E2.4): with the ledger broken, a read answers
// 503 audit_unavailable and none of the data it computed.
func TestAudit_ReadFailsClosed(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := isolationServer(f, f.A.ID).Handler()
	if rec := serveOnce(h, "GET", "/api/identities", ""); rec.Code != http.StatusOK || !leaks(rec.Body.String()) {
		t.Fatalf("baseline read: %d", rec.Code)
	}
	before := storetest.Dump(t, f.DB, f.A.ID)
	tamper, err := f.DB.TamperForTest()
	if err != nil {
		t.Fatal(err)
	}
	if err := tamper.Break(context.Background()); err != nil {
		t.Fatal(err)
	}
	failures := audit.WriteFailures()
	for _, path := range []string{"/api/identities", "/api/summary", "/api/audit/checkpoints"} {
		for _, method := range []string{"GET", "HEAD"} {
			rec := serveOnce(h, method, path, "")
			if rec.Code != http.StatusServiceUnavailable {
				t.Errorf("%s %s with a broken ledger: %d, want 503", method, path, rec.Code)
			}
			body := rec.Body.String()
			if leaks(body) || strings.Contains(body, "Alice") {
				t.Errorf("%s %s leaked data with the 503: %.200s", method, path, body)
			}
			if method == "GET" && (!strings.Contains(body, `"error":"audit_unavailable"`) || !strings.Contains(body, rec.Header().Get("X-Request-Id"))) {
				t.Errorf("503 body: %s", body)
			}
		}
	}
	if audit.WriteFailures() <= failures {
		t.Error("audit_write_failures_total did not increase")
	}
	// A mutation whose domain event cannot be written fails and changes nothing.
	if rec := serveOnce(h, "POST", "/api/reviews/campaigns", `{}`); rec.Code == http.StatusOK {
		t.Error("a mutation succeeded without its audit event")
	}
	if err := tamper.Repair(context.Background()); err != nil {
		t.Fatal(err)
	}
	if storetest.Dump(t, f.DB, f.A.ID) != before {
		t.Error("the failed mutation left changes behind")
	}
	if rec := serveOnce(h, "GET", "/api/identities", ""); rec.Code != http.StatusOK {
		t.Errorf("after repair: %d", rec.Code)
	}
}

// TestAudit_MutationResponseSentWhenRequestEventFails: for a non-read whose
// domain work committed, a failed http.request append is logged and counted,
// and the real response is still sent.
func TestAudit_MutationResponseSentWhenRequestEventFails(t *testing.T) {
	f := storetest.TwoTenants(t)
	srv := isolationServer(f, f.B.ID)
	srv.cfg.AuditAppend = func(context.Context, tenancy.ID, store.AuditEvent) error { return errors.New("disk full") }
	h := srv.Handler()
	failures := audit.WriteFailures()
	if rec := serveOnce(h, "POST", "/api/simulate", `{}`); rec.Code != http.StatusOK {
		t.Errorf("POST with a failing http.request append: %d, want the real 200", rec.Code)
	}
	if rec := serveOnce(h, "GET", "/api/groups", ""); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("GET with a failing append: %d, want 503", rec.Code)
	}
	if audit.WriteFailures() != failures+2 {
		t.Errorf("failures counted: %d", audit.WriteFailures()-failures)
	}
}

// TestIsolation_AuditRoutes: as tenant B, tenant A's event ids look
// nonexistent, and B's audit routes (list, checkpoints, proof, verify,
// export) never read, verify or change A's chain.
func TestIsolation_AuditRoutes(t *testing.T) {
	f := storetest.TwoTenants(t)
	a := isolationServer(f, f.A.ID).Handler()
	serveOnce(a, "GET", "/api/identities", "") // A has request events too
	aEvent := latestEventID(t, f.DB, f.A.ID)
	beforeA := storetest.Dump(t, f.DB, f.A.ID)
	aLedger := len(ledger(t, f.DB, f.A.ID))

	h := isolationServer(f, f.B.ID).Handler()
	cross := serveOnce(h, "GET", "/api/audit/events/"+aEvent+"/proof", "")
	missing := serveOnce(h, "GET", "/api/audit/events/"+uuid.NewString()+"/proof", "")
	if cross.Code != http.StatusNotFound || cross.Body.String() != missing.Body.String() {
		t.Errorf("A's event from B: %d %s; missing: %d %s", cross.Code, cross.Body.String(), missing.Code, missing.Body.String())
	}
	if rec := serveOnce(h, "GET", "/api/audit/events/not-a-uuid/proof", ""); rec.Code != http.StatusNotFound {
		t.Errorf("malformed event id: %d", rec.Code)
	}
	own := serveOnce(h, "GET", "/api/audit/events/"+latestEventID(t, f.DB, f.B.ID)+"/proof", "")
	if own.Code != http.StatusOK {
		t.Fatalf("own proof: %d %s", own.Code, own.Body.String())
	}
	var proof struct {
		Event json.RawMessage `json:"event"`
	}
	if err := json.Unmarshal(own.Body.Bytes(), &proof); err != nil {
		t.Fatal(err)
	}
	if ok, _, err := audit.VerifyRecord(proof.Event); err != nil || !ok {
		t.Errorf("proof record does not verify: %v", err)
	}

	for _, path := range []string{"/api/audit?include_http=true&limit=1000", "/api/audit/checkpoints", "/api/audit/export"} {
		rec := serveOnce(h, "GET", path, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s: %d", path, rec.Code)
		}
		if leaks(rec.Body.String()) || strings.Contains(rec.Body.String(), f.A.ID.String()) {
			t.Errorf("GET %s shows tenant A's chain", path)
		}
	}
	// export: every line is B's and verifies on its own
	sc := bufio.NewScanner(strings.NewReader(serveOnce(h, "GET", "/api/audit/export", "").Body.String()))
	sc.Buffer(nil, 1<<20)
	lines := 0
	for sc.Scan() {
		lines++
		var rec struct {
			TenantID string `json:"tenant_id"`
		}
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil || rec.TenantID != f.B.ID.String() {
			t.Fatalf("export line of tenant %q: %v", rec.TenantID, err)
		}
		if ok, _, err := audit.VerifyRecord(sc.Bytes()); err != nil || !ok {
			t.Errorf("export line %d does not verify: %v", lines, err)
		}
	}
	if lines == 0 {
		t.Error("empty export")
	}

	rep := serveOnce(h, "POST", "/api/audit/verify", `{}`)
	var r audit.Report
	if err := json.Unmarshal(rep.Body.Bytes(), &r); err != nil || rep.Code != http.StatusOK {
		t.Fatalf("verify: %d %s", rep.Code, rep.Body.String())
	}
	if r.TenantID != f.B.ID.String() || r.Result != "ok" || r.ExitCode != 0 {
		t.Errorf("B's verify report: %+v", r)
	}
	if storetest.Dump(t, f.DB, f.A.ID) != beforeA || len(ledger(t, f.DB, f.A.ID)) != aLedger {
		t.Error("tenant B's audit calls changed tenant A")
	}
	verified := false
	for _, e := range ledger(t, f.DB, f.B.ID) {
		verified = verified || e.Action == "audit.verify.run"
	}
	if !verified {
		t.Error("audit.verify.run not recorded in B's chain")
	}
}

// TestAudit_ExportOneRequestEvent: the streamed export writes its
// http.request event once, before streaming, plus an audit.export event.
func TestAudit_ExportOneRequestEvent(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := isolationServer(f, f.B.ID).Handler()
	before := ledger(t, f.DB, f.B.ID)
	rec := serveOnce(h, "GET", "/api/audit/export?from_seq=1", "")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/x-ndjson" {
		t.Fatalf("export: %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	after := ledger(t, f.DB, f.B.ID)
	counts := map[string]int{}
	for _, e := range after[:len(after)-len(before)] {
		counts[e.Action]++
	}
	if counts[store.ActionHTTPRequest] != 1 || counts["audit.export"] != 1 || len(after)-len(before) != 2 {
		t.Errorf("export wrote %v", counts)
	}
	// the export holds every event that existed before it, in order
	if n := strings.Count(rec.Body.String(), "\n"); n != len(before)+1 {
		t.Errorf("export has %d lines, want %d (the chain plus its own request event)", n, len(before)+1)
	}
	tamper, err := f.DB.TamperForTest()
	if err != nil {
		t.Fatal(err)
	}
	if err := tamper.Break(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tamper.Repair(context.Background()) }()
	if rec := serveOnce(h, "GET", "/api/audit/export", ""); rec.Code != http.StatusServiceUnavailable ||
		strings.Contains(rec.Body.String(), "prev_hash") {
		t.Errorf("export with a broken ledger: %d %.200s", rec.Code, rec.Body.String())
	}
}

// TestAudit_ListFilters: the extended /api/audit keeps its fields, adds the
// ledger's, and filters.
func TestAudit_ListFilters(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := isolationServer(f, f.B.ID).Handler()
	serveOnce(h, "GET", "/api/identities", "")
	c := client{t, h}
	all := c.json("GET", "/api/audit?include_http=true&limit=1000", "", http.StatusOK).([]any)
	dom := c.json("GET", "/api/audit?limit=1000", "", http.StatusOK).([]any)
	if len(all) <= len(dom) {
		t.Errorf("include_http adds nothing: %d vs %d", len(all), len(dom))
	}
	for _, r := range dom {
		if at(r, "action") == store.ActionHTTPRequest {
			t.Error("http.request in the default list")
		}
	}
	row := all[0].(map[string]any)
	for _, k := range []string{"id", "at", "actor", "action", "detail", "event_id", "seq", "actor_type", "outcome", "target", "authn", "hash", "prev_hash"} {
		if _, ok := row[k]; !ok {
			t.Errorf("row lacks %s", k)
		}
	}
	only := c.json("GET", "/api/audit?action=http.request&limit=2", "", http.StatusOK).([]any)
	if len(only) != 2 || at(only, 0, "action") != store.ActionHTTPRequest {
		t.Errorf("action filter: %v", only)
	}
	seq := int64(at(all, 0, "seq").(float64))
	older := c.json("GET", fmt.Sprintf("/api/audit?include_http=true&before_seq=%d&limit=1", seq), "", http.StatusOK).([]any)
	if len(older) != 1 || int64(at(older, 0, "seq").(float64)) != seq-1 {
		t.Errorf("before_seq: %v", older)
	}
	c.json("GET", "/api/audit?from=not-a-time", "", http.StatusUnprocessableEntity)
	c.json("GET", "/api/audit?action="+strings.Repeat("x", 300), "", http.StatusUnprocessableEntity)
	if got := c.json("GET", "/api/audit?from=2999-01-01T00:00:00Z", "", http.StatusOK).([]any); len(got) != 0 {
		t.Errorf("from in the future: %d rows", len(got))
	}
}
