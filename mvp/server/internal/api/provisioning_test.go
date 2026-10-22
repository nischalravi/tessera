package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/provision"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/fake"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
	"github.com/nischalravi/tessera/mvp/server/internal/worker"
	"github.com/nischalravi/tessera/mvp/server/policies"
)

func insertProvOp(t *testing.T, db *store.DB, tn tenancy.ID, conn, key string) string {
	t.Helper()
	id := store.NewID()
	if err := db.InTenant(context.Background(), tn, func(c *store.TenantTx) error {
		return c.InsertProvOp(&store.ProvOp{ID: id, ConnectionID: conn, Kind: "disable_account", TargetRef: "sentinel " + tn.String(),
			Payload: `{"account":{"username":"x"}}`, Source: "test", IdempotencyKey: key, RequestedBy: "b"}, storetest.Now)
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

// newTestAPIServerWith is newTestAPIServer with the config adjusted.
func newTestAPIServerWith(t *testing.T, st *testkit.DB, mutate func(*Config)) *Server {
	t.Helper()
	cfg := Config{
		Store: st.DB, Clock: timeutil.Frozen(testkit.Now), Policies: policy.NewLoader(policies.FS),
		Connectors:     func(time.Time) ([]connectors.Connector, error) { return connectors.Load("demo", testkit.Now) },
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		AllowedOrigins: []string{"http://localhost:5173"},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	return New(cfg)
}

// provHarness is the API over the Tiny tenant with a fake SCIM target behind
// a demo Okta connection (system "okta"), write-back off until a test turns it on.
type provHarness struct {
	t       *testing.T
	st      *testkit.DB
	ids     testkit.IDs
	srv     *Server
	c       client
	fake    *fake.Server
	conn    string
	alice   string
	bob     string
	url     string
	aliceID string
}

func newProvHarness(t *testing.T, o fake.Options) *provHarness {
	t.Helper()
	st, ids := testkit.Tiny(t)
	h := &provHarness{t: t, st: st, ids: ids, fake: fake.New(o)}
	fs := httptest.NewServer(h.fake.Handler())
	h.url = fs.URL + "/scim/v2"
	t.Cleanup(fs.Close)
	hc, err := safehttp.NewForTest(t, safehttp.Options{Env: config.Dev, AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	srv := newTestAPIServerWith(t, st, func(c *Config) { c.Outbound = hc; c.FakeTargetURL = fs.URL })
	h.srv = srv
	// these tests fail a target's writes on purpose, many times in a row; the circuit breaker
	// (default: five failures in a row) is tested on its own (TestEngine_OpenBreaker..., worker tests)
	srv.Guard().Defaults = &worker.Limits{MaxConcurrency: 4}
	h.c = client{t, asLinkedAdmin(t, srv, st.DB, st.Tenant, testkit.Now).Handler()}
	v := h.c.json("POST", "/api/connections", `{"name":"Okta (provisioning test)","connector_type":"demo-okta"}`, http.StatusCreated).(map[string]any)
	h.conn = v["id"].(string)
	testkit.Read(t, st, func(c *store.TenantTx) error {
		as, err := c.Accounts()
		for _, a := range as {
			switch a.ExternalID {
			case "alice":
				h.alice = a.Username
			case "bob":
				h.bob = a.Username
			}
		}
		return err
	})
	return h
}

func (h *provHarness) target(body string, want int) map[string]any {
	h.t.Helper()
	return h.c.json("PUT", "/api/provisioning/targets/"+h.conn, body, want).(map[string]any)
}

func (h *provHarness) run() provision.Stats {
	h.t.Helper()
	s, err := h.srv.Provisioning().RunTenant(context.Background(), h.st.Tenant)
	if err != nil {
		h.t.Fatal(err)
	}
	return s
}

func (h *provHarness) ops(query string) []any {
	h.t.Helper()
	return h.c.json("GET", "/api/provisioning/ops"+query, "", 200).(map[string]any)["items"].([]any)
}

func (h *provHarness) edgeID(account, group string) int64 {
	h.t.Helper()
	var id int64
	testkit.Read(h.t, h.st, func(c *store.TenantTx) error {
		e, err := c.EdgeBetween(fmt.Sprintf("account:%d", h.ids["acct:okta:"+account]), fmt.Sprintf("group:%d", h.ids["group:okta:"+group]))
		if err == nil {
			id = e.ID
		}
		return err
	})
	return id
}

func (h *provHarness) hasEdge(account, group string) bool {
	h.t.Helper()
	return h.edgeIDOrZero(account, group) != 0
}

func (h *provHarness) edgeIDOrZero(account, group string) int64 {
	var id int64
	testkit.Read(h.t, h.st, func(c *store.TenantTx) error {
		if e, err := c.EdgeBetween(fmt.Sprintf("account:%d", h.ids["acct:okta:"+account]), fmt.Sprintf("group:%d", h.ids["group:okta:"+group])); err == nil {
			id = e.ID
		}
		return nil
	})
	return id
}

func (h *provHarness) audit() string { return auditActionList(h.t, h.st.DB, h.st.Tenant) }

func (h *provHarness) seedTarget() {
	h.aliceID = h.fake.AddUser(h.alice, "Alice", true)
	h.fake.AddGroup("eng", "eng", h.aliceID, h.fake.AddUser("zed@example.com", "Zed", true))
}

func TestProvisioning_TargetConfigIsValidatedAndCredentialWriteOnly(t *testing.T) {
	h := newProvHarness(t, fake.Options{})
	for name, body := range map[string]string{
		"kind":        `{"kind":"ldap","base_url":"https://x.example"}`,
		"url scheme":  `{"kind":"scim","base_url":"ftp://x.example"}`,
		"url creds":   `{"kind":"scim","base_url":"https://u:p@x.example"}`,
		"url query":   `{"kind":"scim","base_url":"https://x.example/?a=b"}`,
		"dialect":     `{"kind":"scim","base_url":"https://x.example","dialect":"ms"}`,
		"okta no tok": `{"kind":"okta","base_url":"https://x.okta.example"}`,
		"fault":       `{"kind":"scim","base_url":"https://x.example","fault":"drop_writes"}`,
		"unknown":     `{"kind":"scim","base_url":"https://x.example","password":"p"}`,
		"deprovision": `{"kind":"scim","base_url":"https://x.example","on_deprovision":"purge"}`,
	} {
		if rec := h.c.do("PUT", "/api/provisioning/targets/"+h.conn, body); rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("%s: status %d: %s", name, rec.Code, rec.Body)
		}
	}
	if rec := h.c.do("PUT", "/api/provisioning/targets/"+missingUUID, `{"kind":"fake"}`); rec.Code != http.StatusNotFound {
		t.Errorf("unknown connection: %d", rec.Code)
	}
	v := h.target(`{"kind":"scim","base_url":"https://scim.example/scim/v2","dialect":"entra","token":"s3cr3t-token","write_back":false}`, 200)
	if v["has_credential"] != true || v["write_back"] != false || v["dialect"] != "entra" || v["system"] != "okta" {
		t.Errorf("target = %v", v)
	}
	if body, _ := json.Marshal(v); strings.Contains(string(body), "s3cr3t") {
		t.Error("the response carries the token")
	}
	list, _ := json.Marshal(h.c.json("GET", "/api/provisioning/targets", "", 200))
	if strings.Contains(string(list), "s3cr3t") || !strings.Contains(string(list), `"has_credential":true`) {
		t.Errorf("list = %s", list)
	}
	// Stored sealed, and a later edit without a token keeps the credential.
	testkit.Read(t, h.st, func(c *store.TenantTx) error {
		pt, err := c.ProvTarget(h.conn)
		if err != nil || len(pt.CredentialEnc) == 0 || strings.Contains(string(pt.CredentialEnc), "s3cr3t") {
			t.Errorf("stored credential = %q, %v", pt.CredentialEnc, err)
		}
		return nil
	})
	v = h.target(`{"kind":"scim","base_url":"https://scim.example/scim/v2","write_back":true}`, 200)
	if v["has_credential"] != true || v["write_back"] != true || v["on_deprovision"] != nil {
		t.Errorf("after edit: %v", v) // accounts are left disabled by default
	}
	// the per-connection choice of what happens to a deprovisioned guest's account (issue #74)
	if v = h.target(`{"kind":"scim","base_url":"https://scim.example/scim/v2","write_back":true,"on_deprovision":"delete"}`, 200); v["on_deprovision"] != "delete" {
		t.Errorf("on_deprovision = %v", v["on_deprovision"])
	}
	if v = h.target(`{"kind":"scim","base_url":"https://scim.example/scim/v2","write_back":true,"on_deprovision":"disable"}`, 200); v["on_deprovision"] != nil {
		t.Errorf("back to the default: %v", v)
	}
	if a := h.audit(); !strings.Contains(a, "provision.target_set") {
		t.Errorf("audit = %s", a)
	}
	if strings.Contains(h.auditDetail(), "s3cr3t") {
		t.Error("the audit ledger carries the token")
	}
	h.c.json("DELETE", "/api/provisioning/targets/"+h.conn, "", 200)
	if rec := h.c.do("DELETE", "/api/provisioning/targets/"+h.conn, ""); rec.Code != http.StatusNotFound {
		t.Errorf("second delete: %d", rec.Code)
	}
}

func (h *provHarness) auditDetail() string {
	var b strings.Builder
	for _, e := range ledger(h.t, h.st.DB, h.st.Tenant) {
		fmt.Fprintf(&b, "%s %s\n", e.Action, e.Detail)
	}
	return b.String()
}

func TestProvisioning_FakeTargetNeedsDevSetting(t *testing.T) {
	h := newProvHarness(t, fake.Options{})
	v := h.target(`{"kind":"fake","base_url":"https://ignored.example","fault":"drop_writes","write_back":true}`, 200)
	if v["kind"] != "fake" || !strings.HasPrefix(v["base_url"].(string), "http://127.0.0.1:") || v["fault"] != "drop_writes" {
		t.Errorf("fake target = %v", v)
	}
	// A server without the dev fake refuses the kind.
	st, _ := testkit.Tiny(t)
	plain := newTestAPIServerWith(t, st, nil)
	c := client{t, asAdmin(t, plain, st.DB, st.Tenant, testkit.Now).Handler()}
	conn := c.json("POST", "/api/connections", `{"name":"Okta (x)","connector_type":"demo-okta"}`, http.StatusCreated).(map[string]any)["id"].(string)
	if rec := c.do("PUT", "/api/provisioning/targets/"+conn, `{"kind":"fake"}`); rec.Code != http.StatusUnprocessableEntity ||
		!strings.Contains(rec.Body.String(), "fake_unavailable") {
		t.Errorf("fake without the dev setting: %d %s", rec.Code, rec.Body)
	}
}

// With write-back on, a least-privilege revoke goes to the target; the edge is
// deleted only after the re-read confirms the member is gone.
func TestProvisioning_LeastPrivilegeRevokeClosesTheLoop(t *testing.T) {
	h := newProvHarness(t, fake.Options{Token: "tok"})
	h.seedTarget()
	h.target(`{"kind":"scim","base_url":"`+h.url+`","token":"tok","write_back":true}`, 200)
	edge := h.edgeID("alice", "eng")
	out := h.c.json("POST", "/api/least-privilege/revoke", fmt.Sprintf(`{"edge_id":%d,"dry_run":false}`, edge), 200).(map[string]any)
	prov, _ := out["provisioning"].(map[string]any)
	if out["applied"] != false || prov == nil || prov["status"] != "queued" {
		t.Fatalf("revoke = %v", out)
	}
	if !h.hasEdge("alice", "eng") {
		t.Fatal("the edge was deleted before the target confirmed")
	}
	if strings.Contains(h.audit(), "grant.revoke") {
		t.Error("grant.revoke recorded before verification")
	}
	if st := h.run(); st.Verified != 1 {
		t.Fatalf("run = %+v; ops = %v", st, h.ops(""))
	}
	if h.hasEdge("alice", "eng") {
		t.Error("the edge is still there after the target confirmed")
	}
	if a := h.audit(); !strings.Contains(a, "grant.revoke") || !strings.Contains(a, "provision.verified") {
		t.Errorf("audit = %s", a)
	}
	// Repeating the revoke is the same intent: no second operation.
	h.c.do("POST", "/api/least-privilege/revoke", fmt.Sprintf(`{"edge_id":%d,"dry_run":false}`, edge))
	if n := len(h.ops("")); n != 1 {
		t.Errorf("ops = %d, want 1", n)
	}
}

// Write-back off (the default): the same revoke edits the graph at once, as before.
func TestProvisioning_WriteBackOffKeepsTheDirectPath(t *testing.T) {
	h := newProvHarness(t, fake.Options{})
	h.target(`{"kind":"fake","write_back":false}`, 200)
	edge := h.edgeID("alice", "eng")
	out := h.c.json("POST", "/api/least-privilege/revoke", fmt.Sprintf(`{"edge_id":%d,"dry_run":false}`, edge), 200).(map[string]any)
	if out["applied"] != true || out["provisioning"] != nil || h.hasEdge("alice", "eng") || len(h.ops("")) != 0 {
		t.Errorf("revoke = %v", out)
	}
}

// A failed target write leaves the review item open, and a retry closes it.
func TestProvisioning_FailedWriteLeavesReviewItemOpen(t *testing.T) {
	h := newProvHarness(t, fake.Options{Fault: fake.FailWrites})
	h.seedTarget()
	h.srv.Provisioning().Backoff = func(int) time.Duration { return 0 }
	h.target(`{"kind":"scim","base_url":"`+h.url+`","write_back":true}`, 200)
	var item int64
	testkit.Write(t, h.st, func(c *store.TenantTx) error {
		camp, err := c.InsertCampaign(&store.ReviewCampaign{Name: "q", CreatedAt: testkit.Now, Status: "open", UnusedDays: 60})
		if err != nil {
			return err
		}
		e, err := c.EdgeBetween(fmt.Sprintf("account:%d", h.ids["acct:okta:alice"]), fmt.Sprintf("group:%d", h.ids["group:okta:eng"]))
		if err != nil {
			return err
		}
		if err := c.InsertReviewItem(&store.ReviewItem{CampaignID: camp, IdentityID: h.ids["alice"], EdgeID: &e.ID, EdgeSrc: e.Src,
			EdgeDst: e.Dst, GrantLabel: "alice to eng", Reasons: []string{"unused"}, Context: json.RawMessage(`{}`)}); err != nil {
			return err
		}
		items, err := c.CampaignItems(camp)
		item = items[0].ID
		return err
	})
	decide := func() map[string]any {
		return h.c.json("POST", fmt.Sprintf("/api/reviews/items/%d/decision", item), `{"decision":"revoke"}`, 200).(map[string]any)
	}
	if out := decide(); out["decision"] != nil {
		t.Fatalf("a routed revoke decided the item: %v", out)
	}
	// While it is in flight, keeping the item is refused.
	if rec := h.c.do("POST", fmt.Sprintf("/api/reviews/items/%d/decision", item), `{"decision":"keep"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("keep while the revoke is in flight: %d %s", rec.Code, rec.Body)
	}
	for i := 0; i < 5; i++ {
		h.run()
	}
	ops := h.ops("?status=failed")
	if len(ops) != 1 || ops[0].(map[string]any)["can_retry"] != true {
		t.Fatalf("ops = %v", h.ops(""))
	}
	testkit.Read(t, h.st, func(c *store.TenantTx) error {
		it, err := c.Item(item)
		if err != nil || (it.Decision != nil && *it.Decision != "") {
			t.Errorf("item after a failed write = %+v, %v; want it open", it, err)
		}
		return nil
	})
	if !h.hasEdge("alice", "eng") {
		t.Error("the edge was deleted although the write failed")
	}
	// The target recovers; deciding again (or retrying the operation) completes it.
	h.fake.SetFault("")
	opID := ops[0].(map[string]any)["id"].(string)
	h.c.json("POST", "/api/provisioning/ops/"+opID+"/retry", "", 200)
	if st := h.run(); st.Verified != 1 {
		t.Fatalf("run = %+v", st)
	}
	testkit.Read(t, h.st, func(c *store.TenantTx) error {
		it, err := c.Item(item)
		if err != nil || it.Decision == nil || *it.Decision != "revoke" {
			t.Errorf("item after the retry = %+v, %v", it, err)
		}
		return nil
	})
	if h.hasEdge("alice", "eng") {
		t.Error("the edge survived a verified revoke")
	}
}

// The target acknowledges but does not apply: mismatch, a finding, edge kept.
func TestProvisioning_MismatchRaisesAFindingAndKeepsTheGraph(t *testing.T) {
	h := newProvHarness(t, fake.Options{Fault: fake.DropWrites})
	h.seedTarget()
	h.srv.Provisioning().Backoff = func(int) time.Duration { return 0 }
	h.target(`{"kind":"scim","base_url":"`+h.url+`","write_back":true}`, 200)
	edge := h.edgeID("alice", "eng")
	h.c.json("POST", "/api/least-privilege/revoke", fmt.Sprintf(`{"edge_id":%d,"dry_run":false}`, edge), 200)
	for i := 0; i < 4; i++ {
		h.run()
	}
	if ops := h.ops("?status=mismatch"); len(ops) != 1 {
		t.Fatalf("ops = %v", h.ops(""))
	}
	fs := h.c.json("GET", "/api/provisioning/findings?status=open", "", 200).([]any)
	if len(fs) != 1 || at(fs, 0, "code") != "verify_mismatch" || at(fs, 0, "severity") != "high" {
		t.Errorf("findings = %v", fs)
	}
	if !h.hasEdge("alice", "eng") {
		t.Error("the edge was deleted without verification")
	}
	// Cancellation withdraws the operation but leaves the access finding open.
	opID := at(h.ops("?status=mismatch"), 0, "id").(string)
	d := h.c.json("POST", "/api/provisioning/ops/"+opID+"/cancel", "", 200).(map[string]any)
	if d["status"] != "cancelled" {
		t.Errorf("cancel = %v", d)
	}
	if fs := h.c.json("GET", "/api/provisioning/findings?status=open", "", 200).([]any); len(fs) != 1 {
		t.Errorf("open findings after cancel = %v", fs)
	}
	if rec := h.c.do("POST", "/api/provisioning/ops/"+opID+"/cancel", ""); rec.Code != http.StatusConflict {
		t.Errorf("second cancel: %d", rec.Code)
	}
}

func TestProvisioning_RunRouteIsRecordedAsAJob(t *testing.T) {
	h := newProvHarness(t, fake.Options{})
	h.seedTarget()
	h.target(`{"kind":"scim","base_url":"`+h.url+`","write_back":true}`, 200)
	edge := h.edgeID("alice", "eng")
	h.c.json("POST", "/api/least-privilege/revoke", fmt.Sprintf(`{"edge_id":%d,"dry_run":false}`, edge), 200)
	st := h.c.json("POST", "/api/provisioning/run", "", 200).(map[string]any)
	if st["verified"] != float64(1) {
		t.Errorf("run = %v", st)
	}
	jobs := h.c.json("GET", "/api/jobs?kind=provision", "", 200).([]any)
	if len(jobs) != 1 || at(jobs, 0, "status") != "succeeded" || at(jobs, 0, "retryable") != false {
		t.Errorf("jobs = %v", jobs)
	}
}

func TestProvisioning_OpsFiltersAndValidation(t *testing.T) {
	h := newProvHarness(t, fake.Options{})
	for _, q := range []string{"?status=bogus", "?kind=nuke", "?limit=0", "?limit=501", "?connection_id=x"} {
		if rec := h.c.do("GET", "/api/provisioning/ops"+q, ""); rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("%s: %d", q, rec.Code)
		}
	}
	if rec := h.c.do("GET", "/api/provisioning/ops/not-a-uuid", ""); rec.Code != http.StatusNotFound {
		t.Errorf("bad id: %d", rec.Code)
	}
	if rec := h.c.do("GET", "/api/provisioning/findings?status=x", ""); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("findings status: %d", rec.Code)
	}
	out := h.c.json("GET", "/api/provisioning/ops", "", 200).(map[string]any)
	if len(out["items"].([]any)) != 0 || len(out["counts"].(map[string]any)) != 0 {
		t.Errorf("empty list = %v", out)
	}
}

// Tenant B's operations, targets and findings are invisible to A.
func TestIsolation_ProvisioningRoutes(t *testing.T) {
	f := storetest.TwoTenants(t)
	bConn := f.B.Refs["connection:ad"]
	bOp := insertProvOp(t, f.DB, f.B.ID, bConn, "b-iso")
	h := isolationServer(t, f, f.A.ID).Handler()
	beforeB := storetest.Dump(t, f.DB, f.B.ID)
	for _, m := range []struct{ method, path, body string }{
		{"GET", "/api/provisioning/ops/%s", ""},
		{"POST", "/api/provisioning/ops/%s/retry", ""},
		{"POST", "/api/provisioning/ops/%s/cancel", ""},
		{"PUT", "/api/provisioning/targets/%s", `{"kind":"scim","base_url":"https://x.example"}`},
		{"DELETE", "/api/provisioning/targets/%s", ""},
	} {
		id := bOp
		if strings.Contains(m.path, "targets") {
			id = bConn
		}
		cross := serveOnce(h, m.method, fmt.Sprintf(m.path, id), m.body)
		missing := serveOnce(h, m.method, fmt.Sprintf(m.path, missingUUID), m.body)
		if cross.Code != http.StatusNotFound || cross.Body.String() != missing.Body.String() {
			t.Errorf("%s %s: cross %d %s, missing %d %s", m.method, m.path, cross.Code, cross.Body, missing.Code, missing.Body)
		}
	}
	for _, p := range []string{"/api/provisioning/ops", "/api/provisioning/targets", "/api/provisioning/findings"} {
		if rec := serveOnce(h, "GET", p, ""); strings.Contains(rec.Body.String(), bOp) || strings.Contains(rec.Body.String(), bConn) {
			t.Errorf("A's %s lists B's rows", p)
		}
	}
	if storetest.Dump(t, f.DB, f.B.ID) != beforeB {
		t.Error("tenant B changed")
	}
}

// An expired JIT grant in a write-back system is removed from the target
// first; the request stays approved and the edge stays until the re-read
// confirms it, and a failed removal is not retried by the sweeper.
func TestProvisioning_JITExpiryGoesThroughTheEngine(t *testing.T) {
	h := newProvHarness(t, fake.Options{})
	h.seedTarget()
	h.target(`{"kind":"scim","base_url":"`+h.url+`","write_back":true}`, 200)
	var reqID, edgeID int64
	testkit.Write(t, h.st, func(c *store.TenantTx) (err error) {
		exp := testkit.Now.Add(-time.Hour)
		a, g := h.ids["acct:okta:alice"], h.ids["group:okta:platform"]
		edgeID, err = c.InsertEdge(&store.GrantEdge{Src: fmt.Sprintf("account:%d", a), Dst: fmt.Sprintf("group:%d", g),
			Relation: "member_of", Source: "jit", ExpiresAt: &exp, CreatedAt: exp.Add(-time.Hour)})
		if err != nil {
			return err
		}
		reqID, err = c.InsertRequest(&store.AccessRequest{IdentityID: h.ids["alice"], AccountID: a, GroupID: g, Justification: "j",
			DurationHours: 1, Status: "approved", RequestedAt: exp.Add(-time.Hour), ExpiresAt: &exp, EdgeID: &edgeID})
		return err
	})
	h.fake.AddGroup("platform", "platform", h.aliceID)
	state := func() (status string, edge bool) {
		testkit.Read(t, h.st, func(c *store.TenantTx) error {
			r, err := c.Request(reqID)
			if err != nil {
				t.Fatal(err)
			}
			status = r.Status
			_, err = c.Edge(edgeID)
			edge = err == nil
			return nil
		})
		return
	}
	sweep := func() map[string]any {
		return h.c.json("POST", "/api/jit/sweep", "", 200).(map[string]any)
	}
	sweep()
	if status, edge := state(); status != "approved" || !edge {
		t.Fatalf("after the sweep: %s, edge %v; the grant stays until the target confirms", status, edge)
	}
	sweep() // the sweeper runs every 30 seconds: no second operation
	if ops := h.ops(""); len(ops) != 1 || at(ops, 0, "source") != "jit" || at(ops, 0, "kind") != "remove_entitlement" {
		t.Fatalf("ops = %v", ops)
	}
	if st := h.run(); st.Verified != 1 {
		t.Fatalf("run = %+v", st)
	}
	if status, edge := state(); status != "expired" || edge {
		t.Errorf("after verification: %s, edge %v", status, edge)
	}
	if a := h.audit(); !strings.Contains(a, "jit.expire") {
		t.Errorf("audit = %s", a)
	}
	for _, m := range h.fake.Members("platform") {
		if m == h.alice {
			t.Error("alice is still in the target group")
		}
	}
}

func TestProvisioning_JITExpiryFailureIsNotRetriedBySweeper(t *testing.T) {
	h := newProvHarness(t, fake.Options{Fault: fake.FailWrites})
	h.seedTarget()
	h.srv.Provisioning().Backoff = func(int) time.Duration { return 0 }
	h.target(`{"kind":"scim","base_url":"`+h.url+`","write_back":true}`, 200)
	testkit.Write(t, h.st, func(c *store.TenantTx) error {
		exp := testkit.Now.Add(-time.Hour)
		a, g := h.ids["acct:okta:alice"], h.ids["group:okta:eng"]
		_, err := c.InsertRequest(&store.AccessRequest{IdentityID: h.ids["alice"], AccountID: a, GroupID: g, Justification: "j",
			DurationHours: 1, Status: "approved", RequestedAt: exp.Add(-time.Hour), ExpiresAt: &exp, EdgeID: nil})
		return err
	})
	h.c.json("POST", "/api/jit/sweep", "", 200)
	for i := 0; i < 6; i++ { // the engine's default is five attempts
		h.run()
	}
	if ops := h.ops("?status=failed"); len(ops) != 1 {
		t.Fatalf("ops = %v", h.ops(""))
	}
	h.c.json("POST", "/api/jit/sweep", "", 200)
	h.c.json("POST", "/api/jit/sweep", "", 200)
	ops := h.ops("")
	if len(ops) != 1 || at(ops, 0, "status") != "failed" || at(ops, 0, "attempts") != float64(5) {
		t.Errorf("the sweeper retried or duplicated a failed operation: %v", ops)
	}
}

// TestProvisioning_StoredTokenNeverFollowsAMovedTarget (#315): an edit that
// changes the target's origin or kind without a new token is refused, so the
// sealed token is never sent to the new destination; a path-only edit on the
// same origin keeps it; a move with a new token rotates it; the ledger says
// which.
func TestProvisioning_StoredTokenNeverFollowsAMovedTarget(t *testing.T) {
	const oldToken = "old-secret-token"
	h := newProvHarness(t, fake.Options{Token: oldToken})
	h.seedTarget()
	var mu sync.Mutex
	var seen []string
	mover := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("Authorization"))
		mu.Unlock()
		http.Error(w, "nope", http.StatusTeapot)
	}))
	t.Cleanup(mover.Close)
	moved := mover.URL + "/scim/v2"

	v := h.target(`{"kind":"scim","base_url":"`+h.url+`","token":"`+oldToken+`","write_back":true}`, 200)
	ver := v["credential_version"]
	for name, body := range map[string]string{
		"origin": `{"kind":"scim","base_url":"` + moved + `","write_back":true}`,
		"scheme": `{"kind":"scim","base_url":"` + strings.Replace(h.url, "http://", "https://", 1) + `","write_back":true}`,
		"kind":   `{"kind":"okta","base_url":"` + h.url + `","write_back":true}`,
	} {
		rec := h.c.do("PUT", "/api/provisioning/targets/"+h.conn, body)
		if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "credential_required") {
			t.Errorf("%s change without a token: %d %s", name, rec.Code, rec.Body)
		}
	}
	got := h.c.json("GET", "/api/provisioning/targets", "", 200)
	if b, _ := json.Marshal(got); !strings.Contains(string(b), h.url) || strings.Contains(string(b), mover.URL) {
		t.Errorf("a refused edit moved the target: %s", b)
	}
	// A path-only change on the same origin keeps the token: same host, same
	// trust boundary, and the token was issued for that host.
	samePath := strings.Replace(h.url, "/scim/v2", "/tenant-a/scim/v2", 1)
	v = h.target(`{"kind":"scim","base_url":"`+samePath+`","write_back":true}`, 200)
	if v["has_credential"] != true || v["credential_version"] != ver {
		t.Errorf("path-only edit: %v", v)
	}
	h.target(`{"kind":"scim","base_url":"`+h.url+`","write_back":true}`, 200)

	// the worker still writes to the original target with its token, and the
	// other host never sees a request
	h.c.json("POST", "/api/least-privilege/revoke", fmt.Sprintf(`{"edge_id":%d,"dry_run":false}`, h.edgeID("alice", "eng")), 200)
	if st := h.run(); st.Verified != 1 {
		t.Errorf("run = %+v", st)
	}
	mu.Lock()
	if len(seen) != 0 {
		t.Errorf("the moved-to host got requests: %q", seen)
	}
	mu.Unlock()

	// a move with a new token rotates the credential and records both origins
	v = h.target(`{"kind":"scim","base_url":"`+moved+`","token":"new-token","write_back":true}`, 200)
	if v["has_credential"] != true || v["credential_version"] == ver {
		t.Errorf("rebound target: %v", v)
	}
	d := h.auditDetail()
	if !strings.Contains(d, `"credential":"rotated"`) || !strings.Contains(d, `"previous_origin":"`+targetOrigin(h.url)+`"`) ||
		!strings.Contains(d, `"credential":"kept"`) || strings.Contains(d, "credential_changed") ||
		strings.Contains(d, oldToken) || strings.Contains(d, "new-token") {
		t.Errorf("audit = %s", d)
	}
	// a change to the dev fake drops the token
	v = h.target(`{"kind":"fake","write_back":true}`, 200)
	if v["has_credential"] != false || !strings.Contains(h.auditDetail(), `"credential":"cleared"`) {
		t.Errorf("fake target: %v", v)
	}
}

func TestTargetOrigin(t *testing.T) {
	for in, want := range map[string]string{
		"https://X.example/scim/v2":     "https://x.example:443",
		"https://x.example:443/a":       "https://x.example:443",
		"http://x.example/a":            "http://x.example:80",
		"http://127.0.0.1:8401/scim/v2": "http://127.0.0.1:8401",
		"https://[::1]:9/":              "https://[::1]:9",
	} {
		if got := targetOrigin(in); got != want {
			t.Errorf("targetOrigin(%q) = %q, want %q", in, got, want)
		}
	}
}
