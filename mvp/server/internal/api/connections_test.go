package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

// rdClient wraps client with JSON helpers for the readiness routes.
type rdClient struct {
	client
	st *testkit.DB
}

func newRD(t *testing.T, mutate ...func(*Config)) rdClient {
	t.Helper()
	st := testkit.Demo(t)
	return rdClient{client{t, testServer(st, mutate...)}, st}
}

// read runs fn in a read-only transaction of the test tenant. Tests reach
// the database only through the tenant-scoped repositories (no raw SQL
// outside internal/store).
func (c rdClient) read(fn func(tx *store.TenantTx) error) {
	c.t.Helper()
	testkit.Read(c.t, c.st, fn)
}

// systemCounts counts the live accounts, groups, resources and permissions of a system.
func (c rdClient) systemCounts(system string) store.SystemCounts {
	c.t.Helper()
	return testkit.Get(c.t, c.st, func(tx *store.TenantTx) (store.SystemCounts, error) { return tx.CountSystem(system) })
}

// revisionCount counts every connection revision of the tenant.
func (c rdClient) revisionCount() int {
	c.t.Helper()
	n := 0
	c.read(func(tx *store.TenantTx) error {
		conns, err := tx.Connections()
		for _, cn := range conns {
			revs, err := tx.Revisions(cn.ID)
			if err != nil {
				return err
			}
			n += len(revs)
		}
		return err
	})
	return n
}

func (c rdClient) json(method, path, body string, wantStatus int) map[string]any {
	c.t.Helper()
	rec := c.do(method, path, body, "X-Tessera-User", "j.rivera@larkspur.example")
	if rec.Code != wantStatus {
		c.t.Fatalf("%s %s: status %d, want %d: %s", method, path, rec.Code, wantStatus, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		c.t.Fatalf("%s %s: %v: %s", method, path, err, rec.Body.String())
	}
	return out
}

func (c rdClient) createAD() string {
	c.t.Helper()
	v := c.json("POST", "/api/connections", `{"name":"Active Directory (demo)","connector_type":"demo-ad",
		"config":{"technical_owner":"Ingrid Lindqvist","business_owner":"Thandiwe Mokoena"}}`, http.StatusCreated)
	id := v["id"].(string)
	c.json("PUT", "/api/connections/"+id+"/credential", `{"reference":"vault:kv/tessera/ad-corp"}`, http.StatusOK)
	return id
}

func (c rdClient) attest(id, item string) {
	c.t.Helper()
	c.json("POST", "/api/connections/"+id+"/checklist/"+item+"/attest", `{"note":"checked in the AD console"}`, http.StatusOK)
}

func TestConnections_CreateAndChecklist(t *testing.T) {
	t.Parallel()
	c := newRD(t)
	id := c.createAD()
	v := c.json("GET", "/api/connections/"+id, "", http.StatusOK)
	if v["state"] != "draft" || v["simulated"] != true || v["system"] != "ad-corp" {
		t.Errorf("connection: %v", v)
	}
	cl := c.json("GET", "/api/connections/"+id+"/checklist", "", http.StatusOK)
	items := cl["items"].([]any)
	applicable := 0
	for _, it := range items {
		if it.(map[string]any)["applicable"] == true {
			applicable++
		}
	}
	if len(items) != 49 || applicable != 46 {
		t.Errorf("checklist: %d items, %d applicable (want 49, 46)", len(items), applicable)
	}
	next := cl["next"].(map[string]any)
	if next["to"] != "ready_to_validate" {
		t.Errorf("next: %v", next)
	}
	c.attest(id, "base.owner")
	v = c.json("POST", "/api/connections/"+id+"/transition", `{"to":"ready_to_validate"}`, http.StatusOK)
	if v["state"] != "ready_to_validate" {
		t.Errorf("state %v", v["state"])
	}
	// errors
	c.json("POST", "/api/connections", `{"name":"x","connector_type":"mainframe"}`, http.StatusUnprocessableEntity)
	c.json("POST", "/api/connections", `{"name":"Active Directory (demo)","connector_type":"demo-ad"}`, http.StatusConflict)
	c.json("POST", "/api/connections", `{"name":"y","connector_type":"demo-ad","system":"y","password":"p"}`, http.StatusUnprocessableEntity)
	c.json("POST", "/api/connections", `{"name":"z","connector_type":"demo-ad","system":"z","config":{"password":"p"}}`, http.StatusUnprocessableEntity)
	c.json("GET", "/api/connections/not-a-uuid", "", http.StatusNotFound)
	c.json("GET", "/api/connections/00000000-0000-4000-8000-000000000000", "", http.StatusNotFound)
	c.json("POST", "/api/connections/"+id+"/checklist/ad.nope/attest", `{"note":"checked in the AD console"}`, http.StatusNotFound)
	c.json("POST", "/api/connections/"+id+"/checklist/base.stale.threshold/attest", `{"note":"short"}`, http.StatusUnprocessableEntity)
	c.json("POST", "/api/connections/"+id+"/retire", `{}`, http.StatusUnprocessableEntity)
}

func TestActivate_409GateReport(t *testing.T) {
	t.Parallel()
	c := newRD(t)
	id := c.createAD()
	c.attest(id, "base.owner")
	c.json("POST", "/api/connections/"+id+"/transition", `{"to":"ready_to_validate"}`, http.StatusOK)
	r := c.json("POST", "/api/connections/"+id+"/activate", "", http.StatusConflict)
	if r["error"] != "activation_blocked" || r["state"] != "ready_to_validate" {
		t.Fatalf("report: %v", r)
	}
	blocking := r["blocking"].([]any)
	if len(blocking) == 0 {
		t.Fatal("no blockers")
	}
	kinds := map[string]bool{}
	for _, b := range blocking {
		m := b.(map[string]any)
		if m["status"] == nil || m["reason"] == nil {
			t.Errorf("blocker without status or reason: %v", m)
		}
		if item, ok := m["item"].(string); ok {
			kinds[item] = true
		}
	}
	for _, want := range []string{"state", "validation", "ad.bind", "dry_run", "ad.tls.signing_cb"} {
		if !kinds[want] {
			t.Errorf("missing blocker %s in %v", want, kinds)
		}
	}
	// skipping the transition endpoint's rules
	r = c.json("POST", "/api/connections/"+id+"/transition", `{"to":"active"}`, http.StatusUnprocessableEntity)
	if r["error"] != "invalid_target" {
		t.Errorf("transition to active: %v", r)
	}
	r = c.json("POST", "/api/connections/"+id+"/transition", `{"to":"dry_run_reconciled"}`, http.StatusConflict)
	if r["error"] != "transition_blocked" {
		t.Errorf("early reconcile: %v", r)
	}
}

func TestSkipRequired_422(t *testing.T) {
	t.Parallel()
	c := newRD(t)
	id := c.createAD()
	r := c.json("POST", "/api/connections/"+id+"/checklist/ad.bind/skip", `{"reason":"we will fix this after go-live"}`, http.StatusUnprocessableEntity)
	if r["error"] != "required_item_not_skippable" {
		t.Errorf("%v", r)
	}
	r = c.json("POST", "/api/connections/"+id+"/checklist/base.owner/skip", `{"reason":"we will fix this after go-live"}`, http.StatusUnprocessableEntity)
	if r["error"] != "required_item_not_skippable" {
		t.Errorf("%v", r)
	}
}

func TestSkipReasonMinLength(t *testing.T) {
	t.Parallel()
	c := newRD(t)
	id := c.createAD()
	path := "/api/connections/" + id + "/checklist/ad.tls.signing_cb/skip"
	r := c.json("POST", path, `{"reason":"nineteen characters"}`, http.StatusUnprocessableEntity)
	if r["error"] != "reason_too_short" {
		t.Errorf("%v", r)
	}
	c.json("POST", path, `{"reason":"Scheduled for Q1 DC upgrade","review_by":"2027-01-15"}`, http.StatusOK)
	cl := c.json("GET", "/api/connections/"+id+"/checklist", "", http.StatusOK)
	for _, it := range cl["items"].([]any) {
		m := it.(map[string]any)
		if m["id"] == "ad.tls.signing_cb" {
			skip := m["skip"].(map[string]any)
			if m["status"] != "skipped" || skip["actor"] != "j.rivera@larkspur.example" || !strings.HasPrefix(skip["review_by"].(string), "2027-01-15") {
				t.Errorf("skipped item: %v", m)
			}
		}
	}
	audit := c.do("GET", "/api/audit", "").Body.String()
	if !strings.Contains(audit, "readiness.item.skipped") || !strings.Contains(audit, "Scheduled for Q1 DC upgrade") {
		t.Errorf("skip not audited")
	}
	c.json("DELETE", path, "", http.StatusOK)
	c.json("DELETE", path, "", http.StatusNotFound)
	if !strings.Contains(c.do("GET", "/api/audit", "").Body.String(), "readiness.item.unskipped") {
		t.Errorf("unskip not audited")
	}
	c.json("POST", path, `{"reason":"Scheduled for Q1 DC upgrade","review_by":"2020-01-01"}`, http.StatusUnprocessableEntity)
}

func TestCredential_NeverReturned(t *testing.T) {
	t.Parallel()
	c := newRD(t)
	id := c.createAD()
	const secret = "Corr3ct-H0rse-Battery-Staple"
	r := c.json("PUT", "/api/connections/"+id+"/credential", fmt.Sprintf(`{"secret":%q}`, secret), http.StatusOK)
	if r["present"] != true || r["kind"] != "sealed" {
		t.Errorf("credential view: %v", r)
	}
	for _, path := range []string{"/api/connections/" + id, "/api/connections/" + id + "/checklist", "/api/connections", "/api/audit"} {
		if body := c.do("GET", path, "").Body.String(); strings.Contains(body, secret) {
			t.Errorf("%s leaks the secret", path)
		}
	}
	c.json("PUT", "/api/connections/"+id+"/credential", `{"reference":"http://evil"}`, http.StatusUnprocessableEntity)
	c.json("PUT", "/api/connections/"+id+"/credential", `{}`, http.StatusUnprocessableEntity)
}

func TestLegacyConnectors_Unchanged(t *testing.T) {
	t.Parallel()
	c := newRD(t)
	before := c.do("GET", "/api/connectors", "").Body.String()
	v := c.json("POST", "/api/connections", `{"name":"Okta (demo)","connector_type":"demo-okta"}`, http.StatusCreated)
	if v["system"] != "okta" {
		t.Fatalf("okta system: %v", v["system"])
	}
	if after := c.do("GET", "/api/connectors", "").Body.String(); after != before {
		t.Errorf("/api/connectors changed:\n%s\n%s", before, after)
	}
	// The legacy sync path neither creates revisions nor touches gates.
	revs := c.revisionCount()
	if rec := c.do("POST", "/api/connectors/sync", ""); rec.Code != http.StatusOK {
		t.Fatalf("sync: %d", rec.Code)
	}
	list := c.do("GET", "/api/connections", "")
	var conns []map[string]any
	if err := json.Unmarshal(list.Body.Bytes(), &conns); err != nil {
		t.Fatal(err)
	}
	governed, legacy := 0, 0
	for _, x := range conns {
		if x["legacy"] == true {
			legacy++
			if x["system"] == "okta" && x["governed_by"] != v["id"] {
				t.Errorf("legacy okta not linked to its governing connection: %v", x)
			}
		} else {
			governed++
			if x["state"] != "draft" {
				t.Errorf("sync moved a governed connection: %v", x["state"])
			}
		}
	}
	if n := c.revisionCount(); n != revs || n != 1 {
		t.Errorf("revisions %d (before sync %d)", n, revs)
	}
	if governed != 1 || legacy != 5 {
		t.Errorf("governed %d legacy %d", governed, legacy)
	}
	if after := c.do("GET", "/api/connectors", "").Body.String(); !strings.Contains(after, `"system":"okta"`) {
		t.Errorf("connectors after sync: %s", after)
	}
}

func TestValidation_API(t *testing.T) {
	t.Parallel()
	c := newRD(t)
	id := c.createAD()
	r := c.json("POST", "/api/connections/"+id+"/validate", "", http.StatusConflict)
	if r["error"] != "not_ready_to_validate" {
		t.Fatalf("draft validate: %v", r)
	}
	c.attest(id, "base.owner")
	c.json("POST", "/api/connections/"+id+"/transition", `{"to":"ready_to_validate"}`, http.StatusOK)
	run := c.json("POST", "/api/connections/"+id+"/validate", "", http.StatusAccepted)
	if run["simulated"] != true || run["status"] != "completed" {
		t.Fatalf("run: %v", run)
	}
	failing := map[string]bool{}
	for _, x := range run["results"].([]any) {
		m := x.(map[string]any)
		if m["status"] == "fail" {
			failing[m["item_id"].(string)] = true
		}
	}
	if !failing["ad.groups.range"] {
		t.Errorf("gaps scenario: ad.groups.range should fail: %v", failing)
	}
	got := c.json("GET", "/api/connections/"+id+"/validations/"+run["id"].(string), "", http.StatusOK)
	if got["id"] != run["id"] {
		t.Errorf("get run: %v", got["id"])
	}
	v := c.json("GET", "/api/connections/"+id, "", http.StatusOK)
	if v["state"] != "ready_to_validate" || v["latest_validation_id"] != run["id"] {
		t.Errorf("connection after failing validation: %v %v", v["state"], v["latest_validation_id"])
	}
	c.json("PATCH", "/api/connections/"+id+"/config", `{"demo_fixed_checks":["range_retrieval"]}`, http.StatusOK)
	c.json("POST", "/api/connections/"+id+"/validate", "{}", http.StatusAccepted)
	v = c.json("GET", "/api/connections/"+id, "", http.StatusOK)
	if v["state"] != "validated" {
		t.Errorf("after the simulated fix: %v %v", v["state"], v["next"])
	}
	c.json("GET", "/api/connections/"+id+"/validations/00000000-0000-4000-8000-000000000000", "", http.StatusNotFound)
	c.json("GET", "/api/connections/"+id+"/validations/nope", "", http.StatusUnprocessableEntity)
}
