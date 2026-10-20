package api

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
	"github.com/nischalravi/tessera/mvp/server/policies"
)

// Deployment readiness DR-10: step-up on activation and on accepting a
// critical finding, and the two-person rule for write-enabled connections.
// (Permissions per route and role: TestRBACRouteMatrix; step-up on the
// credential and config routes: TestConnectionConfigNeedsStepUp.)

// rdServer is a readiness test server over the demo tenant from which clients
// of different users are made.
type rdServer struct {
	t   *testing.T
	st  *testkit.DB
	srv *Server
}

func newRDServer(t *testing.T) rdServer {
	t.Helper()
	st := testkit.Demo(t)
	srv := New(Config{
		Store: st.DB, Clock: timeutil.Frozen(testkit.Now), Policies: policy.NewLoader(policies.FS),
		Connectors:     func(time.Time) ([]connectors.Connector, error) { return connectors.Load("demo", testkit.Now) },
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		AllowedOrigins: []string{"http://localhost:5173"},
	})
	return rdServer{t, st, srv}
}

// as returns a client signed in as a user holding roles, with the given
// authentication context.
func (s rdServer) as(email string, ctx authtest.Ctx, roles ...auth.Role) rdClient {
	s.t.Helper()
	l := signIn(s.t, s.st.DB, s.st.Tenant, authtest.User{Email: email, Roles: roles}, ctx, testkit.Now)
	return rdClient{client{s.t, testSrv{s.srv, l}.Handler()}, s.st}
}

var staleAuth = authtest.Ctx{AAL: 2, Phr: true, AuthTime: testkit.Now.Add(-20 * time.Minute)}

// status runs a request and returns its status and body.
func (c rdClient) status(method, path, body string) (int, string) {
	c.t.Helper()
	rec := c.do(method, path, body)
	return rec.Code, rec.Body.String()
}

// adReconciled drives a demo AD connection (with extra config) through
// validation and a dry run to dry_run_reconciled, accepting its findings and
// attesting or skipping what remains, as the walkthrough does. It returns the
// connection id and the dry run's findings.
func (c rdClient) adReconciled(extra string) (string, map[string]any) {
	c.t.Helper()
	cfg := `{"technical_owner":"Ingrid Lindqvist","business_owner":"Thandiwe Mokoena",` +
		`"demo_fixed_checks":["range_retrieval"],"expected_counts":{"users":65,"groups":13}` + extra + `}`
	v := c.json("POST", "/api/connections", fmt.Sprintf(`{"name":"Active Directory (demo)","connector_type":"demo-ad","config":%s}`, cfg),
		http.StatusCreated)
	ad := v["id"].(string)
	c.json("PUT", "/api/connections/"+ad+"/credential", `{"reference":"vault:kv/tessera/demo-ad"}`, http.StatusOK)
	c.attest(ad, "base.owner")
	c.attest(ad, "base.correlation.key")
	c.json("POST", "/api/connections/"+ad+"/transition", `{"to":"ready_to_validate"}`, http.StatusOK)
	c.json("POST", "/api/connections/"+ad+"/validate", "", http.StatusAccepted)
	if strings.Contains(extra, "write_mode") {
		// Validation passes the write scope check, which makes the write-back
		// review attestable (it depends on it) and, being Required, sends the
		// revision back to draft until it is attested.
		c.attest(ad, "base.writeback.dryrun")
		c.json("POST", "/api/connections/"+ad+"/transition", `{"to":"ready_to_validate"}`, http.StatusOK)
		c.json("POST", "/api/connections/"+ad+"/validate", "", http.StatusAccepted)
	}
	if v := c.json("GET", "/api/connections/"+ad, "", http.StatusOK); v["state"] != "validated" {
		c.t.Fatalf("not validated: %v", v["next"])
	}
	dr := c.json("POST", "/api/connections/"+ad+"/dry-run", "", http.StatusAccepted)
	for _, f := range findings(dr) {
		if f["severity"] == "critical" || f["severity"] == "high" || f["code"] == "RF-09" {
			c.json("POST", "/api/connections/"+ad+"/findings/"+f["id"].(string)+"/accept",
				`{"reason":"Accepted for go-live; tracked in the remediation plan CHG-2210"}`, http.StatusOK)
		}
	}
	c.json("POST", "/api/connections/"+ad+"/transition", `{"to":"dry_run_reconciled"}`, http.StatusOK)
	return ad, dr
}

// finishChecklist attests or skips every item still blocking activation,
// as the user of c, until only the activation approval (if any) remains.
func (c rdClient) finishChecklist(ad string) {
	c.t.Helper()
	next := c.json("GET", "/api/connections/"+ad, "", http.StatusOK)["next"].(map[string]any)
	for _, b := range next["blocking"].([]any) {
		m := b.(map[string]any)
		item, _ := m["item"].(string)
		if item == "" || item == ApprovalItemName {
			continue
		}
		cl := c.json("GET", "/api/connections/"+ad+"/checklist", "", http.StatusOK)
		attestable := false
		for _, it := range cl["items"].([]any) {
			im := it.(map[string]any)
			if im["id"] != item || im["status"] != "pending" || item == "ad.tls.signing_cb" {
				continue
			}
			for _, v := range im["verify"].([]any) {
				attestable = attestable || v.(map[string]any)["kind"] == "attestation"
			}
		}
		if attestable {
			c.attest(ad, item)
		} else {
			c.json("POST", "/api/connections/"+ad+"/checklist/"+item+"/skip",
				`{"reason":"Scheduled for the Q1 domain controller upgrade"}`, http.StatusOK)
		}
	}
}

// writeEnabledCfg makes the connection write-enabled, with a write scope.
const writeEnabledCfg = `,"write_mode":"scoped","write_scope":["OU=Service Accounts,DC=corp,DC=larkspur,DC=example"]`

// ApprovalItemName is the gate blocker of an unapproved write-enabled activation.
const ApprovalItemName = "activation.approval"

// TestActivate_RequiresStepUp: activating needs connections.activate and a
// fresh phishing-resistant sign-in; the approval needs the same.
func TestActivate_RequiresStepUp(t *testing.T) {
	s := newRDServer(t)
	admin := s.as("ops-admin@larkspur.example", authtest.Phr, auth.RoleTenantAdmin)
	stale := s.as("ops-stale@larkspur.example", staleAuth, auth.RoleTenantAdmin)
	operator := s.as("ops-operator@larkspur.example", authtest.Phr, auth.RoleOperator)
	id := admin.createAD()
	for _, path := range []string{"/activate", "/activation/approve"} {
		code, body := stale.status("POST", "/api/connections/"+id+path, "")
		if code != http.StatusUnauthorized || !strings.Contains(body, "step_up_required") || !strings.Contains(body, "step_up_url") {
			t.Errorf("POST %s with a 20-minute-old sign-in: %d %s, want 401 step_up_required", path, code, body)
		}
		if code, body := operator.status("POST", "/api/connections/"+id+path, ""); code != http.StatusForbidden {
			t.Errorf("POST %s as operator: %d %s, want 403", path, code, body)
		}
		// fresh: the handler runs (the gate, not the step-up, refuses)
		if code, body := admin.status("POST", "/api/connections/"+id+path, ""); code == http.StatusUnauthorized || code == http.StatusForbidden {
			t.Errorf("POST %s with a fresh sign-in: %d %s", path, code, body)
		}
	}
	// rejecting narrows access: no step-up
	if code, body := stale.status("POST", "/api/connections/"+id+"/activation/reject", ""); code != http.StatusConflict ||
		!strings.Contains(body, "no_activation_request") {
		t.Errorf("reject with a stale sign-in: %d %s", code, body)
	}
}

// TestAcceptCriticalFinding_RequiresStepUp: accepting a critical finding
// needs a fresh phishing-resistant sign-in; a lower severity does not.
func TestAcceptCriticalFinding_RequiresStepUp(t *testing.T) {
	s := newRDServer(t)
	admin := s.as("fa-admin@larkspur.example", authtest.Phr, auth.RoleTenantAdmin)
	stale := s.as("fa-stale@larkspur.example", staleAuth, auth.RoleTenantAdmin)
	viewer := s.as("fa-viewer@larkspur.example", authtest.Phr, auth.RoleViewer)
	ad := admin.adValidated()
	dr := admin.json("POST", "/api/connections/"+ad+"/dry-run", "", http.StatusAccepted)
	reason := `{"reason":"Accepted for go-live; tracked in the remediation plan CHG-2210"}`
	var critical, other map[string]any
	for _, f := range findings(dr) {
		switch {
		case f["severity"] == "critical" && critical == nil:
			critical = f
		case f["severity"] != "critical" && other == nil:
			other = f
		}
	}
	if critical == nil || other == nil {
		t.Fatalf("the demo dry run has no critical and non-critical finding: %v", findings(dr))
	}
	path := func(f map[string]any) string {
		return fmt.Sprintf("/api/connections/%s/findings/%s/accept", ad, f["id"])
	}
	if code, body := viewer.status("POST", path(critical), reason); code != http.StatusForbidden {
		t.Errorf("viewer accepting: %d %s, want 403", code, body)
	}
	if code, body := stale.status("POST", path(critical), reason); code != http.StatusUnauthorized || !strings.Contains(body, "step_up_required") {
		t.Errorf("critical finding with a stale sign-in: %d %s, want 401 step_up_required", code, body)
	}
	if code, body := stale.status("POST", path(other), reason); code != http.StatusOK {
		t.Errorf("%s finding with a stale sign-in: %d %s, want 200", other["severity"], code, body)
	}
	if code, body := admin.status("POST", path(critical), reason); code != http.StatusOK {
		t.Errorf("critical finding with a fresh sign-in: %d %s, want 200", code, body)
	}
}

// TestTwoPersonActivation_HTTP: a write-enabled connection is not activated by
// the call that asks for it; a different person who did not attest approves.
func TestTwoPersonActivation_HTTP(t *testing.T) {
	s := newRDServer(t)
	attestor := s.as("tp-attestor@larkspur.example", authtest.Phr, auth.RoleTenantAdmin)
	requester := s.as("tp-requester@larkspur.example", authtest.Phr, auth.RoleTenantAdmin)
	approver := s.as("tp-approver@larkspur.example", authtest.Phr, auth.RoleTenantAdmin)
	auditor := s.as("tp-auditor@larkspur.example", authtest.Phr, auth.RoleAuditor)

	ad, _ := attestor.adReconciled(writeEnabledCfg)
	attestor.finishChecklist(ad)
	act := "/api/connections/" + ad + "/activate"

	// Everything else passes; the gate names the missing approval, which is
	// all that stands between the revision and activation.
	next := attestor.json("GET", "/api/connections/"+ad, "", http.StatusOK)["next"].(map[string]any)
	if b := next["blocking"].([]any); len(b) != 1 || b[0].(map[string]any)["item"] != ApprovalItemName {
		t.Fatalf("blockers of a write-enabled revision with the checklist done: %v", next["blocking"])
	}
	if code, body := requester.status("POST", "/api/connections/"+ad+"/activation/approve", ""); code != http.StatusConflict ||
		!strings.Contains(body, "no_activation_request") {
		t.Fatalf("approving with no request: %d %s", code, body)
	}

	// The request is 202 and changes nothing.
	v := requester.json("POST", act, "", http.StatusAccepted)
	req := v["request"].(map[string]any)
	if v["status"] != "pending_approval" || req["status"] != "pending" || req["requested_by"] != "tp-requester@larkspur.example" ||
		req["write_mode"] != "scoped" {
		t.Fatalf("request: %v", v)
	}
	if got := requester.json("GET", "/api/connections/"+ad, "", http.StatusOK); got["state"] != "dry_run_reconciled" {
		t.Fatalf("state after the request: %v", got["state"])
	}
	if got := auditor.json("GET", "/api/connections/"+ad+"/activation", "", http.StatusOK); got["request"] == nil {
		t.Errorf("activation status: %v", got)
	}

	// Refused: the requester, and the person who attested.
	for name, c := range map[string]rdClient{"requester": requester, "attestor": attestor} {
		code, body := c.status("POST", "/api/connections/"+ad+"/activation/approve", "")
		if code != http.StatusForbidden || !strings.Contains(body, "two_person_rule") {
			t.Errorf("%s approving: %d %s, want 403 two_person_rule", name, code, body)
		}
	}
	if code, _ := auditor.status("POST", "/api/connections/"+ad+"/activation/approve", ""); code != http.StatusForbidden {
		t.Errorf("auditor approving: %d, want 403", code)
	}
	if got := requester.json("GET", "/api/connections/"+ad, "", http.StatusOK); got["state"] != "dry_run_reconciled" {
		t.Fatalf("a refused approval changed the state to %v", got["state"])
	}

	// A different person approves: the connection is active and synced.
	v = approver.json("POST", "/api/connections/"+ad+"/activation/approve", `{"note":"write scope reviewed against CHG-2210"}`, http.StatusOK)
	if v["state"] != "active" {
		t.Fatalf("after approval: %v", v["state"])
	}
	if n := approver.systemCounts("ad-corp").Accounts; n == 0 {
		t.Error("the approved activation ran no first sync")
	}
	got := auditor.json("GET", "/api/connections/"+ad+"/activation", "", http.StatusOK)["request"].(map[string]any)
	if got["status"] != "applied" || got["decided_by"] != "tp-approver@larkspur.example" {
		t.Errorf("applied request: %v", got)
	}
	audit := approver.do("GET", "/api/audit", "").Body.String()
	for _, ev := range []string{"connection.activation.requested", "connection.activation.approved", "connection.activated"} {
		if !strings.Contains(audit, ev) {
			t.Errorf("audit lacks %s", ev)
		}
	}
	approver.json("POST", "/api/connections/"+ad+"/activation/approve", "", http.StatusConflict)
}

// TestTwoPersonActivation_RejectAndReadOnly: the requester cancels, another
// admin rejects; a read-only connection still activates in one step.
func TestTwoPersonActivation_RejectAndReadOnly(t *testing.T) {
	s := newRDServer(t)
	attestor := s.as("rj-attestor@larkspur.example", authtest.Phr, auth.RoleTenantAdmin)
	requester := s.as("rj-requester@larkspur.example", authtest.Phr, auth.RoleTenantAdmin)
	other := s.as("rj-other@larkspur.example", authtest.Phr, auth.RoleTenantAdmin)
	ad, _ := attestor.adReconciled(writeEnabledCfg)
	attestor.finishChecklist(ad)
	act, rej := "/api/connections/"+ad+"/activate", "/api/connections/"+ad+"/activation/reject"
	requester.json("POST", act, "", http.StatusAccepted)
	v := requester.json("POST", rej, `{"note":"not yet"}`, http.StatusOK)["request"].(map[string]any)
	if v["status"] != "cancelled" {
		t.Errorf("requester's close: %v", v)
	}
	requester.json("POST", act, "", http.StatusAccepted)
	v = other.json("POST", rej, `{"note":"scope too broad"}`, http.StatusOK)["request"].(map[string]any)
	if v["status"] != "rejected" || v["decision_note"] != "scope too broad" {
		t.Errorf("other admin's close: %v", v)
	}
	other.json("POST", "/api/connections/"+ad+"/activation/approve", "", http.StatusConflict)
	other.json("POST", rej, `{"note":"`+strings.Repeat("x", 501)+`"}`, http.StatusUnprocessableEntity)
}
