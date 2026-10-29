package admin_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/admin"
	"github.com/nischalravi/tessera/mvp/server/internal/alerts"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Config proposals by machine clients (issue #721): the scope is granted only by two admins, a proposal waits for a
// human, the proposer (and its owner) can never approve it, and every event names the client.

const proposalClientID = "tsc_proposer"

// machine adds a machine client owned by owner and returns its token principal holding scopes.
func (h *harness) machine(owner *store.PlatformUser, scopes ...string) *auth.Principal {
	h.t.Helper()
	cl := &store.APIClient{ClientID: proposalClientID, Name: "terraform", Kind: "machine", GrantTypes: []string{"client_credentials"},
		TokenEndpointAuthMethod: "private_key_jwt", AllowedScopes: []string{"tessera:read"}, Roles: []string{"viewer"},
		OwnerUserID: &owner.ID, CreatedAt: h.clk.now()}
	h.tx(func(tx *store.TenantTx) error { return tx.InsertAPIClient(cl) })
	return h.clientPrincipal(scopes...)
}

func (h *harness) clientPrincipal(scopes ...string) *auth.Principal {
	return &auth.Principal{Kind: auth.KindAPIClient, TenantID: tenantID, ClientID: proposalClientID, Display: "terraform",
		ActiveRoles: auth.RoleSet{auth.RoleViewer: true}, AssignedRoles: auth.RoleSet{auth.RoleViewer: true},
		Scopes: auth.ScopeSetOf(scopes), Via: auth.ViaBearer}
}

// grantScope runs the two-admin grant of config.propose to the client.
func (h *harness) grantScope(a1, a2 *store.PlatformUser) {
	h.t.Helper()
	ch := mustSubmit(h.t, h, h.as(a1), admin.TypeProposeGrant, `{"client_id":"`+proposalClientID+`"}`)
	if _, err := h.svc.Approve(h.ctx, h.as(a2), ch.ID, ch.PayloadHash); err != nil {
		h.t.Fatal(err)
	}
	if got := h.change(ch.ID).Status; got != store.ChangeApplied {
		h.t.Fatalf("the grant is %s, want applied", got)
	}
}

func (h *harness) clientScopes() []string {
	h.t.Helper()
	var s []string
	if err := h.db.ReadTenant(h.ctx, tenantID, func(tx *store.TenantTx) error {
		c, err := tx.APIClientByClientID(proposalClientID)
		if c != nil {
			s = c.AllowedScopes
		}
		return err
	}); err != nil {
		h.t.Fatal(err)
	}
	return s
}

const alertBody = `{"enabled":true,"severity":"critical","threshold":2,"window_minutes":30}`

func TestProposeGrant_NeedsTwoAdmins(t *testing.T) {
	h := newHarness(t)
	ad := h.admins("adm1", "adm2")
	owner := h.user("olu", store.RoleOperator)
	h.machine(owner)

	ch := mustSubmit(t, h, h.as(ad[0]), admin.TypeProposeGrant, `{"client_id":"`+proposalClientID+`"}`)
	if ch.Status != store.ChangePendingApproval || !ch.TwoPerson || ch.CoolingOffSeconds != 0 {
		t.Fatalf("grant = %s two_person %t cooling %d, want pending, two person", ch.Status, ch.TwoPerson, ch.CoolingOffSeconds)
	}
	if strings.Contains(strings.Join(h.clientScopes(), " "), "config.propose") {
		t.Fatal("the scope was added before anyone approved")
	}
	_, err := h.svc.Approve(h.ctx, h.as(ad[0]), ch.ID, ch.PayloadHash)
	wantErr(t, err, http.StatusForbidden, "self_approval_refused")
	// the approval needs a fresh step-up
	_, err = h.svc.Approve(h.ctx, h.asAged(ad[1], 2*time.Hour), ch.ID, ch.PayloadHash)
	wantStepUp(t, err)
	// a machine client cannot approve, whatever scopes it holds
	_, err = h.svc.Approve(h.ctx, h.clientPrincipal("tessera:read", "tessera:write", "config.propose"), ch.ID, ch.PayloadHash)
	if err == nil {
		t.Fatal("a machine client approved its own grant")
	}
	if _, err := h.svc.Approve(h.ctx, h.as(ad[1]), ch.ID, ch.PayloadHash); err != nil {
		t.Fatal(err)
	}
	if got := h.clientScopes(); !strings.Contains(strings.Join(got, " "), "config.propose") {
		t.Fatalf("scopes = %v, want config.propose after the approval", got)
	}
	// a second grant is refused
	_, err = h.submit(h.as(ad[0]), admin.TypeProposeGrant, `{"client_id":"`+proposalClientID+`"}`)
	wantErr(t, err, http.StatusConflict, "already_granted")
}

func TestProposeGrant_Refusals(t *testing.T) {
	h := newHarness(t)
	ad := h.admins("adm1", "adm2")
	h.machine(h.user("olu", store.RoleOperator))
	for _, tc := range []struct {
		name, payload string
		status        int
		code          string
	}{
		{"unknown client", `{"client_id":"tsc_nope"}`, 404, "not_found"},
		{"no client", `{"client_id":""}`, 422, "invalid_payload"},
		{"unknown field", `{"client_id":"` + proposalClientID + `","scope":"tessera:admin"}`, 422, "invalid_payload"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := h.submit(h.as(ad[0]), admin.TypeProposeGrant, tc.payload)
			wantErr(t, err, tc.status, tc.code)
		})
	}
	// a machine principal cannot file the grant either
	_, err := h.submit(h.clientPrincipal("tessera:read"), admin.TypeProposeGrant, `{"client_id":"`+proposalClientID+`"}`)
	if err == nil {
		t.Fatal("a machine client filed its own grant")
	}
	// the grant is not an api-filed proposal kind
	_, err = h.svc.SubmitProposal(h.ctx, h.clientPrincipal("config.propose"), "api_client", "", json.RawMessage(`{}`))
	wantErr(t, err, http.StatusUnprocessableEntity, "invalid_payload")
}

func TestProposal_AppliesOnlyAfterHumanApproval(t *testing.T) {
	h := newHarness(t)
	ad := h.admins("adm1", "adm2")
	owner := h.user("olu", store.RoleOperator, store.RoleTenantAdmin)
	machine := h.machine(owner, "config.propose")

	// without the stored scope (it is in the token only), nothing is filed
	_, err := h.svc.SubmitProposal(h.ctx, machine, admin.KindAlertRule, "signin_failures", json.RawMessage(alertBody))
	wantErr(t, err, http.StatusForbidden, "forbidden")
	h.grantScope(ad[0], ad[1])

	ch, err := h.svc.SubmitProposal(h.ctx, machine, admin.KindAlertRule, "signin_failures", json.RawMessage(alertBody))
	if err != nil {
		t.Fatal(err)
	}
	if ch.Type != admin.TypeConfigProposal || ch.Status != store.ChangePendingApproval || !ch.TwoPerson || ch.RequestedBy != owner.ID {
		t.Fatalf("proposal = %+v, want a pending two-person config.proposal in the owner's name", ch)
	}
	var client string
	if err := h.db.ReadTenant(h.ctx, tenantID, func(tx *store.TenantTx) (err error) {
		client, err = tx.AdminChangeProposer(ch.ID)
		return err
	}); err != nil || client != proposalClientID {
		t.Fatalf("proposer = %q, %v", client, err)
	}
	// nothing was written
	h.tx(func(tx *store.TenantTx) error {
		if cur, err := alerts.EffectiveRule(tx, "signin_failures"); err != nil || cur.Threshold == 2 {
			t.Errorf("rule = %+v, %v: applied before approval", cur, err)
		}
		return nil
	})
	// the proposer's owner is the requester, so they cannot approve even as an admin
	_, err = h.svc.Approve(h.ctx, h.as(owner), ch.ID, ch.PayloadHash)
	wantErr(t, err, http.StatusForbidden, "self_approval_refused")
	// neither can the machine client, and a stale hash is refused
	if _, err = h.svc.Approve(h.ctx, machine, ch.ID, ch.PayloadHash); err == nil {
		t.Fatal("the proposer approved its own proposal")
	}
	_, err = h.svc.Approve(h.ctx, h.as(ad[0]), ch.ID, strings.Repeat("0", 64))
	wantErr(t, err, http.StatusConflict, "payload_hash_mismatch")
	if h.change(ch.ID).Status != store.ChangePendingApproval {
		t.Fatal("a refused approval moved the request")
	}

	got, err := h.svc.Approve(h.ctx, h.as(ad[0]), ch.ID, ch.PayloadHash)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != store.ChangeApplied || got.ApprovedBy == nil || *got.ApprovedBy != ad[0].ID {
		t.Fatalf("approved proposal = %s approved by %v, want applied by adm1", got.Status, got.ApprovedBy)
	}
	h.tx(func(tx *store.TenantTx) error {
		if cur, err := alerts.EffectiveRule(tx, "signin_failures"); err != nil || cur.Threshold != 2 || cur.Severity != "critical" {
			t.Errorf("rule = %+v, %v: not applied after approval", cur, err)
		}
		return nil
	})

	// submitted, approved and applied each carry the client id
	var named []string
	if err := h.db.ReadTenant(h.ctx, tenantID, func(tx *store.TenantTx) error {
		evs, err := tx.AuditLog(-1)
		for _, e := range evs {
			if strings.HasPrefix(e.Action, "admin.change.") && strings.Contains(string(e.Detail), ch.ID.String()) {
				if !strings.Contains(string(e.Detail), `"client_id":"`+proposalClientID+`"`) {
					t.Errorf("%s has no client id: %s", e.Action, e.Detail)
				}
				named = append(named, e.Action)
			}
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"admin.change.submitted", "admin.change.approved", "admin.change.applied"} {
		found := false
		for _, a := range named {
			found = found || a == want
		}
		if !found {
			t.Errorf("no %s event for the proposal (got %v)", want, named)
		}
	}
}

func TestProposal_RejectedAndRefused(t *testing.T) {
	h := newHarness(t)
	ad := h.admins("adm1", "adm2")
	machine := h.machine(h.user("olu", store.RoleOperator), "config.propose")
	h.grantScope(ad[0], ad[1])

	ch, err := h.svc.SubmitProposal(h.ctx, machine, admin.KindAlertRule, "signin_failures", json.RawMessage(alertBody))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Reject(h.ctx, h.as(ad[1]), ch.ID); err != nil {
		t.Fatal(err)
	}
	if h.change(ch.ID).Status != store.ChangeRejected {
		t.Fatal("a rejected proposal is not rejected")
	}
	_, err = h.svc.Approve(h.ctx, h.as(ad[0]), ch.ID, ch.PayloadHash)
	wantErr(t, err, http.StatusConflict, "invalid_state")

	for _, tc := range []struct {
		name, kind, id, body string
		status               int
		code                 string
	}{
		{"unknown kind", "connector", "", `{}`, 422, "invalid_payload"},
		{"unknown field", admin.KindAlertRule, "signin_failures", `{"enabled":true,"severity":"high","threshold":2,"window_minutes":30,"admin":true}`, 422, "invalid_payload"},
		{"trailing data", admin.KindAlertRule, "signin_failures", `{"enabled":true,"severity":"high","threshold":2,"window_minutes":30} {}`, 422, "invalid_payload"},
		{"no rule", admin.KindAlertRule, "no_such_rule", alertBody, 404, "rule_not_found"},
		{"bad severity", admin.KindAlertRule, "signin_failures", `{"enabled":true,"severity":"loud","threshold":2,"window_minutes":30}`, 422, "invalid_severity"},
		{"no rule id", admin.KindAlertRule, "", alertBody, 422, "invalid_payload"},
		{"catalog id not a number", admin.KindCatalogItem, "abc", `{"risk":"low"}`, 422, "invalid_payload"},
		{"catalog group missing", admin.KindCatalogItem, "424242", `{"risk":"low"}`, 404, "not_found"},
		{"role without a name", admin.KindRole, "", `{"risk":"low"}`, 422, ""},
		{"role to change is missing", admin.KindRole, uuid.NewString(), `{"version":1,"name":"x","risk":"low"}`, 404, ""},
		{"ruleset without a name", admin.KindSoDRuleset, "", `{}`, 422, "invalid_payload"},
		{"ruleset to change is missing", admin.KindSoDRuleset, "nope", `{"version":1,"name":"x"}`, 404, "not_found"},
		{"empty body", admin.KindAlertRule, "signin_failures", ``, 422, "invalid_payload"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := h.svc.SubmitProposal(h.ctx, machine, tc.kind, tc.id, json.RawMessage(tc.body))
			if err == nil {
				t.Fatal("accepted")
			}
			var ae *admin.Error
			if tc.code == "" {
				return // a domain refusal: the status is the point
			}
			wantErr(t, err, tc.status, tc.code)
			_ = ae
		})
	}
}

func TestProposal_ScopeAndClientChecks(t *testing.T) {
	h := newHarness(t)
	ad := h.admins("adm1", "adm2")
	owner := h.user("olu", store.RoleOperator)
	h.machine(owner)
	h.grantScope(ad[0], ad[1])

	// a token without the scope proposes nothing, whatever else it holds
	_, err := h.svc.SubmitProposal(h.ctx, h.clientPrincipal("tessera:read", "tessera:write", "tessera:audit"),
		admin.KindAlertRule, "signin_failures", json.RawMessage(alertBody))
	wantErr(t, err, http.StatusForbidden, "forbidden")
	// a person (cookie session) is not a machine client
	_, err = h.svc.SubmitProposal(h.ctx, h.as(ad[0]), admin.KindAlertRule, "signin_failures", json.RawMessage(alertBody))
	wantErr(t, err, http.StatusForbidden, "forbidden")

	machine := h.clientPrincipal("config.propose")
	// a disabled client proposes nothing
	h.tx(func(tx *store.TenantTx) error { return tx.SetAPIClientStatus(proposalClientID, store.ClientDisabled) })
	_, err = h.svc.SubmitProposal(h.ctx, machine, admin.KindAlertRule, "signin_failures", json.RawMessage(alertBody))
	wantErr(t, err, http.StatusForbidden, "forbidden")
	h.tx(func(tx *store.TenantTx) error { return tx.SetAPIClientStatus(proposalClientID, store.ClientActive) })
	if _, err = h.svc.SubmitProposal(h.ctx, machine, admin.KindAlertRule, "signin_failures", json.RawMessage(alertBody)); err != nil {
		t.Fatal(err)
	}
}

func TestProposal_BodyIsCanonical(t *testing.T) {
	a, err := admin.ProposalPayload(admin.KindAlertRule, "signin_failures",
		json.RawMessage(`{"window_minutes":30, "threshold":2,"severity":"critical","enabled":true}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := admin.ProposalPayload(admin.KindAlertRule, "signin_failures", json.RawMessage(alertBody))
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) || admin.HashPayload(a) != admin.HashPayload(b) {
		t.Fatalf("the same body spelled two ways gives two payloads:\n%s\n%s", a, b)
	}
}

// TestProposal_PersonCannotFileOne: a config.proposal comes only from a machine client (issue #740). A person's request
// of that type is refused, so the "Proposed by a machine client" label always has a client behind it.
func TestProposal_PersonCannotFileOne(t *testing.T) {
	h := newHarness(t)
	ad := h.admins("adm1", "adm2")
	payload := `{"kind":"alert_rule","id":"signin_failures","body":` + alertBody + `}`
	_, err := h.submit(h.as(ad[0]), admin.TypeConfigProposal, payload)
	wantErr(t, err, http.StatusUnprocessableEntity, "invalid_payload")
	_, err = h.svc.SubmitChecked(h.ctx, h.as(ad[0]), admin.SubmitInput{Type: admin.TypeConfigProposal, Payload: json.RawMessage(payload)})
	wantErr(t, err, http.StatusUnprocessableEntity, "invalid_payload")
}
