package admin_test

import (
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/admin"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Operator-assisted recovery (design §15.5, §19 PR12).

func (h *harness) recoveryRequest(conn *store.IdPConnection, op, co string) admin.RecoveryRequest {
	return admin.RecoveryRequest{Tenant: tenantID, Operator: admin.Operator{ID: op, PhishingResistant: true},
		CoOperator: admin.Operator{ID: co, PhishingResistant: true}, Ticket: "SUP-1042", ConnectionID: conn.ID,
		Email: "new.admin@acme.example"}
}

func (h *harness) tenantStatus() string {
	h.t.Helper()
	var s string
	h.tx(func(tx *store.TenantTx) error {
		t, err := tx.TenantRecord()
		s = t.Status
		return err
	})
	return s
}

// TestRecoveryNeedsTwoDifferentOperators: one operator, the same operator
// twice (in any case), an operator without a phishing-resistant sign-in, or
// no ticket is refused and changes nothing.
func TestRecoveryNeedsTwoDifferentOperators(t *testing.T) {
	h := newHarness(t)
	conn := h.oidcConnection("okta")
	for name, tc := range map[string]struct {
		mutate func(*admin.RecoveryRequest)
		status int
		code   string
	}{
		"same operator twice":   {func(r *admin.RecoveryRequest) { r.CoOperator.ID = r.Operator.ID }, 422, "two_operators_required"},
		"same, other case":      {func(r *admin.RecoveryRequest) { r.CoOperator.ID = strings.ToUpper(r.Operator.ID) }, 422, "two_operators_required"},
		"same, with whitespace": {func(r *admin.RecoveryRequest) { r.CoOperator.ID = " " + r.Operator.ID + " " }, 422, "two_operators_required"},
		"no co-operator":        {func(r *admin.RecoveryRequest) { r.CoOperator.ID = "" }, 422, "invalid_payload"},
		"no operator":           {func(r *admin.RecoveryRequest) { r.Operator.ID = "" }, 422, "invalid_payload"},
		"operator without phr":  {func(r *admin.RecoveryRequest) { r.Operator.PhishingResistant = false }, 422, "operator_phr_required"},
		"co-operator without":   {func(r *admin.RecoveryRequest) { r.CoOperator.PhishingResistant = false }, 422, "operator_phr_required"},
		"no ticket":             {func(r *admin.RecoveryRequest) { r.Ticket = " " }, 422, "invalid_payload"},
		"bad email":             {func(r *admin.RecoveryRequest) { r.Email = "nobody" }, 422, "invalid_payload"},
	} {
		t.Run(name, func(t *testing.T) {
			req := h.recoveryRequest(conn, "op-jane", "op-raj")
			tc.mutate(&req)
			_, err := h.svc.RequestRecovery(h.ctx, req)
			wantErr(t, err, tc.status, tc.code)
			if got := h.tenantStatus(); got != "active" {
				t.Errorf("tenant status = %s after a refused request, want active", got)
			}
			h.tx(func(tx *store.TenantTx) error {
				if rs, _ := tx.TenantRecoveries(); len(rs) != 0 {
					t.Errorf("%d recoveries recorded by a refused request", len(rs))
				}
				return nil
			})
		})
	}
	res, err := h.svc.RequestRecovery(h.ctx, h.recoveryRequest(conn, "op-jane", "op-raj"))
	if err != nil || res.Recovery.Operator != "op-jane" || res.Recovery.CoOperator != "op-raj" {
		t.Fatalf("two different operators: %v %v", res, err)
	}
	// a second recovery while one is pending is refused
	_, err = h.svc.RequestRecovery(h.ctx, h.recoveryRequest(conn, "op-a", "op-b"))
	wantErr(t, err, http.StatusConflict, "tenant_not_active")
}

// TestRecoveryNotBefore72Hours: the invitation works only 72 hours after the
// request; the tenant is in recovery meanwhile, and everyone is told at once
// (and the platform chain records it).
func TestRecoveryNotBefore72Hours(t *testing.T) {
	h := newHarness(t)
	h.admins("alice", "bob")
	h.contacts("jane@acme.example", "raj@acme.example")
	conn := h.oidcConnection("okta")
	start := h.clk.now()
	res, err := h.svc.RequestRecovery(h.ctx, h.recoveryRequest(conn, "op-jane", "op-raj"))
	if err != nil {
		t.Fatal(err)
	}
	rec := res.Recovery
	if want := start.Add(72 * time.Hour); !rec.NotBefore.Equal(want) {
		t.Fatalf("not_before = %v, want request + 72h = %v", rec.NotBefore, want)
	}
	if !strings.HasPrefix(res.Code, "tbi_") || len(res.Code) < 30 {
		t.Errorf("code %q is not a one-time invitation code", res.Code)
	}
	if got := h.tenantStatus(); got != "recovery" {
		t.Errorf("tenant status = %s, want recovery", got)
	}
	var inv *store.BootstrapInvitation
	h.tx(func(tx *store.TenantTx) error {
		var err error
		inv, err = tx.BootstrapInvitationByCodeHash(seal.SHA256Hex([]byte(res.Code)))
		return err
	})
	if inv.ID != rec.InvitationID || inv.Email != "new.admin@acme.example" || inv.Role != store.RoleTenantAdmin ||
		!inv.ExpiresAt.Equal(rec.NotBefore.Add(24*time.Hour)) || inv.ConsumedAt != nil {
		t.Errorf("invitation %+v does not match recovery %+v", inv, rec)
	}
	// only the hash of the code is stored
	if inv.CodeHash == res.Code || strings.Contains(inv.CodeHash, "tbi_") {
		t.Error("the invitation code is stored in the clear")
	}
	for _, d := range []time.Duration{0, time.Hour, 71 * time.Hour, 72*time.Hour - time.Second} {
		if err := admin.CheckWindow(rec, start.Add(d)); err == nil || err.Reason != admin.ReasonRecoveryNotYet {
			t.Errorf("redeeming %s into the delay: %v, want %s", d, err, admin.ReasonRecoveryNotYet)
		}
	}
	if err := admin.CheckWindow(rec, start.Add(72*time.Hour)); err != nil {
		t.Errorf("redeeming at not_before: %v", err)
	}
	// notifications went out immediately: both admins and both contacts
	var ns []*store.AdminNotification
	h.tx(func(tx *store.TenantTx) error {
		var err error
		ns, err = tx.AdminNotificationsForRecovery(rec.ID)
		return err
	})
	admins, contacts := 0, 0
	for _, n := range ns {
		if n.Kind != "recovery.requested" || !strings.Contains(n.Body, "cancel") {
			t.Errorf("notification %q %q lacks how to cancel", n.Kind, n.Body)
		}
		switch n.RecipientType {
		case store.NotifyAdmin:
			admins++
		case store.NotifyContact:
			contacts++
		}
	}
	if admins != 2 || contacts != 2 {
		t.Errorf("%d admin and %d contact notifications, want 2 and 2", admins, contacts)
	}
	// the tenant's chain and the platform chain both record it
	if !slices.Contains(h.audited(tenantID), "recovery.requested") {
		t.Error("no recovery.requested event in the tenant's chain")
	}
	if !slices.Contains(h.audited(tenancy.Platform), "recovery.requested") {
		t.Error("no recovery.requested event in the platform chain")
	}
}

// TestExistingAdminCanCancelRecovery: any existing admin cancels during the
// 72 hours; the invitation stops working, the tenant is active again and both
// operators are told. Others cannot cancel, and a cancelled recovery cannot
// be cancelled again.
func TestExistingAdminCanCancelRecovery(t *testing.T) {
	h := newHarness(t)
	a := h.admins("alice", "bob")
	viewer := h.user("carol", store.RoleViewer)
	h.contacts("jane@acme.example")
	conn := h.oidcConnection("okta")
	res, err := h.svc.RequestRecovery(h.ctx, h.recoveryRequest(conn, "op-jane", "op-raj"))
	if err != nil {
		t.Fatal(err)
	}
	h.advance(10 * time.Hour)
	_, err = h.svc.CancelRecovery(h.ctx, h.as(viewer), res.Recovery.ID)
	wantErr(t, err, http.StatusForbidden, "forbidden")
	got, err := h.svc.CancelRecovery(h.ctx, h.as(a[1]), res.Recovery.ID)
	if err != nil || got.Status != store.RecoveryCancelled || got.CancelledBy == nil || *got.CancelledBy != a[1].ID {
		t.Fatalf("cancel by an existing admin: %v %v", got, err)
	}
	if status := h.tenantStatus(); status != "active" {
		t.Errorf("tenant status = %s after the cancel, want active", status)
	}
	// the invitation no longer works, even after not_before
	if err := admin.CheckRedemption(got, true, got.NotBefore.Add(time.Hour)); err == nil || err.Reason != admin.ReasonRecoveryClosed {
		t.Errorf("redeeming a cancelled recovery: %v, want %s", err, admin.ReasonRecoveryClosed)
	}
	h.tx(func(tx *store.TenantTx) error {
		inv, err := tx.BootstrapInvitation(got.InvitationID)
		if err != nil || inv.ConsumedAt == nil {
			t.Errorf("the invitation after the cancel: %+v %v, want it spent", inv, err)
		}
		return nil
	})
	var ns []*store.AdminNotification
	h.tx(func(tx *store.TenantTx) error {
		var err error
		ns, err = tx.AdminNotificationsForRecovery(got.ID)
		return err
	})
	var operators []string
	for _, n := range ns {
		if n.Kind == "recovery.cancelled" && n.RecipientType == store.NotifyOperator {
			operators = append(operators, n.RecipientAddress)
		}
	}
	slices.Sort(operators)
	if !slices.Equal(operators, []string{"op-jane", "op-raj"}) {
		t.Errorf("cancellation told operators %v, want both", operators)
	}
	if !slices.Contains(h.audited(tenantID), "recovery.cancelled") {
		t.Error("no recovery.cancelled event")
	}
	_, err = h.svc.CancelRecovery(h.ctx, h.as(a[0]), res.Recovery.ID)
	wantErr(t, err, http.StatusConflict, "invalid_state")
	// a new recovery can then be requested
	if _, err := h.svc.RequestRecovery(h.ctx, h.recoveryRequest(conn, "op-jane", "op-raj")); err != nil {
		t.Errorf("a new recovery after the cancel: %v", err)
	}
}

// TestRecoveryInvitationNeedsPhr: redeeming the invitation needs a
// phishing-resistant step-up, inside the window; a sign-in that is not phr
// (or that only claims it without proof) never redeems it.
func TestRecoveryInvitationNeedsPhr(t *testing.T) {
	h := newHarness(t)
	conn := h.oidcConnection("okta")
	res, err := h.svc.RequestRecovery(h.ctx, h.recoveryRequest(conn, "op-jane", "op-raj"))
	if err != nil {
		t.Fatal(err)
	}
	rec := res.Recovery
	after := rec.NotBefore.Add(time.Minute)
	for _, tc := range []struct {
		name   string
		phr    bool
		at     time.Time
		reason string
	}{
		{"phr, in the window", true, after, ""},
		{"aal2 without phr", false, after, admin.ReasonRecoveryPhr},
		{"phr, too early", true, rec.NotBefore.Add(-time.Second), admin.ReasonRecoveryNotYet},
		{"no phr and too early", false, rec.NotBefore.Add(-time.Second), admin.ReasonRecoveryNotYet},
	} {
		err := admin.CheckRedemption(rec, tc.phr, tc.at)
		switch {
		case tc.reason == "" && err != nil:
			t.Errorf("%s: %v", tc.name, err)
		case tc.reason != "" && (err == nil || err.Reason != tc.reason):
			t.Errorf("%s: %v, want %s", tc.name, err, tc.reason)
		}
	}
	// completing the recovery returns the tenant to active and tells everyone
	newAdmin := h.user("dana", store.RoleViewer)
	h.advance(73 * time.Hour)
	h.tx(func(tx *store.TenantTx) error {
		if err := tx.ConsumeBootstrapInvitation(rec.InvitationID, newAdmin.ID, h.clk.now()); err != nil {
			return err
		}
		return h.svc.CompleteRecovery(tx, rec, newAdmin.ID, h.clk.now())
	})
	if status := h.tenantStatus(); status != "active" {
		t.Errorf("tenant status = %s after the recovery completed, want active", status)
	}
	var got *store.TenantRecovery
	h.tx(func(tx *store.TenantTx) error {
		var err error
		got, err = tx.TenantRecovery(rec.ID)
		return err
	})
	if got.Status != store.RecoveryCompleted || got.CompletedBy == nil || *got.CompletedBy != newAdmin.ID {
		t.Errorf("recovery after completion: %+v", got)
	}
	if err := admin.CheckRedemption(got, true, h.clk.now()); err == nil || err.Reason != admin.ReasonRecoveryClosed {
		t.Errorf("redeeming a completed recovery: %v", err)
	}
	if !slices.Contains(h.audited(tenantID), "recovery.completed") {
		t.Error("no recovery.completed event")
	}
}

// TestRecoveryRefusedForUnusableTenantOrConnection: only an active tenant
// recovers, through an active OIDC or SAML connection of its own.
func TestRecoveryRefusedForUnusableTenantOrConnection(t *testing.T) {
	h := newHarness(t)
	_, err := h.svc.RequestRecovery(h.ctx, h.recoveryRequest(&store.IdPConnection{ID: mustUUID(t, "00000000-0000-4000-8000-00000000dead")},
		"op-jane", "op-raj"))
	wantErr(t, err, http.StatusNotFound, "not_found")
	pending := h.oidcConnection("okta")
	h.tx(func(tx *store.TenantTx) error {
		return tx.SetIdPConnectionStatus(pending.ID, "active", "disabled", h.clk.now(), nil)
	})
	_, err = h.svc.RequestRecovery(h.ctx, h.recoveryRequest(pending, "op-jane", "op-raj"))
	wantErr(t, err, http.StatusConflict, "connection_unusable")
}
