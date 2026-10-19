package admin_test

import (
	"bytes"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/admin"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Admin-change workflow (design §15.2, §19 PR12). Time is the harness's
// injected clock throughout.

// TestRequesterCannotApproveOwnRequest: the second person is a different
// admin; the requester is refused, the other admin is not.
func TestRequesterCannotApproveOwnRequest(t *testing.T) {
	h := newHarness(t)
	a := h.admins("alice", "bob")
	target := h.user("carol", store.RoleViewer)
	ch := mustSubmit(t, h, h.as(a[0]), admin.TypeRoleGrant, grant(target, store.RolePolicyAdmin))
	if ch.Status != store.ChangePendingApproval || !ch.TwoPerson {
		t.Fatalf("a policy_admin grant is %s two_person=%t, want pending_approval and two-person", ch.Status, ch.TwoPerson)
	}
	_, err := h.svc.Approve(h.ctx, h.as(a[0]), ch.ID, ch.PayloadHash)
	wantErr(t, err, http.StatusForbidden, "self_approval_refused")
	if got := h.change(ch.ID); got.Status != store.ChangePendingApproval || got.ApprovedBy != nil {
		t.Errorf("after the refused approval: %s approved_by=%v", got.Status, got.ApprovedBy)
	}
	ch, err = h.svc.Approve(h.ctx, h.as(a[1]), ch.ID, ch.PayloadHash)
	if err != nil || ch.Status != store.ChangeCoolingOff || ch.ApprovedBy == nil || *ch.ApprovedBy != a[1].ID {
		t.Fatalf("approval by the other admin: %v %v", ch, err)
	}
	// rejecting your own request is refused too: cancel it instead
	own := mustSubmit(t, h, h.as(a[0]), admin.TypeRoleGrant, grant(target, store.RoleTenantAdmin))
	_, err = h.svc.Reject(h.ctx, h.as(a[0]), own.ID)
	wantErr(t, err, http.StatusForbidden, "self_rejection_refused")
}

// TestApprovalNeedsFreshAdminStepUp: approval (and submission) needs the
// 5-minute STEP_UP_ADMIN, with the requirement in the denial.
func TestApprovalNeedsFreshAdminStepUp(t *testing.T) {
	for _, tc := range []struct {
		name  string
		age   time.Duration
		stale bool
	}{
		{"just signed in", 0, false},
		{"four minutes", 4 * time.Minute, false},
		{"exactly five minutes", 5 * time.Minute, false},
		{"five minutes and a second", 5*time.Minute + time.Second, true},
		{"an hour", time.Hour, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			a := h.admins("alice", "bob")
			target := h.user("carol", store.RoleViewer)
			ch := mustSubmit(t, h, h.as(a[0]), admin.TypeRoleGrant, grant(target, store.RoleTenantAdmin))
			_, err := h.svc.Approve(h.ctx, h.asAged(a[1], tc.age), ch.ID, ch.PayloadHash)
			if tc.stale {
				wantStepUp(t, err)
				if got := h.change(ch.ID); got.Status != store.ChangePendingApproval {
					t.Errorf("status after a refused approval: %s", got.Status)
				}
			} else if err != nil {
				t.Fatalf("approve: %v", err)
			}
			// submitting needs it too
			_, err = h.submit(h.asAged(a[0], tc.age), admin.TypeRoleGrant, grant(target, store.RoleOperator))
			if tc.stale {
				wantStepUp(t, err)
			} else if err != nil {
				t.Fatalf("submit: %v", err)
			}
		})
	}
}

// TestApprovalWithoutPhrIsNotAnAdmin: a context that is not phishing-resistant
// does not activate the admin role, so the permission is missing (not just
// the step-up).
func TestApprovalWithoutPhrIsNotAnAdmin(t *testing.T) {
	h := newHarness(t)
	a := h.admins("alice", "bob")
	target := h.user("carol", store.RoleViewer)
	ch := mustSubmit(t, h, h.as(a[0]), admin.TypeRoleGrant, grant(target, store.RoleTenantAdmin))
	p := h.as(a[1])
	p.ActiveRoles = auth.RoleSet{} // the role floor of §12.2 left the admin role inactive
	_, err := h.svc.Approve(h.ctx, p, ch.ID, ch.PayloadHash)
	wantErr(t, err, http.StatusForbidden, "role_inactive")
}

// TestPayloadHashMismatch: an approver must echo the hash of the payload they
// reviewed; anything else is 409 and approves nothing.
func TestPayloadHashMismatch(t *testing.T) {
	h := newHarness(t)
	a := h.admins("alice", "bob")
	target := h.user("carol", store.RoleViewer)
	ch := mustSubmit(t, h, h.as(a[0]), admin.TypeRoleGrant, grant(target, store.RoleTenantAdmin))
	for _, bad := range []string{"", strings.Repeat("0", 64), ch.PayloadHash[:63], ch.PayloadHash + "0"} {
		_, err := h.svc.Approve(h.ctx, h.as(a[1]), ch.ID, bad)
		wantErr(t, err, http.StatusConflict, "payload_hash_mismatch")
	}
	if got := h.change(ch.ID); got.Status != store.ChangePendingApproval {
		t.Errorf("status after mismatching approvals: %s", got.Status)
	}
	if want := admin.HashPayload(ch.Payload); ch.PayloadHash != want {
		t.Errorf("payload_hash %s is not the SHA-256 of the stored payload %s", ch.PayloadHash, want)
	}
	if _, err := h.svc.Approve(h.ctx, h.as(a[1]), ch.ID, ch.PayloadHash); err != nil {
		t.Fatalf("approve with the right hash: %v", err)
	}
}

// TestCoolingOffEnforced: applying before effective_at is 409; with the
// injected clock past it, the change applies, and the target's sessions are
// revoked so their roles re-evaluate.
func TestCoolingOffEnforced(t *testing.T) {
	h := newHarness(t)
	a := h.admins("alice", "bob")
	target := h.user("carol", store.RoleViewer)
	sid := h.signedInVia(target, nil)
	ch := mustSubmit(t, h, h.as(a[0]), admin.TypeRoleGrant, grant(target, store.RoleTenantAdmin))
	ch, err := h.svc.Approve(h.ctx, h.as(a[1]), ch.ID, ch.PayloadHash)
	if err != nil {
		t.Fatal(err)
	}
	if want := h.clk.now().Add(24 * time.Hour); ch.EffectiveAt == nil || !ch.EffectiveAt.Equal(want) {
		t.Fatalf("effective_at = %v, want approval + 24h = %v", ch.EffectiveAt, want)
	}
	for _, wait := range []time.Duration{0, 12 * time.Hour, 24*time.Hour - time.Second} {
		h.clk.t = ch.ApprovedAt.Add(wait)
		_, err := h.svc.Apply(h.ctx, h.as(a[0]), ch.ID)
		wantErr(t, err, http.StatusConflict, "cooling_off_active")
		if slices.Contains(h.roles(target), store.RoleTenantAdmin) {
			t.Fatalf("the role was granted %s into the cooling-off", wait)
		}
	}
	if r, err := h.svc.SweepTenant(h.ctx, tenantID); err != nil || r.Applied != 0 {
		t.Errorf("the sweeper applied a change still cooling off: %+v %v", r, err)
	}
	h.clk.t = ch.ApprovedAt.Add(24 * time.Hour)
	got, err := h.svc.Apply(h.ctx, h.as(a[0]), ch.ID)
	if err != nil || got.Status != store.ChangeApplied || got.AppliedAt == nil {
		t.Fatalf("apply after the cooling-off: %v %v", got, err)
	}
	if !slices.Contains(h.roles(target), store.RoleTenantAdmin) {
		t.Errorf("roles after apply = %v, want tenant_admin", h.roles(target))
	}
	h.tx(func(tx *store.TenantTx) error {
		as, _ := tx.RoleAssignments(target.ID)
		for _, x := range as {
			if x.Role == store.RoleTenantAdmin && (x.Source != store.RoleSourceManual || x.ChangeRequestID == nil ||
				*x.ChangeRequestID != ch.ID.String() || x.GrantedByUserID == nil || *x.GrantedByUserID != a[0].ID) {
				t.Errorf("role assignment %+v: want source manual, the change request and the requester", x)
			}
		}
		return nil
	})
	if s := h.session(sid); s.Status != store.SessionRevoked {
		t.Errorf("the target's session is %s, want revoked so roles re-evaluate", s.Status)
	}
	// applying twice is a conflict, not a second grant
	_, err = h.svc.Apply(h.ctx, h.as(a[0]), ch.ID)
	wantErr(t, err, http.StatusConflict, "invalid_state")
}

// TestSweeperAppliesDueChanges: ApplyDue, through Sweep, applies the changes
// whose cooling-off ended, in every active tenant.
func TestSweeperAppliesDueChanges(t *testing.T) {
	h := newHarness(t)
	a := h.admins("alice", "bob")
	target := h.user("carol", store.RoleViewer)
	ch := mustSubmit(t, h, h.as(a[0]), admin.TypeRoleGrant, grant(target, store.RolePolicyAdmin))
	if _, err := h.svc.Approve(h.ctx, h.as(a[1]), ch.ID, ch.PayloadHash); err != nil {
		t.Fatal(err)
	}
	h.advance(24*time.Hour - time.Minute)
	if r, err := h.svc.Sweep(h.ctx); err != nil || r != (admin.SweepResult{}) {
		t.Fatalf("early sweep: %+v %v", r, err)
	}
	h.advance(time.Minute)
	r, err := h.svc.Sweep(h.ctx)
	if err != nil || r.Applied != 1 || r.Failed != 0 {
		t.Fatalf("sweep: %+v %v", r, err)
	}
	if got := h.change(ch.ID); got.Status != store.ChangeApplied {
		t.Errorf("status = %s, want applied", got.Status)
	}
	if !slices.Contains(h.roles(target), store.RolePolicyAdmin) {
		t.Errorf("roles = %v, want policy_admin", h.roles(target))
	}
	if r, err := h.svc.Sweep(h.ctx); err != nil || r != (admin.SweepResult{}) {
		t.Errorf("a second sweep did something: %+v %v", r, err)
	}
}

// TestCancelDuringCoolingOff: any admin cancels a request that is pending or
// cooling off; after that it can never be applied.
func TestCancelDuringCoolingOff(t *testing.T) {
	h := newHarness(t)
	a := h.admins("alice", "bob", "dave")
	target := h.user("carol", store.RoleViewer)
	ch := mustSubmit(t, h, h.as(a[0]), admin.TypeRoleGrant, grant(target, store.RoleTenantAdmin))
	ch, err := h.svc.Approve(h.ctx, h.as(a[1]), ch.ID, ch.PayloadHash)
	if err != nil {
		t.Fatal(err)
	}
	h.advance(time.Hour)
	// a third admin, neither requester nor approver, cancels
	got, err := h.svc.Cancel(h.ctx, h.as(a[2]), ch.ID)
	if err != nil || got.Status != store.ChangeCancelled || got.DecidedBy == nil || *got.DecidedBy != a[2].ID {
		t.Fatalf("cancel: %v %v", got, err)
	}
	h.advance(48 * time.Hour)
	_, err = h.svc.Apply(h.ctx, h.as(a[0]), ch.ID)
	wantErr(t, err, http.StatusConflict, "invalid_state")
	if r, err := h.svc.Sweep(h.ctx); err != nil || r != (admin.SweepResult{}) {
		t.Errorf("the sweeper touched a cancelled request: %+v %v", r, err)
	}
	if slices.Contains(h.roles(target), store.RoleTenantAdmin) {
		t.Error("a cancelled change was applied")
	}
	// cancelling twice, or an applied change, is a conflict
	_, err = h.svc.Cancel(h.ctx, h.as(a[2]), ch.ID)
	wantErr(t, err, http.StatusConflict, "invalid_state")
	// the requester may cancel while it is pending
	pending := mustSubmit(t, h, h.as(a[0]), admin.TypeRoleGrant, grant(target, store.RolePolicyAdmin))
	if got, err := h.svc.Cancel(h.ctx, h.as(a[0]), pending.ID); err != nil || got.Status != store.ChangeCancelled {
		t.Fatalf("cancel by the requester: %v %v", got, err)
	}
	// a viewer cannot cancel
	_, err = h.svc.Cancel(h.ctx, h.as(target), mustSubmit(t, h, h.as(a[0]), admin.TypeRoleGrant, grant(target, store.RolePolicyAdmin)).ID)
	wantErr(t, err, http.StatusForbidden, "forbidden")
}

// TestRejectNeedsAnotherAdmin: any other admin rejects a pending request; a
// cooling-off one is cancelled, not rejected.
func TestRejectNeedsAnotherAdmin(t *testing.T) {
	h := newHarness(t)
	a := h.admins("alice", "bob")
	target := h.user("carol", store.RoleViewer)
	ch := mustSubmit(t, h, h.as(a[0]), admin.TypeRoleGrant, grant(target, store.RoleTenantAdmin))
	got, err := h.svc.Reject(h.ctx, h.as(a[1]), ch.ID)
	if err != nil || got.Status != store.ChangeRejected {
		t.Fatalf("reject: %v %v", got, err)
	}
	_, err = h.svc.Approve(h.ctx, h.as(a[1]), ch.ID, ch.PayloadHash)
	wantErr(t, err, http.StatusConflict, "invalid_state")
	ch2 := mustSubmit(t, h, h.as(a[0]), admin.TypeRoleGrant, grant(target, store.RoleTenantAdmin))
	if _, err := h.svc.Approve(h.ctx, h.as(a[1]), ch2.ID, ch2.PayloadHash); err != nil {
		t.Fatal(err)
	}
	_, err = h.svc.Reject(h.ctx, h.as(a[1]), ch2.ID)
	wantErr(t, err, http.StatusConflict, "invalid_state")
}

// TestExpiryAfter72Hours: a request nobody approves within 72 hours expires
// (by the sweeper, and approval after the deadline is refused even before the
// sweeper ran).
func TestExpiryAfter72Hours(t *testing.T) {
	h := newHarness(t)
	a := h.admins("alice", "bob")
	target := h.user("carol", store.RoleViewer)
	ch := mustSubmit(t, h, h.as(a[0]), admin.TypeRoleGrant, grant(target, store.RoleTenantAdmin))
	if want := h.clk.now().Add(72 * time.Hour); !ch.ExpiresAt.Equal(want) {
		t.Fatalf("expires_at = %v, want %v", ch.ExpiresAt, want)
	}
	start := h.clk.now()
	h.clk.t = start.Add(72*time.Hour - time.Second)
	if r, err := h.svc.Sweep(h.ctx); err != nil || r.Expired != 0 {
		t.Fatalf("sweep one second early: %+v %v", r, err)
	}
	h.clk.t = start.Add(72 * time.Hour)
	// approval at the deadline is refused even though no sweep ran yet
	_, err := h.svc.Approve(h.ctx, h.as(a[1]), ch.ID, ch.PayloadHash)
	wantErr(t, err, http.StatusConflict, "expired")
	r, err := h.svc.Sweep(h.ctx)
	if err != nil || r.Expired != 1 {
		t.Fatalf("sweep at 72h: %+v %v", r, err)
	}
	if got := h.change(ch.ID); got.Status != store.ChangeExpired {
		t.Errorf("status = %s, want expired", got.Status)
	}
	_, err = h.svc.Approve(h.ctx, h.as(a[1]), ch.ID, ch.PayloadHash)
	wantErr(t, err, http.StatusConflict, "invalid_state")
	// the request just before the deadline can still be approved
	h.clk.t = start.Add(73 * time.Hour)
	ok := mustSubmit(t, h, h.as(a[0]), admin.TypeRoleGrant, grant(target, store.RolePolicyAdmin))
	h.advance(72*time.Hour - time.Second)
	if _, err := h.svc.Approve(h.ctx, h.as(a[1]), ok.ID, ok.PayloadHash); err != nil {
		t.Errorf("approval one second before the deadline: %v", err)
	}
}

// TestMinAdminsFloor: revoking a tenant_admin is refused when fewer than
// min_admins active admins would remain, at request time and at apply time;
// so is disabling one.
func TestMinAdminsFloor(t *testing.T) {
	h := newHarness(t)
	a := h.admins("alice", "bob")
	revoke := func(u *store.PlatformUser) string {
		return `{"user_id":"` + u.ID.String() + `","role":"tenant_admin"}`
	}
	// two admins, min_admins 2: neither can lose the role
	_, err := h.submit(h.as(a[0]), admin.TypeRoleRevoke, revoke(a[1]))
	wantErr(t, err, http.StatusConflict, "min_admins")
	_, err = h.submit(h.as(a[0]), admin.TypeRoleRevoke, revoke(a[0])) // self-revoke too
	wantErr(t, err, http.StatusConflict, "min_admins")
	_, err = h.svc.DisableUser(h.ctx, h.as(a[0]), a[1].ID, "left the company")
	wantErr(t, err, http.StatusConflict, "min_admins")

	// three admins: a two-person revoke (no cooling-off) goes through
	c := h.user("carol", store.RoleTenantAdmin)
	ch := mustSubmit(t, h, h.as(a[0]), admin.TypeRoleRevoke, revoke(c))
	if !ch.TwoPerson || ch.CoolingOffSeconds != 0 || ch.Status != store.ChangePendingApproval {
		t.Fatalf("revoking another admin's role: %s two_person=%t cooling=%ds", ch.Status, ch.TwoPerson, ch.CoolingOffSeconds)
	}
	// ... but a second revoke requested meanwhile is refused when it is
	// approved, because the floor is checked again against the tenant as it is
	other := mustSubmit(t, h, h.as(a[0]), admin.TypeRoleRevoke, revoke(a[1]))
	if _, err := h.svc.Approve(h.ctx, h.as(a[1]), ch.ID, ch.PayloadHash); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if got := h.change(ch.ID); got.Status != store.ChangeApplied {
		t.Fatalf("a revoke with no cooling-off is %s after approval, want applied", got.Status)
	}
	if slices.Contains(h.roles(c), store.RoleTenantAdmin) {
		t.Error("carol still holds tenant_admin")
	}
	_, err = h.svc.Approve(h.ctx, h.as(a[1]), other.ID, other.PayloadHash)
	wantErr(t, err, http.StatusConflict, "min_admins")
	if !slices.Contains(h.roles(a[1]), store.RoleTenantAdmin) {
		t.Error("bob lost tenant_admin")
	}
	// a non-admin revoke and a self-revoke of a non-admin role need one person
	v := h.user("viewer", store.RoleViewer)
	imm := mustSubmit(t, h, h.as(a[0]), admin.TypeRoleRevoke, `{"user_id":"`+v.ID.String()+`","role":"viewer"}`)
	if imm.Status != store.ChangeApplied || imm.TwoPerson {
		t.Errorf("revoking a viewer role: %s two_person=%t, want applied with one person", imm.Status, imm.TwoPerson)
	}
}

// TestGroupMappingToAdminRoleRejected: an IdP group never confers an admin
// role, in a new connection or a trust change.
func TestGroupMappingToAdminRoleRejected(t *testing.T) {
	h := newHarness(t)
	a := h.admins("alice", "bob")
	conn := h.oidcConnection("okta")
	for _, role := range []string{"tenant_admin", "policy_admin", "break_glass", "root"} {
		_, err := h.submit(h.as(a[0]), admin.TypeIdPUpdateTrust,
			`{"connection_id":"`+conn.ID.String()+`","group_role_mapping":{"Tessera Admins":"`+role+`"}}`)
		wantErr(t, err, http.StatusUnprocessableEntity, "invalid_payload")
		_, err = h.submit(h.as(a[0]), admin.TypeIdPCreate, oidcCreate("okta2", `"group_role_mapping":{"g":"`+role+`"}`))
		wantErr(t, err, http.StatusUnprocessableEntity, "invalid_payload")
	}
	_, err := h.submit(h.as(a[0]), admin.TypeIdPCreate, oidcCreate("okta3", `"default_role":"tenant_admin"`))
	wantErr(t, err, http.StatusUnprocessableEntity, "invalid_payload")
	// non-admin roles are fine
	if _, err := h.submit(h.as(a[0]), admin.TypeIdPUpdateTrust,
		`{"connection_id":"`+conn.ID.String()+`","group_role_mapping":{"Tessera Viewers":"viewer","Ops":"operator"}}`); err != nil {
		t.Errorf("a mapping to non-admin roles: %v", err)
	}
}

func oidcCreate(name, extra string) string {
	s := `{"name":"` + name + `","protocol":"oidc","profile":"okta","issuer":"https://` + name + `.okta.example","client_id":"cid"`
	if extra != "" {
		s += "," + extra
	}
	return s + "}"
}

// TestTrustChangeRevokesConnectionSessions: a trust change, once applied,
// revokes every session that came through that connection and no other;
// disabling a connection does the same, at once.
func TestTrustChangeRevokesConnectionSessions(t *testing.T) {
	h := newHarness(t)
	a := h.admins("alice", "bob")
	okta, entra := h.oidcConnection("okta"), h.oidcConnection("entra")
	u := h.user("carol", store.RoleViewer)
	viaOkta1, viaOkta2 := h.signedInVia(u, okta), h.signedInVia(h.user("dan", store.RoleViewer), okta)
	viaEntra, noConn := h.signedInVia(u, entra), h.signedInVia(u, nil)

	ch := mustSubmit(t, h, h.as(a[0]), admin.TypeIdPUpdateTrust,
		`{"connection_id":"`+okta.ID.String()+`","issuer":"https://new.okta.example","assume_phishing_resistant":true}`)
	if !ch.TwoPerson || ch.CoolingOffSeconds != 24*3600 {
		t.Fatalf("a trust change is two_person=%t cooling=%ds, want two people and 24h", ch.TwoPerson, ch.CoolingOffSeconds)
	}
	if _, err := h.svc.Approve(h.ctx, h.as(a[1]), ch.ID, ch.PayloadHash); err != nil {
		t.Fatal(err)
	}
	h.advance(24*time.Hour - time.Second)
	if h.session(viaOkta1).Status != store.SessionActive {
		t.Fatal("a session was revoked before the change applied")
	}
	h.advance(time.Second)
	if r, err := h.svc.Sweep(h.ctx); err != nil || r.Applied != 1 {
		t.Fatalf("sweep: %+v %v", r, err)
	}
	for _, c := range []struct {
		name string
		id   uuid.UUID
		want string
	}{{"okta 1", viaOkta1, store.SessionRevoked}, {"okta 2", viaOkta2, store.SessionRevoked},
		{"entra", viaEntra, store.SessionActive}, {"no connection", noConn, store.SessionActive}} {
		if s := h.session(c.id); s.Status != c.want {
			t.Errorf("session %s is %s, want %s", c.name, s.Status, c.want)
		} else if c.want == store.SessionRevoked && (s.RevokedReason == nil || *s.RevokedReason != "idp_trust_changed") {
			t.Errorf("session %s revoked for %v, want idp_trust_changed", c.name, s.RevokedReason)
		}
	}
	h.tx(func(tx *store.TenantTx) error {
		got, err := tx.IdPConnection(okta.ID)
		if err != nil || got.Issuer == nil || *got.Issuer != "https://new.okta.example" || !got.AssumePhishingResistant ||
			got.LastChangeRequestID == nil || *got.LastChangeRequestID != ch.ID.String() {
			t.Errorf("connection after the trust change: %+v %v", got, err)
		}
		return nil
	})

	// disabling is immediate and revokes the connection's sessions too
	more := h.signedInVia(u, entra)
	d := mustSubmit(t, h, h.as(a[0]), admin.TypeIdPDisable, `{"connection_id":"`+entra.ID.String()+`"}`)
	if d.Status != store.ChangeApplied || d.TwoPerson {
		t.Fatalf("disable is %s two_person=%t, want applied with one person", d.Status, d.TwoPerson)
	}
	for _, sid := range []uuid.UUID{viaEntra, more} {
		if s := h.session(sid); s.Status != store.SessionRevoked || s.RevokedReason == nil || *s.RevokedReason != auth.RevokedIdPDisabled {
			t.Errorf("session via the disabled connection: %s %v", s.Status, s.RevokedReason)
		}
	}
	if s := h.session(noConn); s.Status != store.SessionActive {
		t.Errorf("an unrelated session is %s", s.Status)
	}
}

// TestDisableLastConnectionRefused: the last active connection is not
// disabled while no break-glass user exists to sign in without it.
func TestDisableLastConnectionRefused(t *testing.T) {
	h := newHarness(t)
	a := h.admins("alice")
	conn := h.oidcConnection("okta")
	_, err := h.submit(h.as(a[0]), admin.TypeIdPDisable, `{"connection_id":"`+conn.ID.String()+`"}`)
	wantErr(t, err, http.StatusConflict, "last_connection")
	h.oidcConnection("entra")
	if _, err := h.submit(h.as(a[0]), admin.TypeIdPDisable, `{"connection_id":"`+conn.ID.String()+`"}`); err != nil {
		t.Errorf("disabling one of two connections: %v", err)
	}
}

// TestNotificationQueuedForEachTransition: every transition writes an audit
// event and queues a notification to every admin and security contact, with
// what changed, who requested and approved, and how to cancel.
func TestNotificationQueuedForEachTransition(t *testing.T) {
	h := newHarness(t)
	a := h.admins("alice", "bob", "dave")
	h.contacts("jane@acme.example", "raj@acme.example")
	target := h.user("carol", store.RoleViewer)
	wantRecipients := 3 + 2 // three admins and two security contacts

	// submitted, approved, applied
	ch := mustSubmit(t, h, h.as(a[0]), admin.TypeRoleGrant, grant(target, store.RolePolicyAdmin))
	if _, err := h.svc.Approve(h.ctx, h.as(a[1]), ch.ID, ch.PayloadHash); err != nil {
		t.Fatal(err)
	}
	h.advance(24 * time.Hour)
	if _, err := h.svc.Apply(h.ctx, h.as(a[2]), ch.ID); err != nil {
		t.Fatal(err)
	}
	// rejected, cancelled, expired
	rej := mustSubmit(t, h, h.as(a[0]), admin.TypeRoleGrant, grant(target, store.RoleTenantAdmin))
	if _, err := h.svc.Reject(h.ctx, h.as(a[1]), rej.ID); err != nil {
		t.Fatal(err)
	}
	can := mustSubmit(t, h, h.as(a[0]), admin.TypeRoleGrant, grant(h.user("erin", store.RoleViewer), store.RoleTenantAdmin))
	if _, err := h.svc.Cancel(h.ctx, h.as(a[1]), can.ID); err != nil {
		t.Fatal(err)
	}
	exp := mustSubmit(t, h, h.as(a[0]), admin.TypeRoleGrant, grant(h.user("frank", store.RoleViewer), store.RoleTenantAdmin))
	h.advance(72 * time.Hour)
	if _, err := h.svc.ExpireDue(h.ctx, tenantID); err != nil {
		t.Fatal(err)
	}
	// failed: the user is disabled while the change waits
	fail := mustSubmit(t, h, h.as(a[0]), admin.TypeRoleGrant, grant(h.user("gail", store.RoleViewer), store.RolePolicyAdmin))
	failTarget := fail.TargetID
	if _, err := h.svc.Approve(h.ctx, h.as(a[1]), fail.ID, fail.PayloadHash); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.DisableUser(h.ctx, h.as(a[2]), mustUUID(t, failTarget), "left the company"); err != nil {
		t.Fatal(err)
	}
	h.advance(24 * time.Hour)
	_, err := h.svc.Apply(h.ctx, h.as(a[2]), fail.ID)
	wantErr(t, err, http.StatusConflict, "apply_failed")
	if got := h.change(fail.ID); got.Status != store.ChangeFailed || !strings.Contains(got.Failure, "disabled") {
		t.Fatalf("failed change: %s %q", got.Status, got.Failure)
	}

	for _, tc := range []struct {
		id    uuid.UUID
		trans []string
	}{{ch.ID, []string{"submitted", "approved", "applied"}}, {rej.ID, []string{"submitted", "rejected"}},
		{can.ID, []string{"submitted", "cancelled"}}, {exp.ID, []string{"submitted", "expired"}},
		{fail.ID, []string{"submitted", "approved", "failed"}}} {
		ns := h.notifications(tc.id)
		kinds := map[string][]*store.AdminNotification{}
		for _, n := range ns {
			kinds[n.Kind] = append(kinds[n.Kind], n)
		}
		if len(kinds) != len(tc.trans) {
			t.Errorf("request %s: notification kinds %v, want one per transition %v", tc.id, keysOf(kinds), tc.trans)
		}
		for _, tr := range tc.trans {
			got := kinds["admin.change."+tr]
			if len(got) != wantRecipients {
				t.Errorf("request %s %s: %d notifications, want %d (every admin and contact)", tc.id, tr, len(got), wantRecipients)
				continue
			}
			admins, contacts := 0, 0
			for _, n := range got {
				switch n.RecipientType {
				case store.NotifyAdmin:
					admins++
				case store.NotifyContact:
					contacts++
				}
				if !strings.Contains(n.Body, "Requested by: alice") {
					t.Errorf("notification %q does not say who requested it: %q", n.Kind, n.Body)
				}
			}
			if admins != 3 || contacts != 2 {
				t.Errorf("request %s %s: %d admin and %d contact notifications", tc.id, tr, admins, contacts)
			}
		}
	}
	// the approved notification names the approver and the effective time; a
	// pending or cooling-off one says how to cancel
	for _, n := range h.notifications(ch.ID) {
		switch n.Kind {
		case "admin.change.approved":
			if !strings.Contains(n.Body, "Approved by: bob") || !strings.Contains(n.Body, "Takes effect: ") ||
				!strings.Contains(n.Body, "Cancel") {
				t.Errorf("approved notification: %q", n.Body)
			}
		case "admin.change.submitted":
			if !strings.Contains(n.Body, "Awaiting a second admin") || !strings.Contains(n.Body, "Cancel") {
				t.Errorf("submitted notification: %q", n.Body)
			}
		}
	}
	// and one audit event per transition, in the same chain
	audited := h.audited(tenantID)
	for _, tr := range []string{"submitted", "approved", "rejected", "cancelled", "expired", "applied", "failed"} {
		if !slices.Contains(audited, "admin.change."+tr) {
			t.Errorf("no admin.change.%s audit event in %v", tr, audited)
		}
	}
}

func keysOf[V any](m map[string]V) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// TestNotificationsAreIdempotent: replaying a transition's notification does
// not queue it twice (the dedupe key), and a rolled-back transition leaves
// none behind.
func TestNotificationsAreIdempotent(t *testing.T) {
	h := newHarness(t)
	a := h.admins("alice", "bob")
	target := h.user("carol", store.RoleViewer)
	ch := mustSubmit(t, h, h.as(a[0]), admin.TypeRoleGrant, grant(target, store.RoleTenantAdmin))
	before := len(h.notifications(ch.ID))
	h.tx(func(tx *store.TenantTx) error {
		ns, err := tx.AdminNotificationsForChange(ch.ID)
		if err != nil {
			return err
		}
		for _, n := range ns {
			dup := *n
			dup.ID = uuid.Nil
			if inserted, err := tx.InsertAdminNotification(&dup); err != nil || inserted {
				t.Errorf("replayed notification: inserted=%v err=%v", inserted, err)
			}
		}
		return nil
	})
	if got := len(h.notifications(ch.ID)); got != before {
		t.Errorf("%d notifications after a replay, want %d", got, before)
	}
	// a failed submit (invalid payload) queues nothing and records no request
	if _, err := h.submit(h.as(a[0]), admin.TypeRoleGrant, `{"user_id":"x"}`); err == nil {
		t.Fatal("an invalid payload was accepted")
	}
	h.tx(func(tx *store.TenantTx) error {
		all, _ := tx.AdminChanges()
		ns, _ := tx.AdminNotifications()
		if len(all) != 1 || len(ns) != before {
			t.Errorf("after a refused submit: %d requests, %d notifications; want 1 and %d", len(all), len(ns), before)
		}
		return nil
	})
}

// TestIdPActivationRequiresTestLogin: an IdP connection created by a change
// request starts pending after its 24 h; it becomes active only after the
// requester's successful test login, and only the requester activates it.
func TestIdPActivationRequiresTestLogin(t *testing.T) {
	h := newHarness(t)
	a := h.admins("alice", "bob")
	const secret = "s3cr3t-client-secret"
	ch, err := h.svc.Submit(h.ctx, h.as(a[0]), admin.SubmitInput{Type: admin.TypeIdPCreate,
		Payload: []byte(oidcCreate("okta", "")), ClientSecret: secret})
	if err != nil {
		t.Fatal(err)
	}
	if !ch.TwoPerson || ch.CoolingOffSeconds != 24*3600 || len(ch.SecretEnc) == 0 || bytes.Contains(ch.SecretEnc, []byte(secret)) ||
		bytes.Contains(ch.Payload, []byte(secret)) {
		t.Fatalf("created request: two_person=%t cooling=%d sealed=%d (secret leaked? %t)", ch.TwoPerson, ch.CoolingOffSeconds,
			len(ch.SecretEnc), bytes.Contains(ch.Payload, []byte(secret)))
	}
	if _, err := h.svc.Approve(h.ctx, h.as(a[1]), ch.ID, ch.PayloadHash); err != nil {
		t.Fatal(err)
	}
	// no connection exists before the change applies
	h.tx(func(tx *store.TenantTx) error {
		if cs, _ := tx.IdPConnections(); len(cs) != 0 {
			t.Errorf("%d connections before the change was applied", len(cs))
		}
		return nil
	})
	_, err = h.svc.Apply(h.ctx, h.as(a[1]), ch.ID)
	wantErr(t, err, http.StatusConflict, "cooling_off_active")
	h.advance(24 * time.Hour)
	applied, err := h.svc.Apply(h.ctx, h.as(a[1]), ch.ID)
	if err != nil || applied.Status != store.ChangeApplied || len(applied.SecretEnc) != 0 {
		t.Fatalf("apply: %v %v", applied, err)
	}
	connID := mustUUID(t, applied.TargetID)
	var conn *store.IdPConnection
	h.tx(func(tx *store.TenantTx) error {
		var err error
		conn, err = tx.IdPConnection(connID)
		return err
	})
	if conn.Status != "pending" || len(conn.ClientSecretEnc) == 0 || bytes.Contains(conn.ClientSecretEnc, []byte(secret)) {
		t.Fatalf("created connection: status %s sealed secret %d bytes", conn.Status, len(conn.ClientSecretEnc))
	}
	opened, err := h.sealer.Open(conn.ClientSecretEnc, auth.ClientSecretAAD(tenantID, conn.ID))
	if err != nil || string(opened) != secret {
		t.Fatalf("the connection's client secret did not survive the change: %q %v", opened, err)
	}

	// no test login yet: not even the requester can activate it
	_, err = h.svc.ActivateConnection(h.ctx, h.as(a[0]), conn.ID)
	wantErr(t, err, http.StatusConflict, "test_login_required")
	// a test login by someone else does not count
	h.tx(func(tx *store.TenantTx) error {
		if err := admin.RecordTestLogin(tx, conn.ID, a[1].ID, h.clk.now()); err == nil {
			t.Error("a test login by an admin who did not request the connection was recorded")
		}
		return nil
	})
	_, err = h.svc.ActivateConnection(h.ctx, h.as(a[0]), conn.ID)
	wantErr(t, err, http.StatusConflict, "test_login_required")
	// the requester's test login
	h.tx(func(tx *store.TenantTx) error { return admin.RecordTestLogin(tx, conn.ID, a[0].ID, h.clk.now()) })
	// only the requester activates
	_, err = h.svc.ActivateConnection(h.ctx, h.as(a[1]), conn.ID)
	wantErr(t, err, http.StatusForbidden, "not_requester")
	// and with a fresh step-up
	_, err = h.svc.ActivateConnection(h.ctx, h.asAged(a[0], time.Hour), conn.ID)
	wantStepUp(t, err)
	got, err := h.svc.ActivateConnection(h.ctx, h.as(a[0]), conn.ID)
	if err != nil || got.Status != "active" {
		t.Fatalf("activate after the test login: %v %v", got, err)
	}
	_, err = h.svc.ActivateConnection(h.ctx, h.as(a[0]), conn.ID)
	wantErr(t, err, http.StatusConflict, "invalid_state")
	if audited := h.audited(tenantID); !slices.Contains(audited, "idp_connection.test_login") || !slices.Contains(audited, "idp_connection.activated") {
		t.Errorf("audit actions %v lack the test login or the activation", audited)
	}
}

// TestIdPCreateValidation: the connection a request would create is
// validated when it is submitted, with the same rules as the operator CLI.
func TestIdPCreateValidation(t *testing.T) {
	h := newHarness(t)
	a := h.admins("alice", "bob")
	h.oidcConnection("taken")
	for name, tc := range map[string]struct {
		payload, secret string
		status          int
		code            string
	}{
		"no secret":                    {oidcCreate("okta", ""), "", 422, "invalid_payload"},
		"issuer with a trailing slash": {strings.Replace(oidcCreate("okta", ""), "okta.example\"", "okta.example/\"", 1), "s", 422, "invalid_payload"},
		"unknown field":                {oidcCreate("okta", `"client_secret":"leak"`), "s", 422, "invalid_payload"},
		"name taken":                   {oidcCreate("taken", ""), "s", 409, "name_taken"},
		"bad protocol":                 {strings.Replace(oidcCreate("okta", ""), `"oidc"`, `"ldap"`, 1), "s", 422, "invalid_payload"},
		"saml with a bad certificate":  {`{"name":"s","protocol":"saml","profile":"generic_saml","idp_entity_id":"e","idp_sso_url":"https://s.example/sso","idp_signing_certs":["x"]}`, "", 422, "invalid_payload"},
		"oauth2 subject is mail":       {`{"name":"g","protocol":"oauth2","profile":"generic_oauth2","client_id":"c","authorization_endpoint":"https://a.example/a","token_endpoint":"https://a.example/t","userinfo_endpoint":"https://a.example/u","subject_field":"email"}`, "s", 422, "invalid_payload"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := h.svc.Submit(h.ctx, h.as(a[0]), admin.SubmitInput{Type: admin.TypeIdPCreate, Payload: []byte(tc.payload),
				ClientSecret: tc.secret})
			wantErr(t, err, tc.status, tc.code)
		})
	}
	// a secret that is not for this type is refused
	_, err := h.svc.Submit(h.ctx, h.as(a[0]), admin.SubmitInput{Type: admin.TypeRoleGrant,
		Payload: []byte(grant(a[1], store.RoleViewer)), ClientSecret: "x"})
	wantErr(t, err, http.StatusUnprocessableEntity, "invalid_payload")
}

// TestBootstrapTenantRules: a tenant with fewer than two admins can grant
// tenant_admin with one person and the 24 h; nothing else that needs two
// people can be requested.
func TestBootstrapTenantRules(t *testing.T) {
	h := newHarness(t)
	a := h.admins("alice")
	h.contacts("jane@acme.example")
	next := h.user("bob", store.RoleViewer)
	ch := mustSubmit(t, h, h.as(a[0]), admin.TypeRoleGrant, grant(next, store.RoleTenantAdmin))
	if ch.TwoPerson || ch.Status != store.ChangeCoolingOff || ch.EffectiveAt == nil ||
		!ch.EffectiveAt.Equal(h.clk.now().Add(24*time.Hour)) {
		t.Fatalf("bootstrap tenant_admin grant: two_person=%t status=%s effective_at=%v", ch.TwoPerson, ch.Status, ch.EffectiveAt)
	}
	if ns := h.notifications(ch.ID); len(ns) != 2 { // the one admin and the one contact
		t.Errorf("%d notifications, want 2 (the admin and the security contact)", len(ns))
	}
	for _, in := range []admin.SubmitInput{
		{Type: admin.TypeRoleGrant, Payload: []byte(grant(next, store.RolePolicyAdmin))},
		{Type: admin.TypeIdPCreate, Payload: []byte(oidcCreate("okta", "")), ClientSecret: "s"},
		{Type: admin.TypeSecurityContacts, Payload: []byte(`{"contacts":[{"name":"J","email":"j@acme.example"}]}`)},
		{Type: admin.TypeTenantSettings, Payload: []byte(`{"session_admin_idle_s":1800}`)}, // weakening needs two people
	} {
		_, err := h.svc.Submit(h.ctx, h.as(a[0]), in)
		wantErr(t, err, http.StatusConflict, "bootstrap_restricted")
	}
	// after the delay the sweeper applies it, and the tenant has two admins
	h.advance(24 * time.Hour)
	if r, err := h.svc.Sweep(h.ctx); err != nil || r.Applied != 1 {
		t.Fatalf("sweep: %+v %v", r, err)
	}
	if !slices.Contains(h.roles(next), store.RoleTenantAdmin) {
		t.Errorf("roles = %v, want tenant_admin", h.roles(next))
	}
	if _, err := h.submit(h.as(a[0]), admin.TypeRoleGrant, grant(h.user("carol", store.RoleViewer), store.RolePolicyAdmin)); err != nil {
		t.Errorf("with two admins a two-person change is allowed: %v", err)
	}
}

// TestSingleAdminChanges: changes that narrow, or only add a non-admin role,
// need one admin with a step-up and apply at once.
func TestSingleAdminChanges(t *testing.T) {
	h := newHarness(t)
	a := h.admins("alice", "bob")
	conn := h.oidcConnection("okta")
	h.oidcConnection("entra")
	target := h.user("carol", store.RoleViewer)
	viewer := h.user("v1")
	for _, tc := range []struct{ name, typ, payload string }{
		{"viewer grant", admin.TypeRoleGrant, grant(viewer, store.RoleViewer)},
		{"operator grant", admin.TypeRoleGrant, grant(target, store.RoleOperator)},
		{"auditor grant", admin.TypeRoleGrant, grant(target, store.RoleAuditor)},
		{"cosmetic", admin.TypeIdPUpdateCosmetic, `{"connection_id":"` + conn.ID.String() + `","name":"Okta (prod)","verified_domains":["Acme.Example"],"is_default":true}`},
		{"stronger setting", admin.TypeTenantSettings, `{"require_phr_for_all":true,"session_admin_idle_s":600}`},
		{"disable", admin.TypeIdPDisable, `{"connection_id":"` + conn.ID.String() + `"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := h.submit(h.asAged(a[0], 10*time.Minute), tc.typ, tc.payload)
			wantStepUp(t, err) // a stale sign-in changes nothing
			ch, err := h.submit(h.as(a[0]), tc.typ, tc.payload)
			if err != nil {
				t.Fatal(err)
			}
			if ch.Status != store.ChangeApplied || ch.TwoPerson || ch.ApprovedBy != nil {
				t.Errorf("status %s two_person=%t: want applied with no second person", ch.Status, ch.TwoPerson)
			}
		})
	}
	h.tx(func(tx *store.TenantTx) error {
		c, err := tx.IdPConnection(conn.ID)
		if err != nil || c.Name != "Okta (prod)" || string(c.VerifiedDomains) != `["acme.example"]` || c.Status != "disabled" {
			t.Errorf("connection after the cosmetic change and disable: %+v %v", c, err)
		}
		tn, err := tx.TenantRecord()
		if err != nil || !strings.Contains(tn.Settings, `"require_phr_for_all":true`) || !strings.Contains(tn.Settings, `"session_admin_idle_s":600`) {
			t.Errorf("tenant settings = %s %v", tn.Settings, err)
		}
		return nil
	})
}

// TestTenantSettingsPolicy: weakening a setting needs two people and 24 h;
// values outside the design's ranges are refused.
func TestTenantSettingsPolicy(t *testing.T) {
	for name, tc := range map[string]struct {
		payload   string
		weakens   bool
		errCode   string
		errStatus int
	}{
		"longer admin session":  {payload: `{"session_admin_idle_s":1800}`, weakens: true},
		"phr for all off":       {payload: `{"require_phr_for_all":false,"login_acr":"urn:tessera:acr:aal2"}`, weakens: true},
		"device grants":         {payload: `{"device_grant_enabled":true}`, errCode: "invalid_payload", errStatus: 422}, // already true: no change
		"min_admins unchanged":  {payload: `{"min_admins":2}`, errCode: "invalid_payload", errStatus: 422},
		"min_admins below two":  {payload: `{"min_admins":1}`, errCode: "invalid_payload", errStatus: 422},
		"out of range":          {payload: `{"step_up_admin_max_age_s":900}`, errCode: "invalid_payload", errStatus: 422},
		"idle equals absolute":  {payload: `{"session_admin_idle_s":3600,"session_admin_absolute_s":3600}`, weakens: true},
		"unknown key":           {payload: `{"cooling_off_s":3600}`, errCode: "invalid_payload", errStatus: 422},
		"bad acr":               {payload: `{"login_acr":"urn:tessera:acr:aal1"}`, errCode: "invalid_payload", errStatus: 422},
		"stronger min_admins":   {payload: `{"min_admins":3}`},
		"empty diff":            {payload: `{}`, errCode: "invalid_payload", errStatus: 422},
		"stronger acr":          {payload: `{"login_acr":"urn:tessera:acr:phrh"}`},
		"shorter step-up admin": {payload: `{"step_up_admin_max_age_s":120}`},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t) // a fresh tenant: each diff is judged against the defaults
			a := h.admins("alice", "bob")
			ch, err := h.submit(h.as(a[0]), admin.TypeTenantSettings, tc.payload)
			if tc.errCode != "" {
				wantErr(t, err, tc.errStatus, tc.errCode)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if ch.TwoPerson != tc.weakens || (tc.weakens && ch.CoolingOffSeconds != 24*3600) || (!tc.weakens && ch.Status != store.ChangeApplied) {
				t.Errorf("two_person=%t cooling=%d status=%s, want weakens=%t", ch.TwoPerson, ch.CoolingOffSeconds, ch.Status, tc.weakens)
			}
		})
	}
}

// TestSecurityContactsChange: always two people and 24 h; the addresses are
// validated and normalized.
func TestSecurityContactsChange(t *testing.T) {
	h := newHarness(t)
	a := h.admins("alice", "bob")
	for name, payload := range map[string]string{
		"no contacts":    `{"contacts":[]}`,
		"bad address":    `{"contacts":[{"name":"J","email":"not-an-address"}]}`,
		"no name":        `{"contacts":[{"name":"","email":"j@acme.example"}]}`,
		"duplicate":      `{"contacts":[{"name":"J","email":"j@acme.example"},{"name":"K","email":"J@ACME.example"}]}`,
		"extra property": `{"contacts":[{"name":"J","email":"j@acme.example","phone":"1"}]}`,
	} {
		if _, err := h.submit(h.as(a[0]), admin.TypeSecurityContacts, payload); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	ch := mustSubmit(t, h, h.as(a[0]), admin.TypeSecurityContacts,
		`{"contacts":[{"name":"Jane Doe","email":"Jane@Acme.example"},{"name":"Raj Patel","email":"raj@acme.example"}]}`)
	if !ch.TwoPerson || ch.CoolingOffSeconds != 24*3600 {
		t.Fatalf("contacts change: two_person=%t cooling=%d", ch.TwoPerson, ch.CoolingOffSeconds)
	}
	if _, err := h.svc.Approve(h.ctx, h.as(a[1]), ch.ID, ch.PayloadHash); err != nil {
		t.Fatal(err)
	}
	h.advance(24 * time.Hour)
	if _, err := h.svc.Apply(h.ctx, h.as(a[0]), ch.ID); err != nil {
		t.Fatal(err)
	}
	h.tx(func(tx *store.TenantTx) error {
		tn, err := tx.TenantRecord()
		cs := admin.ParseContacts(tn.SecurityContacts)
		if err != nil || len(cs) != 2 || cs[0].Email != "jane@acme.example" {
			t.Errorf("contacts = %s %v", tn.SecurityContacts, err)
		}
		return nil
	})
}

// TestPayloadDecoding: payloads are decoded into typed structs with unknown
// fields refused; types that do not exist (or whose tables have not landed)
// are refused.
func TestPayloadDecoding(t *testing.T) {
	h := newHarness(t)
	a := h.admins("alice", "bob")
	target := h.user("carol", store.RoleViewer)
	for name, tc := range map[string]struct{ typ, payload string }{
		"unknown field":     {admin.TypeRoleGrant, `{"user_id":"` + target.ID.String() + `","role":"viewer","note":"x"}`},
		"trailing data":     {admin.TypeRoleGrant, grant(target, "viewer") + `{}`},
		"not an object":     {admin.TypeRoleGrant, `[]`},
		"bad uuid":          {admin.TypeRoleGrant, `{"user_id":"1","role":"viewer"}`},
		"unknown role":      {admin.TypeRoleGrant, grant(target, "root")},
		"break_glass grant": {admin.TypeRoleGrant, grant(target, "break_glass")},
		"unknown type":      {"role.promote", `{}`},
		"api client":        {"api_client.create", `{}`},
		"break-glass":       {"breakglass.register", `{}`},
		"unknown user":      {admin.TypeRoleGrant, `{"user_id":"00000000-0000-4000-8000-00000000dead","role":"viewer"}`},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := h.submit(h.as(a[0]), tc.typ, tc.payload)
			if name == "unknown user" {
				wantErr(t, err, http.StatusNotFound, "not_found")
				return
			}
			wantErr(t, err, http.StatusUnprocessableEntity, "invalid_payload")
		})
	}
	// the canonical payload is stable: field order and spacing do not change the hash
	one := mustSubmit(t, h, h.as(a[0]), admin.TypeRoleGrant, `{ "role" : "auditor", "user_id":"`+target.ID.String()+`" }`)
	if want := admin.HashPayload([]byte(`{"user_id":"` + target.ID.String() + `","role":"auditor"}`)); one.PayloadHash != want {
		t.Errorf("payload hash %s, want the hash of the canonical form %s", one.PayloadHash, want)
	}
}

// TestUserDisable: disabling a user is immediate, revokes their sessions and
// is audited and notified; you cannot disable yourself.
func TestUserDisable(t *testing.T) {
	h := newHarness(t)
	a := h.admins("alice", "bob")
	u := h.user("carol", store.RoleViewer)
	sid := h.signedInVia(u, nil)
	_, err := h.svc.DisableUser(h.ctx, h.asAged(a[0], time.Hour), u.ID, "left the company")
	wantStepUp(t, err)
	_, err = h.svc.DisableUser(h.ctx, h.as(a[0]), a[0].ID, "oops")
	wantErr(t, err, http.StatusConflict, "self_disable")
	_, err = h.svc.DisableUser(h.ctx, h.as(a[0]), u.ID, "")
	wantErr(t, err, http.StatusUnprocessableEntity, "invalid_payload")
	got, err := h.svc.DisableUser(h.ctx, h.as(a[0]), u.ID, "left the company")
	if err != nil || got.Status != "disabled" {
		t.Fatalf("disable: %v %v", got, err)
	}
	if s := h.session(sid); s.Status != store.SessionRevoked {
		t.Errorf("session is %s", s.Status)
	}
	_, err = h.svc.DisableUser(h.ctx, h.as(a[0]), u.ID, "again")
	wantErr(t, err, http.StatusConflict, "already_disabled")
	if !slices.Contains(h.audited(tenantID), "admin.user.disabled") {
		t.Error("no admin.user.disabled audit event")
	}
}
