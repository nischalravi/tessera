package oauth

import (
	"net/http"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/containment"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// linkedLogin creates an active identity and signs in a user linked to it (#345).
func (h *harness) linkedLogin(slug, email string) (authtest.Login, int64, *store.Identity) {
	h.tb.Helper()
	var id int64
	ident := &store.Identity{TenantID: h.tenantID(slug), ExternalID: "ext-" + email, Name: email, Type: "person",
		Status: "active", CreatedAt: h.clock.Now()}
	h.mutateTenant(slug, func(tx *store.TenantTx) error {
		var err error
		id, err = tx.InsertIdentity(ident)
		return err
	})
	l := authtest.LoginAs(h.tb, h.db, h.tenantID(slug), authtest.User{Email: email, Roles: viewer, IdentityID: &id},
		authtest.Phr, h.clock.Now())
	return l, id, ident
}

// TestIdentityEndedRevokesCLI: when the identity ends (terminated by a leaver
// or lifecycle end, terminated or disabled by a sync, disabled by containment)
// the CLI session and refresh tokens are revoked in the same transaction, so
// the access token, the refresh grant and the device code all stop working.
func TestIdentityEndedRevokesCLI(t *testing.T) {
	cases := []struct {
		name   string
		reason string
		end    func(h *harness, tx *store.TenantTx, id int64, ident *store.Identity) error
	}{
		{"terminate (leaver, lifecycle end)", store.RevokedIdentityTerminated, func(h *harness, tx *store.TenantTx, id int64, _ *store.Identity) error {
			return tx.TerminateIdentity(id, h.clock.Now())
		}},
		{"sync terminated", store.RevokedIdentityTerminated, func(h *harness, tx *store.TenantTx, _ int64, ident *store.Identity) error {
			i := *ident
			i.Status = "terminated"
			return tx.UpsertIdentity(&i)
		}},
		{"sync disabled", auth.RevokedIdentityDisabled, func(h *harness, tx *store.TenantTx, _ int64, ident *store.Identity) error {
			i := *ident
			i.Status = "disabled"
			return tx.UpsertIdentity(&i)
		}},
		{"containment disable", auth.RevokedIdentityDisabled, func(h *harness, tx *store.TenantTx, id int64, _ *store.Identity) error {
			_, err := containment.Disable(tx, id, "admin", "test", "none", h.clock.Now())
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			k := newKey(t)
			l, id, ident := h.linkedLogin(slugA, "alice@a.example")
			d := h.startDevice(slugA, nil)
			if r := h.approve(l, d.UserCode, "approve"); r.Status != http.StatusOK {
				t.Fatalf("approve: %d %s", r.Status, r.Raw)
			}
			tk := tokensOf(t, h.devicePoll(slugA, d, k))
			// a second device grant, approved but not yet collected
			l2 := authtest.LoginAs(t, h.db, tenantAID, authtest.User{Email: "alice@a.example", Roles: viewer, IdentityID: &id},
				authtest.Phr, h.clock.Now())
			d2 := h.startDevice(slugA, nil)
			if r := h.approve(l2, d2.UserCode, "approve"); r.Status != http.StatusOK {
				t.Fatalf("approve 2: %d %s", r.Status, r.Raw)
			}
			if w := h.whoamiReq(k, tk.Access); w.Status != 200 {
				t.Fatalf("whoami before: %d %s", w.Status, w.Raw)
			}
			h.mutateTenant(slugA, func(tx *store.TenantTx) error { return tc.end(h, tx, id, ident) })

			if w := h.whoamiReq(k, tk.Access); w.Status != 401 {
				t.Errorf("access token after: %d %s", w.Status, w.Raw)
			}
			if r := h.tokenReq(slugA, refreshForm(tk.Refresh), k); r.Status != 400 || r.str("error") != "invalid_grant" {
				t.Errorf("refresh after: %d %s", r.Status, r.Raw)
			}
			if r := h.devicePoll(slugA, d2, k); r.Status != 400 || r.str("error") != "invalid_grant" {
				t.Errorf("device code after: %d %s", r.Status, r.Raw)
			}
			row, err := h.refreshRow(slugA, hashHex(tk.Refresh))
			if err != nil || row.RevokedAt == nil || row.RevokedReason == nil || *row.RevokedReason != tc.reason {
				t.Errorf("refresh row %+v %v, want revoked with %q", row, err, tc.reason)
			}
			if s := sessionOf(t, h, slugA, sidOf(t, tk.Access)); s.Status != store.SessionRevoked {
				t.Errorf("CLI session status %s", s.Status)
			}
		})
	}
}

// TestIdentityNotActiveRefused: the checks hold on their own, without any
// revocation (an identity changed by a path that revokes nothing): every
// DPoP request, the refresh grant, the device-code grant and the approval
// refuse a user whose identity is not active.
func TestIdentityNotActiveRefused(t *testing.T) {
	for _, status := range []string{"terminated", "disabled", "merged"} {
		t.Run(status, func(t *testing.T) {
			h := newHarness(t)
			k := newKey(t)
			l, id, _ := h.linkedLogin(slugA, "alice@a.example")
			d := h.startDevice(slugA, nil)
			h.approve(l, d.UserCode, "approve")
			tk := tokensOf(t, h.devicePoll(slugA, d, k))
			d2 := h.startDevice(slugA, nil)
			if r := h.approve(l, d2.UserCode, "approve"); r.Status != 200 {
				t.Fatalf("approve: %d %s", r.Status, r.Raw)
			}
			d3 := h.startDevice(slugA, nil) // still pending at the change
			h.mutateTenant(slugA, func(tx *store.TenantTx) error { return tx.SetIdentityStatus(id, status) })

			if w := h.whoamiReq(k, tk.Access); w.Status != 401 {
				t.Errorf("access: %d %s", w.Status, w.Raw)
			}
			if r := h.tokenReq(slugA, refreshForm(tk.Refresh), k); r.Status != 400 || r.str("error") != "invalid_grant" {
				t.Errorf("refresh: %d %s", r.Status, r.Raw)
			}
			if r := h.devicePoll(slugA, d2, k); r.Status != 400 || r.str("error") != "invalid_grant" {
				t.Errorf("device token: %d %s", r.Status, r.Raw)
			}
			if r := h.approve(l, d3.UserCode, "approve"); r.Status != 401 {
				t.Errorf("approve: %d %s", r.Status, r.Raw)
			}
			if r := h.devicePoll(slugA, d3, k); r.str("error") == "" || r.Status == 200 {
				t.Errorf("a pending grant of the ended identity issued tokens: %d %s", r.Status, r.Raw)
			}
		})
	}
}

// TestDeviceApproveInactiveIdentity: a terminated user cannot approve a device.
func TestDeviceApproveInactiveIdentity(t *testing.T) {
	h := newHarness(t)
	l, id, _ := h.linkedLogin(slugA, "alice@a.example")
	d := h.startDevice(slugA, nil)
	h.mutateTenant(slugA, func(tx *store.TenantTx) error { return tx.TerminateIdentity(id, h.clock.Now()) })
	if r := h.approve(l, d.UserCode, "approve"); r.Status != 401 {
		t.Errorf("approve by a terminated user: %d %s", r.Status, r.Raw)
	}
}

// TestIntrospectInactiveIdentity (#359): a CLI token whose user's identity is
// not active introspects as inactive, even where nothing revoked the session.
func TestIntrospectInactiveIdentity(t *testing.T) {
	for _, status := range []string{"terminated", "disabled", "merged"} {
		t.Run(status, func(t *testing.T) {
			h := newHarness(t)
			k := newKey(t)
			gw := h.addMachine(machineOpts{scopes: []string{ScopeIntrospect}})
			l, id, _ := h.linkedLogin(slugA, "alice@a.example")
			d := h.startDevice(slugA, nil)
			h.approve(l, d.UserCode, "approve")
			tk := tokensOf(t, h.devicePoll(slugA, d, k))
			if r := h.introspect(gw, tk.Access); r.Status != 200 || r.Body["active"] != true {
				t.Fatalf("before: %d %s", r.Status, r.Raw)
			}
			h.mutateTenant(slugA, func(tx *store.TenantTx) error { return tx.SetIdentityStatus(id, status) })
			if r := h.introspect(gw, tk.Access); r.Status != 200 || r.Body["active"] != false || len(r.Body) != 1 {
				t.Errorf("after: %d %s", r.Status, r.Raw)
			}
		})
	}
}
