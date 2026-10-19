package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Admin changes, admin notifications and operator recoveries (design §15,
// schema/0008_admin_changes.sql): a tenant sees and changes only its own
// requests, notifications and recoveries; another tenant's ids look
// nonexistent, and rows that name another tenant's rows are refused by the
// guard triggers.

// adminRows are one tenant's admin-workflow rows.
type adminRows struct {
	authRows
	pending *store.AdminChange // two-person, awaiting approval
	cooling *store.AdminChange // single-person, cooling off (effective now)
	created *store.AdminChange // applied idp_connection.create of conn
	notif   *store.AdminNotification
	rec     *store.TenantRecovery
}

func seedAdminRows(t *testing.T, f *storetest.Fixture) (a, b adminRows) {
	t.Helper()
	now := storetest.Now
	seed := func(tid storetest.Tenant, tag byte) adminRows {
		r := adminRows{authRows: seedAuthRows(t, f.DB, tid.ID, tag)}
		err := f.DB.InTenant(context.Background(), tid.ID, func(c *store.TenantTx) error {
			mk := func(typ, payload string, status string, two bool) *store.AdminChange {
				ch := &store.AdminChange{Type: typ, Payload: json.RawMessage(payload), PayloadHash: hexHash(tag + 5),
					Status: status, TwoPerson: two, CoolingOffSeconds: 86400, RequestedBy: r.user.ID, RequestedAt: now,
					ExpiresAt: now.Add(72 * time.Hour)}
				if status == store.ChangeCoolingOff {
					ch.EffectiveAt = &now
				}
				return ch
			}
			r.pending = mk("tenant.security_contacts.update", `{"contacts":[]}`, store.ChangePendingApproval, true)
			r.cooling = mk("idp_connection.update_cosmetic", `{"connection_id":"x"}`, store.ChangeCoolingOff, false)
			r.created = mk("idp_connection.create", `{"connection_id":"`+r.conn.ID.String()+`"}`, store.ChangeCoolingOff, false)
			r.created.TargetID = r.conn.ID.String()
			for _, ch := range []*store.AdminChange{r.pending, r.cooling, r.created} {
				if err := c.InsertAdminChange(ch); err != nil {
					return err
				}
			}
			if err := c.MarkAdminChangeApplied(r.created.ID, now); err != nil {
				return err
			}
			r.notif = &store.AdminNotification{ChangeRequestID: &r.pending.ID, Kind: "admin_change.submitted",
				RecipientType: store.NotifyAdmin, RecipientUserID: &r.user.ID, Subject: "s", Body: "b",
				DedupeKey: "k-" + string(tag), CreatedAt: now}
			if _, err := c.InsertAdminNotification(r.notif); err != nil {
				return err
			}
			r.rec = &store.TenantRecovery{InvitationID: r.inv.ID, Operator: "op-1", CoOperator: "op-2", Ticket: "T-1",
				NotBefore: now.Add(72 * time.Hour), CreatedAt: now}
			return c.InsertTenantRecovery(r.rec)
		})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	return seed(f.A, 'a'), seed(f.B, 'b')
}

func TestIsolation_AdminRowsReads(t *testing.T) {
	f := storetest.TwoTenants(t)
	a, b := seedAdminRows(t, f)
	now := storetest.Now
	inB(t, f, func(c *store.TenantTx) error {
		all, err := c.AdminChanges()
		if err != nil || len(all) != 3 {
			t.Errorf("AdminChanges in B = %d %v, want 3", len(all), err)
		}
		for _, ch := range all {
			if ch.ID == a.pending.ID || ch.ID == a.cooling.ID || ch.TenantID != f.B.ID {
				t.Errorf("AdminChanges in B returned %v", ch.ID)
			}
		}
		if open, err := c.OpenAdminChanges(); err != nil || len(open) != 2 {
			t.Errorf("OpenAdminChanges in B = %d %v, want 2 (pending, cooling)", len(open), err)
		}
		if due, err := c.DueAdminChanges(now); err != nil || len(due) != 1 || due[0].ID != b.cooling.ID {
			t.Errorf("DueAdminChanges in B = %v %v", due, err)
		}
		if exp, err := c.ExpirableAdminChanges(now.Add(73 * time.Hour)); err != nil || len(exp) != 1 || exp[0].ID != b.pending.ID {
			t.Errorf("ExpirableAdminChanges in B = %v %v", exp, err)
		}
		if _, err := c.AdminChange(a.pending.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("AdminChange(A's) = %v, want ErrNotFound", err)
		}
		if _, err := c.AppliedConnectionCreate(a.conn.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("AppliedConnectionCreate(A's connection) = %v, want ErrNotFound", err)
		}
		if got, err := c.AppliedConnectionCreate(b.conn.ID); err != nil || got.ID != b.created.ID {
			t.Errorf("AppliedConnectionCreate(B's connection) = %v %v", got, err)
		}
		if ns, err := c.AdminNotifications(); err != nil || len(ns) != 1 || ns[0].ID != b.notif.ID {
			t.Errorf("AdminNotifications in B = %v %v", ns, err)
		}
		if ns, err := c.AdminNotificationsForChange(a.pending.ID); err != nil || len(ns) != 0 {
			t.Errorf("AdminNotificationsForChange(A's) = %v %v", ns, err)
		}
		if ns, err := c.AdminNotificationsForRecovery(a.rec.ID); err != nil || len(ns) != 0 {
			t.Errorf("AdminNotificationsForRecovery(A's) = %v %v", ns, err)
		}
		if _, err := c.TenantRecovery(a.rec.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("TenantRecovery(A's) = %v, want ErrNotFound", err)
		}
		if _, err := c.TenantRecoveryByInvitation(a.inv.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("TenantRecoveryByInvitation(A's) = %v, want ErrNotFound", err)
		}
		if r, err := c.PendingTenantRecovery(); err != nil || r.ID != b.rec.ID {
			t.Errorf("PendingTenantRecovery in B = %v %v", r, err)
		}
		if rs, err := c.TenantRecoveries(); err != nil || len(rs) != 1 || rs[0].ID != b.rec.ID {
			t.Errorf("TenantRecoveries in B = %v %v", rs, err)
		}
		if us, err := c.ActiveAdminUsers(now); err != nil || len(us) != 1 || us[0].ID != b.user.ID {
			t.Errorf("ActiveAdminUsers in B = %v %v", us, err)
		}
		if rs, err := c.AllRoleAssignments(); err != nil || len(rs) != 1 || rs[0].ID != b.role.ID {
			t.Errorf("AllRoleAssignments in B = %v %v", rs, err)
		}
		return nil
	})
}

func TestIsolation_AdminRowsWritesScoped(t *testing.T) {
	f := storetest.TwoTenants(t)
	a, _ := seedAdminRows(t, f)
	now := storetest.Now
	inB(t, f, func(c *store.TenantTx) error {
		state := map[string]error{
			"ApproveAdminChange":     c.ApproveAdminChange(a.pending.ID, uuid.New(), now, now.Add(time.Hour)),
			"RejectAdminChange":      c.RejectAdminChange(a.pending.ID, uuid.New(), now),
			"CancelAdminChange":      c.CancelAdminChange(a.pending.ID, uuid.New(), now),
			"ExpireAdminChange":      c.ExpireAdminChange(a.pending.ID, now.Add(100*time.Hour)),
			"MarkAdminChangeApplied": c.MarkAdminChangeApplied(a.cooling.ID, now),
			"MarkAdminChangeFailed":  c.MarkAdminChangeFailed(a.cooling.ID, "x"),
			"CancelTenantRecovery":   c.CancelTenantRecovery(a.rec.ID, uuid.New(), now),
			"CompleteTenantRecovery": c.CompleteTenantRecovery(a.rec.ID, uuid.New(), now),
		}
		for name, err := range state {
			if !errors.Is(err, store.ErrAdminChangeState) {
				t.Errorf("%s on A's row in B = %v, want ErrAdminChangeState", name, err)
			}
		}
		notFound := map[string]error{
			"RecordConnectionTestLogin": c.RecordConnectionTestLogin(a.conn.ID, a.user.ID, now),
			"SetIdPConnectionStatus":    c.SetIdPConnectionStatus(a.conn.ID, "active", "disabled", now, nil),
			"UpdateIdPConnectionTrust":  c.UpdateIdPConnectionTrust(&store.IdPConnection{ID: a.conn.ID, SubjectSource: "x"}, now, nil),
			"UpdateIdPConnectionCosmetic": c.UpdateIdPConnectionCosmetic(&store.IdPConnection{ID: a.conn.ID, Name: "hijack"},
				now, nil),
		}
		for name, err := range notFound {
			if !errors.Is(err, store.ErrNotFound) {
				t.Errorf("%s on A's connection in B = %v, want ErrNotFound", name, err)
			}
		}
		if n, err := c.RevokeConnectionSessions(a.conn.ID, "x", now); err != nil || n != 0 {
			t.Errorf("RevokeConnectionSessions(A's connection) in B = %d %v, want 0", n, err)
		}
		return nil
	})
	inA(t, f, func(c *store.TenantTx) error {
		if ch, err := c.AdminChange(a.pending.ID); err != nil || ch.Status != store.ChangePendingApproval {
			t.Errorf("A's pending change after B's attempts: %v %v", ch, err)
		}
		if ch, err := c.AdminChange(a.cooling.ID); err != nil || ch.Status != store.ChangeCoolingOff {
			t.Errorf("A's cooling change after B's attempts: %v %v", ch, err)
		}
		if r, err := c.TenantRecovery(a.rec.ID); err != nil || r.Status != store.RecoveryPending {
			t.Errorf("A's recovery after B's attempts: %v %v", r, err)
		}
		if conn, err := c.IdPConnection(a.conn.ID); err != nil || conn.Status != "active" || conn.Name == "hijack" {
			t.Errorf("A's connection after B's attempts: %v %v", conn, err)
		}
		if s, err := c.Session(a.session.ID); err != nil || s.Status != store.SessionActive {
			t.Errorf("A's session after B's attempts: %v %v", s, err)
		}
		return nil
	})
}

func TestIsolation_AdminInsertsRefused(t *testing.T) {
	f := storetest.TwoTenants(t)
	a, b := seedAdminRows(t, f)
	now := storetest.Now
	err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		ch := &store.AdminChange{Type: "tenant.security_contacts.update", Payload: json.RawMessage(`{}`), PayloadHash: hexHash('x'),
			Status: store.ChangePendingApproval, TwoPerson: true, RequestedBy: a.user.ID, RequestedAt: now,
			ExpiresAt: now.Add(72 * time.Hour)}
		if err := c.InsertAdminChange(ch); !errors.Is(err, store.ErrCrossTenant) {
			t.Errorf("a change requested by A's user, inserted in B = %v, want ErrCrossTenant", err)
		}
		ch.TenantID, ch.RequestedBy = f.A.ID, b.user.ID
		if err := c.InsertAdminChange(ch); !errors.Is(err, store.ErrCrossTenant) {
			t.Errorf("a change stamped with A's tenant, inserted in B = %v, want ErrCrossTenant", err)
		}
		n := &store.AdminNotification{ChangeRequestID: &a.pending.ID, Kind: "k", RecipientType: store.NotifyContact,
			RecipientAddress: "x@example.com", Subject: "s", Body: "b", DedupeKey: "cross", CreatedAt: now}
		if _, err := c.InsertAdminNotification(n); !errors.Is(err, store.ErrCrossTenant) {
			t.Errorf("a notification naming A's change = %v, want ErrCrossTenant", err)
		}
		n = &store.AdminNotification{RecipientUserID: &a.user.ID, Kind: "k", RecipientType: store.NotifyAdmin,
			Subject: "s", Body: "b", DedupeKey: "cross2", CreatedAt: now}
		if _, err := c.InsertAdminNotification(n); !errors.Is(err, store.ErrCrossTenant) {
			t.Errorf("a notification to A's user = %v, want ErrCrossTenant", err)
		}
		r := &store.TenantRecovery{InvitationID: a.inv.ID, Operator: "o1", CoOperator: "o2", Ticket: "t",
			NotBefore: now.Add(72 * time.Hour), CreatedAt: now}
		if err := c.InsertTenantRecovery(r); !errors.Is(err, store.ErrCrossTenant) {
			t.Errorf("a recovery naming A's invitation = %v, want ErrCrossTenant", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestAdminRows_Constraints: the schema itself enforces the two-person rule,
// two different operators, one pending recovery per tenant, and notification
// idempotence.
func TestAdminRows_Constraints(t *testing.T) {
	f := storetest.TwoTenants(t)
	_, b := seedAdminRows(t, f)
	now := storetest.Now
	inB(t, f, func(c *store.TenantTx) error {
		// the requester cannot approve (statement guard) ...
		if err := c.ApproveAdminChange(b.pending.ID, b.user.ID, now, now.Add(24*time.Hour)); !errors.Is(err, store.ErrAdminChangeState) {
			t.Errorf("approval by the requester = %v, want ErrAdminChangeState", err)
		}
		// ... and not after the 72 h expiry
		if err := c.ApproveAdminChange(b.pending.ID, uuid.New(), now.Add(73*time.Hour), now.Add(97*time.Hour)); !errors.Is(err, store.ErrAdminChangeState) {
			t.Errorf("approval after expiry = %v, want ErrAdminChangeState", err)
		}
		// two operators must differ
		inv := &store.BootstrapInvitation{CodeHash: hexHash('q'), IdPConnectionID: b.conn.ID, Email: "x@example.com",
			CreatedBy: "op", CreatedAt: now, ExpiresAt: now.Add(100 * time.Hour)}
		if err := c.InsertBootstrapInvitation(inv); err != nil {
			t.Fatal(err)
		}
		if err := c.CancelTenantRecovery(b.rec.ID, b.user.ID, now); err != nil {
			t.Fatal(err)
		}
		same := &store.TenantRecovery{InvitationID: inv.ID, Operator: "op-1", CoOperator: "op-1", Ticket: "t",
			NotBefore: now.Add(72 * time.Hour), CreatedAt: now}
		if err := c.InsertTenantRecovery(same); err == nil {
			t.Error("a recovery with one operator twice was accepted")
		}
		ok := &store.TenantRecovery{InvitationID: inv.ID, Operator: "op-1", CoOperator: "op-2", Ticket: "t",
			NotBefore: now.Add(72 * time.Hour), CreatedAt: now}
		if err := c.InsertTenantRecovery(ok); err != nil {
			t.Fatal(err)
		}
		// a second pending recovery in the tenant is refused
		inv2 := &store.BootstrapInvitation{CodeHash: hexHash('r'), IdPConnectionID: b.conn.ID, Email: "y@example.com",
			CreatedBy: "op", CreatedAt: now, ExpiresAt: now.Add(100 * time.Hour)}
		if err := c.InsertBootstrapInvitation(inv2); err != nil {
			t.Fatal(err)
		}
		if err := c.InsertTenantRecovery(&store.TenantRecovery{InvitationID: inv2.ID, Operator: "op-1", CoOperator: "op-2",
			Ticket: "t", NotBefore: now.Add(72 * time.Hour), CreatedAt: now}); !errors.Is(err, store.ErrDuplicate) {
			t.Errorf("a second pending recovery = %v, want ErrDuplicate", err)
		}
		// a retried notification is ignored
		dup := *b.notif
		dup.ID = uuid.Nil
		if inserted, err := c.InsertAdminNotification(&dup); err != nil || inserted {
			t.Errorf("a duplicate notification: inserted=%v err=%v", inserted, err)
		}
		// terminal states clear the sealed secret
		sealed := &store.AdminChange{Type: "idp_connection.create", Payload: json.RawMessage(`{}`), PayloadHash: hexHash('s'),
			SecretEnc: []byte("sealed"), Status: store.ChangePendingApproval, TwoPerson: true, RequestedBy: b.user.ID,
			RequestedAt: now, ExpiresAt: now.Add(72 * time.Hour)}
		if err := c.InsertAdminChange(sealed); err != nil {
			t.Fatal(err)
		}
		if err := c.CancelAdminChange(sealed.ID, b.user.ID, now); err != nil {
			t.Fatal(err)
		}
		if got, err := c.AdminChange(sealed.ID); err != nil || len(got.SecretEnc) != 0 || got.Status != store.ChangeCancelled {
			t.Errorf("cancelled change: %v %v", got, err)
		}
		return nil
	})
}

// TestIsolation_OwnTenantRow: the own-tenant updates of the global tenants
// row touch only the transaction's tenant, refuse out-of-range values and
// are refused in a read-only transaction.
func TestIsolation_OwnTenantRow(t *testing.T) {
	f := storetest.TwoTenants(t)
	inB(t, f, func(c *store.TenantTx) error {
		if err := c.UpdateTenantMinAdmins(3); err != nil {
			t.Error(err)
		}
		if err := c.UpdateTenantMinAdmins(1); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("min_admins 1 = %v, want refused", err)
		}
		if err := c.UpdateTenantSecurityContacts(`[{"name":"J","email":"j@b.example"}]`); err != nil {
			t.Error(err)
		}
		if err := c.UpdateTenantSecurityContacts(`{"not":"an array"}`); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("object as contacts = %v, want refused", err)
		}
		if err := c.UpdateTenantSettings(`{"device_grant_enabled":true}`); err != nil {
			t.Error(err)
		}
		if err := c.UpdateTenantStatus("suspended"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("status suspended = %v, want refused", err)
		}
		if err := c.UpdateTenantStatus("recovery"); err != nil {
			t.Error(err)
		}
		got, err := c.TenantRecord()
		if err != nil || got.ID != f.B.ID || got.MinAdmins != 3 || got.Status != "recovery" ||
			got.SecurityContacts != `[{"name":"J","email":"j@b.example"}]` || got.Settings != `{"device_grant_enabled":true}` {
			t.Errorf("TenantRecord in B = %+v %v", got, err)
		}
		return nil
	})
	err := f.DB.ReadSystem(context.Background(), "test", func(s *store.SystemTx) error {
		a, err := s.TenantByID(f.A.ID)
		if err != nil || a.MinAdmins != 2 || a.Status != "active" || a.SecurityContacts != "[]" || a.Settings != "{}" {
			t.Errorf("tenant A after B's updates = %+v %v", a, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.DB.ReadTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		if err := c.UpdateTenantMinAdmins(5); !errors.Is(err, store.ErrReadOnly) {
			t.Errorf("update in a read-only transaction = %v, want ErrReadOnly", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestIsolation_ConnectionSessionsRevoked: revoking a connection's sessions
// revokes the sessions that signed in through it and leaves the tenant's
// other sessions alone.
func TestIsolation_ConnectionSessionsRevoked(t *testing.T) {
	f := storetest.TwoTenants(t)
	_, b := seedAdminRows(t, f)
	now := storetest.Now
	inB(t, f, func(c *store.TenantTx) error {
		n, err := c.RevokeConnectionSessions(b.conn.ID, "idp_disabled", now)
		if err != nil || n != 1 {
			t.Fatalf("RevokeConnectionSessions = %d %v, want 1", n, err)
		}
		if s, err := c.Session(b.session.ID); err != nil || s.Status != store.SessionRevoked || s.RevokedReason == nil ||
			*s.RevokedReason != "idp_disabled" {
			t.Errorf("session after revoke: %+v %v", s, err)
		}
		if n, err := c.RevokeConnectionSessions(b.conn.ID, "idp_disabled", now); err != nil || n != 0 {
			t.Errorf("second revoke = %d %v, want 0", n, err)
		}
		return nil
	})
}

func adminCovered() map[string]bool {
	out := map[string]bool{}
	for _, k := range []string{"AdminChange", "AdminChanges", "OpenAdminChanges", "DueAdminChanges", "ExpirableAdminChanges",
		"AppliedConnectionCreate", "AdminNotifications", "AdminNotificationsForChange", "AdminNotificationsForRecovery",
		"TenantRecovery", "TenantRecoveryByInvitation", "PendingTenantRecovery", "TenantRecoveries", "ActiveAdminUsers",
		"AllRoleAssignments"} {
		out[k] = true // TestIsolation_AdminRowsReads
	}
	for _, k := range []string{"ApproveAdminChange", "RejectAdminChange", "CancelAdminChange", "ExpireAdminChange",
		"MarkAdminChangeApplied", "MarkAdminChangeFailed", "CancelTenantRecovery", "CompleteTenantRecovery",
		"RecordConnectionTestLogin", "SetIdPConnectionStatus", "UpdateIdPConnectionTrust", "UpdateIdPConnectionCosmetic",
		"RevokeConnectionSessions"} {
		out[k] = true // TestIsolation_AdminRowsWritesScoped
	}
	for _, k := range []string{"InsertAdminChange", "InsertAdminNotification", "InsertTenantRecovery"} {
		out[k] = true // TestIsolation_AdminInsertsRefused
	}
	for _, k := range []string{"TenantRecord", "UpdateTenantSettings", "UpdateTenantMinAdmins",
		"UpdateTenantSecurityContacts", "UpdateTenantStatus"} {
		out[k] = true // TestIsolation_OwnTenantRow
	}
	return out
}
