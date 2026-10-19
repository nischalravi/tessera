package admin_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/admin"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

func TestMain(m *testing.M) { testkit.Main(m) }

var tenantID = tenancy.MustParse("00000000-0000-4000-8000-0000000000c1")

// clock is the injected, settable clock.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

// harness is a tenant "acme" with an injected clock and sealer.
type harness struct {
	t      *testing.T
	db     *store.DB
	svc    *admin.Service
	clk    *clock
	sealer *seal.Sealer
	ctx    context.Context
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	db := testkit.Open(t)
	testkit.CreateTenant(t, db, tenantID, "acme")
	sealer, err := seal.New(seal.RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	clk := &clock{t: testkit.Now}
	return &harness{t: t, db: db, clk: clk, sealer: sealer, ctx: context.Background(),
		svc: &admin.Service{DB: db, Clock: clk.now, Sealer: sealer}}
}

// tx runs fn in a write transaction of the tenant.
func (h *harness) tx(fn func(tx *store.TenantTx) error) {
	h.t.Helper()
	if err := h.db.InTenant(h.ctx, tenantID, fn); err != nil {
		h.t.Fatal(err)
	}
}

// user adds an active user holding roles (admin roles with source bootstrap,
// which the schema allows without a change request).
func (h *harness) user(name string, roles ...string) *store.PlatformUser {
	h.t.Helper()
	email := name + "@acme.example"
	u := &store.PlatformUser{Email: &email, DisplayName: name, CreatedAt: h.clk.now()}
	h.tx(func(tx *store.TenantTx) error {
		if err := tx.InsertPlatformUser(u); err != nil {
			return err
		}
		for _, r := range roles {
			src := store.RoleSourceManual
			if auth.Role(r).IsAdmin() {
				src = store.RoleSourceBootstrap
			}
			if err := tx.InsertRoleAssignment(&store.RoleAssignment{UserID: u.ID, Role: r, Source: src, CreatedAt: h.clk.now()}); err != nil {
				return err
			}
		}
		return nil
	})
	return u
}

// admins adds n tenant admins named admin1..adminN.
func (h *harness) admins(names ...string) []*store.PlatformUser {
	var out []*store.PlatformUser
	for _, n := range names {
		out = append(out, h.user(n, store.RoleTenantAdmin))
	}
	return out
}

// as is u's principal with a phishing-resistant sign-in that happened age ago.
func (h *harness) asAged(u *store.PlatformUser, age time.Duration, roles ...auth.Role) *auth.Principal {
	uid := u.ID
	assigned := auth.RoleSet{}
	h.tx(func(tx *store.TenantTx) error {
		as, err := tx.RoleAssignments(u.ID)
		for _, a := range as {
			assigned[auth.Role(a.Role)] = true
		}
		return err
	})
	for _, r := range roles {
		assigned[r] = true
	}
	return &auth.Principal{Kind: auth.KindUser, TenantID: tenantID, UserID: &uid, Display: u.DisplayName,
		Authn: &auth.AuthnContext{UserID: u.ID, Protocol: "oidc", AAL: 2, PhishingResistant: true, PhrBasis: "acr",
			TesseraACR: auth.ACRPhr, AuthTime: h.clk.now().Add(-age)},
		AssignedRoles: assigned, ActiveRoles: assigned}
}

// as is u's principal, signed in just now.
func (h *harness) as(u *store.PlatformUser) *auth.Principal { return h.asAged(u, 0) }

// advance moves the clock.
func (h *harness) advance(d time.Duration) { h.clk.t = h.clk.t.Add(d) }

// contacts sets the tenant's security contacts.
func (h *harness) contacts(emails ...string) {
	h.t.Helper()
	json := "["
	for i, e := range emails {
		if i > 0 {
			json += ","
		}
		json += `{"name":"` + e + `","email":"` + e + `"}`
	}
	json += "]"
	h.tx(func(tx *store.TenantTx) error { return tx.UpdateTenantSecurityContacts(json) })
}

// oidcConnection adds an active OIDC connection.
func (h *harness) oidcConnection(name string) *store.IdPConnection {
	h.t.Helper()
	iss, cid, method := "https://"+name+".okta.example", "client-"+name, "client_secret_basic"
	c := &store.IdPConnection{Name: name, Protocol: "oidc", Profile: store.ProfileOkta, Status: "active", Issuer: &iss,
		ClientID: &cid, ClientAuthMethod: &method, CreatedAt: h.clk.now(), UpdatedAt: h.clk.now()}
	h.tx(func(tx *store.TenantTx) error { return tx.InsertIdPConnection(c) })
	return c
}

// change reads a request.
func (h *harness) change(id uuid.UUID) *store.AdminChange {
	h.t.Helper()
	var ch *store.AdminChange
	if err := h.db.ReadTenant(h.ctx, tenantID, func(tx *store.TenantTx) error {
		var err error
		ch, err = tx.AdminChange(id)
		return err
	}); err != nil {
		h.t.Fatal(err)
	}
	return ch
}

// notifications lists the notifications of a request.
func (h *harness) notifications(id uuid.UUID) []*store.AdminNotification {
	h.t.Helper()
	var ns []*store.AdminNotification
	if err := h.db.ReadTenant(h.ctx, tenantID, func(tx *store.TenantTx) error {
		var err error
		ns, err = tx.AdminNotificationsForChange(id)
		return err
	}); err != nil {
		h.t.Fatal(err)
	}
	return ns
}

// audited lists the actions of the tenant's ledger.
func (h *harness) audited(tenant tenancy.ID) []string {
	h.t.Helper()
	var out []string
	if err := h.db.ReadTenant(h.ctx, tenant, func(tx *store.TenantTx) error {
		evs, err := tx.AuditLog(-1)
		for _, e := range evs {
			out = append(out, e.Action)
		}
		return err
	}); err != nil {
		h.t.Fatal(err)
	}
	return out
}

// roles lists the roles a user holds.
func (h *harness) roles(u *store.PlatformUser) []string {
	h.t.Helper()
	var out []string
	h.tx(func(tx *store.TenantTx) error {
		as, err := tx.RoleAssignments(u.ID)
		for _, a := range as {
			out = append(out, a.Role)
		}
		return err
	})
	return out
}

// wantErr checks err is an *admin.Error with the status and code.
func wantErr(t *testing.T, err error, status int, code string) {
	t.Helper()
	var ae *admin.Error
	if !errors.As(err, &ae) {
		t.Fatalf("error = %v, want admin.Error %d %s", err, status, code)
	}
	if ae.Status != status || ae.Code != code {
		t.Fatalf("error = %d %s (%s), want %d %s", ae.Status, ae.Code, ae.Msg, status, code)
	}
}

// wantStepUp checks err is the 401 step_up_required denial.
func wantStepUp(t *testing.T, err error) {
	t.Helper()
	wantErr(t, err, http.StatusUnauthorized, "step_up_required")
	var ae *admin.Error
	_ = errors.As(err, &ae)
	if ae.Denial == nil || ae.Denial.Requirement == nil || *ae.Denial.Requirement != auth.StepUpAdmin {
		t.Fatalf("denial = %+v, want a STEP_UP_ADMIN requirement", ae.Denial)
	}
}

func (h *harness) submit(p *auth.Principal, typ, payload string) (*store.AdminChange, error) {
	return h.svc.Submit(h.ctx, p, admin.SubmitInput{Type: typ, Payload: []byte(payload)})
}

func mustSubmit(t *testing.T, h *harness, p *auth.Principal, typ, payload string) *store.AdminChange {
	t.Helper()
	ch, err := h.submit(p, typ, payload)
	if err != nil {
		t.Fatalf("submit %s %s: %v", typ, payload, err)
	}
	return ch
}

func mustUUID(t *testing.T, s string) uuid.UUID {
	t.Helper()
	id, err := uuid.Parse(s)
	if err != nil {
		t.Fatalf("%q is not a uuid: %v", s, err)
	}
	return id
}

func grant(user *store.PlatformUser, role string) string {
	return `{"user_id":"` + user.ID.String() + `","role":"` + role + `"}`
}

// signedInVia creates a session of u whose initial authentication context
// came through connection conn (nil: no connection), and returns its id.
func (h *harness) signedInVia(u *store.PlatformUser, conn *store.IdPConnection) uuid.UUID {
	h.t.Helper()
	var sid uuid.UUID
	h.tx(func(tx *store.TenantTx) error {
		rec := authtest.Record(u.ID, authtest.Phr, h.clk.now())
		if conn != nil {
			rec.IdPConnectionID = &conn.ID
		}
		if err := tx.InsertAuthnContext(rec); err != nil {
			return err
		}
		iss, err := auth.CreateSession(tx, auth.SessionInput{User: u, Authn: rec, Now: h.clk.now()})
		sid = iss.Session.ID
		return err
	})
	return sid
}

func (h *harness) session(id uuid.UUID) *store.Session {
	h.t.Helper()
	var s *store.Session
	if err := h.db.ReadTenant(h.ctx, tenantID, func(tx *store.TenantTx) error {
		var err error
		s, err = tx.Session(id)
		return err
	}); err != nil {
		h.t.Fatal(err)
	}
	return s
}
