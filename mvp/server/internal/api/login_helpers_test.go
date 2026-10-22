package api

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// testAdmin is the principal API tests run as unless they say otherwise: a
// tenant admin and policy admin signed in with a phishing-resistant method,
// so every route's permission and step-up requirement is met.
var testAdmin = authtest.User{Email: "j.rivera@larkspur.example", Display: "J. Rivera",
	Roles: []auth.Role{auth.RoleTenantAdmin, auth.RolePolicyAdmin}}

// testSrv is a server whose Handler sends every request (without its own
// Cookie header) as a signed-in principal of one tenant.
type testSrv struct {
	*Server
	login authtest.Login
}

// Handler is the server's handler, signed in.
func (s testSrv) Handler() http.Handler { return s.login.Handler(s.Server.Handler()) }

// Anonymous is the server's handler without a session.
func (s testSrv) Anonymous() http.Handler { return s.Server.Handler() }

// signIn signs u in to tenant with c at now (authtest.LoginAs).
func signIn(tb testing.TB, db *store.DB, tenant tenancy.ID, u authtest.User, c authtest.Ctx, now time.Time) authtest.Login {
	tb.Helper()
	return authtest.LoginAs(tb, db, tenant, u, c, now)
}

// linkedAdmin is testAdmin linked to an identity of the tenant, for tests that
// decide reviews: a decider with no linked identity is refused
// (reviewer_unlinked, issue #439). It is a demo Security Engineer (emp-1030)
// when the tenant has one, else a grant-less "test-admin" identity made for it.
// Other tests keep the unlinked testAdmin, so identity lists stay as they were.
func linkedAdmin(tb testing.TB, db *store.DB, tenant tenancy.ID, now time.Time) authtest.User {
	tb.Helper()
	u := testAdmin
	u.IdentityID = ensureIdentity(tb, db, tenant, "emp-1030", "test-admin", now)
	return u
}

// asLinkedAdmin is asAdmin with linkedAdmin.
func asLinkedAdmin(tb testing.TB, srv *Server, db *store.DB, tenant tenancy.ID, now time.Time) testSrv {
	tb.Helper()
	return testSrv{srv, signIn(tb, db, tenant, linkedAdmin(tb, db, tenant, now), authtest.Phr, now)}
}

// asAdmin wraps srv with a testAdmin session in tenant.
func asAdmin(tb testing.TB, srv *Server, db *store.DB, tenant tenancy.ID, now time.Time) testSrv {
	tb.Helper()
	return testSrv{srv, signIn(tb, db, tenant, testAdmin, authtest.Phr, now)}
}

// ensureIdentity returns the id of the tenant's identity with the external id
// xid, else of the one with the external id fallback, creating a grant-less
// person for the fallback when there is none.
func ensureIdentity(tb testing.TB, db *store.DB, tenant tenancy.ID, xid, fallback string, now time.Time) *int64 {
	tb.Helper()
	var id int64
	err := db.InTenant(context.Background(), tenant, func(c *store.TenantTx) error {
		i, err := c.IdentityByExternalID(xid)
		if errors.Is(err, store.ErrNotFound) {
			i, err = c.IdentityByExternalID(fallback)
		}
		if errors.Is(err, store.ErrNotFound) {
			id, err = c.InsertIdentity(&store.Identity{TenantID: tenant, ExternalID: fallback, Name: fallback, Type: "human",
				Status: "active", CreatedAt: now})
			return err
		}
		if err == nil {
			id = i.ID
		}
		return err
	})
	if err != nil {
		tb.Fatal(err)
	}
	return &id
}
