package api

import (
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

// asAdmin wraps srv with a testAdmin session in tenant.
func asAdmin(tb testing.TB, srv *Server, db *store.DB, tenant tenancy.ID, now time.Time) testSrv {
	tb.Helper()
	return testSrv{srv, signIn(tb, db, tenant, testAdmin, authtest.Phr, now)}
}
