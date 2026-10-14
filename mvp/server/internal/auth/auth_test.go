package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

func TestMain(m *testing.M) { testkit.Main(m) }

var (
	tenantA = tenancy.MustParse("00000000-0000-4000-8000-00000000a001")
	tenantB = tenancy.MustParse("00000000-0000-4000-8000-00000000b002")
	t0      = time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)
)

// clock is a settable clock for the authenticator.
type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

// env is a database with tenants A and B and an authenticator on a settable clock.
type env struct {
	db    *store.DB
	clock *clock
	a     *auth.Authenticator
}

func newEnv(t *testing.T) *env {
	t.Helper()
	db := testkit.Open(t)
	testkit.CreateTenant(t, db, tenantA, "tenant-a")
	testkit.CreateTenant(t, db, tenantB, "tenant-b")
	c := &clock{now: t0}
	return &env{db: db, clock: c, a: &auth.Authenticator{DB: db, Clock: c.Now}}
}

var (
	admin  = authtest.User{Email: "ada@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}}
	viewer = authtest.User{Email: "vic@a.example", Roles: []auth.Role{auth.RoleViewer}}
)

// request is a GET carrying the session cookie.
func request(cookie *http.Cookie) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/summary", nil)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	return r
}

func (e *env) authenticate(t *testing.T, cookie *http.Cookie) (*auth.Principal, string) {
	t.Helper()
	p, reason, err := e.a.Authenticate(request(cookie))
	if err != nil {
		t.Fatal(err)
	}
	return p, reason
}

func (e *env) session(t *testing.T, tenant tenancy.ID, id uuid.UUID) *store.Session {
	t.Helper()
	var s *store.Session
	if err := e.db.ReadTenant(context.Background(), tenant, func(tx *store.TenantTx) error {
		var err error
		s, err = tx.Session(id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return s
}
