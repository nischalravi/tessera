package sqldb

import (
	"context"
	"database/sql"
	"reflect"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
)

func targetFor(f *fakeDB, cfg Config) *Target {
	return &Target{cfg: cfg, pw: connsync.NewSecret("pw"), rt: prodRT, open: func(bool) (*sql.DB, error) { return f.db(), nil }}
}

func pgFake() *fakeDB {
	f := newFake()
	loadCatalog(f, Postgres, nativeData{accounts: [][]string{{"alice", "active"}, {"bob", "locked"}}},
		[][][]string{{{"readers"}, {"admins"}}}, [][][]string{{{"alice", "readers"}}})
	return f
}

func req(kind, user string) target.Request {
	return target.Request{Kind: kind, Account: target.Account{Username: user}}
}

func withGroup(r target.Request, g string) target.Request {
	r.Group = target.Group{ExternalID: g}
	return r
}

func TestTarget_NativePostgres_Apply(t *testing.T) {
	update := func(user, status string) target.Request {
		r := req(target.UpdateAccount, user)
		r.Account.Attrs = map[string]string{"status": status}
		return r
	}
	tests := []struct {
		name string
		r    target.Request
		want []string
	}{
		{"create new", req(target.CreateAccount, "carol"), []string{`CREATE ROLE "carol" LOGIN`}},
		{"create existing is a no-op", req(target.CreateAccount, "alice"), nil},
		{"disable active", req(target.DisableAccount, "alice"), []string{`ALTER ROLE "alice" NOLOGIN`, `COMMENT ON ROLE "alice" IS 'tessera:locked'`}},
		{"disable already locked is a no-op", req(target.DisableAccount, "bob"), nil},
		{"update to active unlocks", update("bob", "active"), []string{`ALTER ROLE "bob" LOGIN`, `COMMENT ON ROLE "bob" IS NULL`}},
		{"update to active when active", update("alice", "active"), nil},
		{"update to locked", update("alice", "locked"), []string{`ALTER ROLE "alice" NOLOGIN`, `COMMENT ON ROLE "alice" IS 'tessera:locked'`}},
		{"delete", req(target.DeleteAccount, "alice"), []string{`DROP ROLE "alice"`}},
		{"delete missing is a no-op", req(target.DeleteAccount, "zed"), nil},
		{"grant", withGroup(req(target.AddEntitlement, "alice"), "admins"), []string{`GRANT "admins" TO "alice"`}},
		{"grant held is a no-op", withGroup(req(target.AddEntitlement, "alice"), "readers"), nil},
		{"revoke", withGroup(req(target.RemoveEntitlement, "alice"), "readers"), []string{`REVOKE "readers" FROM "alice"`}},
		{"revoke not held is a no-op", withGroup(req(target.RemoveEntitlement, "alice"), "admins"), nil},
		{"hostile name is quoted", req(target.CreateAccount, `x" SUPERUSER; --`), []string{`CREATE ROLE "x"" SUPERUSER; --" LOGIN`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := pgFake()
			if err := targetFor(f, goodConfig(Postgres)).Apply(context.Background(), tt.r); err != nil {
				t.Fatal(err)
			}
			if got := f.execs(); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ran %q, want %q", got, tt.want)
			}
			if !f.Closed {
				t.Error("the connection was left open")
			}
		})
	}
}

func TestTarget_Apply_Refusals(t *testing.T) {
	tests := []struct {
		name string
		r    target.Request
		want string
	}{
		{"no account", target.Request{Kind: target.CreateAccount}, "needs a username"},
		{"unknown kind", req("explode", "alice"), "not supported"},
		{"grant to a missing account", withGroup(req(target.AddEntitlement, "zed"), "admins"), "no account zed"},
		{"disable a missing account", req(target.DisableAccount, "zed"), "no account zed"},
		{"grant without a role", req(target.AddEntitlement, "alice"), "needs a role"},
		{"update without status", req(target.UpdateAccount, "alice"), "attrs.status"},
		{"update with a bad status", func() target.Request {
			r := req(target.UpdateAccount, "alice")
			r.Account.Attrs = map[string]string{"status": "banana"}
			return r
		}(), "active or locked"},
		{"a name that cannot be quoted", req(target.CreateAccount, "a\x00b"), "not a usable name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := pgFake()
			err := targetFor(f, goodConfig(Postgres)).Apply(context.Background(), tt.r)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want one containing %q", err, tt.want)
			}
			if target.Retryable(err) {
				t.Errorf("%v is retryable; no retry fixes it", err)
			}
			if len(f.execs()) != 0 {
				t.Errorf("ran %q", f.execs())
			}
		})
	}
}

// A failing statement is retryable and the password never shows in the error.
func TestTarget_Apply_DatabaseError(t *testing.T) {
	f := pgFake()
	f.failQuery = "CREATE ROLE"
	err := targetFor(f, goodConfig(Postgres)).Apply(context.Background(), req(target.CreateAccount, "carol"))
	if err == nil || !target.Retryable(err) {
		t.Fatalf("err = %v", err)
	}
}

func TestTarget_Apply_PartialReadIsRefused(t *testing.T) {
	f := pgFake()
	cfg := goodConfig(Postgres)
	cfg.MaxRows = 1
	err := targetFor(f, cfg).Apply(context.Background(), req(target.CreateAccount, "carol"))
	if err == nil || !strings.Contains(err.Error(), "read cap") || target.Retryable(err) {
		t.Fatalf("err = %v", err)
	}
	if len(f.execs()) != 0 {
		t.Errorf("ran %q on a partial read", f.execs())
	}
}

func TestTarget_Apply_SQLServerRoles(t *testing.T) {
	f := newFake()
	loadCatalog(f, SQLServer, nativeData{accounts: [][]string{{"svc", "active"}}},
		[][][]string{{{"sysadmin"}}, {{"db_datareader"}}}, [][][]string{{}, {{"svc", "db_datareader"}}})
	tg := targetFor(f, goodConfig(SQLServer))
	if err := tg.Apply(context.Background(), withGroup(req(target.AddEntitlement, "SVC"), "server:sysadmin")); err != nil {
		t.Fatal(err)
	}
	if err := tg.Apply(context.Background(), withGroup(req(target.RemoveEntitlement, "svc"), "db:db_datareader")); err != nil {
		t.Fatal(err)
	}
	// the account is matched case-insensitively and named as the database has it
	want := []string{"ALTER SERVER ROLE [sysadmin] ADD MEMBER [svc]", "ALTER ROLE [db_datareader] DROP MEMBER [svc]"}
	if got := f.execs(); !reflect.DeepEqual(got, want) {
		t.Fatalf("ran %q, want %q", got, want)
	}
}

func TestTarget_Verify(t *testing.T) {
	update := func(user, status string) target.Request {
		r := req(target.UpdateAccount, user)
		r.Account.Attrs = map[string]string{"status": status}
		return r
	}
	tests := []struct {
		name string
		r    target.Request
		ok   bool
		obs  string
	}{
		{"create present", req(target.CreateAccount, "alice"), true, "account is active"},
		{"create absent", req(target.CreateAccount, "zed"), false, "no such account"},
		{"delete absent", req(target.DeleteAccount, "zed"), true, "no such account"},
		{"delete present", req(target.DeleteAccount, "alice"), false, "account is active"},
		{"disable locked", req(target.DisableAccount, "bob"), true, "account is locked"},
		{"disable active", req(target.DisableAccount, "alice"), false, "account is active"},
		{"update to active", update("bob", "active"), false, "account is locked"},
		{"update to locked", update("bob", "locked"), true, "account is locked"},
		{"grant held", withGroup(req(target.AddEntitlement, "alice"), "readers"), true, "holds the role"},
		{"grant not held", withGroup(req(target.AddEntitlement, "alice"), "admins"), false, "does not hold the role"},
		{"revoke done", withGroup(req(target.RemoveEntitlement, "alice"), "admins"), true, "does not hold the role"},
		{"revoke pending", withGroup(req(target.RemoveEntitlement, "alice"), "readers"), false, "holds the role"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := pgFake()
			v, err := targetFor(f, goodConfig(Postgres)).Verify(context.Background(), tt.r)
			if err != nil {
				t.Fatal(err)
			}
			if v.OK != tt.ok || v.Observed != tt.obs {
				t.Fatalf("verdict = %+v, want ok=%v observed %q", v, tt.ok, tt.obs)
			}
			if len(f.execs()) != 0 {
				t.Errorf("Verify changed something: %q", f.execs())
			}
		})
	}
}

func TestTarget_AppMode(t *testing.T) {
	c := appConfig()
	run := func(r target.Request) (*fakeDB, error) {
		f := newFake()
		loadApp(f, c)
		return f, targetFor(f, c).Apply(context.Background(), r)
	}
	r := req(target.CreateAccount, "carol")
	r.Account.Email = "carol@example.com"
	f, err := run(r)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.execs(); !reflect.DeepEqual(got, []string{"INSERT INTO app_users (login, mail) VALUES ($1, $2)"}) {
		t.Fatalf("ran %q", got)
	}
	if got := f.Args[len(f.Args)-1]; !reflect.DeepEqual(got, []any{"carol", "carol@example.com"}) {
		t.Errorf("args = %#v", got)
	}
	// create of an existing account, delete of a missing one, grant held, revoke not held: nothing runs
	for _, noop := range []target.Request{req(target.CreateAccount, "alice"), req(target.DeleteAccount, "zed"),
		withGroup(req(target.AddEntitlement, "alice"), "approver"), withGroup(req(target.RemoveEntitlement, "alice"), "other")} {
		f, err := run(noop)
		if err != nil || len(f.execs()) != 0 {
			t.Errorf("%s: err %v ran %q", noop.Kind, err, f.execs())
		}
	}
	// a hostile value is an argument, never part of the statement
	evil := "x'; DROP TABLE app_users; --"
	f, err = run(withGroup(req(target.AddEntitlement, "alice"), evil))
	if err != nil {
		t.Fatal(err)
	}
	if got := f.execs(); len(got) != 1 || got[0] != "INSERT INTO app_roles (login, role_name) VALUES ($1, $2)" {
		t.Fatalf("ran %q", got)
	}
	if got := f.Args[len(f.Args)-1]; !reflect.DeepEqual(got, []any{"alice", evil}) {
		t.Errorf("args = %#v", got)
	}
	// an operation without a configured statement is refused, permanently
	_, err = run(req(target.UpdateAccount, "alice"))
	if err == nil || !strings.Contains(err.Error(), "not configured") || target.Retryable(err) {
		t.Errorf("err = %v", err)
	}
	// grant to a missing account
	_, err = run(withGroup(req(target.AddEntitlement, "zed"), "approver"))
	if err == nil || !strings.Contains(err.Error(), "no account") {
		t.Errorf("err = %v", err)
	}
	// the account is found by username or by id
	f, err = run(req(target.DeleteAccount, "alice"))
	if err != nil || len(f.execs()) != 1 {
		t.Errorf("delete by username: %v %q", err, f.execs())
	}
	byID := req(target.DeleteAccount, "")
	byID.Account.ExternalID = "8"
	if f, err = run(byID); err != nil || len(f.execs()) != 1 {
		t.Errorf("delete by id: %v %q", err, f.execs())
	}
}

func TestTarget_AppModeVerify(t *testing.T) {
	c := appConfig()
	f := newFake()
	loadApp(f, c)
	tg := targetFor(f, c)
	v, err := tg.Verify(context.Background(), withGroup(req(target.AddEntitlement, "alice"), "approver"))
	if err != nil || !v.OK {
		t.Fatalf("%+v %v", v, err)
	}
	v, _ = tg.Verify(context.Background(), req(target.DeleteAccount, "alice"))
	if v.OK {
		t.Errorf("%+v", v)
	}
	v, _ = tg.Verify(context.Background(), req(target.DisableAccount, "bob"))
	if !v.OK {
		t.Errorf("%+v", v)
	}
}

func TestNewTarget(t *testing.T) {
	if _, err := NewTarget(goodConfig(Oracle), connsync.NewSecret("pw"), prodRT); err != nil {
		t.Fatal(err)
	}
	if _, err := NewTarget(goodConfig(Oracle), connsync.Secret{}, prodRT); err == nil {
		t.Error("no password accepted")
	}
	bad := goodConfig(Oracle)
	bad.Host = ""
	if _, err := NewTarget(bad, connsync.NewSecret("pw"), prodRT); err == nil {
		t.Error("bad config accepted")
	}
}
