package sqldb

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
)

// Live tests run against real servers and skip the engines that have none.
//
//	PostgreSQL  TESSERA_TEST_PG_URL=postgres://postgres@127.0.0.1:5432/postgres?sslmode=disable
//	            (the variable the rest of the suite uses; see mvp/README.md "Postgres")
//	MySQL 8     TESSERA_TEST_SQL_MYSQL=user:password@host:3306/database
//	SQL Server  TESSERA_TEST_SQL_SQLSERVER=user:password@host:1433/database
//	Oracle      TESSERA_TEST_SQL_ORACLE=user:password@host:1521/service
//
// The user must be able to create and drop logins and roles (the tests make
// their own, with random names, and drop them again). TLS is off and
// loopback is allowed: this is the dev runtime.
func liveConfig(t *testing.T, engine string) (Config, connsync.Secret) {
	t.Helper()
	var raw string
	switch engine {
	case Postgres:
		raw = os.Getenv("TESSERA_TEST_PG_URL")
	default:
		raw = os.Getenv("TESSERA_TEST_SQL_" + strings.ToUpper(engine))
	}
	if raw == "" {
		t.Skipf("no %s server: set %s (see the comment in live_test.go)", engine, map[string]string{
			Postgres: "TESSERA_TEST_PG_URL", MySQL: "TESSERA_TEST_SQL_MYSQL", SQLServer: "TESSERA_TEST_SQL_SQLSERVER", Oracle: "TESSERA_TEST_SQL_ORACLE"}[engine])
	}
	if !strings.Contains(raw, "://") {
		raw = "db://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("the %s test URL is not valid", engine)
	}
	pw, _ := u.User.Password()
	if pw == "" {
		pw = "unused-with-trust-auth"
	}
	port, _ := strconv.Atoi(u.Port())
	return Config{Engine: engine, Host: u.Hostname(), Port: port, Database: strings.TrimPrefix(u.Path, "/"), Username: u.User.Username(),
		TLS: TLSDisable, Mode: ModeNative, QueryTimeoutSeconds: 30}, connsync.NewSecret(pw)
}

func rnd(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func liveCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	return ctx
}

func admin(t *testing.T, cfg Config, pw connsync.Secret) *sql.DB {
	t.Helper()
	db, err := Open(cfg, pw, devRT, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.PingContext(liveCtx(t)); err != nil {
		t.Fatalf("cannot reach the %s test server: %v", cfg.Engine, scrub(err, pw))
	}
	return db
}

func exec(t *testing.T, db *sql.DB, q string) {
	t.Helper()
	if _, err := db.ExecContext(liveCtx(t), q); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

func quoted(t *testing.T, engine, name string) string {
	t.Helper()
	var q string
	var err error
	if engine == MySQL {
		q, err = QuoteMySQLAccount(name)
	} else {
		q, err = Quote(engine, name)
	}
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func TestLive_Lifecycle(t *testing.T) {
	for _, engine := range Engines {
		t.Run(engine, func(t *testing.T) {
			cfg, pw := liveConfig(t, engine)
			db := admin(t, cfg, pw)
			suffix := rnd(t, 4)
			login, role := "tsr_u_"+suffix, "tsr_g_"+suffix
			create, dropRole, entitlement := "CREATE ROLE ", "DROP ROLE ", role
			switch engine {
			case MySQL:
				login, role = login+"@%", role+"@%"
				entitlement = role
			case SQLServer:
				create, dropRole, entitlement = "CREATE SERVER ROLE ", "DROP SERVER ROLE ", "server:"+role
			case Oracle:
				login, role = strings.ToUpper(login), strings.ToUpper(role)
				entitlement = role
			}
			fixture := create + quoted(t, engine, role)
			if engine == Postgres {
				fixture += " NOLOGIN" // a group, not an account
			}
			exec(t, db, fixture)
			t.Cleanup(func() {
				c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				// the login first, then the role; errors are fine (the test may have dropped them)
				if s, err := statements(engine, opDrop, login, ""); err == nil {
					for _, q := range s {
						_, _ = db.ExecContext(c, q)
					}
				}
				_, _ = db.ExecContext(c, dropRole+quoted(t, engine, role))
			})

			tg, err := NewTarget(cfg, pw, devRT)
			if err != nil {
				t.Fatal(err)
			}
			conn, err := NewConnector(cfg, pw, devRT)
			if err != nil {
				t.Fatal(err)
			}
			ctx := liveCtx(t)
			apply := func(r target.Request) {
				t.Helper()
				for i := 0; i < 2; i++ { // twice: the second call changes nothing and still succeeds
					if err := tg.Apply(ctx, r); err != nil {
						t.Fatalf("%s (try %d): %v", r.Kind, i+1, err)
					}
				}
				v, err := tg.Verify(ctx, r)
				if err != nil || !v.OK {
					t.Fatalf("verify %s: %+v %v", r.Kind, v, err)
				}
			}
			acct := target.Account{Username: login}
			apply(target.Request{Kind: target.CreateAccount, Account: acct})
			status := func() (string, bool, bool) {
				res, err := conn.Discover(ctx)
				if err != nil {
					t.Fatal(err)
				}
				var st string
				var found bool
				for _, a := range res.Accounts {
					if strings.EqualFold(a.ExternalID, login) {
						st, found = a.Status, true
					}
				}
				return st, found, hasEdge(res, "account", login, "member_of", "group", entitlement)
			}
			if st, found, _ := status(); !found || st != "active" {
				t.Fatalf("after create: found %v status %q", found, st)
			}
			apply(target.Request{Kind: target.AddEntitlement, Account: acct, Group: target.Group{ExternalID: entitlement}})
			if _, _, member := status(); !member {
				t.Error("Discover does not show the new membership")
			}
			apply(target.Request{Kind: target.DisableAccount, Account: acct})
			if st, found, _ := status(); !found || st != "disabled" {
				t.Fatalf("after disable: found %v status %q", found, st)
			}
			up := target.Account{Username: login, Attrs: map[string]string{"status": "active"}}
			apply(target.Request{Kind: target.UpdateAccount, Account: up})
			if st, _, _ := status(); st != "active" {
				t.Fatalf("after unlock: status %q", st)
			}
			apply(target.Request{Kind: target.RemoveEntitlement, Account: acct, Group: target.Group{ExternalID: entitlement}})
			if _, _, member := status(); member {
				t.Error("Discover still shows the removed membership")
			}
			apply(target.Request{Kind: target.DeleteAccount, Account: acct})
			if _, found, _ := status(); found {
				t.Error("the dropped login is still discovered")
			}
		})
	}
}

// A name with quotes and SQL in it stays a name (PostgreSQL, the engine every
// run has): the role is created, found and dropped under exactly that name.
func TestLive_PostgresHostileName(t *testing.T) {
	cfg, pw := liveConfig(t, Postgres)
	admin(t, cfg, pw)
	name := `tsr "x"; DROP ROLE postgres; --` + rnd(t, 3)
	tg, _ := NewTarget(cfg, pw, devRT)
	ctx := liveCtx(t)
	r := target.Request{Kind: target.CreateAccount, Account: target.Account{Username: name}}
	if err := tg.Apply(ctx, r); err != nil {
		t.Fatal(err)
	}
	if v, err := tg.Verify(ctx, r); err != nil || !v.OK {
		t.Fatalf("%+v %v", v, err)
	}
	r.Kind = target.DeleteAccount
	if err := tg.Apply(ctx, r); err != nil {
		t.Fatal(err)
	}
	if v, err := tg.Verify(ctx, r); err != nil || !v.OK {
		t.Fatalf("%+v %v", v, err)
	}
}

// The read-only transaction really refuses a write (PostgreSQL, MySQL).
func TestLive_ReadsAreReadOnly(t *testing.T) {
	for _, engine := range []string{Postgres, MySQL} {
		t.Run(engine, func(t *testing.T) {
			cfg, pw := liveConfig(t, engine)
			db := admin(t, cfg, pw)
			name := "tsr_ro_" + rnd(t, 3)
			stmt := "CREATE ROLE " + quoted(t, engine, name)
			_, err := query(liveCtx(t), db, engine, 10*time.Second, 10, stmt)
			if err == nil {
				exec(t, db, "DROP ROLE "+quoted(t, engine, name))
				t.Fatal("a write ran in the read transaction")
			}
		})
	}
}

func TestLive_RowCapIsPartial(t *testing.T) {
	cfg, pw := liveConfig(t, Postgres)
	db := admin(t, cfg, pw)
	for _, n := range []string{"tsr_cap_a_" + rnd(t, 3), "tsr_cap_b_" + rnd(t, 3)} {
		exec(t, db, "CREATE ROLE "+quoted(t, Postgres, n)+" LOGIN")
		n := n
		t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), "DROP ROLE "+quoted(t, Postgres, n)) })
	}
	cfg.MaxRows = 1
	conn, _ := NewConnector(cfg, pw, devRT)
	res, err := conn.Discover(liveCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Accounts) != 1 || res.Partial == "" {
		t.Fatalf("accounts %d partial %q", len(res.Accounts), res.Partial)
	}
}

// Application tables on PostgreSQL: SELECTs for the read, named placeholders for the writes.
func TestLive_PostgresAppTables(t *testing.T) {
	cfg, pw := liveConfig(t, Postgres)
	db := admin(t, cfg, pw)
	sfx := rnd(t, 3)
	users, roles := "tsr_app_users_"+sfx, "tsr_app_roles_"+sfx
	exec(t, db, "CREATE TABLE "+users+" (id serial PRIMARY KEY, login text UNIQUE NOT NULL, mail text, state text NOT NULL DEFAULT 'active')")
	exec(t, db, "CREATE TABLE "+roles+" (login text NOT NULL, role_name text NOT NULL)")
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), "DROP TABLE "+users)
		_, _ = db.ExecContext(context.Background(), "DROP TABLE "+roles)
	})
	cfg.Mode = ModeApp
	cfg.App = &App{
		AccountsQuery:     "SELECT id::text AS id, login AS username, mail AS email, state AS status FROM " + users + " ORDER BY id",
		EntitlementsQuery: "SELECT login AS account, role_name AS entitlement FROM " + roles,
		CreateAccount:     "INSERT INTO " + users + " (login, mail) VALUES (:username, :email)",
		DisableAccount:    "UPDATE " + users + " SET state = 'disabled' WHERE login = :username",
		DeleteAccount:     "DELETE FROM " + users + " WHERE login = :username",
		AddEntitlement:    "INSERT INTO " + roles + " (login, role_name) VALUES (:username, :entitlement)",
		RemoveEntitlement: "DELETE FROM " + roles + " WHERE login = :username AND role_name = :entitlement",
	}
	tg, err := NewTarget(cfg, pw, devRT)
	if err != nil {
		t.Fatal(err)
	}
	conn, _ := NewConnector(cfg, pw, devRT)
	ctx := liveCtx(t)
	evil := "o'neil'; DROP TABLE " + users + "; --"
	acct := target.Account{Username: evil, Email: "o@example.com"}
	for _, r := range []target.Request{
		{Kind: target.CreateAccount, Account: acct},
		{Kind: target.AddEntitlement, Account: acct, Group: target.Group{ExternalID: "approver"}},
		{Kind: target.DisableAccount, Account: acct},
	} {
		for i := 0; i < 2; i++ {
			if err := tg.Apply(ctx, r); err != nil {
				t.Fatalf("%s: %v", r.Kind, err)
			}
		}
		if v, err := tg.Verify(ctx, r); err != nil || !v.OK {
			t.Fatalf("verify %s: %+v %v", r.Kind, v, err)
		}
	}
	res, err := conn.Discover(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Accounts) != 1 || res.Accounts[0].Username != evil || res.Accounts[0].Status != "disabled" || len(res.Edges) != 1 {
		t.Fatalf("discovered %+v %+v", res.Accounts, res.Edges)
	}
	for _, r := range []target.Request{{Kind: target.RemoveEntitlement, Account: acct, Group: target.Group{ExternalID: "approver"}},
		{Kind: target.DeleteAccount, Account: acct}} {
		if err := tg.Apply(ctx, r); err != nil {
			t.Fatalf("%s: %v", r.Kind, err)
		}
		if v, err := tg.Verify(ctx, r); err != nil || !v.OK {
			t.Fatalf("verify %s: %+v %v", r.Kind, v, err)
		}
	}
	// the table is still there: the hostile value was data
	var n int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM "+users).Scan(&n); err != nil || n != 0 {
		t.Fatalf("users table: %d %v", n, err)
	}
}
