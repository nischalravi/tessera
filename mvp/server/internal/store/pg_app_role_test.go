package store

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"strings"
	"testing"
)

// The request pool logs in as its own role (#430). These run only with
// TESSERA_TEST_PG_URL (the admin URL must be a superuser).

// pgTestRole creates a LOGIN role (extra is appended to CREATE ROLE) and
// returns its name and a DSN for target as that role. The role is dropped
// when the test ends (after the test databases, so it owns nothing then).
func pgTestRole(t *testing.T, admin *sql.DB, target, extra string) (string, string) {
	t.Helper()
	name := "tessera_r_" + randHex(6)
	if _, err := admin.Exec("CREATE ROLE " + name + " LOGIN PASSWORD 'pw' " + extra); err != nil { // #nosec G202 -- generated name
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec("DROP ROLE IF EXISTS " + name) }) // #nosec G202 -- generated name
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword(name, "pw")
	return name, u.String()
}

func TestCheckAppRole_RefusesPrivilegedSessions(t *testing.T) {
	adminURL := PostgresForTest(t)
	admin, err := sql.Open("pgx", adminURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	ctx := context.Background()

	// Roles are made after the database's cleanup is registered, so they
	// are dropped first only if they own nothing: ownership is handed back below.
	probe := TestTarget(t) // owner DSN of a database migrated on first open
	_, bypassDSN := pgTestRole(t, admin, probe, "NOSUPERUSER BYPASSRLS")
	ownerRole, ownerDSN := pgTestRole(t, admin, probe, "NOSUPERUSER NOBYPASSRLS")
	memberName, memberDSN := pgTestRole(t, admin, probe, "NOSUPERUSER NOBYPASSRLS")

	// Migrate once as the admin, then hand tenants to ownerRole and make
	// memberName a member of it.
	seed, err := Open(ctx, probe)
	if err != nil {
		t.Fatal(err)
	}
	_ = seed.Close()
	dbAdmin := func() *sql.DB {
		u, _ := url.Parse(probe)
		d, err := sql.Open("pgx", u.String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = d.Close() })
		return d
	}()
	t.Cleanup(func() { _, _ = dbAdmin.Exec("ALTER TABLE tenants OWNER TO CURRENT_USER") })
	for _, q := range []string{
		"ALTER TABLE tenants OWNER TO " + ownerRole,
		"GRANT " + ownerRole + " TO " + memberName,
	} {
		if _, err := dbAdmin.Exec(q); err != nil { // #nosec G202 -- generated names
			t.Fatal(err)
		}
	}

	for _, tc := range []struct {
		name, dsn, want string
	}{
		{"superuser", probe, "is a superuser"},
		{"bypassrls", bypassDSN, "has BYPASSRLS"},
		{"owner", ownerDSN, "owns tables in the schema"},
		{"member of owner", memberDSN, "member of the schema owner role"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, err := OpenApp(ctx, probe, AppOptions{DSN: tc.dsn})
			if err == nil {
				_ = db.Close()
				t.Fatal("a privileged request pool was accepted")
			}
			if !errors.Is(err, ErrAppRolePrivileged) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v, want %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "pw") && strings.Contains(err.Error(), "://") {
				t.Errorf("the error echoes a DSN: %v", err)
			}
			// the explicit dev override
			db, err = OpenApp(ctx, probe, AppOptions{DSN: tc.dsn, AllowPrivileged: true})
			if err != nil {
				t.Fatalf("override: %v", err)
			}
			_ = db.Close()
		})
	}

	t.Run("no app DSN falls back to the owner and is refused", func(t *testing.T) {
		// An unregistered copy of the owner DSN: no test pairing applies.
		u, _ := url.Parse(probe)
		u.RawQuery = "application_name=t430"
		if _, err := OpenApp(ctx, u.String(), AppOptions{}); !errors.Is(err, ErrAppRolePrivileged) {
			t.Fatalf("err %v", err)
		}
	})

	t.Run("tessera_app passes", func(t *testing.T) {
		app := TestAppDSN(probe)
		if app == "" {
			t.Fatal("no tessera_app DSN registered")
		}
		db, err := OpenApp(ctx, probe, AppOptions{DSN: app})
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		var su string
		if err := db.sql.QueryRowContext(ctx, "SELECT session_user::text").Scan(&su); err != nil || su != "tessera_app" {
			t.Fatalf("session_user %q %v", su, err)
		}
	})
}

// TestAppPool_CannotRaisePrivileges: SQL running on the request pool cannot
// return to the owner (SET ROLE, RESET ROLE, SET SESSION AUTHORIZATION) and
// still sees only its own tenant's rows.
func TestAppPool_CannotRaisePrivileges(t *testing.T) {
	f := newPGFixture(t)
	ctx := context.Background()
	var owner, su string
	if err := f.db.owner.QueryRowContext(ctx, `SELECT pg_get_userbyid(relowner)::text FROM pg_class WHERE relname = 'tenants' AND relnamespace = current_schema()::regnamespace`).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	if err := f.db.sql.QueryRowContext(ctx, `SELECT session_user::text`).Scan(&su); err != nil {
		t.Fatal(err)
	}
	if su == owner || su != "tessera_app" {
		t.Fatalf("request pool logs in as %q (owner %q)", su, owner)
	}
	q := `"` + strings.ReplaceAll(owner, `"`, `""`) + `"`
	for _, stmt := range []string{"SET ROLE " + q, "SET SESSION AUTHORIZATION " + q, "SET LOCAL ROLE " + q} {
		f.asApp(t, pgTenantA.String(), func(tx *sql.Tx) {
			_, err := tx.ExecContext(ctx, stmt)
			if err == nil {
				t.Errorf("%s succeeded on the request pool", stmt)
			} else if s := sqlState(err); s != "42501" {
				t.Errorf("%s: SQLSTATE %q (%v), want 42501 insufficient_privilege", stmt, s, err)
			}
		})
	}
	f.asApp(t, pgTenantA.String(), func(tx *sql.Tx) {
		if _, err := tx.ExecContext(ctx, "RESET ROLE"); err != nil {
			t.Fatal(err)
		}
		var cur string
		if err := tx.QueryRowContext(ctx, "SELECT current_user::text").Scan(&cur); err != nil || cur != "tessera_app" {
			t.Fatalf("after RESET ROLE current_user is %q %v", cur, err)
		}
		a := pgTenantA.String()
		if n := count(t, tx, `SELECT count(*) FROM identities WHERE tenant_id = $1`, a); n != 1 {
			t.Errorf("own identities %d, want 1", n)
		}
		if n := count(t, tx, `SELECT count(*) FROM identities WHERE tenant_id = $1`, pgTenantB.String()); n != 0 {
			t.Errorf("another tenant's identities visible: %d", n)
		}
		if n := count(t, tx, `SELECT count(*) FROM identities`); n != 1 {
			t.Errorf("unfiltered identities %d, want 1", n)
		}
	})
}
