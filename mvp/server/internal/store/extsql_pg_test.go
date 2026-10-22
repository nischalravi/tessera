package store

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCheckPGDSN(t *testing.T) {
	tests := []struct {
		name, dsn string
		prod      bool
		want      string // a substring of the error, "" for none
	}{
		{"ok verify-full", "postgres://u:p@db.example.com:5432/hr?sslmode=verify-full", true, ""},
		{"default is verify-full", "postgresql://u:p@db.example.com/hr", true, ""},
		{"prod refuses require", "postgres://u:p@db.example.com/hr?sslmode=require", true, "verify-full"},
		{"prod refuses disable", "postgres://u:p@db.example.com/hr?sslmode=disable", true, "verify-full"},
		{"dev allows disable", "postgres://u:p@127.0.0.1/hr?sslmode=disable", false, ""},
		{"unknown sslmode", "postgres://u:p@h/hr?sslmode=maybe", false, "sslmode"},
		{"connect_timeout ok", "postgres://u:p@h/hr?connect_timeout=5", true, ""},
		{"connect_timeout range", "postgres://u:p@h/hr?connect_timeout=900", true, "connect_timeout"},
		{"sslrootcert refused", "postgres://u:p@h/hr?sslrootcert=/etc/passwd", false, "only the options"},
		{"passfile refused", "postgres://u:p@h/hr?passfile=/root/.pgpass", false, "only the options"},
		{"options refused", "postgres://u:p@h/hr?options=-c%20search_path%3Dx", false, "only the options"},
		{"key value form refused", "host=h user=u dbname=hr", false, "postgres:// URL"},
		{"mysql refused", "mysql://u:p@h/hr", false, "postgres:// URL"},
		{"no host", "postgres:///hr", false, "host"},
		{"no user", "postgres://h/hr", false, "user"},
		{"no database", "postgres://u@h", false, "database"},
		{"bad port", "postgres://u@h:99999/hr", false, "port"},
		{"duplicate option", "postgres://u@h/hr?sslmode=disable&sslmode=require", false, "twice"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckPGDSN(tc.dsn, tc.prod)
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("CheckPGDSN = %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("CheckPGDSN = %v, want %q", err, tc.want)
			}
			if err != nil && strings.Contains(err.Error(), "p@") {
				t.Errorf("the error carries the DSN: %v", err)
			}
		})
	}
}

func TestPGNamedArgs(t *testing.T) {
	q, args, err := pgNamedArgs(`SELECT a FROM t WHERE seq > @cursor AND note = '@cursor' AND x = @cursor AND y = @other`, map[string]string{"cursor": "42", "other": "abc"})
	if err != nil {
		t.Fatal(err)
	}
	if q != `SELECT a FROM t WHERE seq > $1 AND note = '@cursor' AND x = $1 AND y = $2` {
		t.Errorf("query = %s", q)
	}
	if len(args) != 2 || args[0] != int64(42) || args[1] != "abc" {
		t.Errorf("args = %#v", args)
	}
	if _, _, err := pgNamedArgs(`SELECT @missing`, nil); err == nil {
		t.Error("an unknown parameter was accepted")
	}
}

func TestRunExtQueryPG_RefusesUnsafe(t *testing.T) {
	ok := func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("must not dial") }
	dsn := "postgres://u:secretpw@127.0.0.1:1/hr?sslmode=verify-full"
	for name, q := range map[string]ExtPGQuery{
		"no dialer":  {DSN: dsn, SQL: "SELECT 1"},
		"write":      {DSN: dsn, SQL: "DELETE FROM t", Dial: ok},
		"two":        {DSN: dsn, SQL: "SELECT 1; SELECT 2", Dial: ok},
		"weak tls":   {DSN: "postgres://u:p@h/hr?sslmode=disable", RequireVerifyFull: true, SQL: "SELECT 1", Dial: ok},
		"bad option": {DSN: "postgres://u:p@h/hr?sslrootcert=/etc/passwd", SQL: "SELECT 1", Dial: ok},
	} {
		if _, err := RunExtQueryPG(context.Background(), q); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	// a failed connection must not put the password in the error
	_, err := RunExtQueryPG(context.Background(), ExtPGQuery{DSN: dsn, SQL: "SELECT 1", Dial: ok, Timeout: 3 * time.Second})
	if err == nil || strings.Contains(err.Error(), "secretpw") {
		t.Errorf("err = %v", err)
	}
}

// TestRunExtQueryPG runs against a real server: TESSERA_TEST_PG_URL (a
// superuser URL, as for the other Postgres tests).
func TestRunExtQueryPG(t *testing.T) {
	admin := os.Getenv("TESSERA_TEST_PG_URL")
	if !IsPostgresDSN(admin) {
		t.Skip("TESSERA_TEST_PG_URL is not set")
	}
	ctx := context.Background()
	db, err := sql.Open("pgx", admin)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, s := range []string{
		`DROP TABLE IF EXISTS loader_ext_people`,
		`DROP SEQUENCE IF EXISTS loader_ext_seq`,
		`CREATE SEQUENCE loader_ext_seq`,
		`CREATE TABLE loader_ext_people (grp text, subject text, seq bigint)`,
		`INSERT INTO loader_ext_people VALUES ('a','alice',1),('a','bob',2),('b','carol',3)`,
	} {
		if _, err := db.ExecContext(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DROP TABLE IF EXISTS loader_ext_people`)
		_, _ = db.Exec(`DROP SEQUENCE IF EXISTS loader_ext_seq`)
	})
	u, err := url.Parse(admin)
	if err != nil {
		t.Fatal(err)
	}
	u.RawQuery = "sslmode=disable"
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
	}
	run := func(q ExtPGQuery) (*ExtResult, error) {
		q.DSN, q.Dial = u.String(), dial
		return RunExtQueryPG(ctx, q)
	}
	res, err := run(ExtPGQuery{SQL: `SELECT grp AS group_name, subject AS subject_id FROM loader_ext_people ORDER BY seq`})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rows) != 3 || res.Columns[0] != "group_name" || res.Rows[2][1] != "carol" {
		t.Errorf("rows = %v %v", res.Columns, res.Rows)
	}
	// a parameter, compared as a number
	res, err = run(ExtPGQuery{SQL: `SELECT subject FROM loader_ext_people WHERE seq > @cursor ORDER BY seq`, Args: map[string]string{"cursor": "1"}})
	if err != nil || len(res.Rows) != 2 {
		t.Fatalf("incremental = %v %v", res, err)
	}
	// the row cap is an error, never a cut-off
	if _, err := run(ExtPGQuery{SQL: `SELECT subject FROM loader_ext_people`, MaxRows: 2}); !errors.Is(err, ErrExtRowLimit) {
		t.Errorf("row cap err = %v", err)
	}
	// the session is read-only: nextval passes the keyword check and is refused by the server
	if _, err := run(ExtPGQuery{SQL: `SELECT nextval('loader_ext_seq')`}); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Errorf("a write in the session: %v", err)
	}
	// the server stops a long query
	start := time.Now()
	_, err = run(ExtPGQuery{SQL: `SELECT pg_sleep(5)`, Timeout: time.Second})
	if err == nil || time.Since(start) > 4*time.Second {
		t.Errorf("a long query ran %s: %v", time.Since(start), err)
	}
	// a data-modifying statement is refused before it is sent
	if _, err := run(ExtPGQuery{SQL: `WITH ins AS (INSERT INTO loader_ext_people VALUES ('z','z',9) RETURNING 1) SELECT * FROM ins`}); err == nil {
		t.Error("a data-modifying statement ran")
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM loader_ext_people`).Scan(&n); err != nil || n != 3 {
		t.Errorf("rows after the attempt = %d, %v", n, err)
	}
}
