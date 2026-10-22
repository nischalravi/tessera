package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
)

// Test support for running the whole suite on Postgres (PR14). Like
// TamperForTest it exists for test binaries only (every entry point refuses
// otherwise). It lives in this package because only internal/store may import
// a database driver.
//
// With TESSERA_TEST_PG_URL unset the helpers hand out SQLite files and the
// suite is unchanged. With it set (a superuser or CREATEDB+CREATEROLE URL to
// any database of a throwaway server) every test gets its own database and the
// store opens it as the application role tessera_app, so row-level security
// binds the whole suite:
//
//	TESSERA_TEST_PG_URL='postgres://postgres@127.0.0.1:8455/postgres?sslmode=disable' go test ./...
//
// TESSERA_REQUIRE_PG_TESTS=1 turns "no Postgres configured" into a failure for
// the tests that exist only for Postgres.

// PostgresTestURL is the admin URL of the test server, or "".
func PostgresTestURL() string { return os.Getenv("TESSERA_TEST_PG_URL") }

// RequirePostgresTests reports whether a missing Postgres must fail the
// Postgres-only tests instead of skipping them.
func RequirePostgresTests() bool { return os.Getenv("TESSERA_REQUIRE_PG_TESTS") == "1" }

// PostgresForTest returns the admin URL, skipping the test when none is
// configured (or failing it when TESSERA_REQUIRE_PG_TESTS=1).
func PostgresForTest(tb testing.TB) string {
	tb.Helper()
	mustBeTest()
	u := PostgresTestURL()
	if u == "" {
		if RequirePostgresTests() {
			tb.Fatal("TESSERA_REQUIRE_PG_TESTS=1 but TESSERA_TEST_PG_URL is not set")
		}
		tb.Skip("TESSERA_TEST_PG_URL is not set; skipping the Postgres test")
	}
	return u
}

func mustBeTest() {
	if !testing.Testing() {
		panic(ErrNotATest)
	}
}

// TestTarget returns a database setting for a fresh, empty database of this
// test: a SQLite file in tb.TempDir(), or, with TESSERA_TEST_PG_URL set, a
// new Postgres database (dropped when the test ends). That setting is the
// owner's DSN (it migrates); Open and OpenApp pair it with the tessera_app
// login for the request pool, as a deployment does with TESSERA_DB_APP.
func TestTarget(tb testing.TB) string {
	tb.Helper()
	mustBeTest()
	admin := PostgresTestURL()
	if admin == "" {
		return filepath.Join(tb.TempDir(), "test.db")
	}
	name := "tessera_t_" + randHex(8)
	target, err := createTestDatabase(admin, name, "")
	if err != nil {
		tb.Fatalf("store: test database: %v", err)
	}
	tb.Cleanup(func() { dropTestDatabase(tb, admin, name) })
	return target
}

// TestSharedTarget builds a database once (in dir for SQLite, a template
// database for Postgres), for TestClone to copy per test. build receives the
// setting to open and must close its store before returning. Postgres
// templates of test binaries that are no longer running are dropped first.
func TestSharedTarget(dir, name string, build func(target string) error) (string, error) {
	mustBeTest()
	admin := PostgresTestURL()
	if admin == "" {
		p := filepath.Join(dir, name+".db")
		return p, build(p)
	}
	dropStaleTemplates(admin)
	db := "tessera_tpl_" + strconv.Itoa(os.Getpid()) + "_" + name
	target, err := createTestDatabase(admin, db, "")
	if err != nil {
		return "", err
	}
	sharedMu.Lock()
	shared = append(shared, db)
	sharedMu.Unlock()
	return target, build(target)
}

var (
	sharedMu sync.Mutex
	shared   []string // template databases this binary created
)

// DropSharedTargets drops the Postgres template databases this test binary
// made (testkit.Main calls it). A binary that dies first leaves its template
// for the next run's stale sweep.
func DropSharedTargets() {
	mustBeTest()
	admin := PostgresTestURL()
	if admin == "" {
		return
	}
	db, err := sql.Open("pgx", admin)
	if err != nil {
		return
	}
	defer db.Close()
	sharedMu.Lock()
	defer sharedMu.Unlock()
	for _, n := range shared {
		_, _ = db.Exec("DROP DATABASE IF EXISTS " + n + " WITH (FORCE)") // #nosec G202 -- generated names
	}
	shared = nil
}

// TestClone returns a private copy of a database made by TestSharedTarget: a
// copied SQLite file, or a Postgres database created FROM the template.
func TestClone(tb testing.TB, src string) string {
	tb.Helper()
	mustBeTest()
	if !IsPostgresDSN(src) {
		dst := filepath.Join(tb.TempDir(), filepath.Base(src))
		if err := copyFile(src, dst); err != nil {
			tb.Fatal(err)
		}
		return dst
	}
	admin := PostgresTestURL()
	srcDB, err := dbNameOf(src)
	if err != nil {
		tb.Fatal(err)
	}
	name := "tessera_t_" + randHex(8)
	target, err := createTestDatabase(admin, name, srcDB)
	if err != nil {
		tb.Fatalf("store: clone test database: %v", err)
	}
	tb.Cleanup(func() { dropTestDatabase(tb, admin, name) })
	return target
}

func copyFile(src, dst string) error {
	in, err := os.Open(src) // #nosec G304 -- test fixture path
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst) // #nosec G304 -- test fixture path
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

var ensureRoleOnce sync.Once

// testAppPassword is the password of the tessera_app login on the test server.
const testAppPassword = "tessera_app_test" // #nosec G101 -- throwaway test-server login

var (
	testAppMu   sync.Mutex
	testAppDSNs = map[string]string{} // owner DSN -> tessera_app DSN of the same database
)

// testAppDSN is the application-login DSN registered for a test database's
// owner DSN, or "" (always "" outside test binaries).
func testAppDSN(owner string) string {
	if !testing.Testing() {
		return ""
	}
	testAppMu.Lock()
	defer testAppMu.Unlock()
	return testAppDSNs[owner]
}

// TestAppDSN returns the tessera_app login's DSN for a database made by
// TestTarget or TestClone ("" for SQLite).
func TestAppDSN(target string) string {
	mustBeTest()
	return testAppDSN(target)
}

// createTestDatabase creates database name (FROM template when given) on the
// admin server, makes sure the tessera_app login exists (LOGIN with a
// password, NOSUPERUSER NOBYPASSRLS, member of nothing), and returns the
// owner DSN of the new database, registering its tessera_app DSN. name and template are generated here, never
// taken from input.
func createTestDatabase(adminURL, name, template string) (string, error) {
	db, err := sql.Open("pgx", adminURL)
	if err != nil {
		return "", err
	}
	defer db.Close()
	var roleErr error
	ensureRoleOnce.Do(func() {
		// CREATE ROLE has no IF NOT EXISTS; a concurrent test binary may win the race.
		_, err := db.Exec(`CREATE ROLE tessera_app LOGIN PASSWORD '` + testAppPassword + `' NOSUPERUSER NOBYPASSRLS`) // #nosec G202 -- constant
		if err != nil && !strings.Contains(err.Error(), "already exists") && !strings.Contains(err.Error(), "tuple concurrently updated") {
			roleErr = err
			return
		}
		// A role left NOLOGIN by an older run of the suite.
		if _, err := db.Exec(`ALTER ROLE tessera_app LOGIN PASSWORD '` + testAppPassword + `' NOSUPERUSER NOBYPASSRLS`); err != nil { // #nosec G202 -- constant
			roleErr = err
		}
	})
	if roleErr != nil {
		return "", roleErr
	}
	q := "CREATE DATABASE " + name // #nosec G202 -- generated names
	if template != "" {
		q += " TEMPLATE " + template // #nosec G202 -- generated names
	}
	if _, err := db.Exec(q); err != nil { // #nosec G202 -- generated names
		return "", err
	}
	u, err := url.Parse(adminURL)
	if err != nil {
		return "", errors.New("store: invalid TESSERA_TEST_PG_URL")
	}
	u.Path = "/" + name
	owner := u.String()
	u.User = url.UserPassword("tessera_app", testAppPassword)
	testAppMu.Lock()
	testAppDSNs[owner] = u.String()
	testAppMu.Unlock()
	return owner, nil
}

func dbNameOf(dsn string) (string, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return "", errors.New("store: invalid postgres DSN")
	}
	return strings.TrimPrefix(u.Path, "/"), nil
}

func dropTestDatabase(tb testing.TB, adminURL, name string) {
	db, err := sql.Open("pgx", adminURL)
	if err != nil {
		tb.Logf("store: drop test database %s: %v", name, err)
		return
	}
	defer db.Close()
	if _, err := db.Exec("DROP DATABASE IF EXISTS " + name + " WITH (FORCE)"); err != nil { // #nosec G202 -- generated names
		tb.Logf("store: drop test database %s: %v", name, err)
	}
}

// dropStaleTemplates drops tessera_tpl_<pid>_* databases whose test binary
// is gone. Best effort.
func dropStaleTemplates(adminURL string) {
	db, err := sql.Open("pgx", adminURL)
	if err != nil {
		return
	}
	defer db.Close()
	rows, err := db.Query(`SELECT datname FROM pg_database WHERE datname LIKE 'tessera\_tpl\_%'`)
	if err != nil {
		return
	}
	var stale []string
	for rows.Next() {
		var n string
		if rows.Scan(&n) != nil {
			continue
		}
		parts := strings.SplitN(strings.TrimPrefix(n, "tessera_tpl_"), "_", 2)
		pid, err := strconv.Atoi(parts[0])
		if err != nil || pid == os.Getpid() {
			continue
		}
		if p, err := os.FindProcess(pid); err == nil && p.Signal(syscall.Signal(0)) == nil {
			continue // still running
		}
		stale = append(stale, n)
	}
	_ = rows.Close()
	for _, n := range stale {
		_, _ = db.Exec("DROP DATABASE IF EXISTS " + n + " WITH (FORCE)") // #nosec G202 -- names read back from pg_database with our prefix
	}
}

// ExtPGSource is a throwaway Postgres database that stands for a customer's
// database in the tests of the loaders' Postgres source (RunExtQueryPG). Like
// the rest of this file it is for test binaries only.
type ExtPGSource struct {
	// DSN reaches the database in the form a loader's secret takes
	// (sslmode=disable: the test server has no certificate).
	DSN   string
	admin string
	owner string
}

// NewExtPGSourceForTest creates the database (dropped when the test ends), or
// skips the test when no Postgres is configured.
func NewExtPGSourceForTest(tb testing.TB) *ExtPGSource {
	tb.Helper()
	admin := PostgresForTest(tb)
	name := "tessera_ext_" + randHex(6)
	owner, err := createTestDatabase(admin, name, "")
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { dropTestDatabase(tb, admin, name) })
	u, err := url.Parse(owner)
	if err != nil {
		tb.Fatal(err)
	}
	u.RawQuery = "sslmode=disable"
	return &ExtPGSource{DSN: u.String(), admin: admin, owner: owner}
}

// Statements runs statements on the database as its owner.
func (s *ExtPGSource) Statements(tb testing.TB, stmts ...string) {
	tb.Helper()
	db, err := sql.Open("pgx", s.owner)
	if err != nil {
		tb.Fatal(err)
	}
	defer db.Close()
	for _, q := range stmts {
		if _, err := db.Exec(q); err != nil {
			tb.Fatalf("%s: %v", q, err)
		}
	}
}
