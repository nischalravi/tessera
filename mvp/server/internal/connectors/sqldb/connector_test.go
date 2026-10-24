package sqldb

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

type nativeData struct {
	accounts, roles, members, privs [][]string
}

// loadCatalog answers the engine's fixed catalogue statements with rows. Roles
// and members rows are given per query in order (SQL Server has two of each).
func loadCatalog(f *fakeDB, engine string, d nativeData, rolesPer, membersPer [][][]string) {
	c := catalogues[engine]
	f.answer(c.Accounts, []string{"name", "status"}, d.accounts...)
	for i, p := range c.Roles {
		var rows [][]string
		if i < len(rolesPer) {
			rows = rolesPer[i]
		}
		f.answer(p.SQL, []string{"name"}, rows...)
	}
	for i, p := range c.Members {
		var rows [][]string
		if i < len(membersPer) {
			rows = membersPer[i]
		}
		f.answer(p.SQL, []string{"member", "role"}, rows...)
	}
	f.answer(c.Privs, []string{"grantee", "privilege"}, d.privs...)
}

func connectorFor(f *fakeDB, cfg Config) *Connector {
	return &Connector{cfg: cfg, pw: connsync.NewSecret("pw"), rt: prodRT, open: func(bool) (*sql.DB, error) { return f.db(), nil }}
}

func group(res *connectors.DiscoveryResult, id string) *connectors.GroupRecord {
	for i := range res.Groups {
		if res.Groups[i].ExternalID == id {
			return &res.Groups[i]
		}
	}
	return nil
}

func hasEdge(res *connectors.DiscoveryResult, srcKind, src, rel, dstKind, dst string) bool {
	for _, e := range res.Edges {
		if e.Src.Kind == srcKind && e.Src.ExternalID == src && e.Relation == rel && e.Dst.Kind == dstKind && e.Dst.ExternalID == dst {
			return true
		}
	}
	return false
}

func TestDiscover_NativePostgres(t *testing.T) {
	f := newFake()
	loadCatalog(f, Postgres, nativeData{
		accounts: [][]string{{"alice", "active"}, {"bob", "locked"}},
		privs:    [][]string{{"dba", "SUPERUSER"}, {"readers", "CREATEDB"}, {"ghost", "SUPERUSER"}},
	}, [][][]string{{{"dba"}, {"readers"}}}, [][][]string{{{"alice", "dba"}, {"bob", "readers"}, {"readers", "dba"}}})
	res, err := connectorFor(f, goodConfig(Postgres)).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Partial != "" || len(res.Accounts) != 2 {
		t.Fatalf("partial %q accounts %v", res.Partial, res.Accounts)
	}
	if res.Accounts[0].Username != "alice" || res.Accounts[0].Status != "active" || res.Accounts[1].Status != "disabled" {
		t.Errorf("accounts = %+v", res.Accounts)
	}
	if g := group(res, "dba"); g == nil || !g.Privileged {
		t.Errorf("dba group = %+v", g)
	}
	// readers is a member of dba, so it inherits the superuser role
	if g := group(res, "readers"); g == nil || !g.Privileged {
		t.Errorf("readers group = %+v", g)
	}
	if !hasEdge(res, "account", "alice", "member_of", "group", "dba") || !hasEdge(res, "group", "readers", "member_of", "group", "dba") {
		t.Errorf("edges = %+v", res.Edges)
	}
	if !hasEdge(res, "group", "dba", "grants", "perm", "SUPERUSER") {
		t.Errorf("no grants edge for dba: %+v", res.Edges)
	}
	for _, p := range res.Permissions {
		if p.ExternalID == "SUPERUSER" && !p.Privileged || p.ExternalID == "CREATEDB" && p.Privileged {
			t.Errorf("permission %+v", p)
		}
	}
	// a grant to a name that is neither account nor role is dropped
	if hasEdge(res, "group", "ghost", "grants", "perm", "SUPERUSER") {
		t.Error("an edge for an unknown grantee")
	}
	if len(res.Resources) != 1 || res.Resources[0].Kind != "database" {
		t.Errorf("resources = %+v", res.Resources)
	}
	// reads run in a read-only transaction, and the handle is closed
	for _, o := range f.Txs {
		if !o.ReadOnly {
			t.Errorf("a read ran in a read-write transaction: %+v", f.Txs)
		}
	}
	if len(f.Execs) != 0 || !f.Closed {
		t.Errorf("execs %v closed %v", f.Execs, f.Closed)
	}
}

func TestDiscover_NativeMySQL(t *testing.T) {
	f := newFake()
	loadCatalog(f, MySQL, nativeData{
		accounts: [][]string{{"alice@%", "active"}, {"batch@10.0.0.%", "locked"}},
		privs:    [][]string{{"alice@%", "SUPER"}},
	}, [][][]string{{{"app_read@%"}}}, [][][]string{{{"alice@%", "app_read@%"}}})
	res, err := connectorFor(f, goodConfig(MySQL)).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !hasEdge(res, "account", "alice@%", "member_of", "group", "app_read@%") || !hasEdge(res, "account", "alice@%", "direct_grant", "perm", "SUPER") {
		t.Errorf("edges = %+v", res.Edges)
	}
	if res.Accounts[1].Status != "disabled" || res.Accounts[1].ExternalID != "batch@10.0.0.%" {
		t.Errorf("accounts = %+v", res.Accounts)
	}
	for _, o := range f.Txs {
		if !o.ReadOnly {
			t.Error("MySQL read was not read-only")
		}
	}
}

func TestDiscover_NativeSQLServer(t *testing.T) {
	f := newFake()
	loadCatalog(f, SQLServer, nativeData{
		accounts: [][]string{{"sa", "active"}, {"svc_app", "locked"}},
		privs:    [][]string{{"sa", "CONTROL SERVER"}, {"securityadmin", "ALTER ANY LOGIN"}, {"svc_app", "VIEW ANY DEFINITION"}},
	}, [][][]string{{{"sysadmin"}, {"securityadmin"}}, {{"db_owner"}, {"db_datareader"}}},
		[][][]string{{{"sa", "sysadmin"}}, {{"svc_app", "db_datareader"}, {"svc_app", "db_owner"}}})
	res, err := connectorFor(f, goodConfig(SQLServer)).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]bool{"server:sysadmin": true, "server:securityadmin": true, "db:db_owner": true, "db:db_datareader": false} {
		if g := group(res, id); g == nil || g.Privileged != want {
			t.Errorf("group %s = %+v, want privileged %v", id, g, want)
		}
	}
	if !hasEdge(res, "account", "sa", "member_of", "group", "server:sysadmin") || !hasEdge(res, "account", "svc_app", "member_of", "group", "db:db_owner") {
		t.Errorf("edges = %+v", res.Edges)
	}
	// a server permission granted to a server role (its name has no prefix in the catalogue)
	if !hasEdge(res, "group", "server:securityadmin", "grants", "perm", "ALTER ANY LOGIN") || !hasEdge(res, "account", "sa", "direct_grant", "perm", "CONTROL SERVER") {
		t.Errorf("grant edges missing: %+v", res.Edges)
	}
	// SQL Server has no read-only transaction in its driver: none is asked for, and no statement is sent to fake one
	for _, o := range f.Txs {
		if o.ReadOnly {
			t.Error("SQL Server asked for a read-only transaction, which go-mssqldb refuses")
		}
	}
}

func TestDiscover_NativeOracle(t *testing.T) {
	f := newFake()
	loadCatalog(f, Oracle, nativeData{
		accounts: [][]string{{"APPUSER", "active"}, {"OLDUSER", "locked"}},
		privs:    [][]string{{"DBA", "SELECT ANY TABLE"}, {"APP_RO", "CREATE SESSION"}},
	}, [][][]string{{{"DBA"}, {"APP_RO"}}}, [][][]string{{{"APPUSER", "DBA"}, {"OLDUSER", "APP_RO"}}})
	res, err := connectorFor(f, goodConfig(Oracle)).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if g := group(res, "DBA"); g == nil || !g.Privileged {
		t.Errorf("DBA = %+v", g)
	}
	if g := group(res, "APP_RO"); g == nil || g.Privileged {
		t.Errorf("APP_RO = %+v", g)
	}
	// the read-only transaction is the Oracle statement, sent first
	if len(f.Execs) == 0 || f.Execs[0] != "SET TRANSACTION READ ONLY" {
		t.Errorf("execs = %v", f.Execs)
	}
	for _, e := range f.Execs {
		if e != "SET TRANSACTION READ ONLY" {
			t.Errorf("a read sent %q", e)
		}
	}
}

func TestDiscover_RowCapIsPartial(t *testing.T) {
	f := newFake()
	loadCatalog(f, Postgres, nativeData{accounts: [][]string{{"a", "active"}, {"b", "active"}, {"c", "active"}}}, nil, nil)
	cfg := goodConfig(Postgres)
	cfg.MaxRows = 2
	res, err := connectorFor(f, cfg).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Accounts) != 2 || !strings.Contains(res.Partial, "accounts") {
		t.Fatalf("accounts %d, partial %q", len(res.Accounts), res.Partial)
	}
}

func TestDiscover_ErrorsDoNotLeakThePassword(t *testing.T) {
	f := newFake()
	f.failQuery = "pg_roles"
	_, err := connectorFor(f, goodConfig(Postgres)).Discover(context.Background())
	if err == nil || !strings.Contains(err.Error(), "accounts") {
		t.Fatalf("err = %v", err)
	}
	// an error that echoes the password is scrubbed
	c := connectorFor(f, goodConfig(Postgres))
	c.open = func(bool) (*sql.DB, error) { return nil, errString("cannot log in with pw") }
	_, err = c.Discover(context.Background())
	if err == nil || strings.Contains(err.Error(), "with pw") || !strings.Contains(err.Error(), "REDACTED") {
		t.Fatalf("err = %v", err)
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func appConfig() Config {
	c := goodConfig(Postgres)
	c.Mode = ModeApp
	c.App = &App{
		AccountsQuery:     "SELECT user_id AS id, login AS username, mail AS email, state AS status FROM app_users",
		EntitlementsQuery: "SELECT login AS account, role_name AS entitlement, role_desc AS description FROM app_roles",
		CreateAccount:     "INSERT INTO app_users (login, mail) VALUES (:username, :email)",
		DisableAccount:    "UPDATE app_users SET state = 'disabled' WHERE login = :username",
		DeleteAccount:     "DELETE FROM app_users WHERE login = :username",
		AddEntitlement:    "INSERT INTO app_roles (login, role_name) VALUES (:username, :entitlement)",
		RemoveEntitlement: "DELETE FROM app_roles WHERE login = :username AND role_name = :entitlement",
	}
	return c
}

func loadApp(f *fakeDB, c Config) {
	f.answer(c.App.AccountsQuery, []string{"id", "username", "email", "status"},
		[]string{"7", "alice", "Alice@Example.com", "active"}, []string{"8", "bob", "<null>", "disabled"}, []string{"", "ghost", "", ""})
	f.answer(c.App.EntitlementsQuery, []string{"account", "entitlement", "description"},
		[]string{"alice", "approver", "Can approve"}, []string{"8", "approver", ""}, []string{"alice", "approver", ""}, []string{"nobody", "x", ""})
}

func TestDiscover_AppMode(t *testing.T) {
	c := appConfig()
	f := newFake()
	loadApp(f, c)
	res, err := connectorFor(f, c).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Accounts) != 2 {
		t.Fatalf("accounts = %+v", res.Accounts)
	}
	a := res.Accounts[0]
	if a.ExternalID != "7" || a.Username != "alice" || a.Status != "active" || a.Identity == nil || a.Identity.Email != "alice@example.com" {
		t.Errorf("alice = %+v", a)
	}
	if res.Accounts[1].Status != "disabled" || res.Accounts[1].Identity != nil {
		t.Errorf("bob = %+v", res.Accounts[1])
	}
	if len(res.Groups) != 1 || res.Groups[0].ExternalID != "approver" || res.Groups[0].Description == nil || *res.Groups[0].Description != "Can approve" {
		t.Errorf("groups = %+v", res.Groups)
	}
	// alice by username and bob by id, each once; a row for an unknown account is dropped
	if len(res.Edges) != 2 || !hasEdge(res, "account", "7", "member_of", "group", "approver") || !hasEdge(res, "account", "8", "member_of", "group", "approver") {
		t.Errorf("edges = %+v", res.Edges)
	}
}

func TestDiscover_AppModeNeedsColumns(t *testing.T) {
	c := appConfig()
	f := newFake()
	f.answer(c.App.AccountsQuery, []string{"login"}, []string{"x"})
	if _, err := connectorFor(f, c).Discover(context.Background()); err == nil || !strings.Contains(err.Error(), "column named id") {
		t.Fatalf("err = %v", err)
	}
	f = newFake()
	f.answer(c.App.AccountsQuery, []string{"id"}, []string{"1"})
	f.answer(c.App.EntitlementsQuery, []string{"who"}, []string{"1"})
	if _, err := connectorFor(f, c).Discover(context.Background()); err == nil || !strings.Contains(err.Error(), "account and entitlement") {
		t.Fatalf("err = %v", err)
	}
}

func TestConnector_Identity(t *testing.T) {
	c, err := NewConnector(goodConfig(MySQL), connsync.NewSecret("pw"), prodRT)
	if err != nil {
		t.Fatal(err)
	}
	if c.System() != "sql" || c.DisplayName() != "MySQL" || c.TypeName() != "SQLConnector" {
		t.Errorf("%s %s %s", c.System(), c.DisplayName(), c.TypeName())
	}
	if err := c.StreamEvents(context.Background(), nil, nil); err != nil {
		t.Error(err)
	}
	if _, err := NewConnector(goodConfig(MySQL), connsync.Secret{}, prodRT); err == nil {
		t.Error("no password accepted")
	}
	bad := goodConfig(MySQL)
	bad.TLS = TLSDisable
	if _, err := NewConnector(bad, connsync.NewSecret("pw"), prodRT); err == nil {
		t.Error("tls disable accepted in prod")
	}
}

func TestFromEnv(t *testing.T) {
	env := map[string]string{"TESSERA_SQL_ENGINE": "postgres", "TESSERA_SQL_HOST": "db.example.com", "TESSERA_SQL_USERNAME": "ro",
		"TESSERA_SQL_PASSWORD": "env:DBPW", "DBPW": "s3cret", "TESSERA_SQL_PORT": "6432"}
	getenv := func(k string) string { return env[k] }
	read := func(string) ([]byte, error) { return nil, errString("no file") }
	c, err := FromEnv(getenv, read, prodRT)
	if err != nil {
		t.Fatal(err)
	}
	if c.System() != "sql" {
		t.Error(c.System())
	}
	env["TESSERA_SQL_PASSWORD"] = "literal-password"
	if _, err := FromEnv(getenv, read, prodRT); err == nil || strings.Contains(err.Error(), "literal-password") {
		t.Errorf("a literal password: %v", err)
	}
	env["TESSERA_SQL_PASSWORD"] = "env:DBPW"
	env["TESSERA_SQL_PORT"] = "x"
	if _, err := FromEnv(getenv, read, prodRT); err == nil {
		t.Error("bad port accepted")
	}
	env["TESSERA_SQL_PORT"] = ""
	env["TESSERA_SQL_APP"] = "/etc/app.json"
	if _, err := FromEnv(getenv, read, prodRT); err == nil {
		t.Error("a missing app file was accepted")
	}
}
