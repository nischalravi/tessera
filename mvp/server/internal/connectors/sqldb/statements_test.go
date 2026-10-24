package sqldb

import (
	"regexp"
	"strings"
	"testing"
)

func TestQuote(t *testing.T) {
	long := strings.Repeat("a", 129)
	tests := []struct {
		engine, in, want string
		bad              bool
	}{
		{Postgres, "alice", `"alice"`, false},
		{Postgres, `a"b`, `"a""b"`, false},
		{Postgres, `x"; DROP ROLE y; --`, `"x""; DROP ROLE y; --"`, false},
		{MySQL, "alice", "`alice`", false},
		{MySQL, "a`b", "`a``b`", false},
		{SQLServer, "alice", "[alice]", false},
		{SQLServer, "a]b", "[a]]b]", false},
		{SQLServer, `CORP\alice`, `[CORP\alice]`, false},
		{SQLServer, "x]; DROP LOGIN y; --", "[x]]; DROP LOGIN y; --]", false},
		{Oracle, "ALICE", `"ALICE"`, false},
		{Oracle, `A"B`, "", true}, // Oracle cannot write a double quote inside a quoted name
		{Postgres, "", "", true},
		{Postgres, "a\x00b", "", true},
		{Postgres, "a\nb", "", true},
		{Postgres, long, "", true},
		{Postgres, "a\xffb", "", true},
		{"db2", "alice", "", true},
	}
	for _, tt := range tests {
		got, err := Quote(tt.engine, tt.in)
		if (err != nil) != tt.bad || got != tt.want {
			t.Errorf("Quote(%s, %q) = %q, %v; want %q (bad=%v)", tt.engine, tt.in, got, err, tt.want, tt.bad)
		}
	}
}

func TestQuoteMySQLAccount(t *testing.T) {
	tests := []struct {
		in, want string
		bad      bool
	}{
		{"alice", `'alice'@'%'`, false},
		{"alice@db.example", `'alice'@'db.example'`, false},
		{"alice@corp.com@%", `'alice@corp.com'@'%'`, false},
		{"o'neil@%", `'o''neil'@'%'`, false},
		{`a\b@%`, "", true},
		{"@host", "", true},
		{"user@", "", true},
		{"", "", true},
		{"a\x00@%", "", true},
	}
	for _, tt := range tests {
		got, err := QuoteMySQLAccount(tt.in)
		if (err != nil) != tt.bad || got != tt.want {
			t.Errorf("QuoteMySQLAccount(%q) = %q, %v; want %q (bad=%v)", tt.in, got, err, tt.want, tt.bad)
		}
	}
}

// The golden statements: what each engine runs for each operation. Identifiers
// are quoted, values are never spliced, and a hostile name stays inside its quotes.
func TestStatements_Golden(t *testing.T) {
	tests := []struct {
		name         string
		engine       string
		op           int
		who, role    string
		want         []string
		wantPattern  string // for statements holding the random secret
		wantErrMatch string
	}{
		{name: "pg create", engine: Postgres, op: opCreate, who: "alice", want: []string{`CREATE ROLE "alice" LOGIN`}},
		{name: "pg lock", engine: Postgres, op: opLock, who: "alice", want: []string{`ALTER ROLE "alice" NOLOGIN`, `COMMENT ON ROLE "alice" IS 'tessera:locked'`}},
		{name: "pg unlock", engine: Postgres, op: opUnlock, who: "alice", want: []string{`ALTER ROLE "alice" LOGIN`, `COMMENT ON ROLE "alice" IS NULL`}},
		{name: "pg drop", engine: Postgres, op: opDrop, who: "alice", want: []string{`DROP ROLE "alice"`}},
		{name: "pg grant", engine: Postgres, op: opGrant, who: "alice", role: "readers", want: []string{`GRANT "readers" TO "alice"`}},
		{name: "pg revoke", engine: Postgres, op: opRevoke, who: "alice", role: "readers", want: []string{`REVOKE "readers" FROM "alice"`}},
		{name: "pg hostile", engine: Postgres, op: opGrant, who: `x" TO public; --`, role: `r"`, want: []string{`GRANT "r""" TO "x"" TO public; --"`}},

		{name: "mysql create", engine: MySQL, op: opCreate, who: "alice@%", want: []string{`CREATE USER 'alice'@'%' IDENTIFIED BY RANDOM PASSWORD`}},
		{name: "mysql lock", engine: MySQL, op: opLock, who: "alice@%", want: []string{`ALTER USER 'alice'@'%' ACCOUNT LOCK`}},
		{name: "mysql unlock", engine: MySQL, op: opUnlock, who: "alice@%", want: []string{`ALTER USER 'alice'@'%' ACCOUNT UNLOCK`}},
		{name: "mysql drop", engine: MySQL, op: opDrop, who: "alice@%", want: []string{`DROP USER 'alice'@'%'`}},
		{name: "mysql grant", engine: MySQL, op: opGrant, who: "alice@%", role: "readers@%", want: []string{`GRANT 'readers'@'%' TO 'alice'@'%'`}},
		{name: "mysql revoke", engine: MySQL, op: opRevoke, who: "alice@%", role: "readers@%", want: []string{`REVOKE 'readers'@'%' FROM 'alice'@'%'`}},
		{name: "mysql hostile", engine: MySQL, op: opDrop, who: `x' OR '1'='1@%`, want: []string{`DROP USER 'x'' OR ''1''=''1'@'%'`}},
		{name: "mysql backslash", engine: MySQL, op: opDrop, who: `x\@%`, wantErrMatch: "backslash"},

		{name: "mssql create", engine: SQLServer, op: opCreate, who: "alice", wantPattern: `^CREATE LOGIN \[alice\] WITH PASSWORD = N'[A-Za-z0-9_-]{32}aA1_', CHECK_POLICY = ON$`},
		{name: "mssql lock", engine: SQLServer, op: opLock, who: "alice", want: []string{`ALTER LOGIN [alice] DISABLE`}},
		{name: "mssql unlock", engine: SQLServer, op: opUnlock, who: "alice", want: []string{`ALTER LOGIN [alice] ENABLE`}},
		{name: "mssql drop", engine: SQLServer, op: opDrop, who: "alice", want: []string{`DROP LOGIN [alice]`}},
		{name: "mssql server grant", engine: SQLServer, op: opGrant, who: "alice", role: "server:sysadmin", want: []string{`ALTER SERVER ROLE [sysadmin] ADD MEMBER [alice]`}},
		{name: "mssql server revoke", engine: SQLServer, op: opRevoke, who: "alice", role: "server:sysadmin", want: []string{`ALTER SERVER ROLE [sysadmin] DROP MEMBER [alice]`}},
		{name: "mssql db grant", engine: SQLServer, op: opGrant, who: "alice", role: "db:db_datareader", want: []string{`ALTER ROLE [db_datareader] ADD MEMBER [alice]`}},
		{name: "mssql db revoke", engine: SQLServer, op: opRevoke, who: "alice", role: "db:db_datareader", want: []string{`ALTER ROLE [db_datareader] DROP MEMBER [alice]`}},
		{name: "mssql unscoped role", engine: SQLServer, op: opGrant, who: "alice", role: "sysadmin", wantErrMatch: "server: or db:"},
		{name: "mssql hostile", engine: SQLServer, op: opDrop, who: "x]; DROP LOGIN sa; --", want: []string{`DROP LOGIN [x]]; DROP LOGIN sa; --]`}},

		{name: "oracle create", engine: Oracle, op: opCreate, who: "ALICE", wantPattern: `^CREATE USER "ALICE" IDENTIFIED BY "Tq1[0-9a-f]{24}"$`},
		{name: "oracle lock", engine: Oracle, op: opLock, who: "ALICE", want: []string{`ALTER USER "ALICE" ACCOUNT LOCK`}},
		{name: "oracle unlock", engine: Oracle, op: opUnlock, who: "ALICE", want: []string{`ALTER USER "ALICE" ACCOUNT UNLOCK`}},
		{name: "oracle drop", engine: Oracle, op: opDrop, who: "ALICE", want: []string{`DROP USER "ALICE"`}},
		{name: "oracle grant", engine: Oracle, op: opGrant, who: "ALICE", role: "APP_READ", want: []string{`GRANT "APP_READ" TO "ALICE"`}},
		{name: "oracle revoke", engine: Oracle, op: opRevoke, who: "ALICE", role: "APP_READ", want: []string{`REVOKE "APP_READ" FROM "ALICE"`}},
		{name: "oracle quote refused", engine: Oracle, op: opDrop, who: `A" CASCADE --`, wantErrMatch: "double quote"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := statements(tt.engine, tt.op, tt.who, tt.role)
			if tt.wantErrMatch != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrMatch) {
					t.Fatalf("err = %v, want one containing %q", err, tt.wantErrMatch)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tt.wantPattern != "" {
				if len(got) != 1 || !regexp.MustCompile(tt.wantPattern).MatchString(got[0]) {
					t.Fatalf("got %q, want a match of %s", got, tt.wantPattern)
				}
				return
			}
			if strings.Join(got, "\n") != strings.Join(tt.want, "\n") {
				t.Fatalf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(tt.want, "\n"))
			}
		})
	}
}

// Oracle's throw-away password: at most 30 bytes, starts with a letter, letters and digits only.
func TestOracleSecretRules(t *testing.T) {
	re := regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{7,29}$`)
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		s, err := oracleSecret()
		if err != nil || !re.MatchString(s) || seen[s] {
			t.Fatalf("secret %q err %v (repeat %v)", s, err, seen[s])
		}
		seen[s] = true
	}
}

// Two creates never share a secret.
func TestStatements_SecretsDiffer(t *testing.T) {
	a, _ := statements(SQLServer, opCreate, "x", "")
	b, _ := statements(SQLServer, opCreate, "x", "")
	if a[0] == b[0] {
		t.Fatal("the generated credential repeated")
	}
}

var literalRE = regexp.MustCompile(`'[^']*'`)

// Every catalogue statement is fixed text: it takes no parameter and holds no
// placeholder, and each engine has all four readers.
func TestCatalogues_Shape(t *testing.T) {
	for _, e := range Engines {
		c, ok := catalogues[e]
		if !ok {
			t.Fatalf("no catalogue for %s", e)
		}
		qs := []string{c.Accounts, c.Privs}
		for _, p := range c.Roles {
			qs = append(qs, p.SQL)
		}
		for _, p := range c.Members {
			qs = append(qs, p.SQL)
		}
		if len(c.Roles) == 0 || len(c.Members) == 0 {
			t.Errorf("%s: no role or member statement", e)
		}
		for _, q := range qs {
			up := strings.ToUpper(strings.TrimSpace(literalRE.ReplaceAllString(q, "''"))) // words in literals do not count
			if !strings.HasPrefix(up, "SELECT") {
				t.Errorf("%s: %q is not a SELECT", e, q)
			}
			if strings.ContainsAny(q, "?;") || strings.Contains(q, "$1") || strings.Contains(q, "@p1") {
				t.Errorf("%s: %q takes a parameter or holds a semicolon", e, q)
			}
			for _, w := range []string{"INSERT ", "UPDATE ", "DELETE ", "DROP ", "ALTER ", "CREATE ", "GRANT "} {
				if strings.Contains(up, w) {
					t.Errorf("%s: %q contains %s", e, q, w)
				}
			}
		}
	}
}

func TestPrivileged(t *testing.T) {
	for _, p := range []string{"SUPERUSER", "super", "CONTROL SERVER", "SELECT ANY TABLE", "drop any table", "GRANT ANY ROLE"} {
		if !privilegedPriv(p) {
			t.Errorf("%q should be privileged", p)
		}
	}
	for _, p := range []string{"CREATE SESSION", "CREATEDB", "CONNECT SQL", "PROCESS"} {
		if privilegedPriv(p) {
			t.Errorf("%q should not be privileged", p)
		}
	}
}
