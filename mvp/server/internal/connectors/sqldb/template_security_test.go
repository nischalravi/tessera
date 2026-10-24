package sqldb

import "testing"

// Statement-stacking and dynamic-SQL payloads must be refused for every engine:
// the lexer knows each engine's quoting forms, so nothing can hide a separator.
func TestParseTemplate_RefusesStackingAndDynamicSQL(t *testing.T) {
	reads := []string{
		"SELECT [a'] AS id FROM t; DROP TABLE users; SELECT ['] AS x",
		"SELECT $$a'$$ AS id FROM t; DROP TABLE users; SELECT $$'$$ AS x",
		"SELECT $tag$a'$tag$ AS id FROM t; DROP TABLE users; SELECT $tag$'$tag$",
		"SELECT q'[x']' AS id FROM dual; DROP TABLE users; SELECT q'[']' FROM dual",
		"SELECT nq'[x']' AS id FROM dual",
		"SELECT 1 AS id FROM t；DROP TABLE users", // full-width semicolon
		"SELECT 1 AS id FROM t WHERE x = 'a'; SELECT 2",
		"SELECT id FROM t WHERE n = 'x' -- '; DROP TABLE u",
		"SELECT `a'` AS id FROM t; DROP TABLE users; SELECT `'`",
		"EXEC sp_who",
		"SELECT * FROM OPENROWSET('SQLNCLI', 'x', 'SELECT 1')",
		"SELECT * FROM OPENQUERY(srv, 'SELECT 1')",
		"SELECT xp_cmdshell('dir') AS id",
		"SELECT DBMS_SQL.OPEN_CURSOR AS id FROM dual",
		"SELECT UTL_HTTP.REQUEST('http://x') AS id FROM dual",
		"SELECT LOAD_FILE('/etc/passwd') AS id",
		"SELECT 1 AS id INTO OUTFILE '/tmp/x'",
		"SELECT pg_read_file('/etc/passwd') AS id",
		"SELECT lo_import('/etc/passwd') AS id",
		"CALL do_something()",
		"WITH x AS (SELECT 1) EXECUTE IMMEDIATE 'x'",
		"SELECT 1 AS id; EXECUTE IMMEDIATE 'DROP TABLE t'",
		"COPY (SELECT 1) TO PROGRAM 'id'",
		"SELECT é AS id FROM t",
		"SELECT x$1 AS id, $1 FROM t",
	}
	writes := []string{
		"DELETE FROM [x'] WHERE 1=0; ALTER SERVER ROLE sysadmin ADD MEMBER evil; SELECT [']",
		"INSERT INTO t (a) EXEC sp_executesql N'DROP TABLE x'",
		"INSERT INTO t (a) VALUES (:username); DROP TABLE t",
		"UPDATE t SET a = $$x'$$ WHERE u = :username; DROP TABLE t; SELECT $$'$$",
		"UPDATE t SET a = :username WHERE b IN (SELECT 1 FROM OPENQUERY(s, 'x'))",
		"DELETE FROM t WHERE u = :username; GRANT ALL ON t TO evil",
		"INSERT INTO t (a) SELECT xp_cmdshell('x')",
		"UPDATE t SET a = q'[x']' WHERE u = :username",
		"DELETE FROM t WHERE u = :username OR 1 IN (SELECT 1 FROM dual WHERE DBMS_X.F() = 1)",
		"UPDATE t SET a = 1 WHERE u = :username AND (SELECT 1 FROM x WHERE DROP_ME = 1) = 1 DROP TABLE u",
		"INSERT INTO t (a) VALUES (:username) -- x",
		"DELETE FROM t WHERE u = :username /* ; DROP TABLE t */",
	}
	for _, e := range Engines {
		for _, q := range reads {
			if _, err := ParseTemplate(q, classSelect, e); err == nil {
				t.Errorf("%s accepted the read %q", e, q)
			}
		}
		for _, q := range writes {
			if _, err := ParseTemplate(q, classWrite, e); err == nil {
				t.Errorf("%s accepted the write %q", e, q)
			}
		}
	}
}

// Quoting forms of an engine are lexed as that engine reads them, so a separator or
// keyword inside them is text, not a statement.
func TestParseTemplate_AcceptsEngineQuoting(t *testing.T) {
	tests := []struct {
		engine string
		class  stmtClass
		sql    string
	}{
		{SQLServer, classSelect, "SELECT [id], [a;b], [x]]; DROP]] AS name FROM [users]"},
		{SQLServer, classSelect, "SELECT N'a;b' AS id FROM t"},
		{SQLServer, classWrite, "DELETE FROM [my table] WHERE [user id] = :username"},
		{MySQL, classSelect, "SELECT `id`, `a;b` AS username FROM `users`"},
		{MySQL, classWrite, "UPDATE `users` SET `drop` = 1 WHERE `name` = :username"},
		{Postgres, classSelect, `SELECT "a;b" AS id, 'x;y' AS username, a$b AS email FROM t`},
		{Oracle, classSelect, `SELECT "ID" AS id, 'it''s;' AS username FROM app_users`},
		{Oracle, classWrite, `INSERT INTO app_users (username) VALUES (:username)`},
	}
	for _, tt := range tests {
		if _, err := ParseTemplate(tt.sql, tt.class, tt.engine); err != nil {
			t.Errorf("%s refused %q: %v", tt.engine, tt.sql, err)
		}
	}
}

// Validation uses the connection's engine, so a bracket statement is valid for SQL Server only.
func TestConfig_ValidateUsesTheEngine(t *testing.T) {
	c := goodConfig(SQLServer)
	c.Mode, c.App = ModeApp, &App{AccountsQuery: "SELECT [id] FROM [users]"}
	if err := c.Validate(prodRT); err != nil {
		t.Fatal(err)
	}
	c.Engine = Postgres
	if err := c.Validate(prodRT); err == nil {
		t.Error("a [bracket] statement was valid for PostgreSQL")
	}
}
