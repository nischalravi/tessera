package sqldb

import "testing"

// A banned function name is refused inside every quoted-identifier form too, in either case,
// and string literals are still only text.
func TestParseTemplate_RefusesQuotedFunctionNames(t *testing.T) {
	names := []string{"pg_read_file", "PG_READ_BINARY_FILE", "pg_ls_dir", "pg_stat_file", "lo_import", "lo_export", "dblink", "dblink_exec",
		"pg_terminate_backend", "pg_cancel_backend", "pg_reload_conf", "set_config", "DBMS_XMLGEN", "DBMS_JAVA", "UTL_FILE", "UTL_HTTP",
		"DBMS_SCHEDULER", "LOAD_FILE", "sys_exec", "xp_cmdshell", "XP_regread", "sp_executesql", "OpenRowset"}
	for _, n := range names {
		forms := map[string]struct{ engine, sql string }{
			"double quotes": {Postgres, `SELECT "` + n + `"('x') AS id FROM t`},
			"oracle":        {Oracle, `SELECT "` + n + `"('x') AS id FROM dual`},
			"backticks":     {MySQL, "SELECT `" + n + "`('x') AS id FROM t"},
			"brackets":      {SQLServer, `SELECT [` + n + `]('x') AS id FROM t`},
			"qualified":     {Postgres, `SELECT "public"."` + n + `"('x') AS id FROM t`},
			"write":         {Postgres, `UPDATE t SET a = "` + n + `"(:username)`},
			"in a phrase":   {SQLServer, `SELECT [my ` + n + ` x] AS id FROM t`},
		}
		for form, f := range forms {
			class := classSelect
			if form == "write" {
				class = classWrite
			}
			if _, err := ParseTemplate(f.sql, class, f.engine); err == nil {
				t.Errorf("%s: %s accepted", form, f.sql)
			}
		}
	}
	// a string literal holding the word is text, not a call
	if _, err := ParseTemplate(`SELECT 'pg_read_file' AS id FROM t`, classSelect, Postgres); err != nil {
		t.Errorf("a string literal was refused: %v", err)
	}
	// ordinary quoted names still work
	for engine, q := range map[string]string{Postgres: `SELECT "User ID" AS id FROM "app users"`, MySQL: "SELECT `user_id` AS id FROM `users`",
		SQLServer: `SELECT [user id] AS id FROM [dbo].[users]`, Oracle: `SELECT "USER_ID" AS id FROM "APP"."USERS"`} {
		if _, err := ParseTemplate(q, classSelect, engine); err != nil {
			t.Errorf("%s refused %q: %v", engine, q, err)
		}
	}
}
