package sqldb

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseTemplate_Accepts(t *testing.T) {
	tests := []struct {
		name  string
		class stmtClass
		sql   string
		names []string
	}{
		{"select", classSelect, "SELECT id, username, email, status FROM app_users", nil},
		{"select with cast and literal", classSelect, "SELECT id::text AS id, 'a:b' AS note FROM t WHERE created > '2020-01-01 12:30:00'", nil},
		{"with", classSelect, "WITH x AS (SELECT 1 AS id) SELECT id FROM x", nil},
		{"quoted keyword is text", classSelect, `SELECT 'DROP TABLE x' AS "delete" FROM t`, nil},
		{"insert", classWrite, "INSERT INTO app_users (username, email) VALUES (:username, :email)", []string{"username", "email"}},
		{"update", classWrite, "UPDATE app_users SET display_name = :display_name WHERE username = :username", []string{"display_name", "username"}},
		{"delete", classWrite, "DELETE FROM app_users WHERE username = :username", []string{"username"}},
		{"repeated", classWrite, "UPDATE t SET a = :username WHERE b = :username", []string{"username", "username"}},
		{"attr", classWrite, "UPDATE t SET dept = :attr_department WHERE u = :username", []string{"attr_department", "username"}},
		{"newlines", classWrite, "INSERT INTO t (a)\nVALUES (:username)", []string{"username"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tpl, err := ParseTemplate(tt.sql, tt.class, Postgres)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(tpl.Names, tt.names) {
				t.Fatalf("names = %v, want %v", tpl.Names, tt.names)
			}
		})
	}
}

func TestParseTemplate_Refuses(t *testing.T) {
	tests := []struct {
		name  string
		class stmtClass
		sql   string
		want  string
	}{
		{"empty", classSelect, "  ", "empty"},
		{"two statements", classSelect, "SELECT 1; SELECT 2", "one statement"},
		{"trailing semicolon", classSelect, "SELECT 1;", "one statement"},
		{"line comment", classSelect, "SELECT 1 -- x", "comments"},
		{"block comment", classSelect, "SELECT /* x */ 1", "comments"},
		{"hash comment", classSelect, "SELECT 1 # x", "comments"},
		{"select not first", classSelect, "DELETE FROM t", "start with SELECT"},
		{"write in read", classSelect, "SELECT * FROM t WHERE id IN (DELETE FROM t RETURNING id)", "DELETE"},
		{"select into", classSelect, "SELECT * INTO dup FROM t", "INTO"},
		{"cte write", classSelect, "WITH d AS (DELETE FROM t RETURNING 1) SELECT * FROM d", "DELETE"},
		{"placeholder in read", classSelect, "SELECT * FROM t WHERE u = :username", "no placeholders"},
		{"unknown placeholder", classWrite, "UPDATE t SET a = :password WHERE u = :username", "unknown placeholder :password"},
		{"upper placeholder", classWrite, "UPDATE t SET a = :Username", "lower case"},
		{"numeric placeholder", classWrite, "UPDATE t SET a = :1", "lower case"},
		{"bare colon", classWrite, "UPDATE t SET a = : x", "lower case"},
		{"write must be dml", classWrite, "SELECT 1", "must start with INSERT"},
		{"ddl", classWrite, "DROP TABLE t", "not allowed"},
		{"grant", classWrite, "GRANT ALL ON t TO x", "not allowed"},
		{"cte in write", classWrite, "WITH x AS (SELECT 1) INSERT INTO t SELECT * FROM x", "must start with INSERT"},
		{"unterminated", classSelect, "SELECT 'abc FROM t", "unterminated"},
		{"backslash in quotes", classSelect, `SELECT 'a\' FROM t`, "backslash"},
		{"control", classSelect, "SELECT 1\x00", "control"},
		{"too long", classSelect, "SELECT " + strings.Repeat("1,", 5000) + "1", "8192"},
		{"attr too long", classWrite, "UPDATE t SET a = :attr_" + strings.Repeat("x", 70), "unknown placeholder"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseTemplate(tt.sql, tt.class, Postgres)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want one containing %q", err, tt.want)
			}
		})
	}
}

// Golden rendering: the engine's bind markers, in order, and the arguments.
func TestTemplate_Bind(t *testing.T) {
	tpl, err := ParseTemplate("UPDATE app SET email = :email, note = ':email' WHERE name = :username AND alt = :username", classWrite, Postgres)
	if err != nil {
		t.Fatal(err)
	}
	vals := map[string]string{"username": "o'neil", "email": ""}
	want := map[string]string{
		Postgres:  "UPDATE app SET email = $1, note = ':email' WHERE name = $2 AND alt = $3",
		MySQL:     "UPDATE app SET email = ?, note = ':email' WHERE name = ? AND alt = ?",
		SQLServer: "UPDATE app SET email = @p1, note = ':email' WHERE name = @p2 AND alt = @p3",
		Oracle:    "UPDATE app SET email = :1, note = ':email' WHERE name = :2 AND alt = :3",
	}
	for engine, w := range want {
		got, args := tpl.Bind(engine, vals)
		if got != w {
			t.Errorf("%s: got %q, want %q", engine, got, w)
		}
		if !reflect.DeepEqual(args, []any{nil, "o'neil", "o'neil"}) {
			t.Errorf("%s: args = %#v", engine, args)
		}
		if strings.Contains(got, "neil") {
			t.Errorf("%s: a value was spliced into the statement: %q", engine, got)
		}
	}
}

// A hostile value is only ever an argument.
func TestTemplate_BindNeverSplices(t *testing.T) {
	tpl, _ := ParseTemplate("DELETE FROM t WHERE u = :username", classWrite, MySQL)
	evil := "x'; DROP TABLE t; --"
	q, args := tpl.Bind(MySQL, map[string]string{"username": evil})
	if q != "DELETE FROM t WHERE u = ?" || len(args) != 1 || args[0] != evil {
		t.Fatalf("q=%q args=%v", q, args)
	}
}
