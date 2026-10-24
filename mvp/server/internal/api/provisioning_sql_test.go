package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/provision/fake"
)

// A database target (issue #553): the connection is the sql object, the
// database password is the sealed write-only token, the base URL is derived
// (never typed), and a move to another host needs a new password.
func TestProvisioning_SQLTargetConfig(t *testing.T) {
	h := newProvHarness(t, fake.Options{})
	put := func(body string) (int, string) {
		rec := h.c.do("PUT", "/api/provisioning/targets/"+h.conn, body)
		return rec.Code, rec.Body.String()
	}
	good := `{"engine":"postgres","host":"db.example.com","database":"app","username":"tessera","mode":"native"}`
	for name, body := range map[string]string{
		"no sql":           `{"kind":"sql","token":"pw"}`,
		"no credential":    `{"kind":"sql","sql":` + good + `}`,
		"bad engine":       `{"kind":"sql","token":"pw","sql":{"engine":"db2","host":"db.example.com","username":"u","mode":"native"}}`,
		"host with a port": `{"kind":"sql","token":"pw","sql":{"engine":"postgres","host":"db:5432","username":"u","mode":"native"}}`,
		"bad statement":    `{"kind":"sql","token":"pw","sql":{"engine":"mysql","host":"db.example.com","username":"u","mode":"app","app":{"accounts_query":"DROP TABLE x"}}}`,
		"an agent":         `{"kind":"sql","token":"pw","agent_id":"abc","sql":` + good + `}`,
		"a fault":          `{"kind":"sql","token":"pw","fault":"fail_writes","sql":` + good + `}`,
		"unknown field":    `{"kind":"sql","token":"pw","sql":{"engine":"postgres","host":"db.example.com","username":"u","mode":"native","password":"x"}}`,
	} {
		if code, out := put(body); code != http.StatusUnprocessableEntity && code != http.StatusBadRequest {
			t.Errorf("%s: status %d: %s", name, code, out)
		}
	}
	code, out := put(`{"kind":"sql","token":"s3cr3t-db-pw","write_back":true,"sql":` + good + `}`)
	if code != http.StatusOK {
		t.Fatalf("status %d: %s", code, out)
	}
	if strings.Contains(out, "s3cr3t") {
		t.Error("the response carries the password")
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatal(err)
	}
	if v["kind"] != "sql" || v["has_credential"] != true || v["base_url"] != "sql://db.example.com:5432/postgres" {
		t.Errorf("target = %v", v)
	}
	if s, _ := v["sql"].(map[string]any); s == nil || s["host"] != "db.example.com" || s["username"] != "tessera" {
		t.Errorf("sql settings = %v", v["sql"])
	}
	if strings.Contains(h.auditDetail(), "s3cr3t") {
		t.Error("the audit event carries the password")
	}
	// the same settings keep the password; ANY change to the settings needs a new one
	if code, out := put(`{"kind":"sql","write_back":false,"sql":` + good + `}`); code != http.StatusOK {
		t.Errorf("an edit that keeps the settings: %d %s", code, out)
	}
	for name, edited := range map[string]string{
		"database": strings.Replace(good, `"app"`, `"other"`, 1),
		"host":     strings.Replace(good, "db.example.com", "evil.example.net", 1),
		"port":     strings.Replace(good, `"engine"`, `"port":6543,"engine"`, 1),
		"username": strings.Replace(good, `"tessera"`, `"admin"`, 1),
		"engine":   strings.Replace(good, `"postgres"`, `"mysql"`, 1),
		"mode":     strings.Replace(good, `"native"`, `"app","app":{"accounts_query":"SELECT id FROM u"}`, 1),
		"tls":      strings.Replace(good, `"engine"`, `"tls":"verify-full","engine"`, 1),
		"limits":   strings.Replace(good, `"engine"`, `"max_rows":5,"engine"`, 1),
	} {
		if code, out := put(`{"kind":"sql","write_back":true,"sql":` + edited + `}`); code != http.StatusUnprocessableEntity || !strings.Contains(out, "credential_required") {
			t.Errorf("changing %s without a password: %d %s", name, code, out)
		}
	}
	if code, out := put(`{"kind":"sql","token":"new-pw","write_back":true,"sql":` + strings.Replace(good, `"app"`, `"other"`, 1) + `}`); code != http.StatusOK {
		t.Errorf("a changed database with a new password: %d %s", code, out)
	}
}
