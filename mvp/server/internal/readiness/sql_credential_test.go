package readiness

import (
	"encoding/json"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// The password of a database connection was entered for its settings: any change to the
// sql settings drops the credential (a new one must be entered), other edits keep it.
func TestSQLConfigChangeClearsTheCredential(t *testing.T) {
	st, s := newStore(t), newSvc(t)
	var id string
	write(t, st, func(c *store.TenantTx) error {
		b, err := s.Create(c, CreateInput{Name: "Orders DB", ConnectorType: "sql", System: "orders-db",
			Config: json.RawMessage(`{"technical_owner":"Ingrid","business_owner":"Thandiwe","correlation_key":"username",
				"sql":{"engine":"postgres","host":"db.example.com","database":"orders","username":"tessera_ro","mode":"native"}}`)}, "admin", t0)
		if err != nil {
			return err
		}
		id = b.Conn.ID
		_, err = s.SetCredential(c, id, CredentialInput{Reference: "vault:kv/tessera/orders"}, "admin", t0)
		return err
	})
	patch := func(body string) *ConfigResult {
		var res *ConfigResult
		write(t, st, func(c *store.TenantTx) error {
			var err error
			res, err = s.PatchConfig(c, id, []byte(body), "admin", t0)
			return err
		})
		return res
	}
	present := func(res *ConfigResult) bool { return res.Bundle.Rev.SecretRef != nil }
	if !present(patch(`{"stale_days":60}`)) {
		t.Fatal("an unrelated edit dropped the credential")
	}
	for name, body := range map[string]string{
		"host":     `{"sql":{"engine":"postgres","host":"evil.example.net","database":"orders","username":"tessera_ro","mode":"native"}}`,
		"database": `{"sql":{"engine":"postgres","host":"evil.example.net","database":"other","username":"tessera_ro","mode":"native"}}`,
		"mode":     `{"sql":{"engine":"postgres","host":"evil.example.net","database":"other","username":"tessera_ro","mode":"app","app":{"accounts_query":"SELECT id FROM u"}}}`,
		"limits":   `{"sql":{"engine":"postgres","host":"evil.example.net","database":"other","username":"tessera_ro","mode":"app","max_rows":10,"app":{"accounts_query":"SELECT id FROM u"}}}`,
	} {
		// put a credential back before each change, so each one is shown to clear it
		write(t, st, func(c *store.TenantTx) error {
			_, err := s.SetCredential(c, id, CredentialInput{Reference: "vault:kv/tessera/orders"}, "admin", t0)
			return err
		})
		if res := patch(body); present(res) {
			t.Errorf("changing %s kept the credential", name)
		}
	}
	// the same settings again keep a re-entered credential
	const final = `{"sql":{"engine":"postgres","host":"evil.example.net","database":"other","username":"tessera_ro","mode":"app","max_rows":10,"app":{"accounts_query":"SELECT id FROM u"}}}`
	patch(final)
	write(t, st, func(c *store.TenantTx) error {
		_, err := s.SetCredential(c, id, CredentialInput{Reference: "vault:kv/tessera/orders"}, "admin", t0)
		return err
	})
	if res := patch(final); !present(res) {
		t.Error("an unchanged sql object dropped the credential")
	}
}
