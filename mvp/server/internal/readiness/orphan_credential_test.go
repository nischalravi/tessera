package readiness

import (
	"encoding/json"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Issue #838: a sealed credential row goes with the reference that pointed at it (an endpoint change,
// a replaced credential, a retired connection), so nothing sealed for a dropped credential stays at rest.
func TestSealedCredentialRowsFollowTheReference(t *testing.T) {
	const cfg = `{"technical_owner":"Ingrid","business_owner":"Thandiwe","correlation_key":"username","org_url":"https://acme.okta.com"}`
	setup := func(t *testing.T) (Scope, *Service, string) {
		st, s := newStore(t), liveSvc(t)
		var id string
		write(t, st, func(c *store.TenantTx) error {
			b, err := s.Create(c, CreateInput{Name: "C", ConnectorType: "okta", System: "sys", Config: json.RawMessage(cfg)}, "admin", t0)
			if err != nil {
				return err
			}
			id = b.Conn.ID
			_, err = s.SetCredential(c, id, CredentialInput{Secret: "s1"}, "admin", t0)
			return err
		})
		return st, s, id
	}
	rows := func(t *testing.T, st Scope) int {
		n := 0
		read(t, st, func(c *store.TenantTx) error {
			ks, err := c.Credentials(store.PurposeBind)
			n = len(ks)
			return err
		})
		return n
	}
	t.Run("endpoint change", func(t *testing.T) {
		st, s, id := setup(t)
		if n := rows(t, st); n != 1 {
			t.Fatalf("rows before = %d, want 1", n)
		}
		write(t, st, func(c *store.TenantTx) error {
			_, err := s.PatchConfig(c, id, []byte(`{"org_url":"https://other.okta.com"}`), "admin", t0)
			return err
		})
		if n := rows(t, st); n != 0 {
			t.Fatalf("rows after the endpoint change = %d, want 0", n)
		}
	})
	t.Run("replaced credential", func(t *testing.T) {
		st, s, id := setup(t)
		for _, in := range []CredentialInput{{Secret: "s2"}, {Reference: "vault:kv/tessera/x"}} {
			write(t, st, func(c *store.TenantTx) error {
				_, err := s.SetCredential(c, id, in, "admin", t0)
				return err
			})
		}
		// s1 and s2 were both replaced; the vault reference has no row.
		if n := rows(t, st); n != 0 {
			t.Fatalf("rows after two replacements = %d, want 0", n)
		}
	})
	t.Run("replaced by another secret keeps one row", func(t *testing.T) {
		st, s, id := setup(t)
		write(t, st, func(c *store.TenantTx) error {
			_, err := s.SetCredential(c, id, CredentialInput{Secret: "s2"}, "admin", t0)
			return err
		})
		if n := rows(t, st); n != 1 {
			t.Fatalf("rows = %d, want 1", n)
		}
	})
	t.Run("retire", func(t *testing.T) {
		st, s, id := setup(t)
		write(t, st, func(c *store.TenantTx) error { return s.Retire(c, id, "admin", t0) })
		if n := rows(t, st); n != 0 {
			t.Fatalf("rows after retire = %d, want 0", n)
		}
	})
}
