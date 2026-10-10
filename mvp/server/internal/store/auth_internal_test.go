package store

import (
	"context"
	"strings"
	"testing"
)

// TestLookupLintRejects: the hash-lookup lint accepts only the two §14.2
// shapes, so a lookup cannot widen into a cross-tenant read.
func TestLookupLintRejects(t *testing.T) {
	ok := []string{
		`SELECT s.tenant_id, s.id FROM sessions s WHERE s.secret_hash = @hash`,
		`SELECT t.tenant_id, t.id FROM login_transactions t WHERE t.cookie_hash = @hash`,
	}
	for _, q := range ok {
		if err := lintLookup(q); err != nil {
			t.Errorf("%s: %v", q, err)
		}
	}
	bad := []string{
		`SELECT s.tenant_id, s.id, s.csrf_secret FROM sessions s WHERE s.secret_hash = @hash`,
		`SELECT s.tenant_id, s.id FROM sessions s WHERE s.user_id = @hash`,
		`SELECT s.tenant_id, s.id FROM sessions s WHERE s.secret_hash = @hash OR 1 = 1`,
		`SELECT i.tenant_id, i.id FROM identities i WHERE i.email = @hash`,
		`SELECT s.tenant_id, s.id FROM sessions s`,
		`SELECT s.tenant_id, s.id FROM sessions s WHERE s.secret_hash LIKE @hash`,
	}
	for _, q := range bad {
		if err := lintLookup(q); err == nil {
			t.Errorf("accepted: %s", q)
		}
	}
	n := 0
	for _, st := range statements {
		if st.lookup {
			n++
		}
	}
	if n != len(GlobalHashLookups) {
		t.Errorf("%d lookup statements, want %d (one per GlobalHashLookups entry)", n, len(GlobalHashLookups))
	}
}

// TestAuthnContextsImmutable: authentication records cannot be changed or
// deleted, even with SQL outside the repositories.
func TestAuthnContextsImmutable(t *testing.T) {
	db := openTest(t)
	ctx := context.Background()
	for _, q := range []string{`UPDATE authn_contexts SET aal = 3`, `DELETE FROM authn_contexts`} {
		// the triggers fire per row; insert one row with foreign keys off
		if _, err := db.sql.ExecContext(ctx, `INSERT INTO authn_contexts (id, tenant_id, user_id, protocol, purpose, aal,
			phishing_resistant, phr_basis, tessera_acr, auth_time, mapping_profile, mapping_version, claims_sha256, created_at)
			VALUES ('x1', '00000000-0000-0000-0000-000000000001', 'u', 'oidc', 'login', 1, 0, 'none', 'urn:tessera:acr:aal1',
			't', 'p', 1, 'h', 't') ON CONFLICT DO NOTHING`); err != nil {
			t.Fatal(err)
		}
		if _, err := db.sql.ExecContext(ctx, q); err == nil || !strings.Contains(err.Error(), "immutable") {
			t.Errorf("%s: %v, want refused", q, err)
		}
	}
}
