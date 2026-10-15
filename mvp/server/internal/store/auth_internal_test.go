package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
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

// TestValidReturnTo: only same-site paths are post-login redirect targets.
func TestValidReturnTo(t *testing.T) {
	ok := []string{"/", "/identities", "/jit?status=pending#top", "/a/b%2Fc", "/café", "/a//b"}
	bad := []string{"", "identities", "//evil.example", "///evil.example", "/\\evil.example", "/x\\y", "\\\\evil",
		"/\tevil", "/a\nb", "/a\rb", "/a\x00b", "/a\x7fb", "/a\u0085b", "/a\u009bb", "https://evil.example/",
		"/%zz", "/?", "/" + strings.Repeat("a", MaxReturnToLen), "/\xff"}
	for _, p := range ok {
		if !ValidReturnTo(p) {
			t.Errorf("refused %q", p)
		}
	}
	for _, p := range bad {
		if ValidReturnTo(p) {
			t.Errorf("accepted %q", p)
		}
	}
}

// TestReturnToSchemaCheck: the schema refuses an unsafe return_to even when
// the Go check is bypassed.
func TestReturnToSchemaCheck(t *testing.T) {
	db := openTest(t)
	ctx := context.Background()
	if _, err := db.sql.ExecContext(ctx, `PRAGMA foreign_keys = OFF`); err != nil {
		t.Fatal(err)
	}
	insert := func(i int, rt string) error {
		_, err := db.sql.ExecContext(ctx, `INSERT INTO login_transactions (id, tenant_id, cookie_hash, idp_connection_id,
			purpose, return_to, created_at, expires_at) VALUES (?, '00000000-0000-0000-0000-000000000001', ?, 'c', 'login', ?, 't', 't')`,
			fmt.Sprintf("lt%d", i), fmt.Sprintf("%064d", i), rt)
		return err
	}
	for i, rt := range []string{"/", "/jit?x=1", "/café"} {
		if err := insert(i, rt); err != nil {
			t.Errorf("%q: %v", rt, err)
		}
	}
	for i, rt := range []string{"//evil", "/\\evil", "x", "/a\tb", "/a\nb", "/a\x1fb", "/a\x7fb", "/" + strings.Repeat("a", 2048)} {
		if err := insert(100+i, rt); err == nil || !strings.Contains(err.Error(), "CHECK") {
			t.Errorf("%q: %v, want a CHECK failure", rt, err)
		}
	}
}

// TestReplayCacheUseOnce: a key is accepted once until it expires, then again.
func TestReplayCacheUseOnce(t *testing.T) {
	db := openTest(t)
	ctx := context.Background()
	now := nowUTC()
	h := fmt.Sprintf("%064d", 7)
	use := func(at time.Time) error {
		return db.InSystem(ctx, "test", func(s *SystemTx) error { return s.UseOnce(ReplaySAMLAssertion, h, at, now.Add(time.Minute)) })
	}
	if err := use(now); err != nil {
		t.Fatal(err)
	}
	if err := use(now.Add(30 * time.Second)); !errors.Is(err, ErrDuplicate) {
		t.Errorf("second use: %v", err)
	}
	if err := db.InSystem(ctx, "test", func(s *SystemTx) error {
		return s.UseOnce(ReplayDPoPJTI, h, now, now.Add(time.Minute))
	}); err != nil {
		t.Errorf("same hash, other kind: %v", err)
	}
	if err := use(now.Add(2 * time.Minute)); err != nil {
		t.Errorf("after expiry: %v", err)
	}
}
