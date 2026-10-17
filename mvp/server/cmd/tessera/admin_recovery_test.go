package main

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/keys"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// recoveryDB is a fresh database with tenant acme and an active Okta connection.
func recoveryDB(t *testing.T) (db, connID string) {
	t.Helper()
	t.Setenv("TESSERA_ENV", "dev")
	t.Setenv("TESSERA_NOW", "2026-10-08T09:30:00")
	t.Setenv("TESSERA_PUBLIC_URL", "http://localhost:5173")
	t.Setenv("USER", "op-jane")
	dir := t.TempDir()
	db = filepath.Join(dir, "t.db")
	st, err := store.OpenFresh(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	if _, err := adminRun(t, db, "create-tenant", "-slug", "acme", "-name", "Acme Corp"); err != nil {
		t.Fatal(err)
	}
	secret := writeFile(t, dir, "secret", "s3cret\n")
	out, err := adminRun(t, db, "add-idp", "-tenant", "acme", "-file", writeFile(t, dir, "okta.yaml", oktaYAML), "-client-secret-file", secret)
	m := regexp.MustCompile(`added connection ([0-9a-f-]{36})`).FindStringSubmatch(out)
	if err != nil || m == nil {
		t.Fatalf("add-idp: %v %s", err, out)
	}
	return db, m[1]
}

func openTenant(t *testing.T, db string) (*store.DB, store.Tenant) {
	t.Helper()
	st, err := store.Open(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	var acme store.Tenant
	if err := st.ReadSystem(context.Background(), "test", func(s *store.SystemTx) error {
		var err error
		acme, err = s.TenantBySlug("acme")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return st, acme
}

// TestAdminRecoverTenant (design §15.5): two different operators, each
// attested phishing-resistant, put the tenant in recovery and get a one-time
// invitation that works 72 hours later; refused requests change nothing.
func TestAdminRecoverTenant(t *testing.T) {
	db, conn := recoveryDB(t)
	args := func(extra ...string) []string {
		return append([]string{"recover-tenant", "-tenant", "acme", "-ticket", "SUP-1042", "-connection", conn,
			"-email", "new.admin@acme.example"}, extra...)
	}
	for name, a := range map[string][]string{
		"one operator twice": args("-operator", "op-jane", "-co-operator", "op-jane", "-operator-phr", "-co-operator-phr"),
		"no co-operator":     args("-operator", "op-jane", "-operator-phr", "-co-operator-phr"),
		"no phr attestation": args("-operator", "op-jane", "-co-operator", "op-raj"),
		"one without phr":    args("-operator", "op-jane", "-co-operator", "op-raj", "-operator-phr"),
		"unknown tenant":     {"recover-tenant", "-tenant", "nope", "-operator", "a", "-co-operator", "b", "-operator-phr", "-co-operator-phr"},
		"bad connection":     {"recover-tenant", "-tenant", "acme", "-operator", "a", "-co-operator", "b", "-ticket", "T", "-connection", "x", "-email", "a@b.example", "-operator-phr", "-co-operator-phr"},
	} {
		if out, err := adminRun(t, db, a...); err == nil {
			t.Errorf("%s: accepted: %s", name, out)
		}
	}
	st, acme := openTenant(t, db)
	if acme.Status != "active" {
		t.Fatalf("tenant status %s after refused requests, want active", acme.Status)
	}
	_ = st.Close()

	out, err := adminRun(t, db, args("-operator", "op-jane", "-co-operator", "op-raj", "-operator-phr", "-co-operator-phr")...)
	code := regexp.MustCompile(`/t/acme/bootstrap\?code=(tbi_[A-Za-z0-9_-]+)`).FindStringSubmatch(out)
	if err != nil || code == nil || !strings.Contains(out, "usable from 2026-10-11T09:30:00Z") {
		t.Fatalf("recover-tenant: %v %s", err, out)
	}
	st, acme = openTenant(t, db)
	if acme.Status != "recovery" {
		t.Errorf("tenant status = %s, want recovery", acme.Status)
	}
	if err := st.ReadTenant(context.Background(), acme.ID, func(tx *store.TenantTx) error {
		rec, err := tx.PendingTenantRecovery()
		if err != nil {
			return err
		}
		want := time.Date(2026, 10, 11, 9, 30, 0, 0, time.UTC)
		if rec.Operator != "op-jane" || rec.CoOperator != "op-raj" || rec.Ticket != "SUP-1042" || !rec.NotBefore.Equal(want) {
			t.Errorf("recovery %+v", rec)
		}
		inv, err := tx.BootstrapInvitationByCodeHash(seal.SHA256Hex([]byte(code[1])))
		if err != nil || inv.ID != rec.InvitationID || inv.CreatedBy != "op-jane+op-raj" {
			t.Errorf("invitation %+v %v", inv, err)
		}
		events, err := tx.AuditLog(-1)
		if err != nil {
			return err
		}
		found := false
		for _, e := range events {
			if e.Action == "recovery.requested" && e.ActorType == store.ActorOperator {
				found = true
			}
			if strings.Contains(string(e.Detail), code[1]) {
				t.Errorf("%s leaks the invitation code", e.Action)
			}
		}
		if !found {
			t.Error("no recovery.requested event by the operator in the tenant's chain")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.ReadTenant(context.Background(), tenancy.Platform, func(tx *store.TenantTx) error {
		events, err := tx.AuditLog(-1)
		if err != nil {
			return err
		}
		for _, e := range events {
			if e.Action == "recovery.requested" && strings.Contains(string(e.Detail), "op-jane") && strings.Contains(string(e.Detail), "op-raj") {
				return nil
			}
		}
		t.Error("no recovery.requested event naming both operators in the platform chain")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// a second recovery while one is pending is refused
	if out, err := adminRun(t, db, args("-operator", "op-a", "-co-operator", "op-b", "-operator-phr", "-co-operator-phr")...); err == nil {
		t.Errorf("a second recovery was accepted: %s", out)
	}
}

// TestAdminRevokeSigningKey: revoking a tenant's active signing key drops it
// from the JWKS at once, activates the next key, and is audited by operator.
func TestAdminRevokeSigningKey(t *testing.T) {
	db, _ := recoveryDB(t)
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := cfg.Sealer(config.DevKEKPath(db))
	if err != nil {
		t.Fatal(err)
	}
	st, acme := openTenant(t, db)
	now := cfg.Clock()().UTC()
	var active string
	if err := st.InTenant(context.Background(), acme.ID, func(tx *store.TenantTx) error {
		if err := keys.EnsureKeys(tx, "acme", sealer, now); err != nil {
			return err
		}
		ks, err := keys.PublishedKeys(tx, store.KeyPurposeAccessToken, now)
		for _, k := range ks {
			if k.Status == store.KeyActive {
				active = k.KID
			}
		}
		return err
	}); err != nil || active == "" {
		t.Fatalf("no active key: %v", err)
	}
	_ = st.Close()

	for name, a := range map[string][]string{
		"unknown key":    {"revoke-signing-key", "-tenant", "acme", "-kid", "acme-19990101-zzzzzz", "-reason", "leaked"},
		"no reason":      {"revoke-signing-key", "-tenant", "acme", "-kid", active},
		"unknown tenant": {"revoke-signing-key", "-tenant", "nope", "-kid", active, "-reason", "leaked"},
		"no kid":         {"revoke-signing-key", "-tenant", "acme", "-reason", "leaked"},
	} {
		if out, err := adminRun(t, db, a...); err == nil {
			t.Errorf("%s: accepted: %s", name, out)
		}
	}
	out, err := adminRun(t, db, "revoke-signing-key", "-tenant", "acme", "-kid", active, "-reason", "laptop with the key was stolen")
	if err != nil || !strings.Contains(out, "revoked signing key "+active) {
		t.Fatalf("revoke-signing-key: %v %s", err, out)
	}
	if out, err := adminRun(t, db, "revoke-signing-key", "-tenant", "acme", "-kid", active, "-reason", "again"); err == nil {
		t.Errorf("revoking twice was accepted: %s", out)
	}
	st, acme = openTenant(t, db)
	if err := st.ReadTenant(context.Background(), acme.ID, func(tx *store.TenantTx) error {
		ks, err := keys.PublishedKeys(tx, store.KeyPurposeAccessToken, now)
		if err != nil {
			return err
		}
		newActive := ""
		for _, k := range ks {
			if k.KID == active {
				t.Errorf("the revoked key %s is still published", active)
			}
			if k.Status == store.KeyActive {
				newActive = k.KID
			}
		}
		if newActive == "" || newActive == active {
			t.Errorf("no new active key after the revocation (active %q)", newActive)
		}
		events, err := tx.AuditLog(-1)
		if err != nil {
			return err
		}
		for _, e := range events {
			if e.Action == "keys.signing_key.revoked" {
				if e.ActorType != store.ActorOperator || !strings.Contains(string(e.Detail), "laptop with the key was stolen") {
					t.Errorf("revocation event %s by %s", e.Detail, e.ActorType)
				}
				return nil
			}
		}
		t.Error("no keys.signing_key.revoked event")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
