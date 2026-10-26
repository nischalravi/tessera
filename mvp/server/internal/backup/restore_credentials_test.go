package backup_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/backup"
	"github.com/nischalravi/tessera/mvp/server/internal/keys"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// credRows are the credentials seedCredentials leaves valid in tenant A.
type credRows struct {
	session uuid.UUID
	txn     uuid.UUID
	pending uuid.UUID // unconsumed bootstrap invitation
	used    uuid.UUID // consumed bootstrap invitation
}

func seedCredentials(t *testing.T, f *fixture) credRows {
	t.Helper()
	var r credRows
	hash := func(c byte) string { return strings.Repeat(string(c), 64) }
	err := f.db.InTenant(context.Background(), tenantA, func(c *store.TenantTx) error {
		iss, cid, email := "https://idp.example/", "client", "a@example.com"
		conn := &store.IdPConnection{Name: "conn", Protocol: "oidc", Profile: store.ProfileDevMock, Status: "active",
			Issuer: &iss, ClientID: &cid, CreatedAt: t0, UpdatedAt: t0}
		if err := c.InsertIdPConnection(conn); err != nil {
			return err
		}
		user := &store.PlatformUser{Email: &email, DisplayName: "a", CreatedAt: t0}
		if err := c.InsertPlatformUser(user); err != nil {
			return err
		}
		actx := &store.AuthnContextRecord{UserID: user.ID, IdPConnectionID: &conn.ID, Protocol: "oidc", Purpose: "login",
			AAL: 2, PhishingResistant: true, PhrBasis: "acr", TesseraACR: "urn:tessera:acr:phr", AuthTime: t0,
			MappingProfile: "dev_mock", MappingVersion: 1, ClaimsSHA256: "x", CreatedAt: t0}
		if err := c.InsertAuthnContext(actx); err != nil {
			return err
		}
		h, csrf := hash('a'), "csrf"
		sess := &store.Session{UserID: user.ID, Kind: store.SessionBrowser, SecretHash: &h, CSRFSecret: &csrf,
			InitialAuthnContextID: actx.ID, CurrentAuthnContextID: actx.ID, CreatedAt: t0, LastActivityAt: t0,
			IdleExpiresAt: t0.Add(time.Hour), AbsoluteExpiresAt: t0.Add(24 * time.Hour)}
		if err := c.InsertSession(sess); err != nil {
			return err
		}
		pending := &store.BootstrapInvitation{CodeHash: hash('b'), IdPConnectionID: conn.ID, Email: email, CreatedBy: "op",
			CreatedAt: t0, ExpiresAt: t0.Add(24 * time.Hour)}
		used := &store.BootstrapInvitation{CodeHash: hash('c'), IdPConnectionID: conn.ID, Email: email, CreatedBy: "op",
			CreatedAt: t0, ExpiresAt: t0.Add(24 * time.Hour)}
		for _, inv := range []*store.BootstrapInvitation{pending, used} {
			if err := c.InsertBootstrapInvitation(inv); err != nil {
				return err
			}
		}
		if err := c.ConsumeBootstrapInvitation(used.ID, user.ID, t0); err != nil {
			return err
		}
		txn := &store.LoginTransaction{CookieHash: hash('d'), IdPConnectionID: conn.ID, Purpose: "bootstrap",
			BootstrapInvitationID: &pending.ID, CreatedAt: t0, ExpiresAt: t0.Add(10 * time.Minute)}
		if err := c.InsertLoginTransaction(txn); err != nil {
			return err
		}
		r = credRows{session: sess.ID, txn: txn.ID, pending: pending.ID, used: used.ID}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestRestore_InvalidatesCredentials: a backup holds sessions, sign-in
// transactions, bootstrap codes and access-token keys that may have been
// revoked, consumed or rotated since. The restored database must not trust
// any of them, and a verify-only run changes nothing.
func TestRestore_InvalidatesCredentials(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	rows := seedCredentials(t, f)
	c := f.backup(t)

	if _, err := backup.Restore(ctx, c.Path, f.sealer, backup.RestoreOptions{Now: t0}); err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(f.dir, "restored.db")
	restoredAt := t0.Add(time.Hour)
	res, err := backup.Restore(ctx, c.Path, f.sealer, backup.RestoreOptions{Target: target, Anchors: f.anchorSet(t), Now: restoredAt})
	if err != nil {
		t.Fatal(err)
	}
	// tenant-a and tenant-b each hold an active and a next access_token and aws_federation key;
	// the platform key signs audit checkpoints and is not a tenant credential
	if got := res.Invalidated; got.Sessions != 1 || got.LoginTransactions != 1 || got.Invitations != 1 || got.SigningKeys != 8 {
		t.Errorf("invalidated %+v", got)
	}

	db, err := store.Open(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.ReadTenant(ctx, tenantA, func(tx *store.TenantTx) error {
		s, err := tx.Session(rows.session)
		if err != nil {
			t.Fatal(err)
		}
		if s.Status != "revoked" || s.RevokedReason == nil || *s.RevokedReason != backup.InvalidationReason {
			t.Errorf("session %q reason %v, want revoked/restore", s.Status, s.RevokedReason)
		}
		if _, err := tx.LoginTransaction(rows.txn); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("login transaction survived the restore: %v", err)
		}
		if _, err := tx.BootstrapInvitation(rows.pending); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("unconsumed bootstrap invitation survived the restore: %v", err)
		}
		if inv, err := tx.BootstrapInvitation(rows.used); err != nil || inv.ConsumedAt == nil {
			t.Errorf("a consumed invitation is history and must stay: %v", err)
		}
		access, err := tx.SigningKeys(store.KeyPurposeAccessToken)
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range access {
			if k.Status != store.KeyRevoked {
				t.Errorf("access_token key %s is %s after restore, want revoked", k.KID, k.Status)
			}
		}
		idp, err := tx.SigningKeys(store.KeyPurposeIdPClientAuth)
		if err != nil {
			t.Fatal(err)
		}
		active := 0
		for _, k := range idp {
			if k.Status == store.KeyActive {
				active++
			}
		}
		if active != 1 {
			t.Errorf("idp_client_auth keys are registered with IdPs and must stay: %d active", active)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// the start-up key check mints a fresh, usable access-token key
	if err := keys.EnsureAll(ctx, db, f.sealer, restoredAt); err != nil {
		t.Fatal(err)
	}
	if err := db.InTenant(ctx, tenantA, func(tx *store.TenantTx) error {
		_, err := keys.ActiveSigningKey(tx, store.KeyPurposeAccessToken, f.sealer)
		return err
	}); err != nil {
		t.Errorf("no usable access-token key after start: %v", err)
	}
	if err := db.InTenant(ctx, tenantA, func(tx *store.TenantTx) error {
		_, err := keys.ActiveSigningKey(tx, store.KeyPurposeAWSFederation, f.sealer)
		return err
	}); err != nil {
		t.Errorf("no usable aws_federation key after start: %v", err)
	}
	// invalidation touches no ledger row: the chain heads match the backup
	got, err := backup.Heads(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	for i, h := range got {
		if h != c.Manifest.Tenants[i] {
			t.Errorf("head %s changed: %+v, backup had %+v", h.Slug, h, c.Manifest.Tenants[i])
		}
	}
}

// TestRestore_RefusedRestoreKeepsLiveDatabase: a restore that is refused
// (here: sealed under another KEK) neither replaces nor moves the working
// database.
func TestRestore_RefusedRestoreKeepsLiveDatabase(t *testing.T) {
	f := newFixture(t)
	c := f.backup(t)
	live := filepath.Join(f.dir, "live.db")
	if err := f.db.Checkpoint(context.Background()); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(live)
	if err != nil {
		t.Fatal(err)
	}
	other, err := seal.New(seal.RandomBytes(seal.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	_, err = backup.Restore(context.Background(), c.Path, other, backup.RestoreOptions{Target: live, Force: true, Now: t0})
	if code(err) != "wrong_kek" {
		t.Fatalf("restore under the wrong KEK = %v", err)
	}
	if after, _ := os.ReadFile(live); !bytes.Equal(before, after) {
		t.Error("a refused restore changed the working database")
	}
	if matches, _ := filepath.Glob(live + ".pre-restore-*"); len(matches) != 0 {
		t.Errorf("a refused restore moved the database aside: %v", matches)
	}
}
