package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Break-glass credentials, challenges and uses (design §15.4,
// schema/0009_breakglass.sql): a tenant sees and changes only its own keys,
// challenges and uses; another tenant's ids look nonexistent, rows that name
// another tenant's rows are refused by the guard triggers, and the schema
// itself refuses a backup-eligible key, a "none" attestation and a sign count
// that does not rise.

// bgRows are one tenant's break-glass rows.
type bgRows struct {
	adminRows
	glass  *store.PlatformUser
	change *store.AdminChange // applied breakglass.register
	cred   *store.BreakGlassCredential
	regCh  *store.BreakGlassChallenge // registration challenge
	asrCh  *store.BreakGlassChallenge // assertion challenge
	use    *store.BreakGlassUse
}

func seedBG(t *testing.T, f *storetest.Fixture) (a, b bgRows) {
	t.Helper()
	ar, br := seedAdminRows(t, f)
	now := storetest.Now
	seed := func(tid storetest.Tenant, base adminRows, tag byte) bgRows {
		r := bgRows{adminRows: base}
		err := f.DB.InTenant(context.Background(), tid.ID, func(c *store.TenantTx) error {
			r.glass = &store.PlatformUser{DisplayName: "glass " + string(tag), IsBreakGlass: true, CreatedAt: now}
			if err := c.InsertPlatformUser(r.glass); err != nil {
				return err
			}
			r.change = &store.AdminChange{Type: "breakglass.register", Payload: json.RawMessage(`{"user_id":"` + r.glass.ID.String() +
				`","label":"Safe A","custodian":"Ops"}`), PayloadHash: hexHash(tag + 9), Status: store.ChangeCoolingOff, TwoPerson: false,
				CoolingOffSeconds: 0, RequestedBy: base.user.ID, RequestedAt: now, ExpiresAt: now.Add(72 * time.Hour), EffectiveAt: &now}
			if err := c.InsertAdminChange(r.change); err != nil {
				return err
			}
			if err := c.MarkAdminChangeApplied(r.change.ID, now); err != nil {
				return err
			}
			r.cred = &store.BreakGlassCredential{UserID: r.glass.ID, ChangeRequestID: r.change.ID,
				CredentialID: []byte("credential-id-" + string(tag) + "-0123456789"), PublicKey: []byte("cose-key-" + string(tag)),
				AAGUID: "2fc0579f-8113-47ea-b116-bb5a8db9202a", AttestationFormat: "packed", AttestationTrust: "basic",
				Transports: []string{"usb"}, Label: "Safe A", Custodian: "Ops", CreatedAt: now}
			if err := c.InsertBreakGlassCredential(r.cred); err != nil {
				return err
			}
			r.regCh = &store.BreakGlassChallenge{Purpose: store.BreakGlassRegistration, ChallengeHash: hexHash(tag + 3),
				SessionData: json.RawMessage(`{"challenge":"x"}`), ChangeRequestID: &r.change.ID, UserID: &r.glass.ID,
				CreatedBy: &base.user.ID, CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
			r.asrCh = &store.BreakGlassChallenge{Purpose: store.BreakGlassAssertion, ChallengeHash: hexHash(tag + 4),
				SessionData: json.RawMessage(`{"challenge":"y"}`), CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
			for _, h := range []*store.BreakGlassChallenge{r.regCh, r.asrCh} {
				if err := c.InsertBreakGlassChallenge(h); err != nil {
					return err
				}
			}
			r.use = &store.BreakGlassUse{CredentialID: r.cred.ID, UserID: r.glass.ID, SessionID: base.session.ID, UsedAt: now}
			return c.InsertBreakGlassUse(r.use)
		})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	return seed(f.A, ar, 'a'), seed(f.B, br, 'b')
}

func TestIsolation_BreakGlassRowsReads(t *testing.T) {
	f := storetest.TwoTenants(t)
	a, b := seedBG(t, f)
	now := storetest.Now
	inB(t, f, func(c *store.TenantTx) error {
		if cs, err := c.BreakGlassCredentials(); err != nil || len(cs) != 1 || cs[0].ID != b.cred.ID || cs[0].TenantID != f.B.ID {
			t.Errorf("BreakGlassCredentials in B = %v %v", cs, err)
		}
		if _, err := c.BreakGlassCredential(a.cred.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("BreakGlassCredential(A's) = %v, want ErrNotFound", err)
		}
		if _, err := c.BreakGlassCredentialByCredentialID(a.cred.CredentialID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("BreakGlassCredentialByCredentialID(A's) = %v, want ErrNotFound", err)
		}
		if got, err := c.BreakGlassCredentialByCredentialID(b.cred.CredentialID); err != nil || got.ID != b.cred.ID {
			t.Errorf("BreakGlassCredentialByCredentialID(B's) = %v %v", got, err)
		}
		if _, err := c.BreakGlassCredentialForChange(a.change.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("BreakGlassCredentialForChange(A's) = %v, want ErrNotFound", err)
		}
		if _, err := c.BreakGlassChallengeByHash(store.BreakGlassAssertion, a.asrCh.ChallengeHash); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("BreakGlassChallengeByHash(A's) = %v, want ErrNotFound", err)
		}
		if got, err := c.BreakGlassChallengeByHash(store.BreakGlassAssertion, b.asrCh.ChallengeHash); err != nil || got.ID != b.asrCh.ID {
			t.Errorf("BreakGlassChallengeByHash(B's) = %v %v", got, err)
		}
		if n, err := c.CountOpenBreakGlassChallenges(store.BreakGlassAssertion, now); err != nil || n != 1 {
			t.Errorf("CountOpenBreakGlassChallenges in B = %d %v, want 1", n, err)
		}
		if _, err := c.BreakGlassUse(a.use.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("BreakGlassUse(A's) = %v, want ErrNotFound", err)
		}
		if us, err := c.RecentBreakGlassUses(now.Add(-time.Hour)); err != nil || len(us) != 1 || us[0].ID != b.use.ID {
			t.Errorf("RecentBreakGlassUses in B = %v %v", us, err)
		}
		return nil
	})
}

func TestIsolation_BreakGlassWritesScoped(t *testing.T) {
	f := storetest.TwoTenants(t)
	a, _ := seedBG(t, f)
	now := storetest.Now
	inB(t, f, func(c *store.TenantTx) error {
		if err := c.RevokeBreakGlassCredential(a.cred.ID, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("RevokeBreakGlassCredential(A's) in B = %v, want ErrNotFound", err)
		}
		state := map[string]error{
			"UseBreakGlassCredential":     c.UseBreakGlassCredential(a.cred.ID, 5, now),
			"ConsumeBreakGlassChallenge":  c.ConsumeBreakGlassChallenge(a.asrCh.ID, now),
			"ConsumeBreakGlassChallenge2": c.ConsumeBreakGlassChallenge(a.regCh.ID, now),
			"AnswerBreakGlassUse":         c.AnswerBreakGlassUse(a.use.ID, uuid.New(), "because it was needed", now),
		}
		for name, err := range state {
			if !errors.Is(err, store.ErrBreakGlassState) {
				t.Errorf("%s on A's row in B = %v, want ErrBreakGlassState", name, err)
			}
		}
		if err := c.PurgeBreakGlassChallenges(now.Add(1000 * time.Hour)); err != nil {
			t.Error(err)
		}
		// the revoke-all of B's sessions leaves A's
		if _, err := c.RevokeAllSessionsExcept(uuid.New(), "break_glass", now); err != nil {
			t.Error(err)
		}
		return nil
	})
	inA(t, f, func(c *store.TenantTx) error {
		if got, err := c.BreakGlassCredential(a.cred.ID); err != nil || got.RevokedAt != nil || got.SignCount != 0 {
			t.Errorf("A's key after B's attempts: %v %v", got, err)
		}
		for _, h := range []*store.BreakGlassChallenge{a.regCh, a.asrCh} {
			if got, err := c.BreakGlassChallengeByHash(h.Purpose, h.ChallengeHash); err != nil || got.ConsumedAt != nil {
				t.Errorf("A's %s challenge after B's attempts: %v %v", h.Purpose, got, err)
			}
		}
		if got, err := c.BreakGlassUse(a.use.ID); err != nil || got.AnsweredAt != nil {
			t.Errorf("A's use after B's attempts: %v %v", got, err)
		}
		if s, err := c.Session(a.session.ID); err != nil || s.Status != store.SessionActive {
			t.Errorf("A's session after B's revoke-all: %v %v", s, err)
		}
		return nil
	})
}

func TestIsolation_BreakGlassInsertsRefused(t *testing.T) {
	f := storetest.TwoTenants(t)
	a, b := seedBG(t, f)
	now := storetest.Now
	err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		cred := &store.BreakGlassCredential{UserID: a.glass.ID, ChangeRequestID: b.change.ID, CredentialID: []byte("another-credential-id"),
			PublicKey: []byte("k"), AAGUID: "2fc0579f-8113-47ea-b116-bb5a8db9202a", AttestationFormat: "packed", AttestationTrust: "basic",
			Label: "x", Custodian: "y", CreatedAt: now}
		if err := c.InsertBreakGlassCredential(cred); !errors.Is(err, store.ErrCrossTenant) {
			t.Errorf("a key of A's user, inserted in B = %v, want ErrCrossTenant", err)
		}
		cred.UserID, cred.ChangeRequestID = b.glass.ID, a.change.ID
		if err := c.InsertBreakGlassCredential(cred); !errors.Is(err, store.ErrCrossTenant) {
			t.Errorf("a key enrolled by A's change request, inserted in B = %v, want ErrCrossTenant", err)
		}
		cred.UserID, cred.ChangeRequestID, cred.TenantID = b.glass.ID, b.change.ID, f.A.ID
		if err := c.InsertBreakGlassCredential(cred); !errors.Is(err, store.ErrCrossTenant) {
			t.Errorf("a key stamped with A's tenant, inserted in B = %v, want ErrCrossTenant", err)
		}
		h := &store.BreakGlassChallenge{Purpose: store.BreakGlassRegistration, ChallengeHash: hexHash('z'), SessionData: json.RawMessage(`{}`),
			ChangeRequestID: &a.change.ID, UserID: &b.glass.ID, CreatedBy: &b.user.ID, CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
		if err := c.InsertBreakGlassChallenge(h); !errors.Is(err, store.ErrCrossTenant) {
			t.Errorf("a challenge naming A's change request = %v, want ErrCrossTenant", err)
		}
		h.ChangeRequestID, h.CreatedBy = &b.change.ID, &a.user.ID
		if err := c.InsertBreakGlassChallenge(h); !errors.Is(err, store.ErrCrossTenant) {
			t.Errorf("a challenge created by A's user = %v, want ErrCrossTenant", err)
		}
		u := &store.BreakGlassUse{CredentialID: a.cred.ID, UserID: b.glass.ID, SessionID: b.session.ID, UsedAt: now}
		if err := c.InsertBreakGlassUse(u); !errors.Is(err, store.ErrCrossTenant) {
			t.Errorf("a use of A's key = %v, want ErrCrossTenant", err)
		}
		u = &store.BreakGlassUse{CredentialID: b.cred.ID, UserID: b.glass.ID, SessionID: a.session.ID, UsedAt: now}
		if err := c.InsertBreakGlassUse(u); !errors.Is(err, store.ErrCrossTenant) {
			t.Errorf("a use by A's session = %v, want ErrCrossTenant", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestBreakGlassRows_Constraints: the schema and the statements enforce the
// §15.4 rules themselves.
func TestBreakGlassRows_Constraints(t *testing.T) {
	f := storetest.TwoTenants(t)
	_, b := seedBG(t, f)
	now := storetest.Now
	inB(t, f, func(c *store.TenantTx) error {
		base := *b.cred
		base.ID, base.ChangeRequestID = uuid.Nil, b.change.ID
		// a second chance on the same credential id or the same enrolment request is refused
		dup := base
		dup.CredentialID = []byte("a-different-credential-id")
		if err := c.InsertBreakGlassCredential(&dup); !errors.Is(err, store.ErrDuplicate) {
			t.Errorf("a second key for one enrolment request = %v, want ErrDuplicate", err)
		}
		// a synced passkey, a "none" attestation and an unknown trust never reach the table
		ch2 := &store.AdminChange{Type: "breakglass.register", Payload: json.RawMessage(`{}`), PayloadHash: hexHash('7'),
			Status: store.ChangePendingApproval, TwoPerson: true, RequestedBy: b.user.ID, RequestedAt: now, ExpiresAt: now.Add(72 * time.Hour)}
		if err := c.InsertAdminChange(ch2); err != nil {
			t.Fatal(err)
		}
		for name, mut := range map[string]func(*store.BreakGlassCredential){
			"backup eligible":     func(k *store.BreakGlassCredential) { k.BackupEligible = true },
			"none attestation":    func(k *store.BreakGlassCredential) { k.AttestationFormat = "none" },
			"unknown trust":       func(k *store.BreakGlassCredential) { k.AttestationTrust = "trusted-because-i-said-so" },
			"short aaguid":        func(k *store.BreakGlassCredential) { k.AAGUID = "abc" },
			"empty label":         func(k *store.BreakGlassCredential) { k.Label = "" },
			"empty credential id": func(k *store.BreakGlassCredential) { k.CredentialID = nil },
		} {
			k := base
			k.ChangeRequestID, k.CredentialID = ch2.ID, []byte("fresh-credential-id-"+name)
			mut(&k)
			if err := c.InsertBreakGlassCredential(&k); err == nil {
				t.Errorf("%s: the key was accepted", name)
			}
		}
		// the sign count only rises; a counterless key stays at 0
		if err := c.UseBreakGlassCredential(b.cred.ID, 0, now); err != nil {
			t.Errorf("0 -> 0 (an authenticator without a counter) = %v, want accepted", err)
		}
		if err := c.UseBreakGlassCredential(b.cred.ID, 7, now); err != nil {
			t.Errorf("0 -> 7 = %v", err)
		}
		for _, n := range []uint32{7, 6, 0} {
			if err := c.UseBreakGlassCredential(b.cred.ID, n, now); !errors.Is(err, store.ErrBreakGlassState) {
				t.Errorf("7 -> %d = %v, want ErrBreakGlassState (a cloned key)", n, err)
			}
		}
		if got, err := c.BreakGlassCredential(b.cred.ID); err != nil || got.SignCount != 7 || got.LastUsedAt == nil {
			t.Errorf("key after the uses: %v %v", got, err)
		}
		// a challenge is single use, and not after it expired
		if err := c.ConsumeBreakGlassChallenge(b.asrCh.ID, now); err != nil {
			t.Fatal(err)
		}
		if err := c.ConsumeBreakGlassChallenge(b.asrCh.ID, now); !errors.Is(err, store.ErrBreakGlassState) {
			t.Errorf("a challenge consumed twice = %v, want ErrBreakGlassState", err)
		}
		if err := c.ConsumeBreakGlassChallenge(b.regCh.ID, now.Add(6*time.Minute)); !errors.Is(err, store.ErrBreakGlassState) {
			t.Errorf("an expired challenge consumed = %v, want ErrBreakGlassState", err)
		}
		if n, err := c.CountOpenBreakGlassChallenges(store.BreakGlassAssertion, now); err != nil || n != 0 {
			t.Errorf("open assertion challenges after consuming = %d %v", n, err)
		}
		// a registration challenge names its enrolment; an assertion challenge names nothing
		bad := &store.BreakGlassChallenge{Purpose: store.BreakGlassRegistration, ChallengeHash: hexHash('y'),
			SessionData: json.RawMessage(`{}`), CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
		if err := c.InsertBreakGlassChallenge(bad); err == nil {
			t.Error("a registration challenge without an enrolment was accepted")
		}
		dupHash := &store.BreakGlassChallenge{Purpose: store.BreakGlassAssertion, ChallengeHash: b.asrCh.ChallengeHash,
			SessionData: json.RawMessage(`{}`), CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
		if err := c.InsertBreakGlassChallenge(dupHash); !errors.Is(err, store.ErrDuplicate) {
			t.Errorf("a repeated challenge = %v, want ErrDuplicate", err)
		}
		// a use is explained once
		if err := c.AnswerBreakGlassUse(b.use.ID, b.user.ID, "Production login outage INC-1", now); err != nil {
			t.Fatal(err)
		}
		if err := c.AnswerBreakGlassUse(b.use.ID, b.user.ID, "again", now); !errors.Is(err, store.ErrBreakGlassState) {
			t.Errorf("a use answered twice = %v, want ErrBreakGlassState", err)
		}
		if us, err := c.RecentBreakGlassUses(now.Add(-time.Hour)); err != nil || len(us) != 1 || us[0].Reason == nil ||
			us[0].AnsweredBy == nil || *us[0].AnsweredBy != b.user.ID {
			t.Errorf("answered use: %v %v", us, err)
		}
		// an old, answered use is no longer listed; an unanswered one always is
		if us, err := c.RecentBreakGlassUses(now.Add(time.Hour)); err != nil || len(us) != 0 {
			t.Errorf("an old answered use is listed: %v %v", us, err)
		}
		// revoking a key twice
		if err := c.RevokeBreakGlassCredential(b.cred.ID, now); err != nil {
			t.Fatal(err)
		}
		if err := c.RevokeBreakGlassCredential(b.cred.ID, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("a key revoked twice = %v, want ErrNotFound", err)
		}
		if _, err := c.BreakGlassCredentialByCredentialID(b.cred.CredentialID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("a revoked key by credential id = %v, want ErrNotFound", err)
		}
		if err := c.UseBreakGlassCredential(b.cred.ID, 99, now); !errors.Is(err, store.ErrBreakGlassState) {
			t.Errorf("a revoked key used = %v, want ErrBreakGlassState", err)
		}
		return nil
	})
}

// TestIsolation_RevokeAllSessionsExcept: the break-glass session that asks
// keeps its own session; every other active session of the tenant ends.
func TestIsolation_RevokeAllSessionsExcept(t *testing.T) {
	f, a, b := authFixture(t)
	now := storetest.Now
	inB(t, f, func(c *store.TenantTx) error {
		other := *b.ctx
		other.ID = uuid.Nil
		if err := c.InsertAuthnContext(&other); err != nil {
			t.Fatal(err)
		}
		hash, csrf := hexHash('k'), "csrf-k"
		keep := &store.Session{UserID: b.user.ID, Kind: store.SessionBrowser, SecretHash: &hash, CSRFSecret: &csrf,
			InitialAuthnContextID: other.ID, CurrentAuthnContextID: other.ID, CreatedAt: now, LastActivityAt: now,
			IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(24 * time.Hour)}
		if err := c.InsertSession(keep); err != nil {
			t.Fatal(err)
		}
		n, err := c.RevokeAllSessionsExcept(keep.ID, "break_glass", now)
		if err != nil || n != 1 {
			t.Errorf("RevokeAllSessionsExcept = %d %v, want 1", n, err)
		}
		if s, err := c.Session(keep.ID); err != nil || s.Status != store.SessionActive {
			t.Errorf("the asking session: %v %v", s, err)
		}
		if s, err := c.Session(b.session.ID); err != nil || s.Status != store.SessionRevoked || s.RevokedReason == nil ||
			*s.RevokedReason != "break_glass" {
			t.Errorf("B's other session: %v %v", s, err)
		}
		return nil
	})
	inA(t, f, func(c *store.TenantTx) error {
		if s, err := c.Session(a.session.ID); err != nil || s.Status != store.SessionActive {
			t.Errorf("A's session: %v %v", s, err)
		}
		return nil
	})
}

func breakGlassCovered() map[string]bool {
	out := map[string]bool{}
	for _, k := range []string{"BreakGlassCredential", "BreakGlassCredentials", "BreakGlassCredentialByCredentialID",
		"BreakGlassCredentialForChange", "BreakGlassChallengeByHash", "CountOpenBreakGlassChallenges", "BreakGlassUse",
		"RecentBreakGlassUses"} {
		out[k] = true // TestIsolation_BreakGlassRowsReads
	}
	for _, k := range []string{"RevokeBreakGlassCredential", "UseBreakGlassCredential", "ConsumeBreakGlassChallenge",
		"AnswerBreakGlassUse", "PurgeBreakGlassChallenges", "RevokeAllSessionsExcept"} {
		out[k] = true // TestIsolation_BreakGlassWritesScoped
	}
	for _, k := range []string{"InsertBreakGlassCredential", "InsertBreakGlassChallenge", "InsertBreakGlassUse"} {
		out[k] = true // TestIsolation_BreakGlassInsertsRefused
	}
	return out
}
