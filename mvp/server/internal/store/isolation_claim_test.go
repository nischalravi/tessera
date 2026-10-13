package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Guest claim isolation (issue #69): a tenant sees and changes only its own
// claim tokens, sessions and confirmation codes; another tenant's hash, cookie
// hash or id looks nonexistent, and a row naming another tenant's intake,
// person, token or session is refused by the guard triggers.

type claimRows struct {
	spRows
	token, session, code string // ids
	tokenHash, cookie    string // lookup keys (hashes)
}

func hex64(tag string) string { return strings.Repeat(tag, 64)[:64] }

func seedClaim(t *testing.T, db *store.DB, tn storetest.Tenant, tag string) claimRows {
	t.Helper()
	r := claimRows{spRows: seedSponsorship(t, db, tn, tag), token: uuid.NewString(), code: uuid.NewString(),
		tokenHash: hex64("a" + tag), cookie: hex64("b" + tag)}
	r.session = r.cookie
	now := storetest.Now
	err := db.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
		if err := c.InsertClaimToken(&store.ClaimToken{ID: r.token, IntakeID: r.intake, IdentityID: r.guest, Kind: store.ClaimKindLink,
			Purpose: store.ClaimPurposeClaim, TokenHash: r.tokenHash, EmailHMAC: "mac-" + tag, Status: store.ClaimIssued,
			NotBefore: now, ExpiresAt: now.Add(7 * 24 * time.Hour), CreatedAt: now}); err != nil {
			return err
		}
		if _, err := c.ConsumeClaimToken(r.tokenHash, now.Add(time.Minute)); err != nil {
			return err
		}
		if err := c.InsertClaimSession(&store.ClaimSession{IDHash: r.cookie, TokenID: r.token, IntakeID: r.intake, IdentityID: r.guest,
			KeyJWK: `{"crv":"P-256","kty":"EC","x":"x","y":"y"}`, KeyJKT: "jkt-" + tag, Nonce: strings.Repeat("n", 16), Step: "verify_contact",
			Verified: "{}", CreatedAt: now, ExpiresAt: now.Add(24 * time.Hour)}); err != nil {
			return err
		}
		return c.InsertConfirmationCode(&store.ConfirmationCode{ID: r.code, SessionIDHash: r.cookie, Channel: store.ConfirmChanEmail,
			DestinationHMAC: "dest-" + tag, CodeHash: hex64("c" + tag), CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute)})
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func claimFixture(t *testing.T) (*storetest.Fixture, claimRows, claimRows) {
	t.Helper()
	f := storetest.TwoTenants(t)
	return f, seedClaim(t, f.DB, f.A, "a"), seedClaim(t, f.DB, f.B, "b")
}

func claimDump(t *testing.T, db *store.DB, tid tenancy.ID, r claimRows) string {
	t.Helper()
	out := spDump(t, db, tid)
	if err := db.ReadTenant(context.Background(), tid, func(c *store.TenantTx) error {
		ts, err := c.ClaimTokensForIntake(r.intake)
		if err != nil {
			return err
		}
		ss, err := c.ClaimSessionsForIntake(r.intake)
		if err != nil {
			return err
		}
		cc, err := c.LiveConfirmationCode(r.session)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		b, err := json.Marshal([]any{ts, ss, cc})
		out += "\n" + string(b)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestIsolation_ClaimReads(t *testing.T) {
	f, a, b := claimFixture(t)
	inB(t, f, func(c *store.TenantTx) error {
		if _, err := c.ClaimTokenByHash(a.tokenHash); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ClaimTokenByHash(A's) = %v", err)
		}
		if x, err := c.ClaimTokenByHash(b.tokenHash); err != nil || x.Status != store.ClaimConsumed {
			t.Errorf("ClaimTokenByHash(B's) = %+v, %v", x, err)
		}
		if ts, err := c.ClaimTokensForIntake(a.intake); err != nil || len(ts) != 0 {
			t.Errorf("ClaimTokensForIntake(A's) = %v, %v", ts, err)
		}
		if ts, err := c.ClaimTokensByEmail("mac-a"); err != nil || len(ts) != 0 {
			t.Errorf("ClaimTokensByEmail(A's) = %v, %v", ts, err)
		}
		if _, err := c.ClaimSession(a.cookie); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ClaimSession(A's) = %v", err)
		}
		if ss, err := c.ClaimSessionsForIntake(a.intake); err != nil || len(ss) != 0 {
			t.Errorf("ClaimSessionsForIntake(A's) = %v, %v", ss, err)
		}
		if _, err := c.LiveConfirmationCode(a.session); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("LiveConfirmationCode(A's session) = %v", err)
		}
		if got, err := c.LiveConfirmationCode(b.session); err != nil || got.ID != b.code {
			t.Errorf("LiveConfirmationCode(B's) = %+v, %v", got, err)
		}
		if _, err := c.ClaimSessionByLoginTxn("any"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ClaimSessionByLoginTxn = %v", err)
		}
		if in, err := c.IntakesByInvitation(store.InvitationReady); err != nil || len(in) != 1 || in[0].ID != b.intake {
			t.Errorf("IntakesByInvitation = %v, %v", in, err)
		}
		return nil
	})
}

var claimMutations = map[string]func(c *store.TenantTx, a, b claimRows) error{
	"ConsumeClaimToken": func(c *store.TenantTx, a, _ claimRows) error {
		_, err := c.ConsumeClaimToken(a.tokenHash, storetest.Now)
		return err
	},
	"RevokeClaimTokens/A's intake": func(c *store.TenantTx, a, _ claimRows) error {
		n, err := c.RevokeClaimTokens(a.intake)
		if err == nil && n != 0 {
			t0 := errors.New("revoked another tenant's tokens")
			return t0
		}
		return store.ErrNotFound // nothing changed: the scope held
	},
	"ExpireClaimTokens": func(c *store.TenantTx, _, _ claimRows) error {
		if _, err := c.ExpireClaimTokens(storetest.Now.Add(365 * 24 * time.Hour)); err != nil {
			return err
		}
		return store.ErrNotFound // only B's own rows can change (checked by the dump)
	},
	"SaveClaimSession": func(c *store.TenantTx, a, _ claimRows) error {
		return c.SaveClaimSession(&store.ClaimSession{IDHash: a.cookie, Step: "complete", Verified: "{}", LastSeenAt: storetest.Now})
	},
	"RevokeClaimSessions/A's intake": func(c *store.TenantTx, a, _ claimRows) error {
		if err := c.RevokeClaimSessions(a.intake, storetest.Now); err != nil {
			return err
		}
		return store.ErrNotFound
	},
	"AddConfirmationAttempt": func(c *store.TenantTx, a, _ claimRows) error { return c.AddConfirmationAttempt(a.code) },
	"VoidConfirmationCode":   func(c *store.TenantTx, a, _ claimRows) error { return c.VoidConfirmationCode(a.code, storetest.Now) },
	"VoidConfirmationCodes/A's session": func(c *store.TenantTx, a, _ claimRows) error {
		if err := c.VoidConfirmationCodes(a.session, storetest.Now); err != nil {
			return err
		}
		return store.ErrNotFound
	},
	"UseConfirmationCode": func(c *store.TenantTx, a, _ claimRows) error { return c.UseConfirmationCode(a.code, storetest.Now) },
	"SetIntakeInvitation": func(c *store.TenantTx, a, _ claimRows) error {
		return c.SetIntakeInvitation(a.intake, store.InvitationSent, storetest.Now)
	},
	"SetIntakeExistingAccount": func(c *store.TenantTx, a, _ claimRows) error {
		return c.SetIntakeExistingAccount(a.intake, "yes", storetest.Now)
	},
	"ActivateAffiliation": func(c *store.TenantTx, _, _ claimRows) error { return c.ActivateAffiliation(uuid.NewString()) },
	"InsertClaimToken/A's intake": func(c *store.TenantTx, a, b claimRows) error {
		return c.InsertClaimToken(&store.ClaimToken{ID: uuid.NewString(), IntakeID: a.intake, IdentityID: b.guest, Kind: store.ClaimKindLink,
			Purpose: store.ClaimPurposeClaim, TokenHash: hex64("d"), EmailHMAC: "m", Status: store.ClaimIssued, NotBefore: storetest.Now,
			ExpiresAt: storetest.Now.Add(time.Hour), CreatedAt: storetest.Now})
	},
	"InsertClaimToken/A's person": func(c *store.TenantTx, a, b claimRows) error {
		return c.InsertClaimToken(&store.ClaimToken{ID: uuid.NewString(), IntakeID: b.intake, IdentityID: a.guest, Kind: store.ClaimKindLink,
			Purpose: store.ClaimPurposeClaim, TokenHash: hex64("e"), EmailHMAC: "m", Status: store.ClaimIssued, NotBefore: storetest.Now,
			ExpiresAt: storetest.Now.Add(time.Hour), CreatedAt: storetest.Now})
	},
	"InsertClaimSession/A's token": func(c *store.TenantTx, a, b claimRows) error {
		return c.InsertClaimSession(&store.ClaimSession{IDHash: hex64("f"), TokenID: a.token, IntakeID: b.intake, IdentityID: b.guest,
			KeyJWK: "{}", KeyJKT: "k", Nonce: strings.Repeat("n", 16), Step: "verify_contact", Verified: "{}", CreatedAt: storetest.Now,
			ExpiresAt: storetest.Now.Add(time.Hour)})
	},
	"InsertClaimSession/A's intake": func(c *store.TenantTx, a, b claimRows) error {
		return c.InsertClaimSession(&store.ClaimSession{IDHash: hex64("g"), TokenID: b.token, IntakeID: a.intake, IdentityID: b.guest,
			KeyJWK: "{}", KeyJKT: "k", Nonce: strings.Repeat("n", 16), Step: "verify_contact", Verified: "{}", CreatedAt: storetest.Now,
			ExpiresAt: storetest.Now.Add(time.Hour)})
	},
	"InsertConfirmationCode/A's session": func(c *store.TenantTx, a, _ claimRows) error {
		return c.InsertConfirmationCode(&store.ConfirmationCode{ID: uuid.NewString(), SessionIDHash: a.session, Channel: store.ConfirmChanEmail,
			DestinationHMAC: "d", CodeHash: hex64("h"), CreatedAt: storetest.Now, ExpiresAt: storetest.Now.Add(time.Minute)})
	},
}

func TestIsolation_ClaimMutationsScoped(t *testing.T) {
	for name, fn := range claimMutations {
		t.Run(name, func(t *testing.T) {
			f, a, b := claimFixture(t)
			before := claimDump(t, f.DB, f.A.ID, a)
			err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error { return fn(c, a, b) })
			if !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrCrossTenant) {
				t.Fatalf("%s across tenants = %v, want ErrNotFound or ErrCrossTenant", name, err)
			}
			if after := claimDump(t, f.DB, f.A.ID, a); after != before {
				t.Errorf("%s in B changed A", name)
			}
		})
	}
}

// The schema's own rules: a token is bound and single-use, a final token is
// final, a session keeps its key, a used code stays used.
func TestClaim_SchemaRules(t *testing.T) {
	f, _, b := claimFixture(t)
	now := storetest.Now
	good := func() *store.ClaimToken {
		return &store.ClaimToken{ID: uuid.NewString(), IntakeID: b.intake, IdentityID: b.guest, Kind: store.ClaimKindLink,
			Purpose: store.ClaimPurposeClaim, TokenHash: hex64("9"), EmailHMAC: "m", Status: store.ClaimIssued, NotBefore: now,
			ExpiresAt: now.Add(time.Hour), CreatedAt: now}
	}
	bad := map[string]func(x *store.ClaimToken){
		"short hash":     func(x *store.ClaimToken) { x.TokenHash = "abc" },
		"no email hmac":  func(x *store.ClaimToken) { x.EmailHMAC = "" },
		"unknown status": func(x *store.ClaimToken) { x.Status = "bogus" },
		"unknown kind":   func(x *store.ClaimToken) { x.Kind = "sms" },
		"expires first":  func(x *store.ClaimToken) { x.ExpiresAt = x.NotBefore },
		"consumed new":   func(x *store.ClaimToken) { x.Status = store.ClaimConsumed },
		"same hash":      func(x *store.ClaimToken) { x.TokenHash = b.tokenHash },
	}
	for name, mod := range bad {
		x := good()
		mod(x)
		if err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error { return c.InsertClaimToken(x) }); err == nil {
			t.Errorf("%s: a token the schema forbids was accepted", name)
		}
	}
	// the one use: a consumed token cannot be consumed again, nor revoked or reopened
	inB(t, f, func(c *store.TenantTx) error {
		if _, err := c.ConsumeClaimToken(b.tokenHash, now.Add(time.Hour)); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("second consume = %v, want ErrNotFound", err)
		}
		if n, err := c.RevokeClaimTokens(b.intake); err != nil || n != 0 {
			t.Errorf("revoke of a consumed token = %d, %v", n, err)
		}
		return nil
	})
	// a token past its life cannot be consumed, one before its start neither
	inB(t, f, func(c *store.TenantTx) error {
		x := good()
		x.TokenHash = hex64("8")
		x.NotBefore = now.Add(time.Hour)
		x.ExpiresAt = now.Add(2 * time.Hour)
		if err := c.InsertClaimToken(x); err != nil {
			t.Fatal(err)
		}
		if _, err := c.ConsumeClaimToken(x.TokenHash, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("consume before not_before = %v", err)
		}
		if _, err := c.ConsumeClaimToken(x.TokenHash, now.Add(3*time.Hour)); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("consume after expiry = %v", err)
		}
		if n, err := c.ExpireClaimTokens(now.Add(3 * time.Hour)); err != nil || n != 1 {
			t.Errorf("ExpireClaimTokens = %d, %v", n, err)
		}
		return nil
	})
	// raw rewrites the store has no method for are refused by triggers
	err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error {
		s, err := c.ClaimSession(b.session)
		if err != nil {
			return err
		}
		s.Step = "complete"
		if err := c.SaveClaimSession(s); err != nil {
			return err
		}
		done := now
		s.CompletedAt = &done
		if err := c.SaveClaimSession(s); err != nil {
			return err
		}
		s.CompletedAt = nil
		return c.SaveClaimSession(s) // a completed session stays completed
	})
	if err == nil {
		t.Error("a completed claim session was reopened")
	}
	// a code counts attempts, voids once and cannot then be used
	inB(t, f, func(c *store.TenantTx) error {
		if err := c.AddConfirmationAttempt(b.code); err != nil {
			t.Fatal(err)
		}
		if got, err := c.LiveConfirmationCode(b.session); err != nil || got.Attempts != 1 {
			t.Errorf("attempts = %+v, %v", got, err)
		}
		if err := c.VoidConfirmationCode(b.code, now); err != nil {
			t.Fatal(err)
		}
		if err := c.UseConfirmationCode(b.code, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("use of a void code = %v", err)
		}
		if _, err := c.LiveConfirmationCode(b.session); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("a void code is still live: %v", err)
		}
		return nil
	})
}

func claimCovered() map[string]bool {
	out := map[string]bool{}
	for k := range claimMutations {
		out[k] = true
	}
	for _, k := range []string{"ClaimTokenByHash", "ClaimTokensForIntake", "ClaimTokensByEmail", "ClaimSession", "ClaimSessionsForIntake",
		"ClaimSessionByLoginTxn", "LiveConfirmationCode", "IntakesByInvitation", "InsertClaimToken", "InsertClaimSession", "InsertConfirmationCode"} {
		out[k] = true // TestIsolation_ClaimReads, and the inserts in the mutation cases and seeds
	}
	return out
}
