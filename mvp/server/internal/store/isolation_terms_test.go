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
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Guest terms, attribute consent and recovery isolation (issue #73): a tenant
// sees and changes only its own documents, assignments, acceptances, consents,
// recovery cases and codes; another tenant's id looks nonexistent, and a row
// naming another tenant's person, document, session, token, intake or group is
// refused by the guard triggers.

type termsRows struct {
	claimRows
	doc, accept, recCase, recCode string
	group                         int64
	key, codeHash                 string
}

func seedTerms(t *testing.T, db *store.DB, tn storetest.Tenant, tag string) termsRows {
	t.Helper()
	r := termsRows{claimRows: seedClaim(t, db, tn, tag), doc: uuid.NewString(), accept: uuid.NewString(), recCase: uuid.NewString(),
		recCode: uuid.NewString(), group: tn.IDs["group:okta:payments-clerks"], key: "aup-" + tag, codeHash: hex64("5" + tag)}
	now := storetest.Now
	err := db.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
		if err := c.InsertTermsDocument(&store.TermsDocument{ID: r.doc, Key: r.key, Version: 1, Title: "Acceptable use " + tag,
			Body: "text " + tag, TextSHA256: hex64("7" + tag), GraceDays: 14, CreatedBy: "x", CreatedAt: now}); err != nil {
			return err
		}
		pop := store.PopVisitor
		g := r.group
		if err := c.ReplaceTermsAssignments(r.key, []*store.TermsAssignment{
			{ID: uuid.NewString(), Key: r.key, Scope: "population:visitor", Population: &pop, CreatedAt: now},
			{ID: uuid.NewString(), Key: r.key, Scope: "bundle:" + tag, GroupID: &g, CreatedAt: now}}); err != nil {
			return err
		}
		sess := r.session
		if _, err := c.InsertTermsAcceptance(&store.TermsAcceptance{ID: r.accept, IdentityID: r.guest, DocumentID: r.doc, Key: r.key, Version: 1,
			TextSHA256: hex64("7" + tag), Context: store.TermsContextClaim, SessionHash: &sess, AcceptedAt: now}); err != nil {
			return err
		}
		if _, err := c.InsertAttributeConsent(&store.AttributeConsent{ID: uuid.NewString(), IdentityID: r.guest, SessionHash: r.session,
			Authority: "home_idp", Offered: `["email"]`, Consented: `["email"]`, ConsentedAt: now}); err != nil {
			return err
		}
		if err := c.InsertRecoveryCase(&store.RecoveryCase{ID: r.recCase, IdentityID: r.guest, IntakeID: r.intake, TokenID: r.token,
			IssuedBy: "u-" + tag, Via: store.RecoveryViaDesk, RequiredIAL: 1, CreatedAt: now}); err != nil {
			return err
		}
		return c.InsertRecoveryCode(&store.RecoveryCode{ID: r.recCode, IdentityID: r.guest, Batch: "b-" + tag, CodeHash: r.codeHash, CreatedAt: now})
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func termsFixture(t *testing.T) (*storetest.Fixture, termsRows, termsRows) {
	t.Helper()
	f := storetest.TwoTenants(t)
	return f, seedTerms(t, f.DB, f.A, storetest.Sentinel), seedTerms(t, f.DB, f.B, "b")
}

func termsDump(t *testing.T, db *store.DB, tid tenancy.ID, r termsRows) string {
	t.Helper()
	out := claimDump(t, db, tid, r.claimRows)
	if err := db.ReadTenant(context.Background(), tid, func(c *store.TenantTx) error {
		docs, err := c.TermsDocuments()
		if err != nil {
			return err
		}
		as, err := c.TermsAssignments()
		if err != nil {
			return err
		}
		acc, err := c.TermsAcceptancesFor(r.guest)
		if err != nil {
			return err
		}
		cons, err := c.AttributeConsentsFor(r.guest)
		if err != nil {
			return err
		}
		rc, err := c.RecoveryCases(0, "")
		if err != nil {
			return err
		}
		codes, err := c.RecoveryCodesFor(r.guest)
		if err != nil {
			return err
		}
		b, err := json.Marshal([]any{docs, as, acc, cons, rc, codes})
		out += "\n" + string(b)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestIsolation_TermsReads(t *testing.T) {
	f, a, b := termsFixture(t)
	inB(t, f, func(c *store.TenantTx) error {
		if _, err := c.TermsDocument(a.doc); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("TermsDocument(A's) = %v", err)
		}
		if x, err := c.TermsDocument(b.doc); err != nil || x.ID != b.doc {
			t.Errorf("TermsDocument(B's) = %+v, %v", x, err)
		}
		if ds, err := c.TermsDocuments(); err != nil || len(ds) != 1 || ds[0].ID != b.doc {
			t.Errorf("TermsDocuments = %v, %v", ds, err)
		}
		if has, err := c.HasTermsDocuments(); err != nil || !has {
			t.Errorf("HasTermsDocuments = %v, %v", has, err)
		}
		if as, err := c.TermsAssignments(); err != nil || len(as) != 2 || as[0].Key != b.key {
			t.Errorf("TermsAssignments = %v, %v", as, err)
		}
		if xs, err := c.TermsAcceptancesFor(a.guest); err != nil || len(xs) != 0 && a.guest != b.guest {
			t.Errorf("TermsAcceptancesFor(A's person) = %v, %v", xs, err)
		}
		if _, err := c.AttributeConsentFor(a.session); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("AttributeConsentFor(A's session) = %v", err)
		}
		if _, err := c.AttributeConsentFor(b.session); err != nil {
			t.Errorf("AttributeConsentFor(B's session) = %v", err)
		}
		if _, err := c.RecoveryCase(a.recCase); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("RecoveryCase(A's) = %v", err)
		}
		if _, err := c.RecoveryCaseByToken(a.token); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("RecoveryCaseByToken(A's) = %v", err)
		}
		if _, err := c.RecoveryCaseBySession(a.session); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("RecoveryCaseBySession(A's) = %v", err)
		}
		if xs, err := c.RecoveryCases(0, ""); err != nil || len(xs) != 1 || xs[0].ID != b.recCase {
			t.Errorf("RecoveryCases = %v, %v", xs, err)
		}
		if xs, err := c.OpenRecoveryCases(b.guest); err != nil || len(xs) != 1 {
			t.Errorf("OpenRecoveryCases(B's) = %v, %v", xs, err)
		}
		if xs, err := c.DueRecoveries(storetest.Now.Add(1000 * time.Hour)); err != nil || len(xs) != 0 {
			t.Errorf("DueRecoveries = %v, %v", xs, err)
		}
		if has, err := c.HasCoolingRecoveries(); err != nil || has {
			t.Errorf("HasCoolingRecoveries = %v, %v", has, err)
		}
		if n, err := c.CountLiveRecoveryCodes(b.guest); err != nil || n != 1 {
			t.Errorf("CountLiveRecoveryCodes(B's) = %d, %v", n, err)
		}
		if xs, err := c.RecoveryCodesFor(b.guest); err != nil || len(xs) != 1 || xs[0].ID != b.recCode {
			t.Errorf("RecoveryCodesFor(B's) = %v, %v", xs, err)
		}
		return nil
	})
}

var termsMutations = map[string]func(c *store.TenantTx, a, b termsRows) error{
	"SaveRecoveryCase": func(c *store.TenantTx, a, _ termsRows) error {
		return c.SaveRecoveryCase(&store.RecoveryCase{ID: a.recCase, Status: store.RecoveryCancelled, UpdatedAt: storetest.Now})
	},
	"ConsumeRecoveryToken": func(c *store.TenantTx, a, _ termsRows) error {
		_, err := c.ConsumeRecoveryToken(a.tokenHash, storetest.Now)
		return err
	},
	"RevokeRecoveryTokens/A's person": func(c *store.TenantTx, a, _ termsRows) error {
		if n, err := c.RevokeRecoveryTokens(a.guest); err != nil || n != 0 {
			return errors.New("revoked another tenant's tokens")
		}
		return store.ErrNotFound // nothing changed: the scope held
	},
	"VoidRecoveryCodes/A's person": func(c *store.TenantTx, a, _ termsRows) error {
		if n, err := c.VoidRecoveryCodes(a.guest, storetest.Now); err != nil || n != 0 {
			return errors.New("voided another tenant's codes")
		}
		return store.ErrNotFound
	},
	"UseRecoveryCode": func(c *store.TenantTx, a, _ termsRows) error {
		return c.UseRecoveryCode(a.guest, a.codeHash, storetest.Now)
	},
	"ReplaceTermsAssignments/A's group": func(c *store.TenantTx, a, _ termsRows) error {
		g := a.group
		return c.ReplaceTermsAssignments("k", []*store.TermsAssignment{{ID: uuid.NewString(), Key: "k", Scope: "bundle:x", GroupID: &g, CreatedAt: storetest.Now}})
	},
	"InsertTermsAcceptance/A's document": func(c *store.TenantTx, a, b termsRows) error {
		_, err := c.InsertTermsAcceptance(&store.TermsAcceptance{ID: uuid.NewString(), IdentityID: b.guest, DocumentID: a.doc, Key: "k", Version: 1,
			TextSHA256: hex64("1"), Context: store.TermsContextSignin, AcceptedAt: storetest.Now})
		return err
	},
	"InsertTermsAcceptance/A's person": func(c *store.TenantTx, a, b termsRows) error {
		_, err := c.InsertTermsAcceptance(&store.TermsAcceptance{ID: uuid.NewString(), IdentityID: a.guest, DocumentID: b.doc, Key: "k", Version: 1,
			TextSHA256: hex64("1"), Context: store.TermsContextSignin, AcceptedAt: storetest.Now})
		return err
	},
	"InsertTermsAcceptance/A's session": func(c *store.TenantTx, a, b termsRows) error {
		s := a.session
		_, err := c.InsertTermsAcceptance(&store.TermsAcceptance{ID: uuid.NewString(), IdentityID: b.guest, DocumentID: b.doc, Key: "k2", Version: 2,
			TextSHA256: hex64("1"), Context: store.TermsContextClaim, SessionHash: &s, AcceptedAt: storetest.Now})
		return err
	},
	"InsertAttributeConsent/A's session": func(c *store.TenantTx, a, b termsRows) error {
		_, err := c.InsertAttributeConsent(&store.AttributeConsent{ID: uuid.NewString(), IdentityID: b.guest, SessionHash: a.session,
			Authority: "home_idp", Offered: "[]", Consented: "[]", ConsentedAt: storetest.Now})
		return err
	},
	"InsertAttributeConsent/A's person": func(c *store.TenantTx, a, b termsRows) error {
		_, err := c.InsertAttributeConsent(&store.AttributeConsent{ID: uuid.NewString(), IdentityID: a.guest, SessionHash: hex64("3"),
			Authority: "home_idp", Offered: "[]", Consented: "[]", ConsentedAt: storetest.Now})
		return err
	},
	"InsertRecoveryCase/A's token": func(c *store.TenantTx, a, b termsRows) error {
		return c.InsertRecoveryCase(&store.RecoveryCase{ID: uuid.NewString(), IdentityID: b.guest, IntakeID: b.intake, TokenID: a.token,
			IssuedBy: "x", Via: store.RecoveryViaDesk, CreatedAt: storetest.Now})
	},
	"InsertRecoveryCase/A's intake": func(c *store.TenantTx, a, b termsRows) error {
		return c.InsertRecoveryCase(&store.RecoveryCase{ID: uuid.NewString(), IdentityID: b.guest, IntakeID: a.intake, TokenID: b.token,
			IssuedBy: "x", Via: store.RecoveryViaDesk, CreatedAt: storetest.Now})
	},
	"InsertRecoveryCase/A's person": func(c *store.TenantTx, a, b termsRows) error {
		return c.InsertRecoveryCase(&store.RecoveryCase{ID: uuid.NewString(), IdentityID: a.guest, IntakeID: b.intake, TokenID: b.token,
			IssuedBy: "x", Via: store.RecoveryViaDesk, CreatedAt: storetest.Now})
	},
	"InsertRecoveryCode/A's person": func(c *store.TenantTx, a, _ termsRows) error {
		return c.InsertRecoveryCode(&store.RecoveryCode{ID: uuid.NewString(), IdentityID: a.guest, Batch: "x", CodeHash: hex64("2"), CreatedAt: storetest.Now})
	},
}

func TestIsolation_TermsMutationsScoped(t *testing.T) {
	for name, fn := range termsMutations {
		t.Run(name, func(t *testing.T) {
			f, a, b := termsFixture(t)
			before := termsDump(t, f.DB, f.A.ID, a)
			err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error { return fn(c, a, b) })
			if !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrCrossTenant) {
				t.Fatalf("%s across tenants = %v, want ErrNotFound or ErrCrossTenant", name, err)
			}
			if after := termsDump(t, f.DB, f.A.ID, a); after != before {
				t.Errorf("%s in B changed A", name)
			}
		})
	}
}

// The schema's own rules: versions and acceptances are ledgers, a document
// version is unique, a recovery code is spent once, a recovery case's binding
// never changes and a final case is final, a cooling-off has an end.
func TestTerms_SchemaRules(t *testing.T) {
	f, _, b := termsFixture(t)
	now := storetest.Now
	ctx := context.Background()
	fail := func(what string, err error) {
		t.Helper()
		if err == nil {
			t.Errorf("%s: the schema accepted it", what)
		}
	}
	fail("a duplicate version", f.DB.InTenant(ctx, f.B.ID, func(c *store.TenantTx) error {
		return c.InsertTermsDocument(&store.TermsDocument{ID: uuid.NewString(), Key: b.key, Version: 1, Title: "t", Body: "b",
			TextSHA256: hex64("4"), GraceDays: 1, CreatedAt: now})
	}))
	fail("a short hash", f.DB.InTenant(ctx, f.B.ID, func(c *store.TenantTx) error {
		return c.InsertTermsDocument(&store.TermsDocument{ID: uuid.NewString(), Key: b.key, Version: 2, Title: "t", Body: "b",
			TextSHA256: "abc", GraceDays: 1, CreatedAt: now})
	}))
	fail("an unbounded grace period", f.DB.InTenant(ctx, f.B.ID, func(c *store.TenantTx) error {
		return c.InsertTermsDocument(&store.TermsDocument{ID: uuid.NewString(), Key: b.key, Version: 2, Title: "t", Body: "b",
			TextSHA256: hex64("4"), GraceDays: 4000, CreatedAt: now})
	}))
	fail("an assignment to nothing", f.DB.InTenant(ctx, f.B.ID, func(c *store.TenantTx) error {
		return c.ReplaceTermsAssignments(b.key, []*store.TermsAssignment{{ID: uuid.NewString(), Key: b.key, Scope: "x", CreatedAt: now}})
	}))
	// an acceptance is recorded once per person and version, and stays
	inB(t, f, func(c *store.TenantTx) error {
		fresh, err := c.InsertTermsAcceptance(&store.TermsAcceptance{ID: uuid.NewString(), IdentityID: b.guest, DocumentID: b.doc, Key: b.key,
			Version: 1, TextSHA256: hex64("7b"), Context: store.TermsContextSignin, AcceptedAt: now})
		if err != nil || fresh {
			t.Errorf("a second acceptance of the same version = %v, %v (want not fresh)", fresh, err)
		}
		return nil
	})
	// a recovery code is spent once
	inB(t, f, func(c *store.TenantTx) error {
		if err := c.UseRecoveryCode(b.guest, b.codeHash, now); err != nil {
			t.Errorf("first use = %v", err)
		}
		if err := c.UseRecoveryCode(b.guest, b.codeHash, now); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("second use = %v, want ErrNotFound", err)
		}
		if n, err := c.CountLiveRecoveryCodes(b.guest); err != nil || n != 0 {
			t.Errorf("live codes = %d, %v", n, err)
		}
		return nil
	})
	// a case: cooling-off needs an end; a completed case cannot be reopened
	fail("cooling off without an end", f.DB.InTenant(ctx, f.B.ID, func(c *store.TenantTx) error {
		x, err := c.RecoveryCase(b.recCase)
		if err != nil {
			return err
		}
		x.Status, x.UpdatedAt = store.RecoveryCooling, now
		return c.SaveRecoveryCase(x)
	}))
	fail("reopening a completed case", f.DB.InTenant(ctx, f.B.ID, func(c *store.TenantTx) error {
		x, err := c.RecoveryCase(b.recCase)
		if err != nil {
			return err
		}
		done := now
		x.Status, x.CompletedAt, x.UpdatedAt = store.RecoveryCompleted, &done, now
		if err := c.SaveRecoveryCase(x); err != nil {
			return err
		}
		x.Status, x.CompletedAt = store.RecoveryStarted, nil
		return c.SaveRecoveryCase(x)
	}))
}

func termsCovered() map[string]bool {
	out := map[string]bool{}
	for k := range termsMutations {
		out[k] = true
	}
	for _, k := range []string{"TermsDocument", "TermsDocuments", "HasTermsDocuments", "TermsAssignments", "TermsAcceptancesFor",
		"AttributeConsentFor", "AttributeConsentsFor", "RecoveryCase", "RecoveryCaseByToken", "RecoveryCaseBySession", "RecoveryCases",
		"OpenRecoveryCases", "DueRecoveries", "HasCoolingRecoveries", "CountLiveRecoveryCodes", "RecoveryCodesFor",
		"InsertTermsDocument", "InsertTermsAcceptance", "InsertAttributeConsent", "InsertRecoveryCase", "InsertRecoveryCode"} {
		out[k] = true // TestIsolation_TermsReads, and the inserts in the mutation cases and seeds
	}
	return out
}
