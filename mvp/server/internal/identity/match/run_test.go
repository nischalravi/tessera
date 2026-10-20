package match_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/identity"
	"github.com/nischalravi/tessera/mvp/server/internal/identity/match"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

var now = storetest.Now

type world struct {
	t     *testing.T
	f     *storetest.Fixture
	m     *match.Matcher
	bob   int64
	email string
}

func newWorld(t *testing.T) *world {
	t.Helper()
	f := storetest.TwoTenants(t)
	k := storetest.IdentityKeyer(t)
	w := &world{t: t, f: f, m: match.New(k), bob: f.B.IDs["bob"]}
	w.tx(func(c *store.TenantTx) error {
		if _, err := identity.Backfill(c, k, now); err != nil {
			return err
		}
		i, err := c.Identity(w.bob)
		w.email = strings.ToLower(*i.Email)
		return err
	})
	return w
}

func (w *world) tx(fn func(c *store.TenantTx) error) {
	w.t.Helper()
	if err := w.f.DB.InTenant(context.Background(), w.f.B.ID, fn); err != nil {
		w.t.Fatal(err)
	}
}

// run matches a subject as a new intake and returns what was stored.
func (w *world) run(s match.Subject, channel string) (*match.Stored, *store.IntakeRecord) {
	w.t.Helper()
	var st *match.Stored
	var in *store.IntakeRecord
	w.tx(func(c *store.TenantTx) error {
		id := uuid.NewString()
		if err := c.InsertIntake(&store.IntakeRecord{ID: id, Channel: channel, MatchMode: string(s.Mode), Status: store.IntakeReceived,
			InvitationStatus: store.InvitationReady, CreatedAt: now}); err != nil {
			return err
		}
		var err error
		if st, err = w.m.Run(c, nil, id, s, now); err != nil {
			return err
		}
		in, err = c.Intake(id)
		return err
	})
	return st, in
}

func TestRun_SelfAssertedFlagsAndExplains(t *testing.T) {
	w := newWorld(t)
	st, in := w.run(match.Subject{Mode: match.SelfAsserted, Given: "Robert", Family: "B", Emails: []string{strings.ToUpper(w.email)}}, store.ChannelSponsorInvite)
	if st.Verdict.Outcome != match.OutcomeSuspected || len(st.Rows) == 0 || in.Status != store.IntakeReview {
		t.Fatalf("verdict %+v intake %s", st.Verdict, in.Status)
	}
	var row *store.MatchResult
	for _, r := range st.Rows {
		if r.CandidateID != nil && *r.CandidateID == w.bob {
			row = r
		}
	}
	if row == nil || row.Tier != "C" || row.Status != store.MatchReview || row.Decision == nil || *row.Decision != "suspected" {
		t.Fatalf("row %+v", row)
	}
	// the stored explanation names the rule and masks what was compared
	if !strings.Contains(row.Rules, `"verified_email"`) || !strings.Contains(row.Rules, `"mode":"self_asserted"`) {
		t.Errorf("rules %s", row.Rules)
	}
	if strings.Contains(strings.ToLower(row.Rules), w.email) || strings.Contains(row.Rules, "Robert") {
		t.Errorf("the explanation holds a raw value: %s", row.Rules)
	}
	// the ledger says that matching ran, with no value in it
	w.tx(func(c *store.TenantTx) error {
		evs, err := c.AuditLog(-1)
		found := false
		for _, e := range evs {
			if e.Action == "identity.match" {
				found = true
				if strings.Contains(strings.ToLower(string(mustJSON(e))), w.email) {
					t.Error("the ledger entry holds the address")
				}
			}
		}
		if !found {
			t.Error("no identity.match event")
		}
		return err
	})
}

func TestRun_AuthoritativeExactLinks_NoMatchIsNew(t *testing.T) {
	w := newWorld(t)
	var ext string
	w.tx(func(c *store.TenantTx) error { i, err := c.Identity(w.bob); ext = i.ExternalID; return err })
	st, in := w.run(match.Subject{Mode: match.Authoritative, Given: "Bob", Family: "Re-hired", SOR: "hris", SORID: ext,
		Identifiers: []match.RawIdent{{Type: store.IdentEmployeeID, Value: ext, Authoritative: true}}}, "hris")
	if st.Verdict.Tier != match.TierA || st.Verdict.Outcome != match.OutcomeAutoLink || in.Status != store.IntakeResolved {
		t.Fatalf("a rehire: %+v / %s", st.Verdict, in.Status)
	}
	if r := st.Rows[0]; r.Status != store.MatchLinked || r.Decision == nil || *r.Decision != "auto_link" || *r.CandidateID != w.bob {
		t.Errorf("row %+v", r)
	}
	st, in = w.run(match.Subject{Mode: match.Authoritative, Given: "Zed", Family: "Newhire", SOR: "hris", SORID: "W-new",
		Emails: []string{"zed@newhire.example"}, EmailsVerified: true}, "hris")
	if st.Verdict.Tier != match.TierD || len(st.Rows) != 1 || st.Rows[0].CandidateID != nil || st.Rows[0].Status != store.MatchNewPerson || in.Status != store.IntakeResolved {
		t.Errorf("a new person: %+v %+v %s", st.Verdict, st.Rows, in.Status)
	}
}

func TestRun_DOBTransposedAndSettings(t *testing.T) {
	w := newWorld(t)
	// bob's HR record carries a keyed date of birth, 4 December 1990 (1990-12-04)
	var dob match.DOB
	w.tx(func(c *store.TenantTx) (err error) {
		if dob, err = w.m.DOBKeys(c, "1990-12-04"); err != nil {
			return err
		}
		srcs, err := c.SourceRecordsFor(w.bob)
		if err != nil {
			return err
		}
		// SourceRecord attributes are immutable in the store API; add a second record that carries the key
		return c.InsertSourceRecord(&store.SourceRecord{ID: uuid.NewString(), IdentityID: &w.bob, SOR: "hris", SORID: srcs[0].SORID + "-dob",
			Attributes: `{"dob_key":"` + dob.Exact + `"}`, Status: store.RecordActive, ReceivedAt: now})
	})
	if dob.Swapped == "" {
		t.Fatal("no transposed key for a day under 13")
	}
	// the same person, entered as 12 April 1990 (day and month exchanged): strong, with the same verified address
	subj := match.Subject{Mode: match.Authoritative, Given: "Bob", Family: "B", Emails: []string{w.email}, EmailsVerified: true, DOB: "1990-04-12"}
	var name string
	w.tx(func(c *store.TenantTx) error { i, err := c.Identity(w.bob); name = i.Name; return err })
	n := match.SplitName(name)
	subj.Given, subj.Family = n.Given, n.Family
	st, _ := w.run(subj, "hris")
	if st.Verdict.Tier != match.TierB || st.Verdict.Outcome != match.OutcomeReview {
		t.Fatalf("a transposed date of birth: %+v", st.Verdict)
	}
	if !strings.Contains(st.Rows[0].Rules, "day and month exchanged") {
		t.Errorf("the explanation does not say how the date matched: %s", st.Rows[0].Rules)
	}
	// the tenant allows Tier B to auto-link between authoritative sources: bob is authoritative (HR)
	w.tx(func(c *store.TenantTx) error {
		u := &store.PlatformUser{DisplayName: "admin", CreatedAt: now}
		if err := c.InsertPlatformUser(u); err != nil {
			return err
		}
		return c.PutMatchingSettings(store.MatchingSettings{AutoLinkTierB: true, UnmergeWindowDays: 180}, u.ID.String(), now)
	})
	if st, _ = w.run(subj, "hris"); st.Verdict.Outcome != match.OutcomeAutoLink {
		t.Errorf("tier B with the tenant setting on: %+v", st.Verdict)
	}
	// ... but never for a self-asserted intake
	subj.Mode = match.SelfAsserted
	if st, _ = w.run(subj, store.ChannelSponsorInvite); st.Verdict.Outcome != match.OutcomeSuspected {
		t.Errorf("self-asserted with the same attributes: %+v", st.Verdict)
	}
	// a malformed date of birth is refused, not ignored
	w.tx(func(c *store.TenantTx) error {
		if _, err := w.m.DOBKeys(c, "04/12/1990"); err == nil {
			t.Error("a malformed date of birth was accepted")
		}
		return nil
	})
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }
