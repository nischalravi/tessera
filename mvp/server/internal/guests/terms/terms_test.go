package terms_test

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/guests/terms"
	"github.com/nischalravi/tessera/mvp/server/internal/requests"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

type world struct {
	db     *store.DB
	tn     storetest.Tenant
	guest  int64
	group  int64
	bundle string
}

// newWorld is a tenant with a guest holding a live visitor sponsorship whose
// bundle names one group.
func newWorld(t *testing.T) *world {
	t.Helper()
	f := storetest.TwoTenants(t)
	w := &world{db: f.DB, tn: f.A, guest: f.A.IDs["alice"], group: f.A.IDs["group:okta:payments-clerks"]}
	sponsor := f.A.IDs["carol"]
	intake := uuid.NewString()
	now := storetest.Now
	w.bundle = `[{"group_id":` + strconv.FormatInt(w.group, 10) + `}]`
	w.in(t, func(tx *store.TenantTx) error {
		if err := tx.InsertIntake(&store.IntakeRecord{ID: intake, Channel: store.ChannelSponsorInvite, MatchMode: store.MatchSelfAsserted,
			SponsorIdentityID: &sponsor, Status: store.IntakeReceived, InvitationStatus: store.InvitationReady, CreatedAt: now}); err != nil {
			return err
		}
		return tx.InsertSponsorship(&store.Sponsorship{ID: uuid.NewString(), GuestIdentityID: w.guest, IntakeID: intake, SponsorIdentityID: sponsor,
			Population: store.PopVisitor, Purpose: "x", AccessBundle: w.bundle, RequiredAAL: 1, StartsAt: now, EndsAt: now.Add(90 * 24 * time.Hour),
			Status: store.SponsorActive, PolicyVersion: "v", CreatedAt: now, UpdatedAt: now})
	})
	return w
}

func (w *world) in(t *testing.T, fn func(tx *store.TenantTx) error) {
	t.Helper()
	if err := w.db.InTenant(context.Background(), w.tn.ID, fn); err != nil {
		t.Fatal(err)
	}
}

func grace(n int) *int { return &n }

func TestPublish_Validation(t *testing.T) {
	w := newWorld(t)
	for name, c := range map[string]struct {
		in   terms.Input
		code string
	}{
		"key with a space":  {terms.Input{Key: "a b", Title: "t", Body: "b"}, "invalid_key"},
		"upper case key":    {terms.Input{Key: "AUP", Title: "t", Body: "b"}, "invalid_key"},
		"empty key":         {terms.Input{Key: "", Title: "t", Body: "b"}, "invalid_key"},
		"long key":          {terms.Input{Key: strings.Repeat("a", 65), Title: "t", Body: "b"}, "invalid_key"},
		"no title":          {terms.Input{Key: "k", Title: " ", Body: "b"}, "invalid_title"},
		"long title":        {terms.Input{Key: "k", Title: strings.Repeat("t", 201), Body: "b"}, "invalid_title"},
		"blank text":        {terms.Input{Key: "k", Title: "t", Body: " \n"}, "invalid_body"},
		"huge text":         {terms.Input{Key: "k", Title: "t", Body: strings.Repeat("b", terms.MaxBody+1)}, "invalid_body"},
		"negative grace":    {terms.Input{Key: "k", Title: "t", Body: "b", GraceDays: grace(-1)}, "invalid_grace"},
		"grace over a year": {terms.Input{Key: "k", Title: "t", Body: "b", GraceDays: grace(366)}, "invalid_grace"},
	} {
		t.Run(name, func(t *testing.T) {
			var err error
			w.in(t, func(tx *store.TenantTx) error { _, err = terms.Publish(tx, "u", c.in, storetest.Now); return nil })
			var re *requests.Error
			if !errors.As(err, &re) || re.Code != c.code || re.Status != 422 {
				t.Errorf("err = %v, want %s", err, c.code)
			}
		})
	}
	// versions count up, the hash is of the text as given, an identical text is refused
	var v1, v2 *store.TermsDocument
	var err error
	w.in(t, func(tx *store.TenantTx) error {
		v1, err = terms.Publish(tx, "u", terms.Input{Key: "aup", Title: "AUP", Body: "one"}, storetest.Now)
		if err != nil {
			return err
		}
		v2, err = terms.Publish(tx, "u", terms.Input{Key: "aup", Title: "AUP", Body: "two", GraceDays: grace(0)}, storetest.Now)
		return err
	})
	if v1.Version != 1 || v2.Version != 2 || v1.TextSHA256 != terms.Hash("one") || v2.GraceDays != 0 || v1.GraceDays != terms.DefaultGrace {
		t.Errorf("versions = %+v %+v", v1, v2)
	}
	w.in(t, func(tx *store.TenantTx) error {
		_, err = terms.Publish(tx, "u", terms.Input{Key: "aup", Title: "AUP", Body: "two"}, storetest.Now)
		return nil
	})
	var re *requests.Error
	if !errors.As(err, &re) || re.Code != "unchanged" {
		t.Errorf("republishing the same text = %v", err)
	}
}

// TestRequired_States walks one document through accepted, grace and blocked.
func TestRequired_States(t *testing.T) {
	w := newWorld(t)
	t0 := storetest.Now
	day := 24 * time.Hour
	var d1 *store.TermsDocument
	w.in(t, func(tx *store.TenantTx) error {
		var err error
		if d1, err = terms.Publish(tx, "u", terms.Input{Key: "aup", Title: "AUP", Body: "one", GraceDays: grace(7)}, t0); err != nil {
			return err
		}
		return terms.Assign(tx, "aup", []string{"visitor"}, nil, t0)
	})
	state := func(at time.Time) []terms.Requirement {
		t.Helper()
		var out []terms.Requirement
		if err := w.db.ReadTenant(context.Background(), w.tn.ID, func(tx *store.TenantTx) (err error) {
			out, err = terms.Required(tx, w.guest, at)
			return
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	// never accepted: the grace period runs from the publication
	if r := state(t0.Add(6 * day)); len(r) != 1 || r[0].State != terms.StateGrace {
		t.Errorf("before the end of the grace period: %+v", r)
	}
	if r := state(t0.Add(7 * day)); len(r) != 1 || r[0].State != terms.StateBlocked || !terms.IsBlocked(r) {
		t.Errorf("at the end of the grace period: %+v", r)
	}
	// accept v1
	w.in(t, func(tx *store.TenantTx) error {
		_, err := terms.Accept(tx, terms.Accepting{IdentityID: w.guest, Context: store.TermsContextSignin},
			[]terms.Shown{{DocumentID: d1.ID, SHA256: d1.TextSHA256}}, t0)
		return err
	})
	if r := state(t0.Add(100 * day)); len(r) != 1 || r[0].State != terms.StateAccepted || len(terms.Outstanding(r)) != 0 {
		t.Errorf("after accepting: %+v", r)
	}
	// v2 two days later: grace of its own, from its publication; the person had accepted v1
	t2 := t0.Add(2 * day)
	w.in(t, func(tx *store.TenantTx) error {
		_, err := terms.Publish(tx, "u", terms.Input{Key: "aup", Title: "AUP", Body: "two", GraceDays: grace(3)}, t2)
		return err
	})
	if r := state(t2.Add(day)); len(r) != 1 || r[0].State != terms.StateGrace || !r[0].Prior || r[0].Doc.Version != 2 || !r[0].DueBy.Equal(t2.Add(3*day)) {
		t.Errorf("v2 in its grace period: %+v", r)
	}
	if r := state(t2.Add(3 * day)); len(r) != 1 || r[0].State != terms.StateBlocked {
		t.Errorf("v2 after its grace period: %+v", r)
	}
	// a document assigned later has its grace period from the assignment, not its (older) publication
	t3 := t0.Add(30 * day)
	w.in(t, func(tx *store.TenantTx) error {
		if _, err := terms.Publish(tx, "u", terms.Input{Key: "nda", Title: "NDA", Body: "n", GraceDays: grace(2)}, t0); err != nil {
			return err
		}
		return terms.Assign(tx, "nda", nil, []int64{w.group}, t3)
	})
	for _, r := range state(t3.Add(day)) {
		if r.Doc.Key == "nda" && r.State != terms.StateGrace {
			t.Errorf("nda a day after it was assigned: %+v", r)
		}
	}
	// a person with no sponsorship, and one in another tenant, owe nothing
	if err := w.db.ReadTenant(context.Background(), w.tn.ID, func(tx *store.TenantTx) error {
		r, err := terms.Required(tx, w.tn.IDs["bob"], t3.Add(900*day))
		if err != nil || len(r) != 0 {
			t.Errorf("a person with no sponsorship owes %+v, %v", r, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestAccept_Refusals(t *testing.T) {
	w := newWorld(t)
	var d *store.TermsDocument
	w.in(t, func(tx *store.TenantTx) error {
		var err error
		if d, err = terms.Publish(tx, "u", terms.Input{Key: "aup", Title: "AUP", Body: "one"}, storetest.Now); err != nil {
			return err
		}
		return terms.Assign(tx, "aup", []string{"visitor"}, nil, storetest.Now)
	})
	who := terms.Accepting{IdentityID: w.guest, Context: store.TermsContextSignin}
	for name, shown := range map[string][]terms.Shown{
		"none":              nil,
		"wrong hash":        {{DocumentID: d.ID, SHA256: strings.Repeat("a", 64)}},
		"unknown id":        {{DocumentID: uuid.NewString(), SHA256: d.TextSHA256}},
		"one good, one bad": {{DocumentID: d.ID, SHA256: d.TextSHA256}, {DocumentID: uuid.NewString(), SHA256: d.TextSHA256}},
	} {
		t.Run(name, func(t *testing.T) {
			var err error
			w.in(t, func(tx *store.TenantTx) error { _, err = terms.Accept(tx, who, shown, storetest.Now); return nil })
			var re *requests.Error
			if !errors.As(err, &re) {
				t.Fatalf("err = %v", err)
			}
			w.in(t, func(tx *store.TenantTx) error {
				if xs, err := tx.TermsAcceptancesFor(w.guest); err != nil || len(xs) != 0 {
					t.Errorf("a refused request wrote %v, %v", xs, err)
				}
				return nil
			})
		})
	}
	// the hash may be upper case; a repeat is not written twice
	w.in(t, func(tx *store.TenantTx) error {
		got, err := terms.Accept(tx, who, []terms.Shown{{DocumentID: d.ID, SHA256: strings.ToUpper(d.TextSHA256)}, {DocumentID: d.ID, SHA256: d.TextSHA256}}, storetest.Now)
		if err != nil || len(got) != 1 {
			t.Errorf("Accept = %v, %v", got, err)
		}
		return nil
	})
	// accepting what is already accepted is refused: it is no longer outstanding
	var err error
	w.in(t, func(tx *store.TenantTx) error {
		_, err = terms.Accept(tx, who, []terms.Shown{{DocumentID: d.ID, SHA256: d.TextSHA256}}, storetest.Now)
		return nil
	})
	if err == nil {
		t.Error("accepting twice was allowed")
	}
}

func TestAssign_Validation(t *testing.T) {
	w := newWorld(t)
	w.in(t, func(tx *store.TenantTx) error {
		_, err := terms.Publish(tx, "u", terms.Input{Key: "aup", Title: "AUP", Body: "one"}, storetest.Now)
		return err
	})
	check := func(name string, pops []string, groups []int64, key string, want error, code string) {
		t.Helper()
		var err error
		w.in(t, func(tx *store.TenantTx) error { err = terms.Assign(tx, key, pops, groups, storetest.Now); return nil })
		var re *requests.Error
		switch {
		case want != nil && !errors.Is(err, want):
			t.Errorf("%s: err = %v, want %v", name, err, want)
		case want == nil && code != "" && (!errors.As(err, &re) || re.Code != code):
			t.Errorf("%s: err = %v, want %s", name, err, code)
		case want == nil && code == "" && err != nil:
			t.Errorf("%s: err = %v", name, err)
		}
	}
	check("unknown key", []string{"visitor"}, nil, "nope", store.ErrNotFound, "")
	check("unknown population", []string{"alien"}, nil, "aup", nil, "invalid_population")
	check("unknown group", nil, []int64{987654}, "aup", nil, "invalid_bundle")
	check("good", []string{"visitor", "visitor"}, []int64{w.group}, "aup", nil, "")
	w.in(t, func(tx *store.TenantTx) error {
		as, err := tx.TermsAssignments()
		if err != nil || len(as) != 2 {
			t.Errorf("assignments = %v, %v (a repeated population is one)", as, err)
		}
		return nil
	})
	check("replace with none", nil, nil, "aup", nil, "")
	w.in(t, func(tx *store.TenantTx) error {
		if as, err := tx.TermsAssignments(); err != nil || len(as) != 0 {
			t.Errorf("assignments after clearing = %v, %v", as, err)
		}
		return nil
	})
}

// TestRecordConsent_Validation: an unknown attribute is refused before anything
// is written (the recorded consent itself is covered through the claim API).
func TestRecordConsent_Validation(t *testing.T) {
	w := newWorld(t)
	var err error
	w.in(t, func(tx *store.TenantTx) error {
		err = terms.RecordConsent(tx, w.guest, strings.Repeat("e", 64), "home_idp", []string{"shoe_size"}, storetest.Now)
		return nil
	})
	var re *requests.Error
	if !errors.As(err, &re) || re.Code != "invalid_attribute" {
		t.Errorf("err = %v", err)
	}
	for k, want := range map[string]bool{"home_idp": true, "incommon": true, "edugain": true, "dev_idp": false, "hosted": false, "": false} {
		if terms.ConsentApplies(k) != want {
			t.Errorf("ConsentApplies(%q) = %v", k, !want)
		}
	}
}
