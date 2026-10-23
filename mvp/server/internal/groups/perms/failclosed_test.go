package perms_test

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/attrs"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/model"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/perms"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// junkLimit adds a limit whose name is not a known limit, as a row stored before
// the write path validated limits.
func (w *world) junkLimit(t *testing.T, e attrs.Env, on string) {
	t.Helper()
	bogus, err := attrs.NameByFullName(e.Tx, "app:limits:bogus")
	if err != nil {
		bogus, err = attrs.CreateName(e, attrs.NameInput{Def: w.limits.ID, Extension: "bogus"})
	}
	must(t, err)
	w.limit(t, e, on, bogus, "x")
}

// TestLimits_UncompilableDisallowFailsClosed: an allow whose limit does not
// compile never applies, a disallow whose limit does not compile stays in force
// (also against a broader allow), in the decision and in the Cedar export.
func TestLimits_UncompilableDisallowFailsClosed(t *testing.T) {
	for _, tc := range []string{"unknown limit name", "bad cidr"} {
		t.Run(tc, func(t *testing.T) {
			w := newWorld(t)
			now := storetest.Now
			w.tx(t, now, func(c *store.TenantTx, e attrs.Env) {
				w.grant(t, e, owner(store.AttrOwnerGroup, string(w.staff)), w.ledger, w.read, false) // broader allow
				deny := w.grant(t, e, owner(store.AttrOwnerGroup, string(w.payroll)), w.entry, w.read, true)
				if tc == "bad cidr" {
					w.limit(t, e, deny, w.ip, "not-a-cidr")
				} else {
					w.junkLimit(t, e, deny)
				}
				// an allow with a junk limit grants nothing
				junkAllow := w.grant(t, e, owner(store.AttrOwnerGroup, string(w.staff)), w.entry, w.write, false)
				w.junkLimit(t, e, junkAllow)

				ctx := perms.Context{"ip": "10.0.0.1"}
				if d := decide(t, c, w.alice, "app:perms:entry", "read", ctx, now); d.Allowed || d.Reason != "disallowed" {
					t.Errorf("alice: %+v, want the disallow to hold", d)
				}
				if d := decide(t, c, w.pat, "app:perms:entry", "read", ctx, now); !d.Allowed {
					t.Errorf("pat (not in payroll): %+v, want allowed", d)
				}
				if d := decide(t, c, w.pat, "app:perms:entry", "write", ctx, now); d.Allowed {
					t.Errorf("pat: an allow with a junk limit granted: %+v", d)
				}
				s, err := perms.Load(c)
				must(t, err)
				text := s.Policy(now)
				i := strings.Index(text, "// assignment "+deny+" has a limit that does not compile")
				if i < 0 {
					t.Fatalf("policy does not note the junk limit:\n%s", text)
				}
				stanza := text[i:]
				if j := strings.Index(stanza, ";\n"); j >= 0 {
					stanza = stanza[:j]
				}
				if !strings.Contains(stanza, "forbid (") || strings.Contains(stanza, "when") {
					t.Errorf("want an unconditional forbid, got:\n%s", stanza)
				}
				if !strings.Contains(text, "// assignment "+junkAllow+" is left out") {
					t.Errorf("the junk allow is not left out:\n%s", text)
				}
			})
		})
	}
}

// TestPermissions_PITDisallowOfDeletedMembership: a (role, identity) disallow
// applied while the membership existed, though the row is gone now.
func TestPermissions_PITDisallowOfDeletedMembership(t *testing.T) {
	w := newWorld(t)
	t1 := storetest.Now.Add(time.Hour)
	t2 := t1.Add(time.Hour)
	w.tx(t, t1, func(c *store.TenantTx, e attrs.Env) {
		w.grant(t, e, owner(store.AttrOwnerGroup, string(w.payroll)), w.entry, w.read, false)
		w.grant(t, e, owner(store.AttrOwnerMembership, w.ivanInPayroll), w.entry, w.read, true)
	})
	w.tx(t, t2, func(c *store.TenantTx, e attrs.Env) {
		_, err := (model.Env{Tx: c, Now: t2, TenantAdmin: true}).RemoveMember(w.payroll, strconv.FormatInt(w.ivan, 10))
		must(t, err)
	})
	w.tx(t, t2.Add(time.Hour), func(c *store.TenantTx, _ attrs.Env) {
		at := func(who int64, when time.Time) bool {
			s, err := perms.LoadAt(c, when)
			must(t, err)
			sub, err := perms.SubjectAt(c, who, when)
			must(t, err)
			q, err := s.Resolve("app:perms:entry", "read")
			must(t, err)
			d, err := s.Decide(sub, q, nil, when)
			must(t, err)
			return d.Allowed
		}
		if at(w.ivan, t1.Add(time.Minute)) {
			t.Error("ivan at t1: allowed, but his pair's disallow applied")
		}
		if !at(w.alice, t1.Add(time.Minute)) {
			t.Error("alice at t1: denied")
		}
	})
}

// TestEffective_Bounded: the effective-permission builder stops at MaxEntries
// and says it truncated.
func TestEffective_Bounded(t *testing.T) {
	w := newWorld(t)
	now := storetest.Now
	w.tx(t, now, func(c *store.TenantTx, e attrs.Env) {
		// 1501 resources x 4 actions (write implies read, a1 and a2) > MaxEntries
		const names = 1500
		ids := make([]string, 0, names)
		for i := 0; i < names; i++ {
			n, err := attrs.CreateName(e, attrs.NameInput{Def: w.perms.ID, Extension: "r" + strconv.Itoa(i)})
			must(t, err)
			ids = append(ids, n.ID)
		}
		_, err := attrs.SetNameImplies(e, w.ledger.ID, ids)
		must(t, err)
		var acts []string
		for _, n := range []string{"a1", "a2"} {
			a, err := attrs.CreateAction(e, w.perms.ID, n, "")
			must(t, err)
			acts = append(acts, a.ID)
		}
		_, err = attrs.SetActionImplies(e, w.write.ID, append(acts, w.read.ID))
		must(t, err)
		w.grant(t, e, owner(store.AttrOwnerGroup, string(w.payroll)), w.ledger, w.write, false)
		s, err := perms.Load(c)
		must(t, err)
		sub, err := perms.SubjectOf(c, w.alice, now)
		must(t, err)
		eff, truncated, err := s.Effective(sub, now)
		must(t, err)
		if len(eff) != perms.MaxEntries || !truncated {
			t.Errorf("effective: %d entries, truncated %v; want %d and true", len(eff), truncated, perms.MaxEntries)
		}
	})
}
