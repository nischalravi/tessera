package archive_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/requests"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

type guardWorld struct {
	lines     []string // two denied requests, each with an event log
	campaigns []string // two completed campaigns, each with a frozen population
}

// seedGuards gives a fixture tenant two denied requests and two completed campaigns with a frozen population.
func seedGuards(t *testing.T, f *storetest.Fixture, tn storetest.Tenant) guardWorld {
	t.Helper()
	var w guardWorld
	ids := tn.IDs
	if err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
		a := ids["alice"]
		var alice, pat requests.Actor
		for _, u := range []struct {
			actor *requests.Actor
			name  string
			ident *int64
		}{{&alice, "Alice", &a}, {&pat, "Pat", nil}} {
			pu := &store.PlatformUser{DisplayName: u.name, IdentityID: u.ident, CreatedAt: old}
			if err := c.InsertPlatformUser(pu); err != nil {
				return err
			}
			*u.actor = requests.Actor{UserID: pu.ID, Display: u.name, IdentityID: u.ident}
		}
		pat.Decider = true
		var items []string
		for _, g := range []string{"group:okta:platform", "group:snowflake:PII_READER"} {
			it, err := requests.PutItem(c, ids[g], requests.ItemSpec{Requestable: true, Risk: "low"}, pat, old)
			if err != nil {
				return err
			}
			items = append(items, it.ID)
		}
		_, lines, err := requests.Submit(c, requests.Submission{Beneficiaries: []int64{ids["alice"]}, Items: items, Justification: "project"}, alice, false, old)
		if err != nil {
			return err
		}
		for _, l := range lines {
			if _, err := requests.Deny(c, l.ID, pat, "no", old); err != nil {
				return err
			}
			w.lines = append(w.lines, l.ID)
		}
		for i := range 2 {
			id, err := c.InsertCampaign(&store.ReviewCampaign{TenantID: tn.ID, Name: fmt.Sprintf("c%d", i), CreatedAt: old, Status: "completed"})
			if err != nil {
				return err
			}
			if err := c.InsertReviewPopulation(&store.ReviewPopulation{TenantID: tn.ID, CampaignID: id, CreatedAt: old, PopulationHash: "h",
				SystemCounts: json.RawMessage(`{}`), SourceSyncs: json.RawMessage(`{}`), Scope: json.RawMessage(`{}`), RulesVersion: "v"}, nil); err != nil {
				return err
			}
			w.campaigns = append(w.campaigns, fmt.Sprint(id))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return w
}

// segmentFor catalogues a segment of class that lists items, and moves it to status (written or verified).
func segmentFor(t *testing.T, f *storetest.Fixture, tn storetest.Tenant, class string, items []string, verified bool) {
	t.Helper()
	if err := f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
		g := &store.ArchiveSegment{ID: uuid.NewString(), Class: class, RangeFrom: "x", RangeTo: "y", Count: int64(len(items)),
			Location: store.LocationLocal, ObjectKey: "k", Size: 1, SHA256: strings.Repeat("0", 64), CreatedAt: now}
		if err := c.InsertArchiveSegment(g); err != nil {
			return err
		}
		if err := c.InsertArchiveSegmentItems(g.ID, items); err != nil {
			return err
		}
		if verified {
			return c.MarkArchiveVerified(g.ID, now)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func deletes(f *storetest.Fixture, tn storetest.Tenant, class, id string) error {
	return f.DB.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error { return c.ArchiveDelete(class, id) })
}

// A verified segment unlocks the append-only rows of the records it lists and of no others: not another
// record of the tenant, not a record of another tenant, and not a segment that is only written. A
// segment a crash left verified before its purge is exactly this state.
func TestVerifiedSegmentUnlocksOnlyItsOwnRecords(t *testing.T) {
	f := storetest.TwoTenants(t)
	a, b := seedGuards(t, f, f.A), seedGuards(t, f, f.B)

	for _, c := range []struct {
		class string
		ids   func(guardWorld) []string
	}{
		{store.ClassRequests, func(w guardWorld) []string { return w.lines }},
		{store.ClassCampaigns, func(w guardWorld) []string { return w.campaigns }},
	} {
		t.Run(c.class, func(t *testing.T) {
			bi, ai := c.ids(b), c.ids(a)
			// nothing listed, nothing unlocked
			if err := deletes(f, f.B, c.class, bi[0]); err == nil {
				t.Fatal("deleted with no segment")
			}
			// a segment that lists the first record but is only written unlocks nothing
			segmentFor(t, f, f.B, c.class, bi[:1], false)
			if err := deletes(f, f.B, c.class, bi[0]); err == nil {
				t.Error("a written segment unlocked its record")
			}
			// verified, listing the first record: the crash-before-purge state
			segmentFor(t, f, f.B, c.class, bi[:1], true)
			if err := deletes(f, f.B, c.class, bi[1]); err == nil {
				t.Error("a verified segment unlocked a record it does not list")
			}
			if err := deletes(f, f.A, c.class, ai[0]); err == nil {
				t.Error("tenant B's verified segment unlocked tenant A's record")
			}
			if err := deletes(f, f.B, c.class, bi[0]); err != nil {
				t.Errorf("the listed record is not deletable: %v", err)
			}
			// the class matters: a verified segment of the other class unlocks nothing here
			other := store.ClassRequests
			if c.class == store.ClassRequests {
				other = store.ClassCampaigns
			}
			segmentFor(t, f, f.A, other, ai[:1], true)
			if err := deletes(f, f.A, c.class, ai[0]); err == nil {
				t.Error("a verified segment of another class unlocked a record")
			}
		})
	}
}
