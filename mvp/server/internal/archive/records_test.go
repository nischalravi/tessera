package archive_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/archive"
	"github.com/nischalravi/tessera/mvp/server/internal/requests"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

// Closed requests and completed review campaigns go with their dependants (the
// request's event log and stages; the campaign's items, frozen population and
// auto-decisions), and a record changed after it was archived stays online.
func TestRequestsAndCampaignsWithDependants(t *testing.T) {
	f := storetest.TwoTenants(t)
	tn := f.B.ID
	ids := f.B.IDs
	ctx := context.Background()
	in := func(fn func(c *store.TenantTx) error) {
		t.Helper()
		if err := f.DB.InTenant(ctx, tn, fn); err != nil {
			t.Fatal(err)
		}
	}
	var alice, pat requests.Actor
	var lineID string
	var campaign int64
	in(func(c *store.TenantTx) error {
		a := ids["alice"]
		// a decider with no linked identity is refused (approver_unlinked, issue #443)
		patID, err := c.InsertIdentity(&store.Identity{TenantID: c.Tenant(), ExternalID: "pat", Name: "Pat", Type: "human", Status: "active", CreatedAt: old})
		if err != nil {
			return err
		}
		for _, u := range []struct {
			actor *requests.Actor
			name  string
			ident *int64
		}{{&alice, "Alice", &a}, {&pat, "Pat", &patID}} {
			pu := &store.PlatformUser{DisplayName: u.name, IdentityID: u.ident, CreatedAt: old}
			if err := c.InsertPlatformUser(pu); err != nil {
				return err
			}
			*u.actor = requests.Actor{UserID: pu.ID, Display: u.name, IdentityID: u.ident}
		}
		pat.Decider = true
		it, err := requests.PutItem(c, ids["group:okta:platform"], requests.ItemSpec{Requestable: true, Risk: "low"}, pat, old)
		if err != nil {
			return err
		}
		_, lines, err := requests.Submit(c, requests.Submission{Beneficiaries: []int64{ids["alice"]}, Items: []string{it.ID},
			Justification: "project Atlas"}, alice, false, old)
		if err != nil {
			return err
		}
		lineID = lines[0].ID
		if _, err := requests.Deny(c, lineID, pat, "not needed", old.Add(time.Hour)); err != nil {
			return err
		}
		campaign, err = c.InsertCampaign(&store.ReviewCampaign{TenantID: tn, Name: "old campaign", CreatedAt: old, Status: "completed"})
		if err != nil {
			return err
		}
		return c.InsertReviewItem(&store.ReviewItem{TenantID: tn, CampaignID: campaign, IdentityID: ids["alice"], EdgeSrc: fmt.Sprintf("account:%d", ids["acct:okta:alice"]),
			EdgeDst: fmt.Sprintf("group:%d", ids["group:okta:platform"]), GrantLabel: "okta / platform", Reasons: []string{"unused"}, Context: json.RawMessage(`{}`)})
	})
	// before the archive runs, the append-only event log refuses a delete
	err := f.DB.InTenant(ctx, tn, func(c *store.TenantTx) error { return c.ArchiveDelete(store.ClassRequests, lineID) })
	if err == nil {
		t.Fatal("a request and its event log were deleted with no verified segment")
	}

	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		t.Fatal(err)
	}
	sealer, err := seal.New(kek)
	if err != nil {
		t.Fatal(err)
	}
	local, err := archive.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	svc := &archive.Service{DB: f.DB, Sealer: sealer, Store: local, Clock: func() time.Time { return now }}
	res, err := svc.RunTenant(ctx, tn)
	if err != nil {
		t.Fatal(err)
	}
	if r := res.Classes[store.ClassRequests]; r.Purged != 1 || r.Records != 1 {
		t.Errorf("requests = %+v", r)
	}
	if r := res.Classes[store.ClassCampaigns]; r.Purged != 1 || r.Records != 1 {
		t.Errorf("campaigns = %+v", r)
	}
	if err := f.DB.ReadTenant(ctx, tn, func(c *store.TenantTx) error {
		if _, err := c.RequestLine(lineID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("the request is still online: %v", err)
		}
		if _, err := c.Campaign(campaign); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("the campaign is still online: %v", err)
		}
		if items, err := c.CampaignItems(campaign); err != nil || len(items) != 0 {
			t.Errorf("campaign items online = %v, %v", items, err)
		}
		gs, err := c.ArchiveSegments(store.ArchiveSegmentFilter{Class: store.ClassRequests})
		if err != nil || len(gs) != 1 {
			t.Fatalf("segments = %v, %v", gs, err)
		}
		var buf bytes.Buffer
		if n, err := svc.Export(ctx, tn, gs[0], &buf); err != nil || n != 1 {
			t.Fatalf("export = %d, %v", n, err)
		}
		for _, want := range []string{lineID, "access_request_events", "access_request_stages", "not needed", "denied"} {
			if !strings.Contains(buf.String(), want) {
				t.Errorf("the archived request lacks %q", want)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// A record that changed between the archive and the purge is not deleted with
// the stale copy: the purge keeps it online and the next segment archives its
// current state.
func TestChangedRecordIsNotDeletedWithAStaleCopy(t *testing.T) {
	e := newEnv(t)
	e.seed()
	e.write(func(tx *store.TenantTx) error { // only the campaigns are due
		for _, c := range []string{store.ClassAudit, store.ClassRequests, store.ClassJobRuns, store.ClassOutbox} {
			if err := tx.SetRetentionPolicy(c, 3650, now, ""); err != nil {
				return err
			}
		}
		return nil
	})
	boom := errors.New("down")
	reads := 0
	e.blobs.onGet = func(_ int, b []byte) ([]byte, error) {
		reads++
		if reads == 2 { // the check right before the purge: stop with the segment verified
			return nil, boom
		}
		return b, nil
	}
	if _, err := e.svc.RunTenant(context.Background(), tenantT); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	e.write(func(tx *store.TenantTx) error { // c0 changes after it was archived
		cs, err := tx.CampaignsNewestFirst()
		if err != nil {
			return err
		}
		for _, c := range cs {
			if c.Name == "c0" {
				return tx.SetCampaignTotals(c.ID, 99, 1)
			}
		}
		return errors.New("no c0")
	})
	e.blobs.onGet = nil
	res, err := e.svc.RunTenant(context.Background(), tenantT)
	if err != nil {
		t.Fatal(err)
	}
	if r := res.Classes[store.ClassCampaigns]; r.Kept != 1 || r.Purged != 2 {
		t.Errorf("campaigns = %+v, want the stale copy kept out of the purge and the new state archived", r)
	}
	_, campaigns, _ := e.online()
	if len(campaigns) != 2 || campaigns[0] != "c2" || campaigns[1] != "recent" {
		t.Errorf("campaigns online = %v", campaigns)
	}
	var export strings.Builder
	for _, g := range e.segments() {
		if g.Class == store.ClassCampaigns {
			var buf bytes.Buffer
			if _, err := e.svc.Export(context.Background(), tenantT, g, &buf); err != nil {
				t.Fatal(err)
			}
			export.Write(buf.Bytes())
		}
	}
	if !strings.Contains(export.String(), `"total_grants":99`) {
		t.Error("the changed campaign's current state was not archived")
	}
}
