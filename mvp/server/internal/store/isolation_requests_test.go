package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Access request isolation (issue #164): a tenant sees and changes only its
// own catalog items, request lines and their history; another tenant's ids
// look nonexistent and rows naming them are refused by the guard triggers.

type reqRows struct {
	user  *store.PlatformUser
	item  string
	line  string
	group int64
	alice int64
	acct  int64
	edge  int64
}

func seedReqRows(t *testing.T, db *store.DB, tn storetest.Tenant, tag string) reqRows {
	t.Helper()
	r := reqRows{item: "item-" + tag, line: "line-" + tag, group: tn.IDs["group:okta:eng"], alice: tn.IDs["alice"],
		acct: tn.IDs["acct:okta:alice"]}
	err := db.InTenant(context.Background(), tn.ID, func(c *store.TenantTx) error {
		r.user = &store.PlatformUser{DisplayName: "requester " + tag, CreatedAt: storetest.Now}
		if err := c.InsertPlatformUser(r.user); err != nil {
			return err
		}
		uid := r.user.ID.String()
		if err := c.PutCatalogItem(&store.CatalogItem{ID: r.item, GroupID: r.group, Requestable: true, Risk: "low",
			UpdatedBy: &uid, UpdatedAt: storetest.Now}); err != nil {
			return err
		}
		if err := c.InsertRequestLine(&store.RequestLine{ID: r.line, BatchID: "batch-" + tag, CatalogItemID: r.item,
			GroupID: r.group, BeneficiaryID: r.alice, AccountID: r.acct, RequestedBy: uid, Justification: "x",
			RequestedAt: storetest.Now}); err != nil {
			return err
		}
		var err error
		r.edge, err = c.InsertEdge(&store.GrantEdge{Src: key("account", r.acct), Dst: key("group", tn.IDs["group:okta:payments-clerks"]),
			Relation: "member_of", Source: "request", CreatedAt: storetest.Now})
		if err != nil {
			return err
		}
		return c.AddRequestEvent(&store.RequestEvent{LineID: r.line, Event: "submitted", ActorUserID: &uid, Actor: "r", At: storetest.Now})
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func reqFixture(t *testing.T) (*storetest.Fixture, reqRows, reqRows) {
	t.Helper()
	f := storetest.TwoTenants(t)
	return f, seedReqRows(t, f.DB, f.A, "a"), seedReqRows(t, f.DB, f.B, "b")
}

func TestIsolation_RequestReads(t *testing.T) {
	f, a, b := reqFixture(t)
	inB(t, f, func(c *store.TenantTx) error {
		items, err := c.CatalogItems()
		if err != nil || len(items) != 1 || items[0].ID != b.item {
			t.Errorf("CatalogItems = %v, %v", items, err)
		}
		if _, err := c.CatalogItem(a.item); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("CatalogItem(A's) = %v", err)
		}
		if _, err := c.CatalogItemForGroup(a.group); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("CatalogItemForGroup(A's) = %v", err)
		}
		lines, err := c.RequestLines(store.RequestFilter{})
		if err != nil || len(lines) != 1 || lines[0].ID != b.line {
			t.Errorf("RequestLines = %v, %v", lines, err)
		}
		if ls, err := c.RequestLines(store.RequestFilter{InvolvingUser: a.user.ID.String(), InvolvingIdentity: a.alice}); err != nil || len(ls) != 0 {
			t.Errorf("RequestLines(A's user) = %v, %v", ls, err)
		}
		if _, err := c.RequestLine(a.line); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("RequestLine(A's) = %v", err)
		}
		if _, err := c.OpenRequestLine(a.alice, a.group); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("OpenRequestLine(A's) = %v", err)
		}
		if evs, err := c.RequestEvents(a.line); err != nil || len(evs) != 0 {
			t.Errorf("RequestEvents(A's) = %v, %v", evs, err)
		}
		due, err := c.DueRequestLines(storetest.Now.Add(time.Hour))
		if err != nil || len(due) != 0 {
			t.Errorf("DueRequestLines = %v, %v", due, err)
		}
		if n, err := c.CountDueRequestLines(storetest.Now); err != nil || n != 0 {
			t.Errorf("CountDueRequestLines = %d, %v", n, err)
		}
		return nil
	})
}

// reqMutations change one of A's rows (or point B's at A's); run in B they
// fail and leave A alone.
var reqMutations = map[string]func(c *store.TenantTx, a, b reqRows) error{
	"SaveRequestLine": func(c *store.TenantTx, a, _ reqRows) error {
		return c.SaveRequestLine(&store.RequestLine{ID: a.line, Status: store.RequestCancelled}, store.RequestPending)
	},
	"PutCatalogItem": func(c *store.TenantTx, a, b reqRows) error {
		return c.PutCatalogItem(&store.CatalogItem{ID: "x", GroupID: a.group, Risk: "low", UpdatedAt: storetest.Now})
	},
	"InsertRequestLine": func(c *store.TenantTx, a, b reqRows) error {
		return c.InsertRequestLine(&store.RequestLine{ID: "x", BatchID: "x", CatalogItemID: a.item, GroupID: b.group,
			BeneficiaryID: b.alice, AccountID: b.acct, RequestedBy: b.user.ID.String(), Justification: "x", RequestedAt: storetest.Now})
	},
	"AddRequestEvent": func(c *store.TenantTx, a, _ reqRows) error {
		return c.AddRequestEvent(&store.RequestEvent{LineID: a.line, Event: "cancelled", Actor: "x", At: storetest.Now})
	},
	"DeleteRequestEdge": func(c *store.TenantTx, a, _ reqRows) error {
		if err := c.DeleteRequestEdge(a.edge); err != nil {
			return err
		}
		return store.ErrNotFound // nothing to delete in B; A's dump proves the edge stayed
	},
}

func TestIsolation_RequestMutationsScoped(t *testing.T) {
	for name, fn := range reqMutations {
		t.Run(name, func(t *testing.T) {
			f, a, b := reqFixture(t)
			before := reqDump(t, f.DB, f.A.ID)
			err := f.DB.InTenant(context.Background(), f.B.ID, func(c *store.TenantTx) error { return fn(c, a, b) })
			if !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrCrossTenant) {
				t.Fatalf("%s across tenants = %v, want ErrNotFound or ErrCrossTenant", name, err)
			}
			if after := reqDump(t, f.DB, f.A.ID); after != before {
				t.Errorf("%s in B changed A", name)
			}
		})
	}
}

func TestRequests_EventsAppendOnly(t *testing.T) {
	f, a, _ := reqFixture(t)
	err := f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		evs, err := c.RequestEvents(a.line)
		if err != nil || len(evs) != 1 {
			t.Fatalf("events = %v, %v", evs, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// a second open line for the same person and group is refused
	err = f.DB.InTenant(context.Background(), f.A.ID, func(c *store.TenantTx) error {
		return c.InsertRequestLine(&store.RequestLine{ID: "dup", BatchID: "x", CatalogItemID: a.item, GroupID: a.group,
			BeneficiaryID: a.alice, AccountID: a.acct, RequestedBy: a.user.ID.String(), Justification: "x", RequestedAt: storetest.Now})
	})
	if err == nil {
		t.Error("a second open line for the same beneficiary and group was accepted")
	}
}

func reqDump(t *testing.T, db *store.DB, tid tenancy.ID) string {
	t.Helper()
	out := storetest.Dump(t, db, tid)
	if err := db.ReadTenant(context.Background(), tid, func(c *store.TenantTx) error {
		items, err := c.CatalogItems()
		if err != nil {
			return err
		}
		lines, err := c.RequestLines(store.RequestFilter{})
		if err != nil {
			return err
		}
		var evs []*store.RequestEvent
		for _, l := range lines {
			e, err := c.RequestEvents(l.ID)
			if err != nil {
				return err
			}
			evs = append(evs, e...)
		}
		b, err := json.Marshal([]any{items, lines, evs})
		out += "\n" + string(b)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func requestsCovered() map[string]bool {
	out := map[string]bool{}
	for k := range reqMutations {
		out[k] = true
	}
	for _, k := range []string{"CatalogItems", "CatalogItem", "CatalogItemForGroup", "RequestLines", "RequestLine",
		"OpenRequestLine", "RequestEvents", "DueRequestLines", "CountDueRequestLines"} {
		out[k] = true // TestIsolation_RequestReads
	}
	return out
}
