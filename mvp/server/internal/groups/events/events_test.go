package events_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/events"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

var (
	t0  = time.Date(2026, 10, 8, 9, 30, 0, 123456000, time.UTC)
	tid = tenancy.MustParse("00000000-0000-4000-8000-0000000000e5")
)

func open(t *testing.T) *store.DB {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.InSystem(ctx, "test", func(s *store.SystemTx) error {
		_, err := s.CreateTenant(store.Tenant{ID: tid, Slug: "events-test", Name: "events", CreatedAt: t0})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return db
}

func in(t *testing.T, db *store.DB, fn func(tx *store.TenantTx) error) {
	t.Helper()
	if err := db.InTenant(context.Background(), tid, fn); err != nil {
		t.Fatal(err)
	}
}

func TestAppendValidates(t *testing.T) {
	db := open(t)
	in(t, db, func(tx *store.TenantTx) error {
		for name, e := range map[string]*events.Event{
			"unknown type":     {Type: "group.exploded", ObjectID: "g", OccurredAt: t0},
			"no object id":     {Type: events.GroupCreated, OccurredAt: t0},
			"wrong object":     {Type: events.GroupCreated, ObjectType: store.EventObjFolder, ObjectID: "g", OccurredAt: t0},
			"data not JSON":    {Type: events.GroupCreated, ObjectID: "g", Data: json.RawMessage(`{`), OccurredAt: t0},
			"data too large":   {Type: events.GroupCreated, ObjectID: "g", Data: json.RawMessage(`"` + strings.Repeat("x", events.MaxDataBytes) + `"`), OccurredAt: t0},
			"unknown cause":    {Type: events.GroupCreated, ObjectID: "g", CauseType: "magic", OccurredAt: t0},
			"unknown obj type": {Type: events.GroupCreated, ObjectType: "widget", ObjectID: "g", OccurredAt: t0},
		} {
			if err := events.Append(tx, e); err == nil {
				t.Errorf("%s: accepted", name)
			}
		}
		// the refusals left no number used up
		e := events.New(events.GroupCreated, "g", t0, store.CauseAPI)
		if err := events.Append(tx, e); err != nil || e.Seq != 1 {
			t.Errorf("first valid event = seq %d, %v; want 1", e.Seq, err)
		}
		if e.ObjectType != store.EventObjGroup || string(e.Data) != "{}" {
			t.Errorf("defaults: %+v", e)
		}
		return nil
	})
}

func TestCatalogueIsComplete(t *testing.T) {
	want := []string{"folder.created", "folder.renamed", "folder.moved", "folder.deleted", "group.created", "group.updated",
		"group.renamed", "group.moved", "group.deleted", "group.disabled", "group.enabled", "group.definition_changed",
		"membership.direct.added", "membership.direct.removed", "membership.direct.dates_changed", "membership.effective.added",
		"membership.effective.removed", "privilege.granted", "privilege.revoked", "attribute.assigned", "attribute.removed",
		"attribute.value_changed", "loader.run.applied", "loader.run.held", "loader.run.approved", "loader.run.rejected",
		"provisioning.op.verified", "provisioning.op.failed", "provisioning.op.drift", "attestation.due", "attestation.completed",
		"attestation.overdue_action", "rule.fired"}
	for _, typ := range want {
		if _, ok := events.ObjectType(typ); !ok {
			t.Errorf("design §10.1 type %q is not in the catalogue", typ)
		}
	}
}

func TestCauseRefIsTheRequestID(t *testing.T) {
	db := open(t)
	rid := "req-123"
	ctx := store.WithAuditContext(context.Background(), store.AuditContext{
		Actor: store.AuditActor{Type: store.ActorSystem}, RequestID: &rid})
	err := db.InTenant(ctx, tid, func(tx *store.TenantTx) error {
		e := events.New(events.GroupCreated, "g", t0, store.CauseAPI)
		if err := events.Append(tx, e); err != nil {
			return err
		}
		got, err := tx.GrpEventsAfter(0, 10, 10)
		if err != nil || len(got) != 1 || got[0].CauseRef != rid {
			t.Errorf("events = %+v, %v; want cause_ref %q", got, err, rid)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCursorsPollAck(t *testing.T) {
	db := open(t)
	in(t, db, func(tx *store.TenantTx) error {
		for i := 0; i < 5; i++ {
			if err := events.Append(tx, events.New(events.RuleFired, "r", t0.Add(time.Duration(i)*time.Second), store.CauseRule)); err != nil {
				return err
			}
		}
		return nil
	})
	in(t, db, func(tx *store.TenantTx) error {
		b, err := events.Poll(tx, "webhook:1", 3)
		if err != nil || len(b) != 3 || b[0].Seq != 1 || b[2].Seq != 3 {
			t.Fatalf("first poll = %v, %v", b, err)
		}
		if err := events.Ack(tx, "webhook:1", 3, t0); err != nil {
			t.Fatal(err)
		}
		if lag, err := events.Lag(tx, "webhook:1"); err != nil || lag != 2 {
			t.Errorf("lag = %d, %v; want 2", lag, err)
		}
		b, err = events.Poll(tx, "webhook:1", 100)
		if err != nil || len(b) != 2 || b[0].Seq != 4 {
			t.Errorf("second poll = %v, %v", b, err)
		}
		// another consumer has its own position
		if b, err := events.Poll(tx, "graph", 100); err != nil || len(b) != 5 {
			t.Errorf("an independent consumer sees %d events, %v; want all 5", len(b), err)
		}
		// a cursor never moves back, and never past the head
		if err := events.Ack(tx, "webhook:1", 1, t0); err != nil {
			t.Error(err)
		}
		if cur, _ := tx.GrpCursor("webhook:1"); cur != 3 {
			t.Errorf("cursor after an old ack = %d, want 3", cur)
		}
		if err := events.Ack(tx, "webhook:1", 99, t0); err == nil {
			t.Error("a cursor moved past the last event")
		}
		return nil
	})
}

func TestCloudEvent(t *testing.T) {
	ident := int64(42)
	e := &events.Event{Seq: 7, Type: events.MembershipEffectiveAdded, ObjectType: store.EventObjGroup, ObjectID: "grp-1",
		Identity: &ident, List: "list-1", CauseType: store.CauseEngine, CauseRef: "req-9", OccurredAt: t0,
		Data: json.RawMessage(`{"repair":true}`)}
	b, err := events.ToCloudEvent(tid, e)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]any{
		"specversion":     "1.0",
		"id":              tid.String() + "/7",
		"type":            "io.tessera.groups.membership.effective.added",
		"source":          "/tessera/tenants/" + tid.String() + "/groups",
		"subject":         "grp-1",
		"time":            "2026-10-08T09:30:00.123456Z",
		"datacontenttype": "application/json",
		"sequence":        "7",
		"tenantid":        tid.String(),
	} {
		if got[k] != want {
			t.Errorf("%s = %v, want %v", k, got[k], want)
		}
	}
	data, _ := got["data"].(map[string]any)
	if data["identity_id"] != float64(42) || data["list_id"] != "list-1" || data["cause_type"] != "engine" ||
		data["object_type"] != "group" || data["details"].(map[string]any)["repair"] != true {
		t.Errorf("data = %v", data)
	}
	// the same event always encodes to the same id (redelivery is deduplicated by id)
	b2, _ := events.ToCloudEvent(tid, e)
	if string(b) != string(b2) {
		t.Error("encoding is not deterministic")
	}
	if _, err := events.ToCloudEvent(tid, &events.Event{Type: "nope"}); err == nil {
		t.Error("an unknown type was encoded")
	}
}

// TestCanonicalIsJCS pins the digest's input: RFC 8785 canonical JSON, keys in
// code point order, no spaces, the whole row (every column) included.
func TestCanonicalIsJCS(t *testing.T) {
	ident := int64(5)
	audit := int64(11)
	e := &events.Event{Seq: 3, Type: events.GroupRenamed, ObjectType: store.EventObjGroup, ObjectID: "g", Identity: &ident,
		CauseType: store.CauseAPI, AuditSeq: &audit, OccurredAt: t0, Data: json.RawMessage(`{"b": 2, "a": [1, {"z":null,"y":"é"}]}`)}
	got, err := events.Canonical(e)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"audit_seq":11,"cause_ref":null,"cause_type":"api","data":{"a":[1,{"y":"é","z":null}],"b":2},` +
		`"identity_id":5,"list_id":null,"member_group_id":null,"object_id":"g","object_type":"group",` +
		`"occurred_at":"2026-10-08T09:30:00.123456Z","seq":3,"type":"group.renamed"}`
	if string(got) != want {
		t.Errorf("canonical form\n got %s\nwant %s", got, want)
	}
	// any column changes the form
	e2 := *e
	e2.CauseRef = "x"
	if g2, _ := events.Canonical(&e2); string(g2) == string(got) {
		t.Error("cause_ref is not part of the canonical form")
	}
}
