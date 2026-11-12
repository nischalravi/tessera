package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Issue #963: DELETE routes for alert channels, SIEM sinks, group loaders and connections. Each needs the
// create permission and a fresh sign-in, refuses a row that is still enabled, audits in the same transaction
// and removes the sealed credential with the row.

func deleteAuditCount(t *testing.T, db *store.DB, tn tenancy.ID, action string) int {
	t.Helper()
	n := 0
	if err := db.ReadTenant(context.Background(), tn, func(tx *store.TenantTx) error {
		evs, err := tx.AuditEvents(store.AuditFilter{})
		for _, e := range evs {
			if e.Action == action {
				n++
			}
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

func deleteStaleLogin(t *testing.T, f *storetest.Fixture, tn tenancy.ID, role auth.Role) authtest.Login {
	t.Helper()
	return signIn(t, f.DB, tn, authtest.User{Email: "stale@b.example", Roles: []auth.Role{role}},
		authtest.Ctx{AAL: 2, Phr: true, AuthTime: storetest.Now.Add(-20 * time.Minute)}, storetest.Now)
}

func TestDeleteAlertChannelAPI(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := alertsServer(t, f)
	now := storetest.Now
	admin := signIn(t, f.DB, f.B.ID, authtest.User{Email: "ta@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, now)
	op := signIn(t, f.DB, f.B.ID, authtest.User{Email: "op@b.example", Roles: []auth.Role{auth.RoleOperator}}, authtest.Phr, now)
	stale := deleteStaleLogin(t, f, f.B.ID, auth.RoleTenantAdmin)

	rec := alertsDo(h, admin, "POST", "/api/alerts/channels", `{"name":"Hook","kind":"webhook","target":"https://hooks.slack.com/services/T0/B0/x","min_severity":"high"}`)
	if rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var ch channelView
	_ = json.Unmarshal(rec.Body.Bytes(), &ch)
	path := "/api/alerts/channels/" + ch.ID
	var sealed []byte
	_ = f.DB.ReadTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error {
		c, err := tx.AlertChannel(ch.ID)
		if err == nil {
			sealed = c.SecretSealed
		}
		return err
	})
	if len(sealed) == 0 {
		t.Fatal("the webhook has no sealed secret to delete")
	}

	for _, c := range []struct {
		name string
		l    authtest.Login
		path string
		want int
	}{
		{"operator is denied", op, path, 403},
		{"stale sign-in needs step-up", stale, path, 401},
		{"enabled channel is refused", admin, path, 409},
		{"another id is 404", admin, "/api/alerts/channels/nope", 404},
	} {
		if rec := alertsDo(h, c.l, "DELETE", c.path, ""); rec.Code != c.want {
			t.Errorf("%s: %d %s, want %d", c.name, rec.Code, rec.Body, c.want)
		}
	}
	if rec := alertsDo(h, admin, "DELETE", path, ""); !strings.Contains(rec.Body.String(), "channel_enabled") {
		t.Errorf("enabled refusal code: %s", rec.Body)
	}
	if rec := alertsDo(h, admin, "PUT", path, `{"name":"Hook","enabled":false,"min_severity":"high"}`); rec.Code != 200 {
		t.Fatalf("disable: %d %s", rec.Code, rec.Body)
	}
	if rec := alertsDo(h, admin, "DELETE", path, ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"deleted":true`) {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}
	err := f.DB.ReadTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error { _, err := tx.AlertChannel(ch.ID); return err })
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("channel and its sealed secret remain: %v", err)
	}
	if n := deleteAuditCount(t, f.DB, f.B.ID, "alert.channel.deleted"); n != 1 {
		t.Errorf("alert.channel.deleted audited %d times", n)
	}
}

func TestDeleteAlertChannelAPI_CrossTenant(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := alertsServer(t, f)
	now := storetest.Now
	if err := f.DB.InTenant(context.Background(), f.A.ID, func(tx *store.TenantTx) error {
		return tx.InsertAlertChannel(&store.AlertChannel{ID: "chan-a", Name: "A", Kind: "email", Target: "a@a.example", MinSeverity: "low",
			CreatedAt: now, UpdatedAt: now})
	}); err != nil {
		t.Fatal(err)
	}
	admin := signIn(t, f.DB, f.B.ID, authtest.User{Email: "ta@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, now)
	before := storetest.Dump(t, f.DB, f.A.ID)
	got, want := alertsDo(h, admin, "DELETE", "/api/alerts/channels/chan-a", ""), alertsDo(h, admin, "DELETE", "/api/alerts/channels/nope", "")
	if got.Code != 404 || got.Body.String() != want.Body.String() {
		t.Errorf("cross-tenant: %d %s; missing: %d %s", got.Code, got.Body, want.Code, want.Body)
	}
	if storetest.Dump(t, f.DB, f.A.ID) != before {
		t.Error("tenant A changed")
	}
}

func TestDeleteSiemSinkAPI(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := siemServer(t, f, &okSender{})
	now := storetest.Now
	admin := signIn(t, f.DB, f.B.ID, authtest.User{Email: "ta@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, now)
	au := signIn(t, f.DB, f.B.ID, authtest.User{Email: "au@b.example", Roles: []auth.Role{auth.RoleAuditor}}, authtest.Phr, now)
	stale := deleteStaleLogin(t, f, f.B.ID, auth.RoleTenantAdmin)

	rec := siemDo(h, admin, "POST", "/api/siem/sinks", `{"name":"Splunk","kind":"webhook","format":"json","target":"https://splunk.example:8088/c","flavor":"hec","token":"hec-123"}`)
	if rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var v sinkView
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	path := "/api/siem/sinks/" + v.ID
	var sealed []byte
	_ = f.DB.ReadTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error {
		k, err := tx.SiemSink(v.ID)
		if err == nil {
			sealed = k.SecretSealed
		}
		return err
	})
	if len(sealed) == 0 {
		t.Fatal("the sink has no sealed token to delete")
	}
	for _, c := range []struct {
		name string
		l    authtest.Login
		path string
		want int
	}{
		{"auditor is denied", au, path, 403},
		{"stale sign-in needs step-up", stale, path, 401},
		{"enabled sink is refused", admin, path, 409},
		{"unknown id is 404", admin, "/api/siem/sinks/nope", 404},
	} {
		if rec := siemDo(h, c.l, "DELETE", c.path, ""); rec.Code != c.want {
			t.Errorf("%s: %d %s, want %d", c.name, rec.Code, rec.Body, c.want)
		}
	}
	if rec := siemDo(h, admin, "PUT", path, `{"name":"Splunk","enabled":false}`); rec.Code != 200 {
		t.Fatalf("disable: %d %s", rec.Code, rec.Body)
	}
	if rec := siemDo(h, admin, "DELETE", path, ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"deleted":true`) {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}
	err := f.DB.ReadTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error { _, err := tx.SiemSink(v.ID); return err })
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("sink and its sealed token remain: %v", err)
	}
	if n := deleteAuditCount(t, f.DB, f.B.ID, "siem.sink.deleted"); n != 1 {
		t.Errorf("siem.sink.deleted audited %d times", n)
	}

	// another tenant's sink answers like a missing id and is untouched
	other := seedSiemSink(t, f.DB, f.A.ID, "a")
	before := storetest.Dump(t, f.DB, f.A.ID)
	if rec := siemDo(h, admin, "DELETE", "/api/siem/sinks/"+other, ""); rec.Code != http.StatusNotFound {
		t.Errorf("cross-tenant: %d %s", rec.Code, rec.Body)
	}
	if storetest.Dump(t, f.DB, f.A.ID) != before {
		t.Error("tenant A changed")
	}
}

func TestDeleteGroupLoaderAPI(t *testing.T) {
	e, dir := newLoaderEnv(t)
	writeLoaderFile(t, dir, "people.csv", "id\nalice\nbob\n")
	app := e.admin.folder("", "app")
	id := e.admin.call("POST", "/api/groups/loaders", csvLoaderBody("Staff", app, "people.csv", "staff", ""), 201)["id"].(string)
	path := "/api/groups/loaders/" + id
	// give it a sealed credential and an unresolved-subject row to prove they go with it
	if err := e.f.DB.InTenant(context.Background(), e.f.B.ID, func(tx *store.TenantTx) error {
		l, err := tx.GrpLoader(id)
		if err != nil {
			return err
		}
		l.SecretEnc = []byte("sealed-blob")
		l.UpdatedAt = storetest.Now
		if err := tx.UpdateGrpLoader(l); err != nil {
			return err
		}
		return tx.UpsertGrpLoaderUnresolved(&store.GrpLoaderUnresolved{LoaderID: id, Source: "csv", Identifier: "ghost",
			FirstSeen: storetest.Now, LastSeen: storetest.Now, Groups: "[]"})
	}); err != nil {
		t.Fatal(err)
	}

	op := e.user("op", "bob")
	denied403 := op.do("DELETE", path, "")
	if denied403.Code != 403 {
		t.Errorf("operator: %d %s", denied403.Code, denied403.Body)
	}
	l := deleteStaleLogin(t, e.f, e.f.B.ID, auth.RoleTenantAdmin)
	if rec := (client{t, l.Handler(e.srv.Handler())}).do("DELETE", path, ""); rec.Code != 401 || !strings.Contains(rec.Body.String(), "step_up_required") {
		t.Errorf("stale sign-in: %d %s", rec.Code, rec.Body)
	}
	if rec := e.admin.do("DELETE", path, ""); rec.Code != 409 || !strings.Contains(rec.Body.String(), "loader_not_disabled") {
		t.Errorf("enabled loader: %d %s", rec.Code, rec.Body)
	}
	e.admin.call("DELETE", "/api/groups/loaders/00000000-0000-4000-8000-00000000dead", "", 404)

	// another tenant's loader is a 404 and stays as it was
	other := signIn(t, e.f.DB, e.f.A.ID, authtest.User{Email: "ta@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, storetest.Now)
	before := storetest.Dump(t, e.f.DB, e.f.B.ID)
	if rec := (client{t, other.Handler(e.srv.Handler())}).do("DELETE", path, ""); rec.Code != 404 {
		t.Errorf("cross-tenant: %d %s", rec.Code, rec.Body)
	}
	if storetest.Dump(t, e.f.DB, e.f.B.ID) != before {
		t.Error("tenant B changed")
	}

	e.admin.call("PATCH", path, `{"status":"disabled"}`, 200)
	if got := e.admin.call("DELETE", path, "", 200); got["deleted"] != true || got["id"] != id {
		t.Errorf("delete = %v", got)
	}
	e.admin.call("GET", path, "", 404)
	if err := e.f.DB.ReadTenant(context.Background(), e.f.B.ID, func(tx *store.TenantTx) error {
		if _, err := tx.GrpLoader(id); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("loader and its sealed credential remain: %v", err)
		}
		if n, err := tx.GrpLoaderUnresolvedCount(id); err != nil || n != 0 {
			t.Errorf("unresolved subjects remain: %d %v", n, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if n := deleteAuditCount(t, e.f.DB, e.f.B.ID, "groups.loader.deleted"); n != 1 {
		t.Errorf("groups.loader.deleted audited %d times", n)
	}
}

// A loader that still manages groups is refused: its groups would name a loader that no longer exists.
func TestDeleteGroupLoaderAPI_ManagesGroups(t *testing.T) {
	e, dir := newLoaderEnv(t)
	writeLoaderFile(t, dir, "people.csv", "id\nalice\nbob\n")
	app := e.admin.folder("", "app")
	id := e.admin.call("POST", "/api/groups/loaders", csvLoaderBody("Staff", app, "people.csv", "staff", ""), 201)["id"].(string)
	e.admin.call("POST", "/api/groups/loaders/"+id+"/run", `{}`, 200)
	e.admin.call("PATCH", "/api/groups/loaders/"+id, `{"status":"disabled"}`, 200)
	if rec := e.admin.do("DELETE", "/api/groups/loaders/"+id, ""); rec.Code != 409 || !strings.Contains(rec.Body.String(), "loader_has_groups") {
		t.Errorf("loader with groups: %d %s", rec.Code, rec.Body)
	}
}

func TestDeleteConnectionAPI(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	now := storetest.Now
	ad := f.B.Refs["connection:ad"]
	path := "/api/connections/" + ad
	admin := signIn(t, f.DB, f.B.ID, authtest.User{Email: "ta@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, now)
	op := signIn(t, f.DB, f.B.ID, authtest.User{Email: "op@b.example", Roles: []auth.Role{auth.RoleOperator}}, authtest.Phr, now)
	stale := deleteStaleLogin(t, f, f.B.ID, auth.RoleTenantAdmin)
	write := func(fn func(tx *store.TenantTx) error) {
		t.Helper()
		if err := f.DB.InTenant(context.Background(), f.B.ID, fn); err != nil {
			t.Fatal(err)
		}
	}

	if rec := corrDo(h, op, "DELETE", path, ""); rec.Code != 403 {
		t.Errorf("operator: %d %s", rec.Code, rec.Body)
	}
	if rec := corrDo(h, stale, "DELETE", path, ""); rec.Code != 401 || !strings.Contains(rec.Body.String(), "step_up_required") {
		t.Errorf("stale sign-in: %d %s", rec.Code, rec.Body)
	}
	if rec := corrDo(h, admin, "DELETE", path, ""); rec.Code != 409 || !strings.Contains(rec.Body.String(), "connection_not_retired") {
		t.Errorf("active connection: %d %s", rec.Code, rec.Body)
	}
	if rec := corrDo(h, admin, "DELETE", "/api/connections/"+missingUUID, ""); rec.Code != 404 {
		t.Errorf("unknown id: %d %s", rec.Code, rec.Body)
	}
	// tenant A cannot see B's connection
	adminA := signIn(t, f.DB, f.A.ID, authtest.User{Email: "ta@a.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, now)
	beforeB := storetest.Dump(t, f.DB, f.B.ID)
	if rec := corrDo(h, adminA, "DELETE", path, ""); rec.Code != 404 {
		t.Errorf("cross-tenant: %d %s", rec.Code, rec.Body)
	}
	if storetest.Dump(t, f.DB, f.B.ID) != beforeB {
		t.Error("tenant B changed")
	}
	if rec := corrDo(h, admin, "POST", path+"/retire", `{"confirm":true}`); rec.Code != 200 {
		t.Fatalf("retire: %d %s", rec.Code, rec.Body)
	}

	// a provisioning op in flight, then a running job, each refuse with their own code
	write(func(tx *store.TenantTx) error {
		if err := tx.InsertProvOp(&store.ProvOp{ID: "op-1", ConnectionID: ad, Kind: "disable_account", TargetRef: "x", Payload: "{}",
			Source: "test", IdempotencyKey: "k-1", RequestedBy: "test"}, now); err != nil {
			return err
		}
		return tx.InsertJobRun(&store.JobRun{ID: "job-1", Kind: "sync", Trigger: "manual", Status: "running", ConnectionID: &ad,
			Actor: "test", StartedAt: now})
	})
	if rec := corrDo(h, admin, "DELETE", path, ""); rec.Code != 409 || !strings.Contains(rec.Body.String(), "connection_syncing") {
		t.Errorf("running sync: %d %s", rec.Code, rec.Body)
	}
	write(func(tx *store.TenantTx) error { return tx.FinishJobRun("job-1", "succeeded", now, nil, nil) })
	if rec := corrDo(h, admin, "DELETE", path, ""); rec.Code != 409 || !strings.Contains(rec.Body.String(), "connection_has_pending_ops") {
		t.Errorf("pending op: %d %s", rec.Code, rec.Body)
	}
	write(func(tx *store.TenantTx) error {
		return tx.SetProvOpState("op-1", "queued", store.ProvOpState{Status: "cancelled", NextAttemptAt: now, CompletedAt: &now}, now)
	})
	// a sealed credential that must go with the connection
	write(func(tx *store.TenantTx) error {
		return tx.PutCredential(&store.Credential{ConnectionID: ad, Purpose: "containment", Sealed: []byte("sealed-blob"), UpdatedBy: "test", UpdatedAt: now})
	})

	beforeA := storetest.Dump(t, f.DB, f.A.ID)
	if rec := corrDo(h, admin, "DELETE", path, ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"deleted":true`) {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}
	if storetest.Dump(t, f.DB, f.A.ID) != beforeA {
		t.Error("tenant A changed")
	}
	if rec := corrDo(h, admin, "GET", path, ""); rec.Code != 404 {
		t.Errorf("deleted connection still reads: %d", rec.Code)
	}
	if rec := corrDo(h, admin, "DELETE", path, ""); rec.Code != 404 {
		t.Errorf("second delete: %d %s", rec.Code, rec.Body)
	}
	_ = f.DB.ReadTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error {
		if _, err := tx.Credential(ad, "containment", ""); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("sealed credential remains: %v", err)
		}
		if revs, err := tx.Revisions(ad); err != nil || len(revs) != 0 {
			t.Errorf("revisions remain: %d %v", len(revs), err)
		}
		if _, err := tx.ProvOp("op-1"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("provisioning op remains: %v", err)
		}
		if conns, err := tx.Connections(); err != nil || len(conns) != 1 {
			t.Errorf("the tenant's other connection is gone: %d %v", len(conns), err)
		}
		return nil
	})
	if n := deleteAuditCount(t, f.DB, f.B.ID, "connection.deleted"); n != 1 {
		t.Errorf("connection.deleted audited %d times", n)
	}
}

// A retired connection that still owns synced objects is refused, and nothing it synced is removed.
func TestDeleteConnectionAPI_OwnsSyncedObjects(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	okta := f.B.Refs["connection"]
	admin := signIn(t, f.DB, f.B.ID, authtest.User{Email: "ta@b.example", Roles: []auth.Role{auth.RoleTenantAdmin}}, authtest.Phr, storetest.Now)
	if rec := corrDo(h, admin, "POST", "/api/connections/"+okta+"/retire", `{"confirm":true}`); rec.Code != 200 {
		t.Fatalf("retire: %d %s", rec.Code, rec.Body)
	}
	counts := func() (n int, conn bool) {
		_ = f.DB.ReadTenant(context.Background(), f.B.ID, func(tx *store.TenantTx) error {
			n, _ = tx.CountAccounts()
			_, err := tx.Connection(okta)
			conn = err == nil
			return nil
		})
		return
	}
	accounts, _ := counts()
	rec := corrDo(h, admin, "DELETE", "/api/connections/"+okta, "")
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), "connection_has_synced_objects") {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}
	if n, conn := counts(); n != accounts || accounts == 0 || !conn {
		t.Errorf("a refused delete changed the tenant: %d accounts (was %d), connection kept %v", n, accounts, conn)
	}
}
