package loaders_test

import (
	"context"
	"encoding/json"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/loaders"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

func pgSpec(h *harness, name, extra string) loaders.Spec {
	return loaders.Spec{Name: name, Type: loaders.TypeSQLGroupList, TargetFolder: string(h.ref), Schedule: "@daily",
		Config: []byte(`{"engine":"postgres","query":"SELECT grp AS group_name, subject AS subject_id FROM loader_pg_people ORDER BY seq"` + extra + `}`)}
}

func plainDial(ctx context.Context, network, addr string) (net.Conn, error) {
	return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
}

func TestSQLPostgres_ConfigAndSecretRules(t *testing.T) {
	for name, tc := range map[string]struct {
		typ, cfg, want string
	}{
		"ok":                    {loaders.TypeSQLGroupList, `{"engine":"postgres","query":"SELECT 1"}`, ""},
		"simple ok":             {loaders.TypeSQLSimple, `{"engine":"postgres","query":"SELECT 1 AS subject_id","group":"g"}`, ""},
		"with a database file":  {loaders.TypeSQLGroupList, `{"engine":"postgres","database":"x.db","query":"SELECT 1"}`, "connection string"},
		"unknown engine":        {loaders.TypeSQLGroupList, `{"engine":"mysql","query":"SELECT 1"}`, "engine is sqlite"},
		"file needs database":   {loaders.TypeSQLGroupList, `{"query":"SELECT 1"}`, "database is a file name"},
		"sqlite with ca":        {loaders.TypeSQLGroupList, `{"database":"x.db","ca_pem":"x","query":"SELECT 1"}`, "ca_pem"},
		"bad ca":                {loaders.TypeSQLGroupList, `{"engine":"postgres","ca_pem":"nope","query":"SELECT 1"}`, "ca_pem"},
		"write":                 {loaders.TypeSQLGroupList, `{"engine":"postgres","query":"DELETE FROM t"}`, "SELECT or WITH"},
		"incremental no cursor": {loaders.TypeSQLGroupList, `{"engine":"postgres","query":"SELECT 1","incremental_query":"SELECT 1"}`, "@cursor"},
	} {
		_, err := loaders.ValidateConfig(tc.typ, json.RawMessage(tc.cfg), false)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: refused: %v", name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: error = %v, want %q", name, err, tc.want)
		}
	}
	pg := json.RawMessage(`{"engine":"postgres","query":"SELECT 1"}`)
	file := json.RawMessage(`{"database":"x.db","query":"SELECT 1"}`)
	for _, c := range []struct {
		typ string
		cfg json.RawMessage
		use loaders.SecretUse
	}{
		{loaders.TypeSQLSimple, pg, loaders.SecretRequired}, {loaders.TypeSQLSimple, file, loaders.SecretNone},
		{loaders.TypeCSV, json.RawMessage(`{"url":"https://x.example/a.csv","group":"g","subject_column":"id"}`), loaders.SecretOptional},
		{loaders.TypeCSV, json.RawMessage(`{"path":"a.csv","group":"g","subject_column":"id"}`), loaders.SecretNone},
		{loaders.TypeSCIM, nil, loaders.SecretRequired}, {loaders.TypeLDAPSimple, nil, loaders.SecretRequired},
		{loaders.TypeAttribute, nil, loaders.SecretNone}, {loaders.TypeConnectorGroups, nil, loaders.SecretNone},
	} {
		if got := loaders.SecretPolicy(c.typ, c.cfg); got != c.use {
			t.Errorf("SecretPolicy(%s, %s) = %d, want %d", c.typ, c.cfg, got, c.use)
		}
	}
	// the connection string is checked when it is saved: production wants verify-full
	if err := loaders.CheckSecret(loaders.TypeSQLSimple, pg, "postgres://u:p@db.example.com/hr?sslmode=require", true); err == nil {
		t.Error("prod accepted sslmode=require")
	}
	if err := loaders.CheckSecret(loaders.TypeSQLSimple, pg, "postgres://u:p@db.example.com/hr?sslmode=require", false); err != nil {
		t.Errorf("dev refused sslmode=require: %v", err)
	}
	if err := loaders.CheckSecret(loaders.TypeSQLSimple, pg, "postgres://u:p@db.example.com/hr", true); err != nil {
		t.Errorf("prod refused the default (verify-full): %v", err)
	}
	if err := loaders.CheckSecret(loaders.TypeSQLSimple, pg, "host=db user=u", false); err == nil || strings.Contains(err.Error(), "user=u") {
		t.Errorf("a key=value string: %v", err)
	}
}

func TestSQLPostgres_SavedSealedAndNeverWithoutSecret(t *testing.T) {
	h := newHarness(t)
	dsn := "postgres://reader:db-pw-secret@db.example.com:5432/hr?sslmode=verify-full"
	create := func(prod bool, spec loaders.Spec, secret string) (*store.GrpLoader, error) {
		var l *store.GrpLoader
		err := h.db.InTenant(t.Context(), tid, func(tx *store.TenantTx) error {
			var err error
			l, err = loaders.Create(loaders.SaveEnv{Tx: tx, Now: h.now, Sealer: h.sealer, Prod: prod}, spec, secret)
			return err
		})
		return l, err
	}
	if _, err := create(false, pgSpec(h, "nosecret", ""), ""); errCode(err) != "secret_required" {
		t.Errorf("no secret: %v", err)
	}
	if _, err := create(true, pgSpec(h, "weak", ""), "postgres://r:p@db.example.com/hr?sslmode=require"); errCode(err) != "invalid_secret" {
		t.Errorf("weak tls in prod: %v", err)
	}
	if _, err := create(false, h.csvSpec("file", "a.csv", "g"), "x"); errCode(err) != "secret_not_used" {
		t.Errorf("a secret for a file CSV: %v", err)
	}
	l, err := create(true, pgSpec(h, "ok", ""), dsn)
	if err != nil {
		t.Fatal(err)
	}
	if stored := h.loader(l.ID); len(stored.SecretEnc) == 0 || strings.Contains(string(stored.SecretEnc), "db-pw-secret") {
		t.Errorf("stored as %q", stored.SecretEnc)
	}
	if b, _ := json.Marshal(l.Config); strings.Contains(string(b), "db-pw-secret") {
		t.Error("the config holds the secret")
	}
	// keeping the credential on a change, replacing it, and clearing a required one
	spec, _ := loaders.SpecOf(l)
	spec.Schedule = "@hourly"
	err = h.db.InTenant(t.Context(), tid, func(tx *store.TenantTx) error {
		se := loaders.SaveEnv{Tx: tx, Now: h.now, Sealer: h.sealer, Prod: true}
		if _, err := loaders.Update(se, l.ID, nil, spec, nil); err != nil {
			t.Errorf("update keeping the secret: %v", err)
		}
		empty := ""
		if _, err := loaders.Update(se, l.ID, nil, spec, &empty); errCode(err) != "secret_required" {
			t.Errorf("clearing a required secret: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(h.loader(l.ID).SecretEnc) == 0 {
		t.Error("the credential was lost")
	}
	// a run with no dialer, or in production against a weaker string, fails without a connection
	r := h.run(l, store.RunFull)
	if r.Status != store.RunFailed || !strings.Contains(deref(r.Error), "not available") {
		t.Errorf("no dialer: %s %q", r.Status, deref(r.Error))
	}
	h.svc.PGDial = func(context.Context, string, string) (net.Conn, error) { t.Error("dialed"); return nil, net.ErrClosed }
	h.svc.Prod = true
	weak, err := create(false, pgSpec(h, "weak-later", ""), "postgres://r:p@db.example.com/hr?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	if r := h.run(weak, store.RunFull); r.Status != store.RunFailed || !strings.Contains(deref(r.Error), "verify-full") {
		t.Errorf("prod run of a weak string: %s %q", r.Status, deref(r.Error))
	}
}

// TestSQLPostgres_Run reads a real database: TESSERA_TEST_PG_URL.
func TestSQLPostgres_Run(t *testing.T) {
	src := store.NewExtPGSourceForTest(t)
	src.Statements(t, `CREATE TABLE loader_pg_people (grp text, subject text, seq bigint, op text)`,
		`INSERT INTO loader_pg_people VALUES ('eng','u0',1,'add'),('eng','u1',2,'add'),('eng','u2',3,'add'),('ops','u3',4,'add')`)

	h := newHarness(t)
	h.svc.PGDial = plainDial
	spec := pgSpec(h, "pg", `,"incremental_query":"SELECT grp AS group_name, subject AS subject_id, op, seq FROM loader_pg_people WHERE seq > @cursor ORDER BY seq"`)
	n := int64(60)
	spec.IncrementalSecs = &n
	loose := 100.0 // removing one of three members is a third
	spec.Failsafe = &loaders.Failsafe{MaxRemovedPercent: &loose}
	l := h.create(spec, src.DSN)
	r := h.run(l, store.RunFull)
	if r.Status != store.RunApplied {
		t.Fatalf("run = %s (%v)", r.Status, deref(r.Error))
	}
	wantMembers(t, h, "ref:eng", []string{"u0", "u1", "u2"})
	wantMembers(t, h, "ref:ops", []string{"u3"})
	// an incremental run takes the rows after its cursor, as a number
	src.Statements(t, `INSERT INTO loader_pg_people VALUES ('eng','u4',5,'add'),('eng','u0',6,'remove')`)
	h.now = h.now.Add(time.Minute)
	ri := h.run(h.loader(l.ID), store.RunIncremental)
	if ri == nil || ri.Status != store.RunApplied {
		t.Fatalf("incremental = %+v", ri)
	}
	wantMembers(t, h, "ref:eng", []string{"u1", "u2", "u4"})
	// a query the server refuses fails the run with the server's reason, not the connection string
	bad := h.create(loaders.Spec{Name: "pg-bad", Type: loaders.TypeSQLSimple, TargetFolder: string(h.ref), Schedule: "@daily",
		Config: []byte(`{"engine":"postgres","query":"SELECT nextval('no_such_sequence') AS subject_id","group":"g"}`)}, src.DSN)
	r2 := h.run(bad, store.RunFull)
	if r2.Status != store.RunFailed || strings.Contains(deref(r2.Error), src.DSN) {
		t.Errorf("a refused query: %s %q", r2.Status, deref(r2.Error))
	}
	// a database that is not there
	u, _ := url.Parse(src.DSN)
	u.Path = "/no_such_database"
	u.User = url.UserPassword(u.User.Username(), "pw-not-in-errors")
	gone := h.create(loaders.Spec{Name: "pg-gone", Type: loaders.TypeSQLSimple, TargetFolder: string(h.ref), Schedule: "@daily",
		Config: []byte(`{"engine":"postgres","query":"SELECT 1 AS subject_id","group":"g2"}`)}, u.String())
	if r3 := h.run(gone, store.RunFull); r3.Status != store.RunFailed || strings.Contains(deref(r3.Error), "pw-not-in-errors") {
		t.Errorf("a missing database: %s %q", r3.Status, deref(r3.Error))
	}
}

func TestNeedsSecondApprover(t *testing.T) {
	for _, typ := range loaders.Types() {
		want := map[string]bool{loaders.TypeSQLSimple: true, loaders.TypeSQLGroupList: true, loaders.TypeSCIM: true, loaders.TypeLDAPSimple: true, loaders.TypeLDAPGroupList: true}[typ]
		if got := loaders.NeedsSecondApprover(typ); got != want {
			t.Errorf("NeedsSecondApprover(%s) = %v, want %v", typ, got, want)
		}
	}
}
