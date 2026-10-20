package all_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync/connsynctest"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/google"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/workday"
	"github.com/nischalravi/tessera/mvp/server/internal/ingest"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
	"github.com/nischalravi/tessera/mvp/server/internal/testkit"
)

func testKeyPEM(t testing.TB) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// testServiceAccountKey is a synthetic service account JSON key file.
func testServiceAccountKey(t testing.TB) string {
	t.Helper()
	b, err := json.Marshal(map[string]string{"type": "service_account", "client_email": "reader@fixture-project.iam.example.com",
		"private_key": testKeyPEM(t), "private_key_id": "kid-1"})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Workday (HR-authoritative) and Google Workspace through the real connectors
// and the real ingest: Google accounts correlate to the Workday identities by
// employee id first, then by e-mail address.
func TestWorkdayAndGoogleCorrelateThroughIngest(t *testing.T) {
	wd := connsynctest.New(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ccx/oauth2/fixture_tenant/token":
			fmt.Fprint(w, `{"token_type":"Bearer","expires_in":3600,"access_token":"wd-token"}`)
		case "/ccx/api/v1/fixture_tenant/workers":
			fmt.Fprint(w, `{"total":2,"data":[
			 {"id":"w-1","descriptor":"Avery Example","employeeId":"E1001","primaryWorkEmail":"avery.example@example.com","hireDate":"2021-04-12"},
			 {"id":"w-2","descriptor":"Riley Sample","employeeId":"E1002","primaryWorkEmail":"riley.sample@example.com","hireDate":"2023-06-01"}]}`)
		case "/ccx/api/v1/fixture_tenant/workerEvents":
			fmt.Fprint(w, `{"total":1,"data":[{"id":"EVT-1","type":"TERMINATE","effectiveDate":"2026-10-20","worker":{"id":"w-2"}}]}`)
		default:
			t.Errorf("workday: unexpected %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	gg := connsynctest.New(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			fmt.Fprint(w, `{"token_type":"Bearer","expires_in":3600,"access_token":"g-token"}`)
		case "/admin/directory/v1/users":
			fmt.Fprint(w, `{"users":[
			 {"id":"g1","primaryEmail":"a.example@example.com","name":{"fullName":"Avery E"},"externalIds":[{"type":"organization","value":"E1001"}],"lastLoginTime":"2026-10-07T08:00:00.000Z"},
			 {"id":"g2","primaryEmail":"Riley.Sample@Example.com","name":{"fullName":"Riley S"}},
			 {"id":"g3","primaryEmail":"stranger@example.com","name":{"fullName":"Stranger"}}]}`)
		default:
			t.Errorf("google: unexpected %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	now := time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	wdc, err := workday.New(workday.Config{Tenant: "fixture_tenant", BaseURL: wd.URL, ClientID: "cid",
		ClientSecret: connsync.NewSecret("s"), EmitIdentities: true}, connsynctest.Runtime, testClient(t, wd, 0), clock)
	if err != nil {
		t.Fatal(err)
	}
	gc, err := google.New(google.Config{ServiceAccountEmail: "reader@fixture-project.iam.example.com", AdminEmail: "admin@example.com",
		PrivateKey: connsync.NewSecret(testKeyPEM(t)), APIURL: gg.URL, TokenURL: gg.URL + "/token"}, connsynctest.Runtime, testClient(t, gg, 0), clock)
	if err != nil {
		t.Fatal(err)
	}

	db := testkit.Open(t)
	tn := tenancy.MustParse("00000000-0000-4000-8000-0000000000a1")
	testkit.CreateTenant(t, db, tn, "hr-google")
	var st ingest.SyncStats
	if err := db.InTenant(context.Background(), tn, func(c *store.TenantTx) error {
		var err error
		st, err = ingest.Sync(c, now, []connectors.Connector{wdc, gc}, nil)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if st.Discovery.Identities != 2 || st.Discovery.Accounts != 5 || st.Events.Hris != 1 {
		t.Fatalf("stats = %+v", st)
	}
	testkit.Read(t, &testkit.DB{DB: db, Tenant: tn}, func(tx *store.TenantTx) error {
		idents, _ := tx.Identities()
		id := map[string]int64{}
		for _, i := range idents {
			id[i.ExternalID] = i.ID
		}
		if len(id) != 2 {
			t.Errorf("identities = %v, want only the two Workday people", id)
		}
		accts, _ := tx.Accounts()
		got := map[string]*int64{}
		for _, a := range accts {
			got[a.System+"/"+a.ExternalID] = a.IdentityID
		}
		want := map[string]int64{"workday/E1001": id["E1001"], "workday/E1002": id["E1002"],
			"google/g1": id["E1001"], // employee id in externalIds, though the e-mail address differs
			"google/g2": id["E1002"], // e-mail address, case-insensitive
		}
		for k, w := range want {
			if got[k] == nil || *got[k] != w {
				t.Errorf("%s -> %v, want %d", k, got[k], w)
			}
		}
		if got["google/g3"] != nil {
			t.Errorf("google/g3 -> %v: no worker, no identity", got["google/g3"])
		}
		evs, _ := tx.HrisEvents()
		if len(evs) != 1 || evs[0].Type != "leaver" || evs[0].IdentityID == nil || *evs[0].IdentityID != id["E1002"] || evs[0].Status != "pending" {
			t.Errorf("hris events = %+v", evs)
		}
		return nil
	})
}
