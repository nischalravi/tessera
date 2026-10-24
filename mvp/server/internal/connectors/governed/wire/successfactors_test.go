package wire_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed/wire"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/checks"
)

const sfPassword = "sf-p4ssword-SECRET"

// sfFake is a minimal SuccessFactors OData v2 tenant: basic authentication, one
// page per entity, reads only.
func sfFake(t *testing.T) http.Handler {
	t.Helper()
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("tessera-api@acme:"+sfPassword))
	data := map[string][]map[string]any{
		"User": {{"userId": "1001", "username": "alice", "displayName": "Alice A", "email": "alice@acme.example", "status": "active",
			"hireDate": "/Date(1580688000000)/"}},
		"EmpEmployment": {{"userId": "1001", "personIdExternal": "P1001", "startDate": "/Date(1580688000000)/", "endDate": "/Date(253402214400000)/"}},
		"EmpJob": {{"userId": "1001", "seqNumber": 1, "startDate": "/Date(1580688000000)/", "endDate": "/Date(253402214400000)/",
			"department": "D10", "managerId": "NO_MANAGER", "departmentNav": map[string]any{"name": "Engineering"}}},
		"PerPerson": {},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("a read-only connector sent %s", r.Method)
		}
		if !strings.HasPrefix(r.URL.Path, "/odata/v2/") {
			http.NotFound(w, r) // the reachability probe of the host root
			return
		}
		if r.Header.Get("Authorization") != want {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"d": map[string]any{"results": data[strings.TrimPrefix(r.URL.Path, "/odata/v2/")]}})
	})
}

func sfParams(base, secret string) governed.Params {
	return governed.Params{Type: governed.SuccessFactors, BaseURL: base, Secret: secret,
		Settings: map[string]string{"company_id": "acme", "username": "tessera-api"}}
}

func TestSuccessFactorsProber(t *testing.T) {
	srv, n := serve(t, sfFake(t))
	pr := prober(t, sfParams(srv.URL, sfPassword), n)
	wantPass(t, pr, "successfactors", "endpoint_reachable", "auth_ok", "read_probe", "field_inventory")
	r := run(t, pr, "field_inventory", checks.Env{TemplateID: "successfactors"})
	if r.Status != checks.Pass || r.Observed["fields"] == 0 {
		t.Errorf("field inventory: %+v", r)
	}
}

func TestSuccessFactorsProber_WrongPassword(t *testing.T) {
	srv, n := serve(t, sfFake(t))
	pr := prober(t, sfParams(srv.URL, "not-the-password"), n)
	r := run(t, pr, "auth_ok", checks.Env{TemplateID: "successfactors"})
	if r.Status != checks.Fail {
		t.Errorf("a refused credential: %s %s", r.Status, r.Message)
	}
	if strings.Contains(r.Message, "not-the-password") || strings.Contains(r.Message, sfPassword) {
		t.Errorf("the message leaks the credential: %s", r.Message)
	}
}

func TestSuccessFactorsConnector(t *testing.T) {
	srv, n := serve(t, sfFake(t))
	cn, err := wire.Connector(sfParams(srv.URL, sfPassword), n)
	if err != nil {
		t.Fatal(err)
	}
	if cn.System() != "successfactors" {
		t.Errorf("system %q", cn.System())
	}
	res, err := cn.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Identities) != 1 || len(res.Accounts) != 1 || res.Accounts[0].Attributes["person_id"] != "P1001" {
		t.Errorf("result %+v", res)
	}
	// the staged counts the readiness data checks read
	if res.Stats == nil || res.Stats.Classes["user"] == nil || res.Stats.Classes["user"].Total != 1 {
		t.Errorf("stats %+v", res.Stats)
	}
}

func TestSuccessFactorsRefusesAForeignHost(t *testing.T) {
	_, n := serve(t, sfFake(t))
	for _, base := range []string{"https://evil.example", "https://successfactors.com.evil.example", "https://169.254.169.254"} {
		if _, err := wire.Prober(sfParams(base, sfPassword), n); err == nil {
			t.Errorf("prober accepted %s", base)
		}
		if _, err := wire.Connector(sfParams(base, sfPassword), n); err == nil {
			t.Errorf("connector accepted %s", base)
		}
	}
}

func TestSuccessFactorsSecretNeverPrints(t *testing.T) {
	p := sfParams("https://api4.successfactors.com", sfPassword)
	for _, s := range []string{p.String(), p.GoString()} {
		if strings.Contains(s, sfPassword) {
			t.Errorf("%q", s)
		}
	}
}
