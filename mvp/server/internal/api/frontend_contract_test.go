package api

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/authtest"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

var updateContract = flag.Bool("update-contract", false, "rewrite testdata/contract/session.json")

// shape replaces every value with its JSON type, keeping object keys and the
// shape of the first element of each array, so the snapshot pins the
// contract and not the data.
func shape(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, e := range x {
			out[k] = shape(e)
		}
		return out
	case []any:
		if len(x) == 0 {
			return []any{}
		}
		return []any{shape(x[0])}
	case string:
		return "string"
	case float64:
		return "number"
	case bool:
		return "boolean"
	case nil:
		return "null"
	}
	return "unknown"
}

// TestFrontendContract_Session (§19 PR7): the shape of GET /api/auth/session,
// which the UI (src/api.ts SessionInfo) reads, is a reviewed snapshot in
// testdata/contract/session.json. A change needs the UI type updated too;
// go test -run TestFrontendContract -update-contract rewrites the file.
func TestFrontendContract_Session(t *testing.T) {
	f := storetest.TwoTenants(t)
	h := newIsolationServer(f).Handler()
	// a weak sign-in, so inactive_roles has an element
	l := signIn(t, f.DB, f.B.ID, authtest.User{Email: "ada@b.example", Display: "Ada",
		Roles: []auth.Role{auth.RoleTenantAdmin, auth.RoleOperator}}, authtest.AAL2, storetest.Now)
	got, err := json.MarshalIndent(shape(decode(t, serve(h, authed(l, "GET", "/api/auth/session", "")))), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	path := filepath.Join("..", "..", "testdata", "contract", "session.json")
	if *updateContract {
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path) // #nosec G304 -- a fixed test fixture
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		var keys []string
		var g map[string]any
		_ = json.Unmarshal(got, &g)
		for k := range g {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		t.Errorf("GET /api/auth/session changed shape (update src/api.ts SessionInfo, then run with -update-contract):\n%s\nkeys: %v", got, keys)
	}
}
