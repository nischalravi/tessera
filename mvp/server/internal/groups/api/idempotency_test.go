package api_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/groups/api"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/store/storetest"
)

func TestValidKey(t *testing.T) {
	for k, want := range map[string]bool{
		"a": true, "key-1": true, "3f2b9c1e-1111-4222-8333-944455556666": true, "a.b_c~d:e+f=g": true,
		"": false, "has space": false, "tab\t": false, "ü": false, "a/b": false, "a,b": false, "line\nbreak": false,
	} {
		if got := api.ValidKey(k); got != want {
			t.Errorf("ValidKey(%q) = %v, want %v", k, got, want)
		}
	}
	long := make([]byte, api.MaxKeyLen)
	for i := range long {
		long[i] = 'k'
	}
	if !api.ValidKey(string(long)) || api.ValidKey(string(long)+"k") {
		t.Error("the length limit is not 255")
	}
}

func TestRequestHash_DependsOnEverythingTheRequestSays(t *testing.T) {
	base := api.RequestHash("POST", "/api/groups/1/members:batch", []byte(`{"add":[]}`))
	for name, h := range map[string]string{
		"method": api.RequestHash("PUT", "/api/groups/1/members:batch", []byte(`{"add":[]}`)),
		"path":   api.RequestHash("POST", "/api/groups/2/members:batch", []byte(`{"add":[]}`)),
		"body":   api.RequestHash("POST", "/api/groups/1/members:batch", []byte(`{"add":[ ]}`)),
		// the separators keep ("a", "bc") and ("ab", "c") apart
		"boundary": api.RequestHash("POST/api/groups/1/members:batch", "", []byte(`{"add":[]}`)),
	} {
		if h == base {
			t.Errorf("a different %s hashes the same", name)
		}
	}
	if api.RequestHash("POST", "/p", nil) != api.RequestHash("POST", "/p", []byte{}) {
		t.Error("an empty body hashes two ways")
	}
}

// The keys are stored in the request's transaction, expire, and belong to a
// tenant and a caller.
func TestIdempotency_StoreScopeAndExpiry(t *testing.T) {
	f := storetest.TwoTenants(t)
	ctx := context.Background()
	now := storetest.Now
	k := api.Key{Principal: "user:u1", Key: "k1", Hash: "h1"}
	in := func(tn storetest.Tenant, fn func(tx *store.TenantTx) error) {
		t.Helper()
		if err := f.DB.InTenant(ctx, tn.ID, fn); err != nil {
			t.Fatal(err)
		}
	}
	in(f.B, func(tx *store.TenantTx) error {
		if r, err := api.Lookup(tx, now, k); r != nil || err != nil {
			t.Errorf("a new key = %v, %v", r, err)
		}
		return api.Save(tx, now, k, 201, []byte(`{"a":1}`))
	})
	in(f.B, func(tx *store.TenantTx) error {
		r, err := api.Lookup(tx, now.Add(time.Hour), k)
		if err != nil || r == nil || r.Status != 201 || string(r.Body) != `{"a":1}` {
			t.Errorf("replay = %+v, %v", r, err)
		}
		// the same key with another request
		if _, err := api.Lookup(tx, now, api.Key{Principal: k.Principal, Key: k.Key, Hash: "h2"}); !errors.Is(err, api.ErrKeyReused) {
			t.Errorf("another request = %v, want ErrKeyReused", err)
		}
		// another caller's key of the same name is a different key
		if r, err := api.Lookup(tx, now, api.Key{Principal: "user:u2", Key: k.Key, Hash: "h1"}); r != nil || err != nil {
			t.Errorf("another principal = %v, %v", r, err)
		}
		// a key can be stored once; the stored row is never changed
		if err := api.Save(tx, now, k, 200, []byte(`{}`)); err == nil {
			t.Error("a key was stored twice")
		}
		return nil
	})
	// another tenant has no such key, and may use the same one
	in(f.A, func(tx *store.TenantTx) error {
		if r, err := api.Lookup(tx, now, k); r != nil || err != nil {
			t.Errorf("tenant A sees B's key = %v, %v", r, err)
		}
		return api.Save(tx, now, k, 200, []byte(`{"tenant":"a"}`))
	})
	in(f.B, func(tx *store.TenantTx) error {
		if r, _ := api.Lookup(tx, now, k); r == nil || string(r.Body) != `{"a":1}` {
			t.Errorf("B's key after A's = %+v", r)
		}
		return nil
	})
	// expiry: just before the TTL it replays, at the TTL it is gone (and purged)
	in(f.B, func(tx *store.TenantTx) error {
		if r, _ := api.Lookup(tx, now.Add(api.IdempotencyTTL-time.Second), k); r == nil {
			t.Error("the key expired early")
		}
		r, err := api.Lookup(tx, now.Add(api.IdempotencyTTL), k)
		if r != nil || err != nil {
			t.Errorf("an expired key = %v, %v", r, err)
		}
		if n, err := tx.GrpIdempotencyCount(); err != nil || n != 0 {
			t.Errorf("%d keys left in B after the purge, %v", n, err)
		}
		// the same key can be used again, with another request
		return api.Save(tx, now.Add(api.IdempotencyTTL), api.Key{Principal: k.Principal, Key: k.Key, Hash: "h3"}, 200, []byte(`{"again":true}`))
	})
	// the purge is the tenant's own: A's key, written at the same time, is still there
	in(f.A, func(tx *store.TenantTx) error {
		if n, _ := tx.GrpIdempotencyCount(); n != 1 {
			t.Errorf("A has %d keys after B's purge, want 1", n)
		}
		return nil
	})
	// a stored answer cannot be edited (the schema refuses an UPDATE): there is no repository method that tries,
	// and Save of the same key fails above
}

func TestOpenAPI_BuildsFromRoutes(t *testing.T) {
	routes := []api.RouteInfo{
		{Method: "POST", Pattern: "/api/groups/{id}/members:batch", Perm: "groups.write"},
		{Method: "GET", Pattern: "/api/groups", Perm: "graph.read"}, // the connected-system list: not described
		{Method: "GET", Pattern: "/api/summary", Perm: "graph.read"},
		{Method: "GET", Pattern: "/scim/v2/Users/{id}", Perm: "groups.read"},
		{Method: "PUT", Pattern: "/api/groups/users/{id}/identity", Perm: "groups.admin", StepUp: true},
		{Method: "GET", Pattern: "/api/groups/undocumented", Perm: "groups.read"}, // left out, the API test catches it
	}
	a, err := api.OpenAPI(routes, "__Host-sid")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := api.OpenAPI(routes, "__Host-sid")
	if string(a) != string(b) {
		t.Error("the document is not deterministic")
	}
	doc := string(a)
	for _, want := range []string{`"/api/groups/{id}/members:batch"`, `"Idempotency-Key"`, `"x-tessera-permission": "groups.write"`, `"BatchRequest"`,
		`"/scim/v2/Users/{id}"`, `"x-tessera-step-up": true`, `"__Host-sid"`, `"securitySchemes"`} {
		if !contains(doc, want) {
			t.Errorf("the document lacks %s", want)
		}
	}
	for _, not := range []string{`"/api/summary"`, `"/api/groups":`, `undocumented`} {
		if contains(doc, not) {
			t.Errorf("the document has %s", not)
		}
	}
	// every entry is unique, and covered by Covers
	keys := api.Documented()
	seen := map[string]bool{}
	for _, k := range keys {
		if seen[k] {
			t.Errorf("%s is documented twice", k)
		}
		seen[k] = true
	}
	if len(keys) < 45 {
		t.Errorf("%d documented routes", len(keys))
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }
