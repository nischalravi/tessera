package restgen

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
)

// A lookup that is really a search may answer several fuzzy matches, none, or someone else: the target must
// not guess, and must write nothing.
func TestTarget_LookupMustAnswerExactlyTheRequestedAccount(t *testing.T) {
	var writes atomic.Int32
	rec := func(id, login string) map[string]any {
		return map[string]any{"id": id, "login": login, "state": "active"}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writes.Add(1)
			w.WriteHeader(204)
			return
		}
		var matches []any
		switch strings.TrimPrefix(r.URL.Path, "/users/") {
		case "several": // a fuzzy search
			matches = []any{rec("u1", "several"), rec("u2", "several2")}
		case "other": // one record, but someone else
			matches = []any{rec("u9", "someone-else")}
		case "good":
			matches = []any{rec("u3", "Good")} // user names compare as the SCIM target does
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"matches": matches})
	}))
	defer srv.Close()
	spec := &Spec{BaseURL: srv.URL, Auth: bearerAuth(), Limits: Limits{RequestsPerSecond: 100, Burst: 100},
		Users: &Resource{Path: "/users", Fields: userFieldMap},
		Writes: &Writes{
			Lookup:    &Operation{Method: "GET", Path: "/users/{username}", RecordPath: "$.matches"},
			Disable:   &Operation{Method: "POST", Path: "/disable/{external_id}"},
			AddMember: &Operation{Method: "PUT", Path: "/g/{group_id}/m/{external_id}"},
			IsMember:  &Operation{Method: "GET", Path: "/users/{username}"},
		}}
	tg, _ := newTarget(t, spec)
	ctx := context.Background()
	for _, name := range []string{"several", "other", "nobody"} {
		for _, kind := range []string{target.DisableAccount, target.AddEntitlement} {
			err := tg.Apply(ctx, target.Request{Kind: kind, Account: target.Account{Username: name}, Group: target.Group{ExternalID: "g1"}})
			if err == nil || target.Retryable(err) {
				t.Errorf("%s %s: err = %v", kind, name, err)
			}
		}
	}
	if n := writes.Load(); n != 0 {
		t.Fatalf("%d writes went out on an ambiguous lookup", n)
	}
	// an id that does not match the record is refused too
	if err := tg.Apply(ctx, target.Request{Kind: target.DisableAccount, Account: target.Account{Username: "good", ExternalID: "u-other"}}); err == nil {
		t.Error("a record with another id was accepted")
	}
	if n := writes.Load(); n != 0 {
		t.Fatalf("%d writes", n)
	}
	// exactly one matching record works
	if err := tg.Apply(ctx, target.Request{Kind: target.DisableAccount, Account: target.Account{Username: "good"}}); err != nil {
		t.Fatal(err)
	}
	if n := writes.Load(); n != 1 {
		t.Errorf("%d writes, want 1", n)
	}
}
