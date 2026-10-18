package okta_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/okta"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/replay"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

const (
	alice = "alice@larkspur.example"
	bob   = "bob@larkspur.example"
)

// client serves a recorded Okta cassette; {{base}} in a recording is the test server.
func client(t *testing.T, name string) (*okta.Client, *replay.Cassette) {
	t.Helper()
	cas, err := replay.Load(filepath.Join("testdata", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var base string
	srv := httptest.NewServer(cas.Handler(func() string { return base }))
	base = srv.URL
	t.Cleanup(srv.Close)
	hc, err := safehttp.NewForTest(t, safehttp.Options{Env: config.Dev, AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	return &okta.Client{HTTP: hc, BaseURL: srv.URL, Token: "okta-secret-token"}, cas
}

func done(t *testing.T, cas *replay.Cassette) {
	t.Helper()
	if u := cas.Unmatched(); len(u) > 0 {
		t.Errorf("requests no recording answers: %v", u)
	}
	if u := cas.Unused(); len(u) > 0 {
		t.Errorf("recorded interactions never requested: %v", u)
	}
}

func req(kind, user string) target.Request {
	return target.Request{Kind: kind, Key: "k-" + kind, Account: target.Account{Username: user}}
}

func member(kind string) target.Request {
	r := req(kind, bob)
	r.Group = target.Group{ExternalID: "00g1", Name: "engineering"}
	return r
}

func applyVerify(t *testing.T, name string, r target.Request) target.Verdict {
	t.Helper()
	c, cas := client(t, name)
	ctx := context.Background()
	if err := c.Apply(ctx, r); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	v, err := c.Verify(ctx, r)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	done(t, cas)
	return v
}

func TestOkta_DisableDeactivates(t *testing.T) {
	if v := applyVerify(t, "disable", req(target.DisableAccount, alice)); !v.OK {
		t.Errorf("Verify = %+v", v)
	}
}

func TestOkta_DisableNotApplied(t *testing.T) {
	v := applyVerify(t, "disable_not_applied", req(target.DisableAccount, alice))
	if v.OK || v.Observed != "status=ACTIVE" {
		t.Errorf("Verify = %+v; want a mismatch", v)
	}
}

func TestOkta_Create(t *testing.T) {
	r := req(target.CreateAccount, bob)
	r.Account.DisplayName, r.Account.Email = "Bob Ng", bob
	if v := applyVerify(t, "create", r); !v.OK {
		t.Errorf("Verify = %+v", v)
	}
}

func TestOkta_DeleteDeactivatesThenDeletes(t *testing.T) {
	if v := applyVerify(t, "delete", req(target.DeleteAccount, alice)); !v.OK {
		t.Errorf("Verify = %+v", v)
	}
}

func TestOkta_GroupMembersPagedByLink(t *testing.T) {
	if v := applyVerify(t, "group_add_paged", member(target.AddEntitlement)); !v.OK {
		t.Errorf("add: Verify = %+v", v)
	}
	if v := applyVerify(t, "group_remove_paged", member(target.RemoveEntitlement)); !v.OK {
		t.Errorf("remove: Verify = %+v", v)
	}
}

func TestOkta_GroupFoundByNameWhenIDUnknown(t *testing.T) {
	c, cas := client(t, "group_by_name")
	r := req(target.AddEntitlement, bob)
	r.Group = target.Group{ExternalID: "eng", Name: "engineering"}
	if err := c.Apply(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	done(t, cas)
}

func TestOkta_PagingLinkMustStayOnOrigin(t *testing.T) {
	c, _ := client(t, "link_off_origin")
	err := c.Apply(context.Background(), member(target.AddEntitlement))
	if err == nil || target.Retryable(err) || !strings.Contains(err.Error(), "leaves the Okta org") {
		t.Fatalf("err = %v, want a permanent refusal", err)
	}
}

func TestOkta_ErrorsAreClassifiedAndNeverEchoTheToken(t *testing.T) {
	for name, retry := range map[string]bool{"rate_limited": true, "bad_token": false} {
		c, _ := client(t, name)
		err := c.Apply(context.Background(), req(target.DisableAccount, alice))
		var te *target.Error
		if !errors.As(err, &te) || te.Retryable != retry {
			t.Errorf("%s: err = %v, want retryable=%v", name, err, retry)
		}
		if err != nil && strings.Contains(err.Error(), "okta-secret-token") {
			t.Errorf("%s: error echoes the token", name)
		}
	}
}

func TestOkta_SendsSSWSAuthAndIdempotencyKey(t *testing.T) {
	var auth, key string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		if r.Method == http.MethodPost {
			key = r.Header.Get("Idempotency-Key")
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`[{"id":"00u1","status":"ACTIVE","profile":{"login":"alice@larkspur.example"}}]`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	hc, _ := safehttp.NewForTest(t, safehttp.Options{Env: config.Dev, AllowLoopback: true})
	c := &okta.Client{HTTP: hc, BaseURL: srv.URL, Token: "t0k"}
	if err := c.Apply(context.Background(), req(target.DisableAccount, alice)); err != nil {
		t.Fatal(err)
	}
	if auth != "SSWS t0k" || key != "k-disable_account" {
		t.Errorf("Authorization = %q, Idempotency-Key = %q", auth, key)
	}
}
