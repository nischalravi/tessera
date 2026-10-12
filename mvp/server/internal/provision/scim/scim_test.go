package scim_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/fake"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/replay"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/scim"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

const (
	alice = "alice@larkspur.example"
	bob   = "bob@larkspur.example"
)

func httpClient(t *testing.T) *http.Client {
	t.Helper()
	c, err := safehttp.New(safehttp.Options{Env: config.Dev, AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newClient(t *testing.T, h http.Handler, dialect string) *scim.Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &scim.Client{HTTP: httpClient(t), BaseURL: srv.URL + "/scim/v2", Token: "tok", Dialect: dialect}
}

// replayClient serves a recorded cassette at the SCIM root.
func replayClient(t *testing.T, name, dialect string) (*scim.Client, *replay.Cassette) {
	t.Helper()
	cas, err := replay.Load(filepath.Join("testdata", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var base string
	srv := httptest.NewServer(http.StripPrefix("/scim/v2", cas.Handler(func() string { return base })))
	base = srv.URL
	t.Cleanup(srv.Close)
	return &scim.Client{HTTP: httpClient(t), BaseURL: srv.URL + "/scim/v2", Token: "tok", Dialect: dialect}, cas
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

func member(kind, user string) target.Request {
	r := req(kind, user)
	r.Group = target.Group{ExternalID: "eng", Name: "engineering"}
	return r
}

// Recorded Entra ID exchange: active is the string "True"/"False" and PATCH
// operation names are capitalised. The client reads both spellings and sends
// the Entra form in the entra dialect.
func TestScim_EntraStringBooleans(t *testing.T) {
	c, cas := replayClient(t, "entra_disable", scim.Entra)
	ctx := context.Background()
	if err := c.Apply(ctx, req(target.DisableAccount, alice)); err != nil {
		t.Fatal(err)
	}
	v, err := c.Verify(ctx, req(target.DisableAccount, alice))
	if err != nil || !v.OK {
		t.Fatalf("Verify = %+v, %v; want the re-read to show active \"False\" as disabled", v, err)
	}
	done(t, cas)
}

func TestScim_EntraAcknowledgedButNotApplied(t *testing.T) {
	c, cas := replayClient(t, "entra_disable_not_applied", scim.Entra)
	ctx := context.Background()
	if err := c.Apply(ctx, req(target.DisableAccount, alice)); err != nil {
		t.Fatal(err)
	}
	v, err := c.Verify(ctx, req(target.DisableAccount, alice))
	if err != nil {
		t.Fatal(err)
	}
	if v.OK || v.Observed != "active=true" || v.Expected != "account disabled" {
		t.Errorf("Verify = %+v; want a mismatch (still active)", v)
	}
	done(t, cas)
}

func TestScim_StandardAlreadyInactiveSendsNoPatch(t *testing.T) {
	c, cas := replayClient(t, "standard_disable_already", scim.Standard)
	if err := c.Apply(context.Background(), req(target.DisableAccount, alice)); err != nil {
		t.Fatal(err)
	}
	done(t, cas)
}

func TestScim_UserListIsPaginated(t *testing.T) {
	c, cas := replayClient(t, "user_second_page", scim.Standard)
	v, err := c.Verify(context.Background(), req(target.CreateAccount, alice))
	if err != nil || !v.OK {
		t.Fatalf("Verify = %+v, %v; want the user found on the second list page", v, err)
	}
	done(t, cas)
}

// A group of 140 members answers 100 at a time. Add walks both pages before
// it concludes the user is missing; the re-read finds the user on page two.
func TestScim_LargeGroupAdd(t *testing.T) {
	c, cas := replayClient(t, "large_group_add", scim.Standard)
	ctx := context.Background()
	if err := c.Apply(ctx, member(target.AddEntitlement, bob)); err != nil {
		t.Fatal(err)
	}
	v, err := c.Verify(ctx, member(target.AddEntitlement, bob))
	if err != nil || !v.OK {
		t.Fatalf("Verify = %+v, %v", v, err)
	}
	done(t, cas)
}

func TestScim_LargeGroupRemove(t *testing.T) {
	c, cas := replayClient(t, "large_group_remove", scim.Standard)
	ctx := context.Background()
	if err := c.Apply(ctx, member(target.RemoveEntitlement, bob)); err != nil {
		t.Fatal(err)
	}
	v, err := c.Verify(ctx, member(target.RemoveEntitlement, bob))
	if err != nil || !v.OK {
		t.Fatalf("Verify = %+v, %v", v, err)
	}
	done(t, cas)
}

// Every operation kind against the stateful fake, in both dialects, and
// repeating an operation changes nothing (idempotent).
func TestScim_OperationsAgainstFake(t *testing.T) {
	for _, dialect := range []string{scim.Standard, scim.Entra} {
		t.Run(dialect, func(t *testing.T) {
			f := fake.New(fake.Options{Token: "tok", StringBooleans: dialect == scim.Entra, MemberPage: 3})
			c := newClient(t, f.Handler(), dialect)
			ctx := context.Background()
			steps := []struct {
				r      target.Request
				before func()
			}{
				{r: target.Request{Kind: target.CreateAccount, Key: "k1", Account: target.Account{Username: bob, ExternalID: "x-bob", DisplayName: "Bob Ng", Email: bob}}},
				{r: member(target.AddEntitlement, bob), before: func() { f.AddGroup("engineering", "eng") }},
				{r: target.Request{Kind: target.UpdateAccount, Key: "k3", Account: target.Account{Username: bob, Attrs: map[string]string{"displayName": "Robert Ng"}}}},
				{r: member(target.RemoveEntitlement, bob)},
				{r: req(target.DisableAccount, bob)},
				{r: req(target.DeleteAccount, bob)},
			}
			for _, s := range steps {
				if s.before != nil {
					s.before()
				}
				for i := 0; i < 2; i++ { // the second run is a repeat
					if err := c.Apply(ctx, s.r); err != nil {
						t.Fatalf("%s #%d Apply: %v", s.r.Kind, i, err)
					}
					v, err := c.Verify(ctx, s.r)
					if err != nil || !v.OK {
						t.Fatalf("%s #%d Verify = %+v, %v", s.r.Kind, i, v, err)
					}
				}
			}
			if exists, _ := f.Active(bob); exists {
				t.Error("the user still exists after delete_account")
			}
			for _, k := range f.IdempotencyKeys() {
				if k == "" {
					t.Error("a write was sent without an Idempotency-Key")
				}
			}
		})
	}
}

// A paginated group of 20 with 3 members per response: membership is still found.
func TestScim_MembershipInLargeFakeGroup(t *testing.T) {
	f := fake.New(fake.Options{MemberPage: 3})
	var ids []string
	for i := 0; i < 20; i++ {
		ids = append(ids, f.AddUser("user"+strings.Repeat("x", i)+"@e.example", "", true))
	}
	f.AddUser(bob, "", true)
	f.AddGroup("engineering", "eng", ids...)
	c := newClient(t, f.Handler(), scim.Standard)
	ctx := context.Background()
	if err := c.Apply(ctx, member(target.AddEntitlement, bob)); err != nil {
		t.Fatal(err)
	}
	if v, err := c.Verify(ctx, member(target.AddEntitlement, bob)); err != nil || !v.OK {
		t.Fatalf("Verify = %+v, %v", v, err)
	}
	if got := len(f.Members("engineering")); got != 21 {
		t.Errorf("members = %d, want 21", got)
	}
}

func TestScim_DroppedWriteIsCaughtByVerify(t *testing.T) {
	f := fake.New(fake.Options{Fault: fake.DropWrites})
	f.AddUser(alice, "Alice", true)
	c := newClient(t, f.Handler(), scim.Standard)
	ctx := context.Background()
	if err := c.Apply(ctx, req(target.DisableAccount, alice)); err != nil {
		t.Fatalf("Apply = %v; a dropped write is acknowledged", err)
	}
	v, err := c.Verify(ctx, req(target.DisableAccount, alice))
	if err != nil || v.OK {
		t.Fatalf("Verify = %+v, %v; want a mismatch", v, err)
	}
}

func TestScim_ErrorClassification(t *testing.T) {
	cases := []struct {
		name      string
		h         http.HandlerFunc
		retryable bool
	}{
		{"503", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }, true},
		{"429", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(429) }, true},
		{"401", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(401) }, false},
		{"400", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(400) }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newClient(t, tc.h, scim.Standard)
			err := c.Apply(context.Background(), req(target.DisableAccount, alice))
			var te *target.Error
			if !errors.As(err, &te) || te.Retryable != tc.retryable {
				t.Fatalf("err = %v, want *target.Error{Retryable: %v}", err, tc.retryable)
			}
			if strings.Contains(err.Error(), "tok") {
				t.Errorf("error mentions the credential: %v", err)
			}
		})
	}
	// A dead server is a retryable transport failure.
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	c := &scim.Client{HTTP: httpClient(t), BaseURL: url + "/scim/v2"}
	if err := c.Apply(context.Background(), req(target.DisableAccount, alice)); !target.Retryable(err) {
		t.Errorf("transport failure = %v, want retryable", err)
	}
}

func TestScim_DisableMissingUserIsPermanent(t *testing.T) {
	c := newClient(t, fake.New(fake.Options{}).Handler(), scim.Standard)
	err := c.Apply(context.Background(), req(target.DisableAccount, "ghost@x.example"))
	if err == nil || target.Retryable(err) {
		t.Fatalf("err = %v, want a permanent error", err)
	}
}

func TestScim_RejectsBadUpdatePath(t *testing.T) {
	f := fake.New(fake.Options{})
	f.AddUser(alice, "Alice", true)
	c := newClient(t, f.Handler(), scim.Standard)
	r := target.Request{Kind: target.UpdateAccount, Account: target.Account{Username: alice, Attrs: map[string]string{"x;drop": "1"}}}
	if err := c.Apply(context.Background(), r); err == nil || target.Retryable(err) {
		t.Fatalf("err = %v, want a permanent error", err)
	}
}
