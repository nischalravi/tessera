package devidp_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/devidp"
	"github.com/nischalravi/tessera/mvp/server/internal/devidp/devidptest"
)

func register(t *testing.T, idp *devidptest.IdP, user, pass, body string) int {
	t.Helper()
	req, err := http.NewRequest("POST", idp.URL+"/_register", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if user != "" {
		req.SetBasicAuth(url.QueryEscape(user), url.QueryEscape(pass))
	}
	resp, err := http.DefaultClient.Do(req) // #nosec G107 G704 -- the in-process test IdP on loopback
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// TestRegister: a runtime user can sign in; only guest-prefixed subjects are
// accepted, never one of users.yaml; the caller must be a registered client.
func TestRegister(t *testing.T) {
	idp := devidptest.Start(t, devidp.Config{})
	const ok = `{"sub":"guest-1","email":"g@x.example","name":"G","tenant":"larkspur","authenticators":["passkey"]}`
	if c := register(t, idp, devidptest.ClientID, devidptest.ClientSecret, ok); c != 204 {
		t.Fatalf("register = %d", c)
	}
	// idempotent, and it can be replaced
	if c := register(t, idp, devidptest.ClientID, devidptest.ClientSecret, strings.Replace(ok, `"G"`, `"G2"`, 1)); c != 204 {
		t.Errorf("re-register = %d", c)
	}
	var got *devidp.User
	for _, u := range idp.Users() {
		if u.Sub == "guest-1" {
			got = &u
		}
	}
	if got == nil || got.Name != "G2" || len(got.Authenticators) != 1 || got.Authenticators[0] != devidp.MethodPasskey {
		t.Fatalf("registered user = %+v", got)
	}
	cases := map[string]struct {
		user, pass, body string
		want             int
	}{
		"no credentials":        {"", "", ok, 401},
		"wrong secret":          {devidptest.ClientID, "nope", ok, 401},
		"unknown client":        {"nobody", devidptest.ClientSecret, ok, 401},
		"configured user's sub": {devidptest.ClientID, devidptest.ClientSecret, strings.Replace(ok, "guest-1", "00u-alice-admin", 1), 400},
		"wrong prefix":          {devidptest.ClientID, devidptest.ClientSecret, strings.Replace(ok, "guest-1", "user-1", 1), 400},
		"no authenticator":      {devidptest.ClientID, devidptest.ClientSecret, strings.Replace(ok, `["passkey"]`, `[]`, 1), 400},
		"unknown authenticator": {devidptest.ClientID, devidptest.ClientSecret, strings.Replace(ok, "passkey", "telepathy", 1), 400},
		"unknown field":         {devidptest.ClientID, devidptest.ClientSecret, strings.Replace(ok, `"name"`, `"role":"admin","name"`, 1), 400},
		"no email":              {devidptest.ClientID, devidptest.ClientSecret, strings.Replace(ok, `"g@x.example"`, `""`, 1), 400},
		"not json":              {devidptest.ClientID, devidptest.ClientSecret, `x`, 400},
	}
	for name, c := range cases {
		if got := register(t, idp, c.user, c.pass, c.body); got != c.want {
			t.Errorf("%s: %d, want %d", name, got, c.want)
		}
	}
	for _, u := range idp.Users() {
		if u.Sub == "00u-alice-admin" && len(u.Roles) == 0 {
			t.Error("a configured user was replaced")
		}
	}
}
