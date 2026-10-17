package credential_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/devidp"
	"github.com/nischalravi/tessera/mvp/server/internal/devidp/devidptest"
	"github.com/nischalravi/tessera/mvp/server/internal/guests/credential"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

func TestDevIdP_RefusesProduction(t *testing.T) {
	hc := &http.Client{}
	for _, env := range []string{"prod", ""} {
		if _, err := credential.NewDevIdP(env, hc); err == nil {
			t.Errorf("env %q: the dev authority was built", env)
		}
	}
	if _, err := credential.NewDevIdP("dev", nil); err == nil {
		t.Error("built without the safehttp client")
	}
	a, err := credential.NewDevIdP("test", hc)
	if err != nil || a.Kind() != "dev_idp" || a.Profile() != "dev_mock" {
		t.Errorf("NewDevIdP = %v, %v", a, err)
	}
}

func TestDevIdP_RegistersTheGuest(t *testing.T) {
	idp := devidptest.Start(t, devidp.Config{})
	hc, err := safehttp.NewForTest(t, safehttp.Options{Env: config.Dev, AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	a, err := credential.NewDevIdP("dev", hc)
	if err != nil {
		t.Fatal(err)
	}
	c := credential.Connection{Issuer: idp.URL, ClientID: devidptest.ClientID, ClientSecret: devidptest.ClientSecret}
	g := credential.Guest{Tenant: "larkspur", Ref: "1234-abcd", Email: "g@x.example", Name: "Gwen"}
	reg, err := a.Register(context.Background(), c, g)
	if err != nil || reg.Subject != "guest-1234-abcd" || reg.LoginHint != reg.Subject {
		t.Fatalf("Register = %+v, %v", reg, err)
	}
	if reg2, err := a.Register(context.Background(), c, g); err != nil || reg2 != reg {
		t.Errorf("registering twice = %+v, %v", reg2, err)
	}
	found := false
	for _, u := range idp.Users() {
		found = found || u.Sub == reg.Subject && u.Email == "g@x.example" && u.Tenant == "larkspur"
	}
	if !found {
		t.Error("the dev IdP does not know the guest")
	}
	bad := c
	bad.ClientSecret = "wrong"
	if _, err := a.Register(context.Background(), bad, g); !errors.Is(err, credential.ErrUnavailable) {
		t.Errorf("a wrong client secret = %v", err)
	}
	if _, err := a.Register(context.Background(), c, credential.Guest{Tenant: "larkspur", Ref: "has space", Email: "x@y", Name: "n"}); err == nil {
		t.Error("a bad reference was registered")
	}
	// the safehttp guard stands: a production-style client refuses loopback
	prod, err := safehttp.NewForTest(t, safehttp.Options{Env: config.Prod})
	if err != nil {
		t.Fatal(err)
	}
	pa, _ := credential.NewDevIdP("dev", prod)
	if _, err := pa.Register(context.Background(), c, g); err == nil {
		t.Error("the SSRF guard let a loopback address through")
	}
}
