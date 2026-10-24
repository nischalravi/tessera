package wire_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/atlassian/atfake"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/governed/wire"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/servicenow/snfake"
	"github.com/nischalravi/tessera/mvp/server/internal/readiness/checks"
)

const (
	snUser, snPass       = "tessera.integration", "sn-password-secret"
	snClient, snClientSe = "sn-client-id", "sn-client-secret"
	atEmail, atToken     = "tessera@acme.example", "ATATT-token-secret"
	atOrg, atAdminKey    = "org-1", "admin-key-secret"
	atAccount            = "5b10ac8d82e05b22cc7d4ef5"
	atGroup              = "276f955c-63d7-42c8-9520-92d01dca0625"
)

func snRig(t *testing.T, oauth bool) (governed.Params, governed.Net, *snfake.Fake) {
	t.Helper()
	fk := snfake.New(snUser, snPass, snClient, snClientSe)
	fk.Set("sys_user", snfake.Row{"sys_id": "6816f79cc0a8016401c5a33be04be441", "user_name": "ada", "email": "ada@acme.example", "active": "true"})
	fk.Set("sys_user_group", snfake.Row{"sys_id": "0000000000000000000000000000a001", "name": "Network"})
	fk.Set("sys_user_role", snfake.Row{"sys_id": "0000000000000000000000000000b002", "name": "admin"})
	fk.Set("sys_user_has_role", snfake.Row{"sys_id": "h1", "user": "6816f79cc0a8016401c5a33be04be441", "role": "0000000000000000000000000000b002", "inherited": "false", "state": "active"})
	srv, n := serve(t, fk)
	p := governed.Params{Type: governed.ServiceNow, BaseURL: srv.URL, Settings: map[string]string{"username": snUser}, Secret: snPass}
	if oauth {
		p.Settings, p.Secret = map[string]string{"auth_mode": "oauth", "client_id": snClient}, snClientSe
	}
	return p, n, fk
}

func TestServiceNowProberAndConnector(t *testing.T) {
	for _, oauth := range []bool{false, true} {
		t.Run(fmt.Sprintf("oauth=%v", oauth), func(t *testing.T) {
			p, n, fk := snRig(t, oauth)
			pr := prober(t, p, n)
			wantPass(t, pr, "servicenow", "endpoint_reachable", "auth_ok", "read_probe")
			if _, _, w := fk.Counts(); w != 0 {
				t.Errorf("the probe wrote %d times", w)
			}
			auth, err := pr.Authenticate(context.Background())
			wantMode, wantID := "basic", snUser
			if oauth {
				wantMode, wantID = "client_credentials", snClient
			}
			if err != nil || !auth.OK || auth.Mode != wantMode || auth.Identity != wantID {
				t.Errorf("auth = %+v, %v", auth, err)
			}
			s, err := pr.Sample(context.Background(), connectors.SampleQuery{Op: "probe"})
			if err != nil || !s.Available || s.PerClass["user"] != 1 || s.PerClass["group"] != 1 || s.PerClass["role"] != 1 || s.PerClass["role_assignment"] != 1 {
				t.Errorf("sample = %+v, %v", s, err)
			}
			cn, err := wire.Connector(p, n)
			if err != nil {
				t.Fatal(err)
			}
			res, err := cn.Discover(context.Background())
			if err != nil || cn.System() != "servicenow" || len(res.Accounts) != 1 || len(res.Groups) != 2 || res.Stats == nil || len(res.Edges) != 1 {
				t.Errorf("discover = %+v, %v", res, err)
			}
			priv := false
			for _, g := range res.Groups {
				priv = priv || (g.Name == "admin" && g.Privileged)
			}
			if !priv {
				t.Error("admin is not privileged")
			}
		})
	}
}

func TestServiceNowProber_WrongSecret(t *testing.T) {
	for _, oauth := range []bool{false, true} {
		p, n, _ := snRig(t, oauth)
		p.Secret = "not-the-secret"
		if r := run(t, prober(t, p, n), "auth_ok", checks.Env{TemplateID: "servicenow"}); r.Status != checks.Fail {
			t.Errorf("oauth=%v: auth_ok with a wrong secret: %s %s", oauth, r.Status, r.Message)
		}
	}
}

func TestServiceNowHostAllowList(t *testing.T) {
	p := governed.Params{Type: governed.ServiceNow, BaseURL: "https://acme.example.com", Settings: map[string]string{"username": "u"}, Secret: "s"}
	n := governed.Net{RT: connsync.Runtime{Env: config.Prod}}
	// the client is nil in this Net, so the build fails either way; the host check must be what refuses first
	_, err := wire.Prober(p, n)
	if err == nil || !strings.Contains(err.Error(), "safehttp") && !strings.Contains(err.Error(), "ServiceNow domain") {
		t.Errorf("prober: %v", err)
	}
	_, n2 := serve(t, snfake.New("a", "b", "", ""))
	n2.RT = connsync.Runtime{Env: config.Prod}
	if _, err := wire.Prober(p, n2); err == nil || !strings.Contains(err.Error(), "ServiceNow domain") {
		t.Errorf("prober with a client: %v", err)
	}
	if _, err := wire.Connector(p, n2); err == nil || !strings.Contains(err.Error(), "ServiceNow domain") {
		t.Errorf("connector: %v", err)
	}
	p.BaseURL = "https://acme.service-now.com"
	if _, err := wire.Prober(p, n2); err != nil {
		t.Errorf("a service-now.com host in prod: %v", err)
	}
	if _, err := wire.Connector(p, n2); err != nil {
		t.Errorf("connector for a service-now.com host in prod: %v", err)
	}
}

func atRig(t *testing.T, admin bool) (governed.Params, governed.Net, *atfake.Fake) {
	t.Helper()
	fk := atfake.New(atEmail, atToken, atOrg, atAdminKey)
	fk.Users = []atfake.User{{AccountID: atAccount, Type: "atlassian", Email: "ada@acme.example", Name: "Ada", Active: true}}
	fk.Groups = []atfake.Group{{ID: atGroup, Name: "developers"}}
	fk.Members = map[string][]string{atGroup: {atAccount}}
	fk.AdminUsers = []atfake.AdminUser{{AccountID: atAccount, Email: "ada@acme.example", Status: "active", Products: []atfake.Product{{Key: "jira-software", Name: "Jira"}}}}
	srv, n := serve(t, fk)
	p := governed.Params{Type: governed.Atlassian, BaseURL: srv.URL, Settings: map[string]string{"email": atEmail}, Secret: atToken}
	if admin {
		p.Settings["org_id"] = atOrg
		p.Secret = `{"api_token":"` + atToken + `","admin_api_key":"` + atAdminKey + `"}`
		n.Endpoints = map[string]string{"TESSERA_ATLASSIAN_ADMIN_URL": srv.URL}
	}
	return p, n, fk
}

func TestAtlassianProberAndConnector(t *testing.T) {
	for _, admin := range []bool{false, true} {
		t.Run(fmt.Sprintf("admin=%v", admin), func(t *testing.T) {
			p, n, fk := atRig(t, admin)
			pr := prober(t, p, n)
			wantPass(t, pr, "atlassian", "endpoint_reachable", "auth_ok", "read_probe")
			if _, w, _ := fk.Counts(); w != 0 {
				t.Errorf("the probe wrote %d times", w)
			}
			s, err := pr.Sample(context.Background(), connectors.SampleQuery{Op: "probe"})
			if err != nil || !s.Available || s.PerClass["user"] != 1 || s.PerClass["group"] != 1 || (s.PerClass["organization_user"] == 1) != admin {
				t.Errorf("sample = %+v, %v", s, err)
			}
			auth, _ := pr.Authenticate(context.Background())
			if !auth.OK || auth.Mode != "api_token" || auth.Identity != atEmail {
				t.Errorf("auth = %+v", auth)
			}
			cn, err := wire.Connector(p, n)
			if err != nil {
				t.Fatal(err)
			}
			res, err := cn.Discover(context.Background())
			wantGroups := 1
			if admin {
				wantGroups = 2 // the product
			}
			if err != nil || cn.System() != "atlassian" || len(res.Accounts) != 1 || len(res.Groups) != wantGroups || res.Stats == nil {
				t.Errorf("discover = %+v, %v", res, err)
			}
		})
	}
}

func TestAtlassianProber_WrongToken(t *testing.T) {
	p, n, _ := atRig(t, false)
	p.Secret = "not-the-token"
	if r := run(t, prober(t, p, n), "auth_ok", checks.Env{TemplateID: "atlassian"}); r.Status != checks.Fail {
		t.Errorf("auth_ok with a wrong token: %s %s", r.Status, r.Message)
	}
}

// The admin API is api.atlassian.com in production: an override is a dev setting, refused by the wiring in any
// other runtime and absent from every connection.
func TestAtlassianAdminURLOverrideIsRefusedOutsideDev(t *testing.T) {
	p, n, _ := atRig(t, true)
	for _, env := range []string{config.Prod, config.Test} {
		n.RT = connsync.Runtime{Env: env}
		if _, err := wire.Prober(p, n); err == nil || !strings.Contains(err.Error(), "refused outside dev") {
			t.Errorf("%s prober: %v", env, err)
		}
		if _, err := wire.Connector(p, n); err == nil {
			t.Errorf("%s connector accepted an override", env)
		}
	}
	// a prod connection with no override builds against the public admin API (and the site host is checked)
	n.RT, n.Endpoints = connsync.Runtime{Env: config.Prod}, nil
	p.BaseURL = "https://acme.atlassian.net"
	if _, err := wire.Prober(p, n); err != nil {
		t.Errorf("prod without overrides: %v", err)
	}
	p.BaseURL = "https://acme.example.com"
	if _, err := wire.Prober(p, n); err == nil || !strings.Contains(err.Error(), "atlassian.net") {
		t.Errorf("a host outside *.atlassian.net: %v", err)
	}
}

func TestSaaSParamsNeverPrintTheSecret(t *testing.T) {
	for _, p := range []governed.Params{
		{Type: governed.ServiceNow, BaseURL: "https://acme.service-now.com", Settings: map[string]string{"username": "u"}, Secret: "TOP-SECRET-VALUE"},
		{Type: governed.Atlassian, BaseURL: "https://acme.atlassian.net", Settings: map[string]string{"email": "a@b.c"}, Secret: "TOP-SECRET-VALUE"},
	} {
		for _, f := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			if got := fmt.Sprintf(f, p); strings.Contains(got, "TOP-SECRET-VALUE") {
				t.Errorf("%s %s prints the secret: %s", p.Type, f, got)
			}
		}
		env, err := p.Env()
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range []string{"TESSERA_SERVICENOW_SECRET", "TESSERA_ATLASSIAN_CREDENTIAL"} {
			if v := env(k); v != "" && (strings.Contains(v, "TOP-SECRET") || !strings.HasPrefix(v, "env:")) {
				t.Errorf("%s = %q", k, v)
			}
		}
		if v := env("TESSERA_ATLASSIAN_ADMIN_URL"); v != "" {
			t.Errorf("a connection carries an admin API override: %q", v)
		}
	}
}
