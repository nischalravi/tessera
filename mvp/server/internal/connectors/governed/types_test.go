package governed

import (
	"strings"
	"testing"
)

func TestLookup(t *testing.T) {
	want := map[string]string{"awsorg": "awsorg", "githubscan": "githubscan", "sap": "erp", "oracle": "erp", "cyberark": "pam",
		"beyondtrust": "pam", "delinea": "pam", "fieldglass": "vms", "beeline": "vms", "csvfeed": "vms", "agentcore": "agentcore", "successfactors": "successfactors"}
	if len(Types) != len(want) {
		t.Errorf("%d types, want %d", len(Types), len(want))
	}
	for id, tmpl := range want {
		got, ok := Lookup(id)
		if !ok || got.Template != tmpl || got.System == "" || got.ID != id {
			t.Errorf("%s -> %+v %v", id, got, ok)
		}
		if len(SettingSpecs(id)) == 0 {
			t.Errorf("%s has no settings", id)
		}
	}
	if _, ok := Lookup("ldap"); ok {
		t.Error("ldap is not a governed type")
	}
	// the connectors that read straight into the graph, and the ones that hand over to a feature
	for id, feature := range map[string]bool{"sap": false, "cyberark": false, "githubscan": false, "agentcore": false, "successfactors": false,
		"awsorg": true, "fieldglass": true, "beeline": true, "csvfeed": true} {
		if got, _ := Lookup(id); got.Feature != feature {
			t.Errorf("%s feature = %v", id, got.Feature)
		}
	}
}

func TestValidateSettings(t *testing.T) {
	good := map[string]map[string]string{
		CyberArk:       {"username": "svc-tessera", "api_root": "/PasswordVault/API"},
		BeyondTrust:    {"username": "tessera"},
		SAP:            {"client_id": "tessera-client", "token_path": "/oauth/token"},
		Oracle:         {"client_id": "x"},
		GitHubScan:     {"org": "acme-co"},
		AgentCore:      {"snapshot": "agentcore.json"},
		Fieldglass:     {"workers_path": "/api/v1/workers", "page_size": "200"},
		Beeline:        {},
		CSVFeed:        {"csv_path": "/feeds/contractors.csv"},
		SuccessFactors: {"company_id": "ACME_prod", "username": "tessera-api"},
		AWSOrg:         {"regions": "us-east-1, eu-west-1", "management_account_id": "111111111111", "external_id": "tessera-abc123", "role_name": "TesseraReader"},
	}
	for typ, set := range good {
		if errs := ValidateSettings(typ, set); len(errs) != 0 {
			t.Errorf("%s: %v", typ, errs)
		}
	}
	type bad struct {
		typ string
		set map[string]string
		key string
	}
	for _, c := range []bad{
		{CyberArk, map[string]string{}, "username"},
		{CyberArk, map[string]string{"username": "a\nb"}, "username"},
		{CyberArk, map[string]string{"username": "u", "org": "x"}, "org"},
		{CyberArk, map[string]string{"username": "u", "api_root": "/a/../b"}, "api_root"},
		{CyberArk, map[string]string{"username": "u", "api_root": "https://evil.example/x"}, "api_root"},
		{SAP, map[string]string{"client_id": "has space"}, "client_id"},
		{SAP, map[string]string{"client_id": "c", "token_path": "//x"}, "token_path"},
		{GitHubScan, map[string]string{"org": "-bad"}, "org"},
		{GitHubScan, map[string]string{"org": "a/b"}, "org"},
		{AgentCore, map[string]string{"snapshot": "../x.json"}, "snapshot"},
		{AgentCore, map[string]string{"snapshot": "/etc/passwd"}, "snapshot"},
		{AgentCore, map[string]string{"snapshot": "a/b.json"}, "snapshot"},
		{SuccessFactors, map[string]string{"username": "u"}, "company_id"},
		{SuccessFactors, map[string]string{"company_id": "acme"}, "username"},
		{SuccessFactors, map[string]string{"company_id": "a/b", "username": "u"}, "company_id"},
		{SuccessFactors, map[string]string{"company_id": "acme", "username": "a:b"}, "username"},
		{SuccessFactors, map[string]string{"company_id": "acme", "username": "u", "auth": "ntlm"}, "auth"},
		{SuccessFactors, map[string]string{"company_id": "acme", "username": "u", "auth": "saml_bearer"}, "client_id"},
		{SuccessFactors, map[string]string{"company_id": "acme", "username": "u", "legal_entity": "a\nb"}, "legal_entity"},
		{SuccessFactors, map[string]string{"company_id": "acme", "username": "u", "org": "x"}, "org"},
		{Fieldglass, map[string]string{"page_size": "0"}, "page_size"},
		{Fieldglass, map[string]string{"page_size": "5000"}, "page_size"},
		{Fieldglass, map[string]string{"csv_path": "/x.csv"}, "csv_path"},
		{CSVFeed, map[string]string{}, "csv_path"},
		{AWSOrg, map[string]string{"external_id": "e1"}, "regions"},
		{AWSOrg, map[string]string{"regions": "mars-1", "external_id": "e1"}, "regions"},
		{AWSOrg, map[string]string{"regions": "us-east-1"}, "external_id"},
		{AWSOrg, map[string]string{"regions": "us-east-1", "external_id": "e1", "account_ids": "123"}, "account_ids"},
		{AWSOrg, map[string]string{"regions": "us-east-1", "external_id": "e1", "management_account_id": "12345678901x"}, "management_account_id"},
		{AWSOrg, map[string]string{"regions": "us-east-1", "external_id": "bad id with spaces"}, "external_id"},
		{AWSOrg, map[string]string{"regions": "us-east-1", "external_id": "e1", "role_name": "a b"}, "role_name"},
	} {
		errs := ValidateSettings(c.typ, c.set)
		found := false
		for _, e := range errs {
			found = found || e.Key == c.key
		}
		if !found {
			t.Errorf("%s %v: no error for %s (%v)", c.typ, c.set, c.key, errs)
		}
	}
}

func TestBaseURLUse(t *testing.T) {
	for typ, want := range map[string][2]bool{CyberArk: {true, true}, SAP: {true, true}, Fieldglass: {true, true}, CSVFeed: {true, true}, SuccessFactors: {true, true},
		GitHubScan: {false, true}, AWSOrg: {false, false}, AgentCore: {false, false}} {
		if req, takes := BaseURLUse(typ); req != want[0] || takes != want[1] {
			t.Errorf("%s: required %v takes %v", typ, req, takes)
		}
	}
}

func TestClipAndList(t *testing.T) {
	if got := List(" a, b ,,c "); strings.Join(got, "|") != "a|b|c" {
		t.Errorf("List = %v", got)
	}
	if len(clip(strings.Repeat("x", 100))) != 40 {
		t.Error("clip")
	}
}

func TestEnvSuccessFactors(t *testing.T) {
	p := Params{Type: SuccessFactors, BaseURL: "https://api4.successfactors.com", Secret: "pw-SECRET",
		Settings: map[string]string{"company_id": "acme", "username": "tessera-api", "auth": "saml_bearer", "client_id": "key", "legal_entity": " ACME_US "}}
	env, err := p.Env()
	if err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{
		"TESSERA_SUCCESSFACTORS_BASE_URL": "https://api4.successfactors.com", "TESSERA_SUCCESSFACTORS_COMPANY_ID": "acme",
		"TESSERA_SUCCESSFACTORS_USER": "tessera-api", "TESSERA_SUCCESSFACTORS_AUTH": "saml_bearer",
		"TESSERA_SUCCESSFACTORS_CLIENT_ID": "key", "TESSERA_SUCCESSFACTORS_LEGAL_ENTITY": "ACME_US",
		// the credential is only ever behind a reference that this closure resolves
		"TESSERA_SUCCESSFACTORS_PASSWORD": "env:" + secretVar, "TESSERA_SUCCESSFACTORS_PRIVATE_KEY": "env:" + secretVar,
	} {
		if got := env(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if env(secretVar) != "pw-SECRET" {
		t.Error("the credential is not reachable through its reference")
	}
}
