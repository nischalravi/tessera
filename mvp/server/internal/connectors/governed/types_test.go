package governed

import (
	"strings"
	"testing"
)

func TestLookup(t *testing.T) {
	want := map[string]string{"awsorg": "awsorg", "githubscan": "githubscan", "sap": "erp", "oracle": "erp", "cyberark": "pam",
		"beyondtrust": "pam", "delinea": "pam", "fieldglass": "vms", "beeline": "vms", "csvfeed": "vms", "agentcore": "agentcore"}
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
	for id, feature := range map[string]bool{"sap": false, "cyberark": false, "githubscan": false, "agentcore": false,
		"awsorg": true, "fieldglass": true, "beeline": true, "csvfeed": true} {
		if got, _ := Lookup(id); got.Feature != feature {
			t.Errorf("%s feature = %v", id, got.Feature)
		}
	}
}

func TestValidateSettings(t *testing.T) {
	good := map[string]map[string]string{
		CyberArk:    {"username": "svc-tessera", "api_root": "/PasswordVault/API"},
		BeyondTrust: {"username": "tessera"},
		SAP:         {"client_id": "tessera-client", "token_path": "/oauth/token"},
		Oracle:      {"client_id": "x"},
		GitHubScan:  {"org": "acme-co"},
		AgentCore:   {"snapshot": "agentcore.json"},
		Fieldglass:  {"workers_path": "/api/v1/workers", "page_size": "200"},
		Beeline:     {},
		CSVFeed:     {"csv_path": "/feeds/contractors.csv"},
		AWSOrg:      {"regions": "us-east-1, eu-west-1", "management_account_id": "111111111111", "external_id": "tessera-abc123", "role_name": "TesseraReader"},
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
	for typ, want := range map[string][2]bool{CyberArk: {true, true}, SAP: {true, true}, Fieldglass: {true, true}, CSVFeed: {true, true},
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
