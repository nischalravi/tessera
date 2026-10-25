package governed

import (
	"strings"
	"testing"
)

func TestLookup(t *testing.T) {
	want := map[string]string{"awsorg": "awsorg", "githubscan": "githubscan", "sap": "erp", "oracle": "erp", "cyberark": "pam",
		"beyondtrust": "pam", "delinea": "pam", "fieldglass": "vms", "beeline": "vms", "csvfeed": "vms", "agentcore": "agentcore", "azurerbac": "azurerbac", "gcpiam": "gcpiam", "successfactors": "successfactors", "unixssh": "unixssh", "sftpdrop": "sftpdrop",
		"servicenow": "servicenow", "atlassian": "atlassian", "mcp": "mcp", "bedrock": "bedrock",
		"vertex": "vertex", "foundry": "foundry", "copilot": "copilot", "agentforce": "agentforce"}
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
	for id, feature := range map[string]bool{"sap": false, "cyberark": false, "githubscan": false, "agentcore": false, "azurerbac": false, "gcpiam": false, "successfactors": false, "unixssh": false, "sftpdrop": false, "servicenow": false, "atlassian": false, "mcp": false, "bedrock": false, "vertex": false, "foundry": false, "copilot": false, "agentforce": false,
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
		AzureRBAC: {"tenant_id": "11111111-2222-3333-4444-555555555555", "client_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			"subscription_ids": "aaaa1111-0000-0000-0000-000000000001, bbbb2222-0000-0000-0000-000000000002", "management_group_ids": "corp,Platform_1", "include_eligible": "true"},
		GCPIAM:         {"organization_id": "123456789012", "folder_ids": "1000,2000", "project_ids": "alpha-proj-1, beta-proj-22"},
		SuccessFactors: {"company_id": "ACME_prod", "username": "tessera-api"},
		UnixSSH:        {"host": "host1.example.com", "port": "2222", "username": "tessera", "host_key": "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8", "use_sudo": "true"},
		ServiceNow:     {"username": "tessera.integration"},
		Atlassian:      {"email": "tessera@acme.example", "org_id": "abc-123", "project_keys": "PROJ, OPS_1"},
		MCP:            {"owner": "olu@acme.example", "server_name": "Acme tools", "auth_header": "X-Api-Key"},
		Bedrock:        {"region": "eu-west-1"},
		Vertex:         {"project_id": "acme-agents-prod", "location": "europe-west4", "owner": "olu@acme.example"},
		Foundry:        {"tenant_id": "11111111-2222-3333-4444-555555555555", "client_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "owner": "olu@acme.example"},
		Copilot:        {"tenant_id": "11111111-2222-3333-4444-555555555555", "client_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
		Agentforce:     {"api_version": "v61.0"},
	}
	for name, set := range map[string]map[string]string{"servicenow basic": {"auth_mode": "basic", "username": "svc"}, "servicenow oauth": {"auth_mode": "oauth", "client_id": "cid"}} {
		if errs := ValidateSettings(ServiceNow, set); len(errs) != 0 {
			t.Errorf("%s: %v", name, errs)
		}
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
		{AzureRBAC, map[string]string{"client_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}, "tenant_id"},
		{AzureRBAC, map[string]string{"tenant_id": "contoso.onmicrosoft.com", "client_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}, "tenant_id"},
		{AzureRBAC, map[string]string{"tenant_id": "11111111-2222-3333-4444-555555555555"}, "client_id"},
		{AzureRBAC, map[string]string{"tenant_id": "11111111-2222-3333-4444-555555555555", "client_id": "not-a-guid"}, "client_id"},
		{AzureRBAC, map[string]string{"tenant_id": "11111111-2222-3333-4444-555555555555", "client_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "subscription_ids": "../x"}, "subscription_ids"},
		{AzureRBAC, map[string]string{"tenant_id": "11111111-2222-3333-4444-555555555555", "client_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "management_group_ids": "a/b"}, "management_group_ids"},
		{AzureRBAC, map[string]string{"tenant_id": "11111111-2222-3333-4444-555555555555", "client_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "include_eligible": "yes"}, "include_eligible"},
		{AzureRBAC, map[string]string{"tenant_id": "11111111-2222-3333-4444-555555555555", "client_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "management_url": "https://x.example"}, "management_url"},
		{UnixSSH, map[string]string{"username": "u", "host_key": "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8"}, "host"},
		{UnixSSH, map[string]string{"host": "https://h.example.com", "username": "u", "host_key": "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8"}, "host"},
		{UnixSSH, map[string]string{"host": "h.example.com:22", "username": "u", "host_key": "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8"}, "host"},
		{UnixSSH, map[string]string{"host": "h", "username": "u", "host_key": "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8", "port": "0"}, "port"},
		{UnixSSH, map[string]string{"host": "h", "username": "u", "host_key": "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8", "port": "70000"}, "port"},
		{UnixSSH, map[string]string{"host": "h", "username": "bad user; rm", "host_key": "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8"}, "username"},
		{UnixSSH, map[string]string{"host": "h", "username": "u"}, "host_key"},
		{UnixSSH, map[string]string{"host": "h", "username": "u", "host_key": "SHA256:short"}, "host_key"},
		{UnixSSH, map[string]string{"host": "h", "username": "u", "host_key": "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8", "use_sudo": "yes"}, "use_sudo"},
		{UnixSSH, map[string]string{"host": "h", "username": "u", "host_key": "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8", "command": "id"}, "command"},
		{MCP, map[string]string{}, "owner"},
		{MCP, map[string]string{"owner": "not-an-email"}, "owner"},
		{MCP, map[string]string{"owner": "a@b.c", "server_name": "bad\nname"}, "server_name"},
		{MCP, map[string]string{"owner": "a@b.c", "auth_header": "X Bad"}, "auth_header"},
		{MCP, map[string]string{"owner": "a@b.c", "auth_header": "Host"}, "auth_header"},
		{MCP, map[string]string{"owner": "a@b.c", "auth_header": "Connection"}, "auth_header"},
		{MCP, map[string]string{"owner": "a@b.c", "auth_header": "mcp-session-id"}, "auth_header"},
		{MCP, map[string]string{"owner": "a@b.c", "auth_header": "x-api-key\r\nHost"}, "auth_header"},
		{MCP, map[string]string{"owner": "a@b.c", "url": "https://x.example"}, "url"},
		{Bedrock, map[string]string{}, "region"},
		{Bedrock, map[string]string{"region": "us-east-1.evil.example"}, "region"},
		{Bedrock, map[string]string{"region": "us-east-1", "agent_url": "https://x.example"}, "agent_url"},
		{Vertex, map[string]string{"location": "us-central1"}, "project_id"},
		{Vertex, map[string]string{"project_id": "A/B", "location": "us-central1"}, "project_id"},
		{Vertex, map[string]string{"project_id": "acme-agents-prod"}, "location"},
		{Vertex, map[string]string{"project_id": "acme-agents-prod", "location": "us-central1.evil.example"}, "location"},
		{Vertex, map[string]string{"project_id": "acme-agents-prod", "location": "us-central1", "owner": "nope"}, "owner"},
		{Vertex, map[string]string{"project_id": "acme-agents-prod", "location": "us-central1", "api_url": "https://x.example"}, "api_url"},
		{Foundry, map[string]string{"client_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}, "tenant_id"},
		{Foundry, map[string]string{"tenant_id": "11111111-2222-3333-4444-555555555555", "client_id": "not-a-guid"}, "client_id"},
		{Foundry, map[string]string{"tenant_id": "11111111-2222-3333-4444-555555555555", "client_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "authority_url": "https://x.example"}, "authority_url"},
		{Copilot, map[string]string{"tenant_id": "11111111-2222-3333-4444-555555555555"}, "client_id"},
		{Copilot, map[string]string{"tenant_id": "x", "client_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}, "tenant_id"},
		{Agentforce, map[string]string{"api_version": "61"}, "api_version"},
		{Agentforce, map[string]string{"login_url": "https://evil.example"}, "login_url"},
		{SFTPDrop, map[string]string{"host": "h", "username": "u", "host_key": "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8", "accounts_file": "a.csv", "accounts_account_id": "ID", "accounts_username": "U", "directory": "/d/../etc"}, "directory"},
		{SFTPDrop, map[string]string{"host": "h", "username": "u", "host_key": "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8", "accounts_file": "a.csv", "accounts_account_id": "ID", "accounts_username": "U", "directory": "relative"}, "directory"},
		{SFTPDrop, map[string]string{"host": "h", "username": "u", "host_key": "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8", "accounts_file": "a.csv", "accounts_account_id": "ID", "accounts_username": "U", "directory": "/d//x"}, "directory"},
		{SFTPDrop, map[string]string{"host": "h", "username": "u", "host_key": "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8", "directory": "/d", "accounts_account_id": "ID", "accounts_username": "U", "accounts_file": "../a.csv"}, "accounts_file"},
		{SFTPDrop, map[string]string{"host": "h", "username": "u", "host_key": "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8", "directory": "/d", "accounts_account_id": "ID", "accounts_username": "U", "accounts_file": "sub/a.csv"}, "accounts_file"},
		{SFTPDrop, map[string]string{"host": "h", "username": "u", "host_key": "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8", "directory": "/d", "accounts_file": "a.csv", "accounts_account_id": "ID", "accounts_username": "U", "entitlements_file": "/etc/passwd"}, "entitlements_file"},
		{SFTPDrop, map[string]string{"host": "h", "username": "u", "host_key": "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8", "directory": "/d", "accounts_file": "a.csv", "accounts_account_id": "ID", "accounts_username": "U", "accounts_email": "bad\ncol"}, "accounts_email"},
		{SFTPDrop, map[string]string{"host": "h", "username": "u", "host_key": "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8", "directory": "/d", "accounts_file": "a.csv", "accounts_account_id": "ID", "accounts_username": "U", "command": "id"}, "command"},
		{SFTPDrop, map[string]string{"host": "h", "username": "u", "host_key": "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8", "directory": "/d"}, "accounts_file"},
		{SFTPDrop, map[string]string{"host": "h", "username": "u", "host_key": "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8", "directory": "/d", "accounts_file": "a.csv", "accounts_username": "U"}, "accounts_account_id"},
		{GCPIAM, map[string]string{}, "organization_id"},
		{GCPIAM, map[string]string{"organization_id": "organizations/1"}, "organization_id"},
		{GCPIAM, map[string]string{"folder_ids": "a"}, "folder_ids"},
		{GCPIAM, map[string]string{"project_ids": "A_B"}, "project_ids"},
		{GCPIAM, map[string]string{"organization_id": "1", "token_url": "https://x.example"}, "token_url"},
		{ServiceNow, map[string]string{}, "username"},
		{ServiceNow, map[string]string{"auth_mode": "oauth"}, "client_id"},
		{ServiceNow, map[string]string{"auth_mode": "oauth", "client_id": "c", "username": "u"}, "username"},
		{ServiceNow, map[string]string{"username": "u", "client_id": "c"}, "client_id"},
		{ServiceNow, map[string]string{"auth_mode": "saml", "username": "u"}, "auth_mode"},
		{ServiceNow, map[string]string{"username": "has space"}, "username"},
		{ServiceNow, map[string]string{"username": "u", "login_url": "https://evil.example"}, "login_url"},
		{Atlassian, map[string]string{}, "email"},
		{Atlassian, map[string]string{"email": "not-an-email"}, "email"},
		{Atlassian, map[string]string{"email": "a b@c.d"}, "email"},
		{Atlassian, map[string]string{"email": "a@b.c", "org_id": "a/b"}, "org_id"},
		{Atlassian, map[string]string{"email": "a@b.c", "project_keys": "A B"}, "project_keys"},
		{Atlassian, map[string]string{"email": "a@b.c", "project_keys": "../x"}, "project_keys"},
		{Atlassian, map[string]string{"email": "a@b.c", "project_keys": strings.TrimSuffix(strings.Repeat("PROJ,", 51), ",")}, "project_keys"},
		{Atlassian, map[string]string{"email": "a@b.c", "admin_url": "https://evil.example"}, "admin_url"},
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
		GitHubScan: {false, true}, AWSOrg: {false, false}, AgentCore: {false, false}, ServiceNow: {true, true}, Atlassian: {true, true}} {
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
