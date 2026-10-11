package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth/oauth2rp"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/samlsp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

func adminRun(t *testing.T, db string, args ...string) (string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	err := run(context.Background(), append(append([]string{"admin"}, args...), "-db", db), &out, &errOut)
	return out.String() + errOut.String(), err
}

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const oktaYAML = `name: Okta
protocol: oidc
profile: okta
issuer: https://acme.okta.com
client_id: 0oa1b2c3d4EXAMPLE
scopes: [openid, email, profile, groups]
verified_domains: [acme.example]
groups_claim: groups
group_role_mapping: {"Tessera Viewers": viewer, "Tessera Operators": operator}
`

// TestAdminBootstrap (§15.3): create-tenant, add-idp and invite-admin run
// as the operator, are audited, and the invitation keeps only its hash.
func TestAdminBootstrap(t *testing.T) {
	t.Setenv("TESSERA_ENV", "dev")
	t.Setenv("TESSERA_NOW", "2026-10-08T09:30:00")
	t.Setenv("TESSERA_PUBLIC_URL", "http://localhost:5173")
	t.Setenv("USER", "op-jane")
	dir := t.TempDir()
	db := filepath.Join(dir, "t.db")
	st, err := store.OpenFresh(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Migrate(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()

	if out, err := adminRun(t, db, "create-tenant", "-slug", "acme", "-name", "Acme Corp"); err != nil || !strings.Contains(out, "created tenant acme") {
		t.Fatalf("create-tenant: %v %s", err, out)
	}
	if _, err := adminRun(t, db, "create-tenant", "-slug", "acme", "-name", "Again"); err == nil {
		t.Error("a duplicate slug was accepted")
	}
	secret := writeFile(t, dir, "secret", "s3cret\n")
	out, err := adminRun(t, db, "add-idp", "-tenant", "acme", "-file", writeFile(t, dir, "okta.yaml", oktaYAML), "-client-secret-file", secret)
	if err != nil {
		t.Fatalf("add-idp: %v %s", err, out)
	}
	m := regexp.MustCompile(`added connection ([0-9a-f-]{36})`).FindStringSubmatch(out)
	if m == nil || !strings.Contains(out, "http://localhost:5173/api/auth/oidc/"+m[1]+"/callback") {
		t.Fatalf("add-idp output: %s", out)
	}
	for name, body := range map[string]string{
		"admin role from a group": strings.Replace(oktaYAML, "operator}", "tenant_admin}", 1),
		"private_key_jwt":         oktaYAML + "client_auth_method: private_key_jwt\n",
		"unknown key":             oktaYAML + "client_secret: nope\n",
		"trailing slash issuer":   strings.Replace(oktaYAML, "okta.com\n", "okta.com/\n", 1),
		"saml":                    strings.Replace(oktaYAML, "protocol: oidc", "protocol: saml", 1),
		"admin default role":      oktaYAML + "default_role: tenant_admin\n",
	} {
		if out, err := adminRun(t, db, "add-idp", "-tenant", "acme", "-file", writeFile(t, dir, "bad.yaml", body), "-client-secret-file", secret); err == nil {
			t.Errorf("%s: accepted: %s", name, out)
		}
	}
	if _, err := adminRun(t, db, "invite-admin", "-tenant", "acme", "-connection", m[1], "-email", "jane@acme.example", "-ttl", "48h"); err == nil {
		t.Error("an invitation longer than 24h was accepted")
	}
	out, err = adminRun(t, db, "invite-admin", "-tenant", "acme", "-connection", m[1], "-email", "jane@acme.example")
	code := regexp.MustCompile(`/t/acme/bootstrap\?code=(tbi_[A-Za-z0-9_-]+)`).FindStringSubmatch(out)
	if err != nil || code == nil {
		t.Fatalf("invite-admin: %v %s", err, out)
	}

	st, err = store.Open(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var acme store.Tenant
	if err := st.ReadSystem(context.Background(), "test", func(s *store.SystemTx) error {
		var err error
		acme, err = s.TenantBySlug("acme")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.ReadTenant(context.Background(), acme.ID, func(tx *store.TenantTx) error {
		inv, err := tx.BootstrapInvitationByCodeHash(seal.SHA256Hex([]byte(code[1])))
		if err != nil || inv.Email != "jane@acme.example" || inv.CreatedBy != "op-jane" {
			t.Errorf("invitation %+v %v", inv, err)
		}
		cs, err := tx.IdPConnections()
		if err != nil || len(cs) != 1 || len(cs[0].ClientSecretEnc) == 0 || bytes.Contains(cs[0].ClientSecretEnc, []byte("s3cret")) {
			t.Errorf("connection %v %v", cs, err)
		}
		events, err := tx.AuditLog(-1)
		if err != nil {
			return err
		}
		seen := map[string]bool{}
		for _, e := range events {
			if e.ActorType == store.ActorOperator {
				seen[e.Action] = true
			}
			if strings.Contains(string(e.Detail), code[1]) || strings.Contains(string(e.Detail), "s3cret") {
				t.Errorf("%s leaks a secret: %s", e.Action, e.Detail)
			}
		}
		for _, a := range []string{"tenant.created", "idp.connection.created", "recovery.invitation.created"} {
			if !seen[a] {
				t.Errorf("no %s event by the operator", a)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestAdminAddSAMLIdP: add-idp with protocol saml pins the IdP certificate,
// generates and seals an SP key, and prints what to register at the IdP.
func TestAdminAddSAMLIdP(t *testing.T) {
	t.Setenv("TESSERA_ENV", "dev")
	t.Setenv("TESSERA_NOW", "2026-10-08T09:30:00")
	t.Setenv("TESSERA_PUBLIC_URL", "http://localhost:5173")
	dir := t.TempDir()
	db := filepath.Join(dir, "t.db")
	st, err := store.OpenFresh(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Migrate(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	if _, err := adminRun(t, db, "create-tenant", "-slug", "acme", "-name", "Acme Corp"); err != nil {
		t.Fatal(err)
	}
	_, idpCert, err := samlsp.GenerateSPKey("an IdP", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	indented := "    " + strings.ReplaceAll(strings.TrimSpace(idpCert), "\n", "\n    ")
	samlYAML := "name: Corp SAML\nprotocol: saml\nprofile: generic_saml\nidp_entity_id: https://idp.corp.example/saml\n" +
		"idp_sso_url: https://idp.corp.example/saml/sso\nsubject_source: attribute:employeeID\nidp_signing_certs:\n  - |\n" + indented + "\n"
	out, err := adminRun(t, db, "add-idp", "-tenant", "acme", "-file", writeFile(t, dir, "saml.yaml", samlYAML))
	m := regexp.MustCompile(`added connection ([0-9a-f-]{36})`).FindStringSubmatch(out)
	if err != nil || m == nil || !strings.Contains(out, "http://localhost:5173/api/auth/saml/"+m[1]+"/metadata") ||
		!strings.Contains(out, "http://localhost:5173/api/auth/saml/"+m[1]+"/acs") {
		t.Fatalf("add-idp: %v %s", err, out)
	}
	for name, body := range map[string]string{
		"no pinned certificate": strings.Split(samlYAML, "idp_signing_certs:")[0],
		"bad certificate":       strings.Split(samlYAML, "idp_signing_certs:")[0] + "idp_signing_certs: [nope]\n",
		"email as subject":      strings.Replace(samlYAML, "attribute:employeeID", "email", 1),
		"oidc profile":          strings.Replace(samlYAML, "generic_saml", "okta", 1),
		"attested phr":          samlYAML + "assume_phishing_resistant: true\n",
		"no sso url":            strings.Replace(samlYAML, "idp_sso_url: https://idp.corp.example/saml/sso\n", "", 1),
	} {
		if out, err := adminRun(t, db, "add-idp", "-tenant", "acme", "-file", writeFile(t, dir, "bad.yaml", body)); err == nil {
			t.Errorf("%s: accepted: %s", name, out)
		}
	}
	st, err = store.Open(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var acme store.Tenant
	if err := st.ReadSystem(context.Background(), "test", func(s *store.SystemTx) error {
		acme, err = s.TenantBySlug("acme")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.ReadTenant(context.Background(), acme.ID, func(tx *store.TenantTx) error {
		cs, err := tx.IdPConnections()
		if err != nil || len(cs) != 1 {
			t.Fatalf("connections %v %v", cs, err)
		}
		c := cs[0]
		if c.Protocol != "saml" || *c.IdPEntityID != "https://idp.corp.example/saml" || len(c.SPKeyEnc) == 0 ||
			c.SPCertPEM == nil || c.SubjectSource != "attribute:employeeID" || bytes.Contains(c.SPKeyEnc, []byte("PRIVATE KEY")) {
			t.Errorf("connection %+v", c)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestAdminAddOAuth2IdP: add-idp with protocol oauth2 (github defaults its
// endpoints and the numeric id subject; generic_oauth2 needs them) seals the
// client secret and prints the OAuth 2.0 redirect URI.
func TestAdminAddOAuth2IdP(t *testing.T) {
	t.Setenv("TESSERA_ENV", "dev")
	t.Setenv("TESSERA_NOW", "2026-10-08T09:30:00")
	t.Setenv("TESSERA_PUBLIC_URL", "http://localhost:5173")
	dir := t.TempDir()
	db := filepath.Join(dir, "t.db")
	st, err := store.OpenFresh(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Migrate(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	if _, err := adminRun(t, db, "create-tenant", "-slug", "acme", "-name", "Acme Corp"); err != nil {
		t.Fatal(err)
	}
	secret := writeFile(t, dir, "secret", "gh-s3cret\n")
	github := "name: GitHub\nprotocol: oauth2\nprofile: github\nclient_id: Iv1.abc\n"
	out, err := adminRun(t, db, "add-idp", "-tenant", "acme", "-file", writeFile(t, dir, "gh.yaml", github), "-client-secret-file", secret)
	m := regexp.MustCompile(`added connection ([0-9a-f-]{36})`).FindStringSubmatch(out)
	if err != nil || m == nil || !strings.Contains(out, "http://localhost:5173/api/auth/oauth2/"+m[1]+"/callback") {
		t.Fatalf("add-idp: %v %s", err, out)
	}
	generic := "name: Corp OAuth\nprotocol: oauth2\nprofile: generic_oauth2\nclient_id: c\nsubject_field: uid\n" +
		"authorization_endpoint: https://sso.corp.example/oauth/authorize\ntoken_endpoint: https://sso.corp.example/oauth/token\n" +
		"userinfo_endpoint: https://sso.corp.example/api/me\n"
	if out, err := adminRun(t, db, "add-idp", "-tenant", "acme", "-file", writeFile(t, dir, "g.yaml", generic), "-client-secret-file", secret); err != nil {
		t.Fatalf("generic: %v %s", err, out)
	}
	for name, body := range map[string]string{
		"email as subject":       strings.Replace(generic, "subject_field: uid", "subject_field: email", 1),
		"login as subject":       github + "subject_field: login\n",
		"generic without fields": "name: X\nprotocol: oauth2\nprofile: generic_oauth2\nclient_id: c\n",
		"oidc profile":           strings.Replace(github, "profile: github", "profile: okta", 1),
		"attested phr":           github + "assume_phishing_resistant: true\n",
		"no client id":           strings.Replace(github, "client_id: Iv1.abc\n", "", 1),
		"issuer set":             github + "issuer: https://github.com\n",
	} {
		if out, err := adminRun(t, db, "add-idp", "-tenant", "acme", "-file", writeFile(t, dir, "bad.yaml", body), "-client-secret-file", secret); err == nil {
			t.Errorf("%s: accepted: %s", name, out)
		}
	}
	if _, err := adminRun(t, db, "add-idp", "-tenant", "acme", "-file", writeFile(t, dir, "gh2.yaml", strings.Replace(github, "GitHub", "GitHub 2", 1))); err == nil {
		t.Error("an OAuth 2.0 connection without a client secret was accepted")
	}
	st, err = store.Open(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var acme store.Tenant
	if err := st.ReadSystem(context.Background(), "test", func(s *store.SystemTx) error {
		acme, err = s.TenantBySlug("acme")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.ReadTenant(context.Background(), acme.ID, func(tx *store.TenantTx) error {
		cs, err := tx.IdPConnections()
		if err != nil || len(cs) != 2 {
			t.Fatalf("connections %v %v", cs, err)
		}
		gh := cs[0]
		if gh.Protocol != "oauth2" || *gh.TokenEndpoint != oauth2rp.GitHubTokenURL || *gh.UserinfoEndpoint != oauth2rp.GitHubUserURL ||
			gh.SubjectSource != "field:id" || string(gh.Scopes) != `["read:user","user:email"]` || len(gh.ClientSecretEnc) == 0 ||
			bytes.Contains(gh.ClientSecretEnc, []byte("gh-s3cret")) {
			t.Errorf("github connection %+v", gh)
		}
		if cs[1].SubjectSource != "field:uid" || *cs[1].UserinfoEndpoint != "https://sso.corp.example/api/me" {
			t.Errorf("generic connection %+v", cs[1])
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestAdminAddCASIdP: add-idp with protocol cas needs the server URL, keys
// users on cas:user or an attribute (never the email), and prints the
// service URL pattern to register.
func TestAdminAddCASIdP(t *testing.T) {
	t.Setenv("TESSERA_ENV", "dev")
	t.Setenv("TESSERA_NOW", "2026-10-08T09:30:00")
	t.Setenv("TESSERA_PUBLIC_URL", "http://localhost:5173")
	dir := t.TempDir()
	db := filepath.Join(dir, "t.db")
	st, err := store.OpenFresh(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Migrate(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	if _, err := adminRun(t, db, "create-tenant", "-slug", "uni", "-name", "A University"); err != nil {
		t.Fatal(err)
	}
	casYAML := "name: Campus CAS\nprotocol: cas\nprofile: generic_cas\ncas_server_url: https://cas.uni.example/cas/\n" +
		"authn_mapping: {amr_attribute: successfulAuthenticationHandlers, phr_amr: [[WebAuthnAuthenticationHandler]]}\n"
	out, err := adminRun(t, db, "add-idp", "-tenant", "uni", "-file", writeFile(t, dir, "cas.yaml", casYAML))
	m := regexp.MustCompile(`added connection ([0-9a-f-]{36})`).FindStringSubmatch(out)
	if err != nil || m == nil || !strings.Contains(out, "http://localhost:5173/api/auth/cas/"+m[1]+"/callback?state=*") {
		t.Fatalf("add-idp: %v %s", err, out)
	}
	for name, body := range map[string]string{
		"email subject":  casYAML + "subject_source: attribute:mail\n",
		"no server":      strings.Replace(casYAML, "cas_server_url: https://cas.uni.example/cas/\n", "", 1),
		"saml profile":   strings.Replace(casYAML, "generic_cas", "generic_saml", 1),
		"oidc settings":  casYAML + "client_id: x\n",
		"attested phr":   casYAML + "assume_phishing_resistant: true\n",
		"bad subject":    casYAML + "subject_source: nameid\n",
		"server w/query": strings.Replace(casYAML, "cas/\n", "cas?x=1\n", 1),
	} {
		if out, err := adminRun(t, db, "add-idp", "-tenant", "uni", "-file", writeFile(t, dir, "bad.yaml", body)); err == nil {
			t.Errorf("%s: accepted: %s", name, out)
		}
	}
	st, err = store.Open(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var uni store.Tenant
	if err := st.ReadSystem(context.Background(), "test", func(s *store.SystemTx) error {
		uni, err = s.TenantBySlug("uni")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.ReadTenant(context.Background(), uni.ID, func(tx *store.TenantTx) error {
		cs, err := tx.IdPConnections()
		if err != nil || len(cs) != 1 || cs[0].Protocol != "cas" || *cs[0].Issuer != "https://cas.uni.example/cas" ||
			cs[0].SubjectSource != "cas_user" || !strings.Contains(string(cs[0].AuthnMapping), "WebAuthnAuthenticationHandler") {
			t.Errorf("connections %+v %v", cs, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestAdminAddWSFedIdP: add-idp with protocol wsfed pins the token-signing
// certificate, refuses UPN or email subjects and prints the realm and reply
// URL for the ADFS relying party trust.
func TestAdminAddWSFedIdP(t *testing.T) {
	t.Setenv("TESSERA_ENV", "dev")
	t.Setenv("TESSERA_NOW", "2026-10-08T09:30:00")
	t.Setenv("TESSERA_PUBLIC_URL", "http://localhost:5173")
	dir := t.TempDir()
	db := filepath.Join(dir, "t.db")
	st, err := store.OpenFresh(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Migrate(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	if _, err := adminRun(t, db, "create-tenant", "-slug", "corp", "-name", "Corp"); err != nil {
		t.Fatal(err)
	}
	_, cert, err := samlsp.GenerateSPKey("adfs", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	indented := "    " + strings.ReplaceAll(strings.TrimSpace(cert), "\n", "\n    ")
	y := "name: ADFS\nprotocol: wsfed\nprofile: adfs\nidp_entity_id: http://adfs.corp.example/adfs/services/trust\n" +
		"wsfed_endpoint: https://adfs.corp.example/adfs/ls/\n" +
		"subject_source: attribute:http://schemas.microsoft.com/identity/claims/objectidentifier\nidp_signing_certs:\n  - |\n" + indented + "\n"
	out, err := adminRun(t, db, "add-idp", "-tenant", "corp", "-file", writeFile(t, dir, "adfs.yaml", y))
	m := regexp.MustCompile(`added connection ([0-9a-f-]{36})`).FindStringSubmatch(out)
	if err != nil || m == nil || !strings.Contains(out, "identifier (realm) http://localhost:5173/api/auth/wsfed/"+m[1]+"\n") ||
		!strings.Contains(out, "http://localhost:5173/api/auth/wsfed/"+m[1]+"/callback") {
		t.Fatalf("add-idp: %v %s", err, out)
	}
	for name, body := range map[string]string{
		"upn subject":   strings.Replace(y, "http://schemas.microsoft.com/identity/claims/objectidentifier", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn", 1),
		"email subject": strings.Replace(y, "http://schemas.microsoft.com/identity/claims/objectidentifier", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", 1),
		"no cert":       strings.Split(y, "idp_signing_certs:")[0],
		"no endpoint":   strings.Replace(y, "wsfed_endpoint: https://adfs.corp.example/adfs/ls/\n", "", 1),
		"saml profile":  strings.Replace(y, "profile: adfs", "profile: generic_saml", 1),
		"attested phr":  y + "assume_phishing_resistant: true\n",
	} {
		if out, err := adminRun(t, db, "add-idp", "-tenant", "corp", "-file", writeFile(t, dir, "bad.yaml", body)); err == nil {
			t.Errorf("%s: accepted: %s", name, out)
		}
	}
}
