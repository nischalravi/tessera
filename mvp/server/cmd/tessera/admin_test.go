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
