package seed

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/samlsp"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// User is a bootstrap platform user of a demo tenant. They mirror the dev
// IdP's users.yaml (internal/devidp; TestSeedUsersMatchDevIdP keeps the two
// in step): the same subjects, so a sign-in through the dev IdP (PR6) or the
// dev sign-in shim (PR5) resolves to them through the (connection, subject)
// link, never by email.
type User struct {
	Subject string
	Email   string
	Name    string
	Roles   []string
}

// Bootstrap users of the demo tenants (design §18.5): Alice and Ivan are
// tenant admins, Pat a policy admin, Olu an operator, Vic a viewer; Gina is
// Globex's admin. Admin roles are granted with source "bootstrap", the only
// way an admin role exists without a two-person change request.
var (
	LarkspurUsers = []User{
		{"00u-alice-admin", "alice.admin@larkspur.example", "Alice (tenant admin)", []string{store.RoleTenantAdmin}},
		{"00u-ivan-admin2", "ivan.admin@larkspur.example", "Ivan (2nd admin)", []string{store.RoleTenantAdmin}},
		{"00u-pat-policy", "pat.policy@larkspur.example", "Pat (policy admin)", []string{store.RolePolicyAdmin}},
		{"00u-olu-operator", "olu@larkspur.example", "Olu (operator)", []string{store.RoleOperator}},
		{"00u-vic-viewer", "vic@larkspur.example", "Vic (viewer)", []string{store.RoleViewer}},
	}
	GlobexUsers = []User{
		{"00u-gina-globex", "gina@globex.example", "Gina (Globex admin)", []string{store.RoleTenantAdmin}},
	}
)

// DevClientID is the dev IdP's registered client (internal/devidp).
const DevClientID = "tessera-dev"

// WithDevIdP returns tenants with a dev_mock OIDC connection to the dev IdP
// at issuer and their bootstrap users (dev and test only: cmd/tessera never
// calls it with TESSERA_ENV=prod, and prod refuses to start with a dev_mock
// connection, §18.4).
func WithDevIdP(tenants []Tenant, issuer string) []Tenant {
	out := make([]Tenant, len(tenants))
	for i, t := range tenants {
		t.DevIdP = issuer
		switch t.ID {
		case LarkspurID:
			t.Users = LarkspurUsers
		case GlobexID:
			t.Users = GlobexUsers
		}
		out[i] = t
	}
	return out
}

// DevIdPClient is the dev IdP connection's client secret, sealed into
// client_secret_enc (dev and test only). SAMLCert, when set, is the dev
// IdP's SAML signing certificate (PEM, tessera-devidp -print-saml-cert):
// a dev_mock SAML connection pinning it is seeded too, with an SP key
// sealed by Sealer.
type DevIdPClient struct {
	Sealer   *seal.Sealer
	Secret   string
	SAMLCert string
	// GitHub seeds a dev_mock OAuth 2.0 connection to the dev IdP's
	// GitHub emulation (no ID token; AAL1 sign-ins), with the same secret.
	GitHub bool
}

// DevGitHubID is the dev IdP's GitHub-style numeric id for a subject
// (devidp.GitHubID; seed must not import the dev IdP).
func DevGitHubID(sub string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(sub))
	return strconv.FormatInt(1_000_000+int64(h.Sum32()%9_000_000), 10)
}

// devGitHubConnection is the dev_mock OAuth 2.0 connection to the dev IdP's
// GitHub emulation at issuer.
func devGitHubConnection(t tenancy.ID, issuer string, dc *DevIdPClient, domains json.RawMessage, now time.Time) (*store.IdPConnection, error) {
	authz, token, user := issuer+"/github/login/oauth/authorize", issuer+"/github/login/oauth/access_token", issuer+"/github/user"
	clientID := DevClientID
	c := &store.IdPConnection{ID: uuid.New(), Name: "Dev IdP (GitHub OAuth)", Protocol: "oauth2", Profile: store.ProfileDevMock,
		Status: "active", VerifiedDomains: domains, ClientID: &clientID, AuthorizationEndpoint: &authz, TokenEndpoint: &token,
		UserinfoEndpoint: &user, Scopes: json.RawMessage(`["read:user","user:email"]`), SubjectSource: "field:id",
		AuthnMapping: json.RawMessage(`{"dev_emulation":"github"}`), PinCerts: true, JITProvisioning: false,
		DefaultRole: store.RoleViewer, CreatedAt: now, UpdatedAt: now}
	var err error
	c.ClientSecretEnc, err = dc.Sealer.Seal([]byte(dc.Secret), auth.ClientSecretAAD(t, c.ID))
	return c, err
}

// The dev IdP's SAML class refs (internal/devidp; seed must not import it).
const (
	devSAMLClassPhrh = "urn:devidp:ac:phrh"
	devSAMLClassPhr  = "urn:devidp:ac:phr"
	devSAMLClassMFA  = "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract"
)

// devSAMLConnection is the dev_mock SAML connection to the dev IdP at
// issuer: Tessera requests the dev IdP's phr/phrh/MFA class refs and trusts
// them only when requested (normalize rule 2). A phr request also accepts
// phrh (Comparison=exact admits any listed ref).
func devSAMLConnection(t tenancy.ID, issuer string, dc *DevIdPClient, domains json.RawMessage, now time.Time) (*store.IdPConnection, error) {
	entity, sso := issuer+"/saml/metadata", issuer+"/saml/sso"
	certs, err := json.Marshal([]string{dc.SAMLCert})
	if err != nil {
		return nil, err
	}
	stepUp, err := json.Marshal(map[string]any{
		string(auth.ACRPhrh): map[string][]string{"authn_context_class_refs": {devSAMLClassPhrh}},
		string(auth.ACRPhr):  map[string][]string{"authn_context_class_refs": {devSAMLClassPhr, devSAMLClassPhrh}},
		string(auth.ACRAAL2): map[string][]string{"authn_context_class_refs": {devSAMLClassMFA}}})
	if err != nil {
		return nil, err
	}
	mapping, err := json.Marshal(map[string]any{"dev_emulation": "saml",
		"phr_authn_context_class_refs":  []string{devSAMLClassPhr},
		"phrh_authn_context_class_refs": []string{devSAMLClassPhrh},
		"aal2_authn_context_class_refs": []string{devSAMLClassMFA, devSAMLClassPhr, devSAMLClassPhrh}})
	if err != nil {
		return nil, err
	}
	c := &store.IdPConnection{ID: uuid.New(), Name: "Dev IdP (SAML)", Protocol: "saml", Profile: store.ProfileDevMock,
		Status: "active", VerifiedDomains: domains, IdPEntityID: &entity, IdPSSOURL: &sso, IdPSigningCerts: certs,
		PinCerts: true, StepUpRequest: stepUp, AuthnMapping: mapping, JITProvisioning: false, DefaultRole: store.RoleViewer,
		CreatedAt: now, UpdatedAt: now}
	keyPEM, certPEM, err := samlsp.GenerateSPKey("Tessera SP "+c.ID.String(), now)
	if err != nil {
		return nil, err
	}
	if c.SPKeyEnc, err = dc.Sealer.Seal(keyPEM, auth.SPKeyAAD(t, c.ID)); err != nil {
		return nil, err
	}
	c.SPCertPEM = &certPEM
	return c, nil
}

// WithDevIdPClient is WithDevIdP with the client secret the dev IdP expects,
// so browser sign-in through it (PR6) works.
func WithDevIdPClient(tenants []Tenant, issuer string, client DevIdPClient) []Tenant {
	out := WithDevIdP(tenants, issuer)
	for i := range out {
		c := client
		out[i].DevIdPClient = &c
	}
	return out
}

// seedAuth creates the tenant's dev_mock connection and bootstrap users.
// It writes no audit event, so the ledger of a fresh seed is unchanged.
func seedAuth(c *store.TenantTx, t Tenant, now time.Time) error {
	if t.DevIdP == "" || len(t.Users) == 0 {
		return nil
	}
	issuer, clientID, method := t.DevIdP, DevClientID, "client_secret_basic"
	domains, err := json.Marshal([]string{t.Slug + ".example"})
	if err != nil {
		return err
	}
	conn := &store.IdPConnection{ID: uuid.New(), Name: "Dev IdP (OIDC)", Protocol: "oidc", Profile: store.ProfileDevMock,
		Status: "active", IsDefault: true, VerifiedDomains: domains, Issuer: &issuer, ClientID: &clientID,
		ClientAuthMethod: &method, PinCerts: true, JITProvisioning: false, DefaultRole: store.RoleViewer,
		CreatedAt: now, UpdatedAt: now}
	if dc := t.DevIdPClient; dc != nil && dc.Sealer != nil && dc.Secret != "" {
		if conn.ClientSecretEnc, err = dc.Sealer.Seal([]byte(dc.Secret), auth.ClientSecretAAD(c.Tenant(), conn.ID)); err != nil {
			return err
		}
	}
	if err := c.InsertIdPConnection(conn); err != nil {
		return fmt.Errorf("seed: dev IdP connection: %w", err)
	}
	conns := []*store.IdPConnection{conn}
	if dc := t.DevIdPClient; dc != nil && dc.Sealer != nil && dc.SAMLCert != "" {
		sc, err := devSAMLConnection(c.Tenant(), issuer, dc, domains, now)
		if err != nil {
			return fmt.Errorf("seed: dev IdP SAML connection: %w", err)
		}
		if err := c.InsertIdPConnection(sc); err != nil {
			return fmt.Errorf("seed: dev IdP SAML connection: %w", err)
		}
		conns = append(conns, sc)
	}
	if dc := t.DevIdPClient; dc != nil && dc.Sealer != nil && dc.Secret != "" && dc.GitHub {
		gc, err := devGitHubConnection(c.Tenant(), issuer, dc, domains, now)
		if err == nil {
			err = c.InsertIdPConnection(gc)
		}
		if err != nil {
			return fmt.Errorf("seed: dev IdP GitHub connection: %w", err)
		}
		conns = append(conns, gc)
	}
	for _, u := range t.Users {
		email := u.Email
		pu := &store.PlatformUser{Email: &email, DisplayName: u.Name, CreatedAt: now}
		if err := c.InsertPlatformUser(pu); err != nil {
			return err
		}
		for _, cn := range conns {
			iss, sub := issuer, u.Subject
			switch cn.Protocol {
			case "saml":
				iss = *cn.IdPEntityID
			case "oauth2":
				iss, sub = issuer, DevGitHubID(u.Subject)
			}
			if err := c.InsertExternalLogin(&store.ExternalLogin{UserID: pu.ID, IdPConnectionID: cn.ID, Issuer: iss,
				Subject: sub, CreatedAt: now}); err != nil {
				return err
			}
		}
		for _, r := range u.Roles {
			if err := c.InsertRoleAssignment(&store.RoleAssignment{UserID: pu.ID, Role: r,
				Source: store.RoleSourceBootstrap, CreatedAt: now}); err != nil {
				return fmt.Errorf("seed: role %s for %s: %w", r, u.Subject, err)
			}
		}
	}
	return nil
}
