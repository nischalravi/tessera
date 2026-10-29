package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/mail"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.yaml.in/yaml/v3"

	"github.com/nischalravi/tessera/mvp/server/internal/admin"
	"github.com/nischalravi/tessera/mvp/server/internal/api"
	"github.com/nischalravi/tessera/mvp/server/internal/audit"
	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/auth/samlsp"
	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/policygroups"
	"github.com/nischalravi/tessera/mvp/server/internal/keys"
	"github.com/nischalravi/tessera/mvp/server/internal/oauth"
	"github.com/nischalravi/tessera/mvp/server/internal/oauth/dpop"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/seal"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/tenancy"
)

// Operator bootstrap and recovery (design §15.3, §15.5, §18.2):
//
//	tessera admin create-tenant -slug acme -name "Acme Corp"
//	tessera admin add-idp       -tenant acme -file okta.yaml [-client-secret-file path]
//	tessera admin invite-admin  -tenant acme -connection <id> -email jane@acme.com [-ttl 24h]
//	tessera admin recover-tenant -tenant acme -operator <id> -co-operator <id> -ticket <ref> ...
//	tessera admin revoke-signing-key -tenant acme -kid <kid> -reason "..."
//	tessera admin add-client    -tenant acme -name "ETL" -owner jane@acme.com -jwks-file pub.jwks -scope "tessera:read" -roles viewer
//	tessera admin list-overprivileged-clients -tenant acme
//	tessera admin check-group-policies -tenant acme
//
// Every command runs as the operator (the OS user) and is audited in the
// tenant's chain. invite-admin and recover-tenant print a one-time URL; only
// its hash is kept.
const adminUsage = `usage:
  tessera admin create-tenant -slug slug -name "Display name" [-db path]
  tessera admin add-idp       -tenant slug -file connection.yaml [-client-secret-file path] [-db path]
  tessera admin invite-admin  -tenant slug -connection id -email address [-ttl 24h] [-db path]
  tessera admin recover-tenant -tenant slug -operator id -co-operator id -ticket ref -connection id -email address
                              -operator-phr -co-operator-phr [-db path]
  tessera admin revoke-signing-key -tenant slug -kid kid -reason text [-db path]
  tessera admin gen-rls       [-out path] [-check]   (Postgres row-level security; needs no database)
  tessera admin wrap-kek      -kms aws:arn:…|azure:https://<vault>/keys/<k>/<v>|gcp:projects/… [-generate]   (KEK on stdin; prints TESSERA_KEK_WRAPPED)
  tessera admin add-client    -tenant slug -name "Display name" -owner user-id-or-email -jwks-file public.jwks
                              -scope "tessera:read ..." -roles viewer,operator,auditor [-dpop=false] [-db path]
  tessera admin list-overprivileged-clients -tenant slug [-db path]
                              (machine clients whose permissions exceed their approver's: they get no token; issue #522)
  tessera admin check-group-policies -tenant slug [-db path]
                              (stored policy group files the Cedar-aligned fragment now refuses; issue #698; exits 1 on any finding)
  (-db is a SQLite path or a postgres:// DSN)`

// maxInviteTTL is the longest a bootstrap invitation may live (§15.3).
const maxInviteTTL = 24 * time.Hour

type adminEnv struct {
	ctx    context.Context
	db     *store.DB
	cfg    *config.Config
	sealer *seal.Sealer
	now    time.Time
	stdout io.Writer
}

func adminCmd(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New(adminUsage)
	}
	sub, args := args[0], args[1:]
	if sub == "gen-rls" {
		return genRLS(args, stdout, stderr)
	}
	if sub == "wrap-kek" {
		return wrapKEKCmd(ctx, args, stdin, stdout, stderr)
	}
	fset := flag.NewFlagSet("tessera admin "+sub, flag.ContinueOnError)
	fset.SetOutput(stderr)
	dbFlag := fset.String("db", dbPath(os.Getenv("TESSERA_DB")), "SQLite database path or postgres:// DSN")
	var run func(e *adminEnv) error
	switch sub {
	case "create-tenant":
		slug := fset.String("slug", "", "tenant slug (^[a-z0-9][a-z0-9-]{2,39}$)")
		name := fset.String("name", "", "display name")
		run = func(e *adminEnv) error { return createTenant(e, *slug, *name) }
	case "add-idp":
		tenant := fset.String("tenant", "", "tenant slug")
		file := fset.String("file", "", "connection YAML (§18.2)")
		secretFile := fset.String("client-secret-file", "", "file holding the client secret (client_secret_basic)")
		run = func(e *adminEnv) error { return addIdP(e, *tenant, *file, *secretFile) }
	case "invite-admin":
		tenant := fset.String("tenant", "", "tenant slug")
		conn := fset.String("connection", "", "IdP connection id the admin signs in through")
		email := fset.String("email", "", "the invited admin's email at that IdP")
		ttl := fset.Duration("ttl", maxInviteTTL, "how long the invitation is valid (at most 24h)")
		run = func(e *adminEnv) error { return inviteAdmin(e, *tenant, *conn, *email, *ttl) }
	case "recover-tenant":
		in := recoverFlags{}
		fset.StringVar(&in.tenant, "tenant", "", "tenant slug")
		fset.StringVar(&in.operator, "operator", "", "id of the first Tessera operator")
		fset.StringVar(&in.coOperator, "co-operator", "", "id of the second, different operator")
		fset.StringVar(&in.ticket, "ticket", "", "the support ticket recording the two contacts' confirmation (§15.5 step 1)")
		fset.StringVar(&in.connection, "connection", "", "IdP connection id the new admin signs in through")
		fset.StringVar(&in.email, "email", "", "the new admin's email at that IdP")
		fset.BoolVar(&in.operatorPhr, "operator-phr", false, "the first operator signed in to this hardened host with a hardware key")
		fset.BoolVar(&in.coOperatorPhr, "co-operator-phr", false, "the second operator signed in to this hardened host with a hardware key")
		run = func(e *adminEnv) error { return recoverTenant(e, in) }
	case "revoke-signing-key":
		tenant := fset.String("tenant", "", "tenant slug")
		kid := fset.String("kid", "", "key id (from the tenant's JWKS)")
		reason := fset.String("reason", "", "why the key is revoked (audited)")
		run = func(e *adminEnv) error { return revokeSigningKey(e, *tenant, *kid, *reason) }
	case "add-client":
		tenant := fset.String("tenant", "", "tenant slug")
		name := fset.String("name", "", "display name of the machine client")
		owner := fset.String("owner", "", "the accountable owner: the id or email of an active user of the tenant")
		jwksFile := fset.String("jwks-file", "", "file holding the client's PUBLIC keys as a JWKS (EC P-256 or Ed25519, each with a kid)")
		scope := fset.String("scope", "", "scopes the client may be granted (space or comma separated)")
		roles := fset.String("roles", "", "roles the client acts with: viewer, operator, auditor (comma separated)")
		dpopFlag := fset.Bool("dpop", true, "require DPoP-bound tokens; -dpop=false lets the client use Bearer tokens")
		run = func(e *adminEnv) error {
			return addClient(e, addClientArgs{tenant: *tenant, name: *name, owner: *owner, jwksFile: *jwksFile, scope: *scope,
				roles: *roles, dpop: *dpopFlag})
		}
	case "list-overprivileged-clients":
		tenant := fset.String("tenant", "", "tenant slug")
		run = func(e *adminEnv) error { return listOverprivilegedClients(e, *tenant) }
	case "check-group-policies":
		tenant := fset.String("tenant", "", "tenant slug")
		run = func(e *adminEnv) error { return checkGroupPolicies(e, *tenant) }
	default:
		return fmt.Errorf("unknown admin command %q\n%s", sub, adminUsage)
	}
	if err := fset.Parse(args); err != nil {
		return err
	}
	if os.Getenv("TESSERA_ENV") == "" {
		return errors.New("set TESSERA_ENV=dev, test or prod")
	}
	cfg, err := config.Load(envWithDB(*dbFlag))
	if err != nil {
		return err
	}
	sealer, err := loadSealer(ctx, cfg, config.DevKEKPath(*dbFlag))
	if err != nil {
		return err
	}
	db, err := store.Open(ctx, *dbFlag)
	if err != nil {
		return err
	}
	defer db.Close()
	ctx = audit.WithOperatorActor(ctx, operatorName())
	return run(&adminEnv{ctx: ctx, db: db, cfg: cfg, sealer: sealer, now: cfg.Clock()().UTC(), stdout: stdout})
}

func createTenant(e *adminEnv, slug, name string) error {
	if !store.ValidSlug(slug) || slug == store.PlatformSlug {
		return fmt.Errorf("create-tenant: -slug %q must match ^[a-z0-9][a-z0-9-]{2,39}$", slug)
	}
	if strings.TrimSpace(name) == "" || len(name) > 200 {
		return errors.New("create-tenant: -name is required (at most 200 characters)")
	}
	var t store.Tenant
	if err := e.db.InSystem(e.ctx, "admin create-tenant "+slug, func(s *store.SystemTx) error {
		var err error
		t, err = s.CreateTenant(store.Tenant{Slug: slug, Name: strings.TrimSpace(name), CreatedAt: e.now})
		return err
	}); err != nil {
		return fmt.Errorf("create-tenant: %w", err)
	}
	if err := e.db.InTenant(e.ctx, t.ID, func(tx *store.TenantTx) error {
		_, err := audit.Record(e.ctx, tx, "tenant.created", ojson.Object{{Key: "slug", Value: t.Slug}, {Key: "name", Value: t.Name}},
			audit.At(e.now), audit.Target("tenant", t.ID.String()))
		return err
	}); err != nil {
		return err
	}
	fmt.Fprintf(e.stdout, "created tenant %s (%s)\nnext: tessera admin add-idp -tenant %s -file <connection.yaml>\n", t.Slug, t.ID, t.Slug)
	return nil
}

// idpFile is a connection file (§18.2). Unknown keys are refused, so a typo
// cannot silently weaken a setting. Secrets never live in it. The fields
// are admin.IdPConfig's, which also validates them (the admin-change
// workflow creates connections from the same shape).
type idpFile struct {
	Name             string            `yaml:"name"`
	Protocol         string            `yaml:"protocol"`
	Profile          string            `yaml:"profile"`
	Issuer           string            `yaml:"issuer"`
	ClientID         string            `yaml:"client_id"`
	ClientAuthMethod string            `yaml:"client_auth_method"`
	Scopes           []string          `yaml:"scopes"`
	IDTokenAlgs      []string          `yaml:"id_token_algs"`
	VerifiedDomains  []string          `yaml:"verified_domains"`
	GroupsClaim      string            `yaml:"groups_claim"`
	GroupRoleMapping map[string]string `yaml:"group_role_mapping"`
	JITProvisioning  *bool             `yaml:"jit_provisioning"`
	DefaultRole      string            `yaml:"default_role"`
	Default          bool              `yaml:"default"`
	EntraTenantID    string            `yaml:"entra_tenant_id"`
	StepUpRequest    map[string]any    `yaml:"step_up_request"`
	AuthnMapping     map[string]any    `yaml:"authn_mapping"`
	// SAML (protocol: saml)
	IdPEntityID     string            `yaml:"idp_entity_id"`
	IdPSSOURL       string            `yaml:"idp_sso_url"`
	IdPSigningCerts []string          `yaml:"idp_signing_certs"` // PEM or base64 DER; pinned
	SubjectSource   string            `yaml:"subject_source"`    // nameid_persistent (default) | attribute:<name>
	AttributeMap    map[string]string `yaml:"attribute_map"`     // email, name, groups -> attribute names
	AssumePhr       bool              `yaml:"assume_phishing_resistant"`
	// OAuth 2.0-only providers (protocol: oauth2)
	AuthorizationEndpoint string `yaml:"authorization_endpoint"`
	TokenEndpoint         string `yaml:"token_endpoint"`
	UserinfoEndpoint      string `yaml:"userinfo_endpoint"`
	SubjectField          string `yaml:"subject_field"` // the user object's immutable id field ("id" for github)
	// CAS 3.0 (protocol: cas)
	CASServerURL string `yaml:"cas_server_url"`
	// WS-Federation (protocol: wsfed): idp_entity_id is the token issuer,
	// idp_signing_certs the pinned token-signing certificates
	WSFedEndpoint string `yaml:"wsfed_endpoint"` // the passive endpoint, e.g. https://adfs.corp.example/adfs/ls/
}

func readIdPFile(path string) (*idpFile, error) {
	b, err := os.ReadFile(path) // #nosec G304 G703 -- a path the operator passes to their own CLI
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var f idpFile
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &f, nil
}

// connection checks a connection file and returns the store row it
// describes, active (the operator creates connections at bootstrap).
// assume_phishing_resistant is refused here: it needs a two-person admin
// change (§15.2).
func (f *idpFile) connection(prod bool, now time.Time) (*store.IdPConnection, error) {
	cfg := admin.IdPConfig{Name: f.Name, Protocol: f.Protocol, Profile: f.Profile, Issuer: f.Issuer, ClientID: f.ClientID,
		ClientAuthMethod: f.ClientAuthMethod, Scopes: f.Scopes, IDTokenAlgs: f.IDTokenAlgs, VerifiedDomains: f.VerifiedDomains,
		GroupsClaim: f.GroupsClaim, GroupRoleMapping: f.GroupRoleMapping, JITProvisioning: f.JITProvisioning,
		DefaultRole: f.DefaultRole, Default: f.Default, EntraTenantID: f.EntraTenantID, StepUpRequest: f.StepUpRequest,
		AuthnMapping: f.AuthnMapping, IdPEntityID: f.IdPEntityID, IdPSSOURL: f.IdPSSOURL, IdPSigningCerts: f.IdPSigningCerts,
		SubjectSource: f.SubjectSource, AttributeMap: f.AttributeMap, AssumePhr: f.AssumePhr,
		AuthorizationEndpoint: f.AuthorizationEndpoint, TokenEndpoint: f.TokenEndpoint, UserinfoEndpoint: f.UserinfoEndpoint,
		SubjectField: f.SubjectField, CASServerURL: f.CASServerURL,
		WSFedEndpoint: f.WSFedEndpoint}
	c, err := cfg.Connection(admin.IdPOptions{Prod: prod}, now)
	if err != nil {
		return nil, err
	}
	c.Status = "active"
	return c, nil
}

func lookupTenant(e *adminEnv, slug string) (store.Tenant, error) {
	var t store.Tenant
	err := e.db.ReadSystem(e.ctx, "admin tenant", func(s *store.SystemTx) error {
		var err error
		t, err = s.TenantBySlug(slug)
		return err
	})
	if errors.Is(err, store.ErrNotFound) || (err == nil && t.ID == tenancy.Platform) {
		return t, fmt.Errorf("no tenant %q", slug)
	}
	return t, err
}

func addIdP(e *adminEnv, slug, file, secretFile string) error {
	if file == "" {
		return errors.New("add-idp: -file is required")
	}
	t, err := lookupTenant(e, slug)
	if err != nil {
		return err
	}
	f, err := readIdPFile(file)
	if err != nil {
		return err
	}
	c, err := f.connection(e.cfg.IsProd(), e.now)
	if err != nil {
		return fmt.Errorf("add-idp: %w", err)
	}
	if err := sealConnectionSecrets(e, t.ID, c, secretFile); err != nil {
		return err
	}
	if err := e.db.InTenant(e.ctx, t.ID, func(tx *store.TenantTx) error {
		if err := tx.InsertIdPConnection(c); err != nil {
			return err
		}
		_, err := audit.Record(e.ctx, tx, "idp.connection.created", ojson.Object{{Key: "connection_id", Value: c.ID.String()},
			{Key: "name", Value: c.Name}, {Key: "protocol", Value: c.Protocol}, {Key: "profile", Value: c.Profile},
			{Key: "issuer", Value: firstOf(c.Issuer, c.IdPEntityID, c.UserinfoEndpoint)},
			{Key: "jit_provisioning", Value: c.JITProvisioning}, {Key: "default_role", Value: c.DefaultRole}},
			audit.At(e.now), audit.Target("idp_connection", c.ID.String()))
		return err
	}); err != nil {
		return fmt.Errorf("add-idp: %w", err)
	}
	fmt.Fprintf(e.stdout, "added connection %s (%s) to %s\n", c.ID, c.Name, t.Slug)
	if c.Protocol == "saml" {
		fmt.Fprintf(e.stdout, "register at the IdP: SP entity ID (audience) and metadata %s\nACS URL (HTTP-POST) %s\n",
			api.SPEntityID(e.cfg.PublicURL, c.ID), api.ACSURL(e.cfg.PublicURL, c.ID))
		return nil
	}
	path := "oidc"
	switch c.Protocol {
	case "oauth2":
		path = "oauth2"
	case "wsfed":
		fmt.Fprintf(e.stdout, "register a relying party trust: identifier (realm) %s\nWS-Federation passive endpoint (reply) %s\n",
			api.WSFedRealm(e.cfg.PublicURL, c.ID), api.WSFedReply(e.cfg.PublicURL, c.ID))
		return nil
	case "cas":
		fmt.Fprintf(e.stdout, "register this service URL pattern at the CAS server: %s/api/auth/cas/%s/callback?state=*\n",
			strings.TrimRight(e.cfg.PublicURL, "/"), c.ID)
		return nil
	}
	fmt.Fprintf(e.stdout, "redirect URI to register at the IdP: %s/api/auth/%s/%s/callback\n",
		strings.TrimRight(e.cfg.PublicURL, "/"), path, c.ID)
	return nil
}

// sealConnectionSecrets seals an OIDC client secret (from secretFile), or
// generates and seals a SAML connection's SP signing key.
func sealConnectionSecrets(e *adminEnv, t tenancy.ID, c *store.IdPConnection, secretFile string) error {
	if c.Protocol == "cas" || c.Protocol == "wsfed" {
		return nil // no client secret: CAS tickets are validated at the server, WS-Federation tokens are signed
	}
	if c.Protocol == "saml" {
		keyPEM, certPEM, err := samlsp.GenerateSPKey("Tessera SP "+c.ID.String(), e.now)
		if err != nil {
			return err
		}
		if c.SPKeyEnc, err = e.sealer.Seal(keyPEM, auth.SPKeyAAD(t, c.ID)); err != nil {
			return err
		}
		c.SPCertPEM = &certPEM
		return nil
	}
	if secretFile == "" {
		return errors.New("add-idp: -client-secret-file is required for client_secret_basic")
	}
	secret, err := os.ReadFile(secretFile) // #nosec G304 G703 -- a path the operator passes to their own CLI
	if err != nil {
		return err
	}
	secret = bytes.TrimSpace(secret)
	if len(secret) == 0 {
		return errors.New("add-idp: the client secret file is empty")
	}
	c.ClientSecretEnc, err = e.sealer.Seal(secret, auth.ClientSecretAAD(t, c.ID))
	return err
}

// firstOf is the first non-nil value.
func firstOf(vs ...*string) string {
	for _, v := range vs {
		if v != nil {
			return *v
		}
	}
	return ""
}

func inviteAdmin(e *adminEnv, slug, connID, email string, ttl time.Duration) error {
	t, err := lookupTenant(e, slug)
	if err != nil {
		return err
	}
	id, err := uuid.Parse(connID)
	if err != nil {
		return fmt.Errorf("invite-admin: -connection %q is not a connection id", connID)
	}
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email {
		return fmt.Errorf("invite-admin: -email %q is not an address", email)
	}
	if ttl <= 0 || ttl > maxInviteTTL {
		return fmt.Errorf("invite-admin: -ttl must be between 0 and %s", maxInviteTTL)
	}
	code := "tbi_" + seal.RandomSecret(32)
	inv := &store.BootstrapInvitation{CodeHash: seal.SHA256Hex([]byte(code)), IdPConnectionID: id, Email: email,
		CreatedBy: operatorName(), CreatedAt: e.now, ExpiresAt: e.now.Add(ttl)}
	if err := e.db.InTenant(e.ctx, t.ID, func(tx *store.TenantTx) error {
		c, err := tx.IdPConnection(id)
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("no connection %s in %s", id, slug)
		} else if err != nil {
			return err
		}
		if c.Status != "active" || (c.Protocol != "oidc" && c.Protocol != "saml" && c.Protocol != "cas" && c.Protocol != "wsfed") {
			return fmt.Errorf("connection %s is not an active OIDC or SAML connection", id)
		}
		if err := tx.InsertBootstrapInvitation(inv); err != nil {
			return err
		}
		_, err = audit.Record(e.ctx, tx, "recovery.invitation.created", ojson.Object{{Key: "invitation_id", Value: inv.ID.String()},
			{Key: "connection_id", Value: id.String()}, {Key: "email", Value: email},
			{Key: "expires_at", Value: inv.ExpiresAt.Format(time.RFC3339)}},
			audit.At(e.now), audit.Target("bootstrap_invitation", inv.ID.String()))
		return err
	}); err != nil {
		return fmt.Errorf("invite-admin: %w", err)
	}
	fmt.Fprintf(e.stdout, "one-time bootstrap URL for %s (valid until %s; send it out of band):\n%s/t/%s/bootstrap?code=%s\n",
		email, inv.ExpiresAt.Format(time.RFC3339), strings.TrimRight(e.cfg.PublicURL, "/"), t.Slug, url.QueryEscape(code))
	return nil
}

// recoverFlags are the arguments of recover-tenant.
type recoverFlags struct {
	tenant, operator, coOperator, ticket, connection, email string
	operatorPhr, coOperatorPhr                              bool
}

// recoverTenant is operator-assisted recovery (design §15.5): two different
// operators, each attested phishing-resistant, move the tenant to status
// recovery and create an invitation that works 72 hours later. Everything
// is audited in the tenant's chain and the platform chain, and every admin
// and security contact is notified at once.
func recoverTenant(e *adminEnv, in recoverFlags) error {
	t, err := lookupTenant(e, in.tenant)
	if err != nil {
		return err
	}
	conn, err := uuid.Parse(in.connection)
	if err != nil {
		return fmt.Errorf("recover-tenant: -connection %q is not a connection id", in.connection)
	}
	svc := &admin.Service{DB: e.db, Clock: func() time.Time { return e.now }, Sealer: e.sealer, Prod: e.cfg.IsProd(), PolicyMaxSteps: e.cfg.PolicyMaxSteps}
	res, err := svc.RequestRecovery(e.ctx, admin.RecoveryRequest{Tenant: t.ID,
		Operator:   admin.Operator{ID: in.operator, PhishingResistant: in.operatorPhr},
		CoOperator: admin.Operator{ID: in.coOperator, PhishingResistant: in.coOperatorPhr},
		Ticket:     in.ticket, ConnectionID: conn, Email: in.email})
	if err != nil {
		return fmt.Errorf("recover-tenant: %w", err)
	}
	fmt.Fprintf(e.stdout, "recovery %s requested for %s (ticket %s). All admins and security contacts were notified; "+
		"any existing admin can cancel it.\none-time recovery URL for %s, usable from %s (phishing-resistant sign-in required; send it out of band):\n"+
		"%s/t/%s/bootstrap?code=%s\n", res.Recovery.ID, t.Slug, res.Recovery.Ticket, in.email,
		res.Recovery.NotBefore.Format(time.RFC3339), strings.TrimRight(e.cfg.PublicURL, "/"), t.Slug, url.QueryEscape(res.Code))
	return nil
}

// revokeSigningKey revokes one of a tenant's signing keys (design §10.6: a
// leaked key is revoked at once and dropped from the JWKS), restoring the
// steady state if it was the active key.
func revokeSigningKey(e *adminEnv, slug, kid, reason string) error {
	t, err := lookupTenant(e, slug)
	if err != nil {
		return err
	}
	kid, reason = strings.TrimSpace(kid), strings.TrimSpace(reason)
	if kid == "" || len(kid) > 200 {
		return errors.New("revoke-signing-key: -kid is required")
	}
	if len(reason) < 3 || len(reason) > 500 {
		return errors.New("revoke-signing-key: -reason is required (3 to 500 characters)")
	}
	if err := e.db.InTenant(e.ctx, t.ID, func(tx *store.TenantTx) error {
		if err := keys.RevokeKey(tx, t.Slug, kid, e.sealer, e.now); errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("no active, next or retired signing key %q in %s", kid, slug)
		} else if err != nil {
			return err
		}
		_, err := audit.Record(e.ctx, tx, "keys.signing_key.revoked", ojson.Object{{Key: "kid", Value: kid},
			{Key: "reason", Value: reason}}, audit.At(e.now), audit.Target("signing_key", kid))
		return err
	}); err != nil {
		return fmt.Errorf("revoke-signing-key: %w", err)
	}
	fmt.Fprintf(e.stdout, "revoked signing key %s of %s; a new key is active and the JWKS no longer lists it\n", kid, t.Slug)
	return nil
}

// machineRoles are the roles a machine client may be given: never an admin
// role, and approvals and policy changes stay human-only (§9.5).
var machineRoles = []string{string(auth.RoleViewer), string(auth.RoleOperator), string(auth.RoleAuditor)}

type addClientArgs struct {
	tenant, name, owner, jwksFile, scope, roles string
	dpop                                        bool
}

// addClient registers a machine client (§9.5, §19 PR11). Until the change
// request workflow of PR12, this operator command is the way to create one. It
// takes only PUBLIC keys: the client keeps its private key, so there is no
// secret to print or store. Nothing here can grant an admin role.
func addClient(e *adminEnv, a addClientArgs) error {
	t, err := lookupTenant(e, a.tenant)
	if err != nil {
		return err
	}
	name := strings.TrimSpace(a.name)
	if name == "" || len(name) > 200 {
		return errors.New("add-client: -name is required (at most 200 characters)")
	}
	if a.jwksFile == "" {
		return errors.New("add-client: -jwks-file is required")
	}
	raw, err := os.ReadFile(a.jwksFile) // #nosec G304 G703 -- a path the operator passes to their own CLI
	if err != nil {
		return err
	}
	set, jwks, err := oauth.ParseClientJWKS(raw)
	if err != nil {
		return fmt.Errorf("add-client: -jwks-file: %w", err)
	}
	var thumbprints []any
	for i := range set.Keys {
		jkt, err := dpop.Thumbprint(&set.Keys[i])
		if err != nil {
			return fmt.Errorf("add-client: key %d: %w", i, err)
		}
		thumbprints = append(thumbprints, jkt)
	}
	scopes := splitList(a.scope)
	if len(scopes) == 0 {
		return errors.New("add-client: -scope is required")
	}
	for _, s := range scopes {
		if !slices.Contains(oauth.MachineScopes, s) {
			return fmt.Errorf("add-client: unknown scope %q (one of %s)", s, strings.Join(oauth.MachineScopes, ", "))
		}
	}
	roles := splitList(a.roles)
	if len(roles) == 0 {
		return errors.New("add-client: -roles is required")
	}
	for _, r := range roles {
		if !slices.Contains(machineRoles, r) {
			return fmt.Errorf("add-client: a machine client cannot have the role %q (allowed: %s)", r, strings.Join(machineRoles, ", "))
		}
	}
	clientID, err := newClientID()
	if err != nil {
		return err
	}
	c := &store.APIClient{ClientID: clientID, Name: name, Kind: store.ClientMachine, // #nosec G101 -- names of an auth method and a grant, not a credential
		GrantTypes: []string{oauth.GrantClientCredentials}, TokenEndpointAuthMethod: "private_key_jwt", JWKS: jwks,
		DPoPRequired: a.dpop, AllowedScopes: scopes, Roles: roles, ApprovedBy: store.ApprovedByOperator, Status: store.ClientActive, CreatedAt: e.now}
	if err := e.db.InTenant(e.ctx, t.ID, func(tx *store.TenantTx) error {
		owner, err := findOwner(tx, a.owner)
		if err != nil {
			return err
		}
		c.OwnerUserID = &owner.ID
		if err := tx.InsertAPIClient(c); err != nil {
			return err
		}
		_, err = audit.Record(e.ctx, tx, "oauth.client.created", ojson.Object{{Key: "client_id", Value: c.ClientID},
			{Key: "name", Value: c.Name}, {Key: "kind", Value: c.Kind}, {Key: "owner_user_id", Value: owner.ID.String()},
			{Key: "roles", Value: stringsAny(roles)}, {Key: "scopes", Value: stringsAny(scopes)},
			{Key: "dpop_required", Value: c.DPoPRequired}, {Key: "key_thumbprints", Value: thumbprints}},
			audit.At(e.now), audit.Target("api_client", c.ID.String()))
		return err
	}); err != nil {
		return fmt.Errorf("add-client: %w", err)
	}
	base := strings.TrimRight(e.cfg.PublicURL, "/") + "/t/" + t.Slug
	fmt.Fprintf(e.stdout, "added machine client %s (%s) to %s\ntoken endpoint %s/oauth/token (the assertion's aud must be exactly that URL)\n",
		c.ClientID, c.Name, t.Slug, base)
	if !c.DPoPRequired {
		fmt.Fprintln(e.stdout, "warning: DPoP is not required; a token this client gets without a DPoP proof is a Bearer token")
	}
	return nil
}

// listOverprivilegedClients prints the tenant's active machine clients whose effective permissions (roles ∩ scopes)
// exceed what the person who vouched for them holds now (issue #522, auth.ClientExceedsApprover): clients made before
// the creator check of #509, and clients whose approving admin lost a role or left. The token endpoint and the API
// refuse them already; this is the inventory to fix them (an admin who holds the permissions rotates the client's
// keys, which approves it again, or the client is revoked).
func listOverprivilegedClients(e *adminEnv, slug string) error {
	t, err := lookupTenant(e, slug)
	if err != nil {
		return err
	}
	n := 0
	if err := e.db.ReadTenant(e.ctx, t.ID, func(tx *store.TenantTx) error {
		cs, err := tx.APIClients()
		if err != nil {
			return err
		}
		for _, c := range cs {
			if c.Kind != store.ClientMachine || c.Status != store.ClientActive {
				continue
			}
			missing, err := auth.ClientExceedsApprover(tx, c, c.AllowedScopes, e.now)
			if err != nil {
				return err
			}
			if len(missing) == 0 {
				continue
			}
			n++
			fmt.Fprintf(e.stdout, "%s\t%s\tapprover %s\troles %s\tscopes %s\tlacks %s\n", c.ClientID, c.Name, approverID(c),
				strings.Join(c.Roles, ","), strings.Join(c.AllowedScopes, " "), strings.Join(missing, ","))
		}
		return nil
	}); err != nil {
		return fmt.Errorf("list-overprivileged-clients: %w", err)
	}
	fmt.Fprintf(e.stdout, "%d machine client(s) hold permissions their approver lacks in %s\n", n, t.Slug)
	return nil
}

// approverID is who is compared with the client: its recorded approver, else (made before it was recorded) its owner.
func approverID(c *store.APIClient) string {
	switch {
	case c.ApprovedBy != "":
		return c.ApprovedBy
	case c.OwnerUserID != nil:
		return "owner " + c.OwnerUserID.String()
	}
	return "none"
}

// newClientID is "tsc_" and 16 base32 characters (80 random bits).
func newClientID() (string, error) {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "tsc_" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)), nil
}

// splitList splits a comma or space separated list, dropping repeats.
func splitList(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		if !slices.Contains(out, f) {
			out = append(out, f)
		}
	}
	return out
}

func stringsAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

// findOwner resolves -owner (a user id or an email) to an active user of the
// tenant of tx: every machine client has an accountable owner.
func findOwner(tx *store.TenantTx, owner string) (*store.PlatformUser, error) {
	if owner == "" {
		return nil, errors.New("-owner is required (the user accountable for this client)")
	}
	users, err := tx.PlatformUsers()
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		if u.ID.String() == owner || (u.Email != nil && strings.EqualFold(*u.Email, owner)) {
			if u.Status != "active" {
				return nil, fmt.Errorf("the owner %q is not an active user", owner)
			}
			return u, nil
		}
	}
	return nil, fmt.Errorf("no user %q in this tenant", owner)
}

// checkGroupPolicies re-reads the policy group files stored for the tenant with the current fragment parser and
// prints each finding (issue #698: the fragment is Cedar's grammar now, so a file with `attr in [..]`, a
// multi-value @provision, a guard carried from a when into an unless, or a raw control character in a string is
// refused on its next apply). Stored groups keep working: only the source is re-parsed, never the compiled policy.
// It exits non-zero when any file has a finding, so a migration can gate on it.
func checkGroupPolicies(e *adminEnv, slug string) error {
	t, err := lookupTenant(e, slug)
	if err != nil {
		return err
	}
	files, bad := 0, 0
	schema := policygroups.DefaultSchema()
	if err := e.db.ReadTenant(e.ctx, t.ID, func(tx *store.TenantTx) error {
		srcs, err := tx.GrpPolicySources("")
		if err != nil {
			return err
		}
		for _, s := range srcs {
			files++
			if _, diags := policygroups.ParseFile(s.Path, s.Cedar, schema); len(diags) > 0 {
				bad++
				for _, d := range diags {
					fmt.Fprintln(e.stdout, d)
				}
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("check-group-policies: %w", err)
	}
	fmt.Fprintf(e.stdout, "%d of %d stored policy group file(s) need a rewrite in %s\n", bad, files, t.Slug)
	if bad > 0 {
		return fmt.Errorf("check-group-policies: %d file(s) need a rewrite", bad)
	}
	return nil
}
