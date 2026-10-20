package okta

// Okta agent discovery (issue #116). Additive to the directory read: it runs
// only when Config.DiscoverAgents is set, reuses the apps the directory read
// already listed, and only reads.
//
// An Okta AI agent or machine integration is an OIDC service app
// (settings.oauthClient.application_type = "service"): it has no user, signs in
// with a client secret or a private key JWT and calls the Okta Management API
// with the scopes granted to it. Each one becomes:
//
//	identity  okta-app:<id>, type ai_agent, owned by its sponsor
//	account   svc:<id>, kind agent
//	secrets   one per active client secret (credentials/secrets) and public
//	          key (credentials/jwks), by id, creation date and kind only: the
//	          secret hash and the key material are never decoded
//	scopes    one permission per granted API scope on the Okta Management API
//	          resource, direct_grant from the agent (a .manage scope is privileged)
//
// Okta's apps have no native creator or sponsor field. The convention read here
// is two custom app profile properties, "creator" and "sponsor", holding an
// e-mail address or employee number; an app without them has no sponsor, which
// the nhi-ownership policy reports. Okta's own AI agent registry has no stable
// public API this connector can rely on, so it is not used. Exercised against
// recorded fixtures only, not a live org.

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// AgentKind is the AgentRecord kind of an Okta service app.
const AgentKind = "okta_service_app"

// apiResource is the Okta Management API as a resource the scopes act on.
const apiResource = "api:okta-management"

type apiSecret struct {
	ID      string `json:"id"`
	Created string `json:"created"`
	Status  string `json:"status"`
}

type apiKey struct {
	ID      string `json:"id"`
	KID     string `json:"kid"`
	Created string `json:"created"`
	Status  string `json:"status"`
}

type apiGrant struct {
	ScopeID string `json:"scopeId"`
	Status  string `json:"status"`
}

func isServiceApp(a apiApp) bool {
	return strings.EqualFold(a.SignOnMode, "OPENID_CONNECT") && strings.EqualFold(a.Settings.OAuthClient.ApplicationType, "service")
}

// profileRef reads a custom profile property as an identity reference: an
// address with "@" is an e-mail, anything else an employee number.
func profileRef(p map[string]any, key string) (*connectors.IdentityRef, string) {
	v, _ := p[key].(string)
	v = strings.TrimSpace(v)
	if v == "" || len(v) > 256 {
		return nil, ""
	}
	if strings.Contains(v, "@") {
		return &connectors.IdentityRef{Email: v}, v
	}
	return &connectors.IdentityRef{ExternalID: v}, v
}

func (c *Connector) discoverAgents(ctx context.Context, apps []*appAssign, res *connectors.DiscoveryResult) error {
	api := connectors.ResourceRecord{System: System, ExternalID: apiResource, Name: "Okta Management API", Kind: "api",
		Tags: []string{"okta-management-api"}}
	haveAPI := false
	for _, a := range apps {
		if !isServiceApp(a.app) {
			continue
		}
		app := a.app
		id := url.PathEscape(app.ID)
		name := app.Label
		if name == "" {
			name = app.Name
		}
		if name == "" {
			name = app.ID
		}
		xid, acctID := "okta-app:"+app.ID, "svc:"+app.ID
		creator, creatorRef := profileRef(app.Profile, "creator")
		sponsor, sponsorRef := profileRef(app.Profile, "sponsor")
		res.Identities = append(res.Identities, connectors.IdentityRecord{ExternalID: xid, Name: name, Type: "ai_agent",
			Status: "active", Description: strp("Okta OAuth service app"), Owner: sponsor})
		acctRef := connectors.Ref{Kind: "account", System: System, ExternalID: acctID}
		username := app.Credentials.OAuthClient.ClientID
		if username == "" {
			username = app.ID
		}
		res.Accounts = append(res.Accounts, connectors.AccountRecord{System: System, ExternalID: acctID, Username: username,
			Identity: &connectors.IdentityRef{ExternalID: xid}, Kind: "agent", Status: "active", CreatedAt: parseTime(app.Created),
			Attributes: map[string]string{"appId": app.ID, "signOnMode": app.SignOnMode}})
		res.Agents = append(res.Agents, connectors.AgentRecord{System: System, ExternalID: app.ID,
			Identity: connectors.IdentityRef{ExternalID: xid}, Kind: AgentKind, Creator: creator, CreatorRef: creatorRef,
			Sponsor: sponsor, SponsorRef: sponsorRef})

		var secrets []apiSecret
		if err := c.optional(ctx, "/api/v1/apps/"+id+"/credentials/secrets", &secrets); err != nil {
			return fmt.Errorf("okta: agent secrets: %w", err)
		}
		for _, s := range secrets {
			if validID(s.ID) && !strings.EqualFold(s.Status, "INACTIVE") {
				c.addSecret(res, app.ID, acctRef, "client_secret", "client secret", s.ID, s.Created)
			}
		}
		var keys []apiKey
		if err := c.optional(ctx, "/api/v1/apps/"+id+"/credentials/jwks", &keys); err != nil {
			return fmt.Errorf("okta: agent keys: %w", err)
		}
		for _, k := range keys {
			if validID(k.ID) && !strings.EqualFold(k.Status, "INACTIVE") {
				label := "private key JWT key"
				if k.KID != "" && len(k.KID) <= 64 {
					label += " " + k.KID
				}
				c.addSecret(res, app.ID, acctRef, "jwk", label, k.ID, k.Created)
			}
		}
		var grants []apiGrant
		if err := c.optional(ctx, "/api/v1/apps/"+id+"/grants", &grants); err != nil {
			return fmt.Errorf("okta: agent grants: %w", err)
		}
		for _, g := range grants {
			if g.ScopeID == "" || len(g.ScopeID) > 128 || strings.EqualFold(g.Status, "INACTIVE") {
				continue
			}
			if !haveAPI {
				haveAPI = true
				res.Resources = append(res.Resources, api)
			}
			perm := apiResource + ":" + g.ScopeID
			if !hasPerm(res, perm) {
				res.Permissions = append(res.Permissions, connectors.PermissionRecord{System: System, ExternalID: perm,
					Action: g.ScopeID, ResourceExternalID: apiResource, Privileged: strings.HasSuffix(g.ScopeID, ".manage")})
			}
			res.Edges = append(res.Edges, connectors.EdgeRecord{Src: acctRef, Dst: connectors.Ref{Kind: "perm", System: System,
				ExternalID: perm}, Relation: "direct_grant"})
		}
	}
	res.AgentSnapshotOf = append(res.AgentSnapshotOf, System)
	return nil
}

func hasPerm(res *connectors.DiscoveryResult, ext string) bool {
	for _, p := range res.Permissions {
		if p.ExternalID == ext {
			return true
		}
	}
	return false
}

// optional GETs a JSON list; a 403 or 404 (the scope is not granted, or the
// app has no such credential type) leaves it empty.
func (c *Connector) optional(ctx context.Context, path string, v any) error {
	_, err := c.api.GetJSON(ctx, c.path(path, nil), nil, v)
	if err != nil {
		if s := connsync.Status(err); s == 403 || s == 404 {
			return nil
		}
	}
	return err
}

func (c *Connector) addSecret(res *connectors.DiscoveryResult, appID string, acct connectors.Ref, kind, name, id, created string) {
	at := parseTime(created)
	if at == nil {
		t := c.now()
		at = &t
	}
	res.Secrets = append(res.Secrets, connectors.SecretRecord{System: System, ExternalID: appID + ":" + id, Account: acct,
		Kind: kind, Name: name, CreatedAt: *at})
}
