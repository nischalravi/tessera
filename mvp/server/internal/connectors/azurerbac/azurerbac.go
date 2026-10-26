// Package azurerbac is the read connector for Azure role-based access control (issue #557): the
// role assignments and role definitions of the subscriptions and management groups of one Entra
// tenant, over Azure Resource Manager (Microsoft.Authorization, api-version 2022-04-01), plus the
// PIM eligible assignments (roleEligibilityScheduleInstances, 2020-10-01) when asked. It feeds the
// effective-permission analysis. It is read-only: only GET requests are sent (and the token POST),
// and the service principal needs only Reader at the scopes it reads.
//
// Authentication is the OAuth 2.0 client credentials flow against login.microsoftonline.com for the
// scope https://management.azure.com/.default, with a client secret or a certificate (a PEM holding
// the certificate and its RSA private key, sent as a signed client assertion).
//
// Mapping onto Tessera's model:
//
//	scope (management group, subscription, resource group, resource) -> resource (kind azure_*)
//	role at a scope       -> permission "<scope>|<role guid>", Action = the role name, on the scope's
//	                         resource; privileged when the role holds "*" or Microsoft.Authorization
//	                         rights. An eligible (PIM) assignment is a separate permission with
//	                         "|eligible" and Action "<role name> (eligible)", so eligibility never
//	                         reads as access held now.
//	user, device, service principal -> account (kind user, service) -direct_grant-> permission
//	group principal                           -> group (kind entra_group)             -grants->       permission
//
// Principals are object ids: names and group membership live in Microsoft Graph (the entra
// connector), which this connector does not call.
package azurerbac

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/config"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
	"github.com/nischalravi/tessera/mvp/server/internal/safehttp"
)

// System is the graph system name.
const System = "azure"

// Public cloud endpoints. They are the only hosts a production connection reaches: an override is a
// dev or test setting and is refused in prod (Open).
const (
	DefaultManagementURL = "https://management.azure.com"
	DefaultAuthorityURL  = "https://login.microsoftonline.com"
)

// API versions, as documented for each operation.
const (
	apiRBAC          = "2022-04-01" // roleAssignments, roleDefinitions
	apiEligibility   = "2020-10-01" // roleEligibilityScheduleInstances
	apiSubscriptions = "2022-12-01" // subscriptions
	apiMgmtGroups    = "2020-05-01" // managementGroups
)

// allowedHosts are the hosts a production connection may reach (exact names).
var allowedHosts = map[string]bool{"management.azure.com": true, "login.microsoftonline.com": true}

// Bounds, so a source that never stops cannot keep a sync running.
const (
	maxScopes      = 5000
	maxAssignments = 500000
)

var (
	guidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	// mgRE is a management group id (1 to 90 characters).
	mgRE = regexp.MustCompile(`^[A-Za-z0-9._()-]{1,90}$`)
	// armIDRE is the shape of an Azure resource id the connector will put in a request path.
	armIDRE = regexp.MustCompile(`^/[A-Za-z0-9._()/-]{1,1000}$`)
)

// ErrCredential: Microsoft Entra refused the client credentials (a token endpoint answer of 400, 401
// or 403). A probe reports it as "not authenticated".
var ErrCredential = errors.New("azurerbac: the credential was refused")

// Config configures one tenant.
type Config struct {
	// TenantID is the directory (tenant) GUID; ClientID the application (client) id.
	TenantID, ClientID string
	// Credential is a client secret or, when it starts with "-----BEGIN", a PEM holding the
	// certificate and its RSA private key.
	Credential connsync.Secret
	// SubscriptionIDs and ManagementGroupIDs are the scopes to read. Both empty: every subscription
	// and management group the application can list.
	SubscriptionIDs, ManagementGroupIDs []string
	// IncludeEligible also reads PIM eligible assignments.
	IncludeEligible bool
	// ManagementURL and AuthorityURL override the public cloud endpoints. Dev and test only
	// (a fake server); Open refuses them outside the dev runtime.
	ManagementURL, AuthorityURL string
}

// Connector implements connectors.Connector for Azure RBAC.
type Connector struct {
	cfg  Config
	arm  *url.URL
	api  *connsync.Client
	tok  *tokenSource
	now  func() time.Time
	mode string // client_secret or certificate
}

// New builds a connector. hc must be the server's shared outbound client (safehttp.ForConfig).
func New(cfg Config, rt connsync.Runtime, hc *http.Client, now func() time.Time) (*Connector, error) {
	if !guidRE.MatchString(cfg.TenantID) {
		return nil, errors.New("azurerbac: tenant id must be the directory GUID")
	}
	if !guidRE.MatchString(cfg.ClientID) {
		return nil, errors.New("azurerbac: client id must be the application GUID")
	}
	if cfg.Credential.Empty() {
		return nil, errors.New("azurerbac: a client secret or certificate is required")
	}
	if hc == nil {
		return nil, errors.New("azurerbac: an internal/safehttp client is required")
	}
	for _, s := range cfg.SubscriptionIDs {
		if !guidRE.MatchString(s) {
			return nil, errors.New("azurerbac: a subscription id must be a GUID")
		}
	}
	for _, m := range cfg.ManagementGroupIDs {
		if !mgRE.MatchString(m) {
			return nil, errors.New("azurerbac: a management group id has characters Azure does not allow")
		}
	}
	arm, err := endpoint(cfg.ManagementURL, DefaultManagementURL, "management URL", rt)
	if err != nil {
		return nil, err
	}
	authority, err := endpoint(cfg.AuthorityURL, DefaultAuthorityURL, "authority URL", rt)
	if err != nil {
		return nil, err
	}
	signer, err := parseCredential(cfg.Credential.Reveal())
	if err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	hc = safehttp.WithConfiguredPorts(hc, arm.String(), authority.String())
	c := &Connector{cfg: cfg, arm: arm, now: now, mode: "client_secret"}
	if signer != nil {
		c.mode = "certificate"
	}
	c.api = &connsync.Client{HC: hc, Now: now, Header: http.Header{
		"Accept": {"application/json"}, "User-Agent": {"tessera-connector/azurerbac"}}}
	c.tok = newTokenSource(cfg, authority, arm, signer, c.api, now)
	c.api.Authorize = c.tok.authorization
	c.api.OnUnauthorized = c.tok.invalidate
	return c, nil
}

// endpoint resolves an endpoint: the public default when raw is empty or equal to it, an override
// only in the dev runtime. Whatever is returned has passed the host allow-list in prod.
func endpoint(raw, def, what string, rt connsync.Runtime) (*url.URL, error) {
	override := raw != "" && strings.TrimRight(raw, "/") != def
	if override && rt.Env != config.Dev {
		return nil, fmt.Errorf("azurerbac: %s: an endpoint override is a dev setting and is refused outside dev", what)
	}
	if raw == "" {
		raw = def
	}
	u, err := connsync.ParseBaseURL(raw, rt)
	if err != nil {
		return nil, fmt.Errorf("azurerbac: %s: %w", what, err)
	}
	if !override && (!allowedHosts[strings.ToLower(u.Hostname())] || u.Path != "" || u.Port() != "") {
		return nil, fmt.Errorf("azurerbac: %s: host is not an allowed Azure endpoint", what)
	}
	return u, nil
}

func (c *Connector) System() string      { return System }
func (c *Connector) DisplayName() string { return "Azure RBAC" }
func (c *Connector) TypeName() string    { return "AzureRBACConnector" }

// Mode is how the connector authenticates: client_secret or certificate.
func (c *Connector) Mode() string { return c.mode }

// StreamEvents: Azure RBAC reports no usage here.
func (*Connector) StreamEvents(context.Context, *time.Time, func(connectors.Event) error) error {
	return nil
}

// Scope is a management group or a subscription to read.
type Scope struct {
	ID   string // /providers/Microsoft.Management/managementGroups/<id> or /subscriptions/<guid>
	Name string
}

// Assignment is one role assignment, or one eligible (PIM) assignment.
type Assignment struct {
	ID, Scope, PrincipalID, PrincipalType, RoleDefinitionID string
	Conditional                                             bool
	Eligible                                                bool
	End                                                     *time.Time
}

// RoleDef is a role definition.
type RoleDef struct {
	ID, Name, Type      string
	Actions, NotActions []string
	Privileged          bool
}

// Snapshot is what one read found.
type Snapshot struct {
	Scopes      []Scope
	Assignments []Assignment
	Roles       map[string]RoleDef // by roleKey (the lower-case GUID)
	// Partial says why the read is not the whole picture (a scope or the eligible assignments
	// could not be read); empty when it is complete.
	Partial string
	// ReadScopes are the ids of the scopes whose role assignments (and eligible assignments, when
	// read) were listed in full. Only those scopes' edges may be pruned.
	ReadScopes []string
}

func lower(s string) string { return strings.ToLower(s) }

// roleKey is the identity of a role definition: the GUID at the end of its id.
func roleKey(id string) string {
	if i := strings.LastIndex(id, "/"); i >= 0 {
		id = id[i+1:]
	}
	return lower(id)
}

// ScopeKind names the kind of an Azure scope id.
func ScopeKind(id string) string {
	l := lower(id)
	switch {
	case strings.HasPrefix(l, "/providers/microsoft.management/managementgroups/"):
		return "azure_management_group"
	case strings.Count(l, "/") == 2 && strings.HasPrefix(l, "/subscriptions/"):
		return "azure_subscription"
	case strings.Count(l, "/") == 4 && strings.Contains(l, "/resourcegroups/"):
		return "azure_resource_group"
	}
	return "azure_resource"
}

func shortName(id string) string {
	if i := strings.LastIndex(id, "/"); i >= 0 && i < len(id)-1 {
		return id[i+1:]
	}
	return id
}

// Discover reads the scopes, their role definitions and assignments, and maps them.
func (c *Connector) Discover(ctx context.Context) (*connectors.DiscoveryResult, error) {
	snap, err := c.Read(ctx)
	if err != nil {
		return nil, err
	}
	return c.build(snap), nil
}

func (c *Connector) build(s *Snapshot) *connectors.DiscoveryResult {
	res := &connectors.DiscoveryResult{System: System, Partial: s.Partial, EdgeSnapshotOf: []string{System}}
	for _, sc := range s.ReadScopes {
		res.EdgeScopesRead = append(res.EdgeScopesRead, lower(sc))
	}
	names := map[string]string{}
	for _, sc := range s.Scopes {
		names[lower(sc.ID)] = sc.Name
	}
	resSeen := map[string]bool{}
	addResource := func(scope string) string {
		k := lower(scope)
		if !resSeen[k] {
			resSeen[k] = true
			name := names[k]
			if name == "" {
				name = shortName(scope)
			}
			kind := ScopeKind(scope)
			res.Resources = append(res.Resources, connectors.ResourceRecord{System: System, ExternalID: k, Name: name, Kind: kind,
				Tags: []string{"azure", strings.TrimPrefix(kind, "azure_")}})
		}
		return k
	}
	for _, sc := range s.Scopes {
		addResource(sc.ID)
	}
	permSeen := map[string]bool{}
	acctSeen := map[string]bool{}
	groupSeen := map[string]bool{}
	edgeSeen := map[[2]string]bool{}
	list := append([]Assignment(nil), s.Assignments...)
	sort.SliceStable(list, func(i, j int) bool {
		a, b := list[i], list[j]
		return a.Scope+a.RoleDefinitionID+a.PrincipalID < b.Scope+b.RoleDefinitionID+b.PrincipalID
	})
	for _, a := range list {
		rk := addResource(a.Scope)
		role := s.Roles[roleKey(a.RoleDefinitionID)]
		name := role.Name
		if name == "" {
			name = "role " + roleKey(a.RoleDefinitionID)
		}
		id := rk + "|" + roleKey(a.RoleDefinitionID)
		action := name
		if a.Conditional {
			sum := sha256.Sum256([]byte(a.ID))
			id += "|c" + hex.EncodeToString(sum[:4])
			action += " (conditional)"
		}
		if a.Eligible {
			id += "|eligible"
			action += " (eligible)"
		}
		if !permSeen[id] {
			permSeen[id] = true
			res.Permissions = append(res.Permissions, connectors.PermissionRecord{System: System, ExternalID: id, Action: action,
				ResourceExternalID: rk, Privileged: role.Privileged})
		}
		perm := connectors.Ref{Kind: "perm", System: System, ExternalID: id}
		var src connectors.Ref
		var rel string
		switch strings.ToLower(a.PrincipalType) {
		case "group", "foreigngroup":
			if !groupSeen[a.PrincipalID] {
				groupSeen[a.PrincipalID] = true
				res.Groups = append(res.Groups, connectors.GroupRecord{System: System, ExternalID: a.PrincipalID, Name: a.PrincipalID, Kind: "entra_group"})
			}
			src, rel = connectors.Ref{Kind: "group", System: System, ExternalID: a.PrincipalID}, "grants"
		default:
			if !acctSeen[a.PrincipalID] {
				acctSeen[a.PrincipalID] = true
				res.Accounts = append(res.Accounts, connectors.AccountRecord{System: System, ExternalID: a.PrincipalID, Username: a.PrincipalID,
					Kind: accountKind(a.PrincipalType), Status: "active"})
			}
			src, rel = connectors.Ref{Kind: "account", System: System, ExternalID: a.PrincipalID}, "direct_grant"
		}
		if k := [2]string{src.Kind + ":" + src.ExternalID, id}; !edgeSeen[k] {
			edgeSeen[k] = true
			res.Edges = append(res.Edges, connectors.EdgeRecord{Src: src, Dst: perm, Relation: rel})
		}
	}
	return res
}

func accountKind(principalType string) string {
	switch strings.ToLower(principalType) {
	case "serviceprincipal", "agentserviceprincipal":
		return "service"
	}
	return "user"
}
