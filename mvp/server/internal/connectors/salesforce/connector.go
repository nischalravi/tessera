package salesforce

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// System is the connector's system name.
const System = "salesforce"

// ResOrg is the resource the system permission flags act on.
const ResOrg = "org"

// Group kinds.
const (
	KindProfile = "salesforce_profile"
	KindRole    = "salesforce_role"
	KindPermSet = "salesforce_permission_set"
	KindPSG     = "salesforce_permission_set_group"
)

// flags are the system permissions read from a profile or permission set (the Permissions* fields of
// PermissionSet), and whether holding one is privileged: it reaches every record, changes who has
// access, or runs code.
var flags = []struct {
	Name       string
	Privileged bool
}{
	{"ModifyAllData", true}, {"ViewAllData", true}, {"ManageUsers", true}, {"ManageInternalUsers", true},
	{"AssignPermissionSets", true}, {"ManageProfilesPermissionsets", true}, {"AuthorApex", true},
	{"CustomizeApplication", true}, {"DataExport", true}, {"ApiEnabled", false}, {"ExportReport", false},
}

func flagFields() string {
	f := make([]string, len(flags))
	for i, x := range flags {
		f[i] = "Permissions" + x.Name
	}
	return strings.Join(f, ", ")
}

func flagPerm(name string) string { return "sf:" + name }

// Connector is the read connector (connectors.Connector).
type Connector struct {
	c   *Client
	now func() time.Time
}

// NewConnector wraps a client; now decides which expiring assignments still hold.
func NewConnector(c *Client, now func() time.Time) *Connector {
	if now == nil {
		now = time.Now
	}
	return &Connector{c, now}
}

func (*Connector) System() string      { return System }
func (*Connector) DisplayName() string { return "Salesforce" }
func (*Connector) TypeName() string    { return "SalesforceConnector" }

// StreamEvents: no usage is read here.
func (*Connector) StreamEvents(context.Context, *time.Time, func(connectors.Event) error) error {
	return nil
}

// FromEnv builds the read connector from TESSERA_SALESFORCE_*:
//
//	TESSERA_SALESFORCE_BASE_URL     https://acme.my.salesforce.com
//	TESSERA_SALESFORCE_LOGIN_URL    optional: https://test.salesforce.com for a sandbox
//	TESSERA_SALESFORCE_CLIENT_ID    the connected app's consumer key
//	TESSERA_SALESFORCE_USERNAME     the integration user
//	TESSERA_SALESFORCE_PRIVATE_KEY  reference to the PEM private key: file:/abs/path or env:NAME
//	TESSERA_SALESFORCE_API_VERSION  optional, v61.0
func FromEnv(getenv func(string) string, rt connsync.Runtime, hc *http.Client, now func() time.Time) (connectors.Connector, error) {
	const p = "TESSERA_SALESFORCE_"
	key, err := connsync.ResolveSecret(getenv(p+"PRIVATE_KEY"), getenv)
	if err != nil {
		return nil, errors.New(p + "PRIVATE_KEY: " + err.Error())
	}
	c, err := Open(Config{BaseURL: getenv(p + "BASE_URL"), LoginURL: getenv(p + "LOGIN_URL"), ClientID: getenv(p + "CLIENT_ID"),
		Username: getenv(p + "USERNAME"), PrivateKey: key, APIVersion: getenv(p + "API_VERSION")}, rt, hc, now)
	if err != nil {
		return nil, err
	}
	return NewConnector(c, now), nil
}

// Discover reads every user, profile, role, permission set and group, and their assignments.
func (c *Connector) Discover(ctx context.Context) (*connectors.DiscoveryResult, error) {
	read := func(what, soql string) ([]record, error) {
		rs, err := c.c.rows(ctx, soql)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", what, err)
		}
		return rs, nil
	}
	profiles, err := read("profiles", "SELECT Id, Name, Description FROM Profile")
	if err != nil {
		return nil, err
	}
	roles, err := read("roles", "SELECT Id, Name FROM UserRole")
	if err != nil {
		return nil, err
	}
	sets, err := read("permission sets", "SELECT Id, Name, Label, Description, IsOwnedByProfile, ProfileId, Type, "+flagFields()+" FROM PermissionSet")
	if err != nil {
		return nil, err
	}
	groups, err := read("permission set groups", "SELECT Id, DeveloperName, MasterLabel, Description FROM PermissionSetGroup")
	if err != nil {
		return nil, err
	}
	comps, err := read("permission set group components", "SELECT PermissionSetGroupId, PermissionSetId FROM PermissionSetGroupComponent")
	if err != nil {
		return nil, err
	}
	users, err := read("users", "SELECT Id, Username, Email, Name, IsActive, ProfileId, UserRoleId, UserType, Title, Department, EmployeeNumber, LastLoginDate, CreatedDate FROM User")
	if err != nil {
		return nil, err
	}
	logins, err := read("user logins", "SELECT UserId, IsFrozen FROM UserLogin")
	if err != nil {
		return nil, err
	}
	assigns, err := read("permission set assignments", "SELECT AssigneeId, PermissionSetId, PermissionSetGroupId, ExpirationDate FROM PermissionSetAssignment")
	if err != nil {
		return nil, err
	}

	res := &connectors.DiscoveryResult{}
	res.Resources = []connectors.ResourceRecord{{System: System, ExternalID: ResOrg, Name: "Salesforce org", Kind: "salesforce_org", Tags: []string{"saas", System}}}
	known := map[string]bool{}
	for _, f := range flags {
		known[f.Name] = false
	}
	ref := func(id string) connectors.Ref { return connectors.Ref{Kind: "group", System: System, ExternalID: id} }
	group := func(id, name, kind, desc string, priv, requestable bool) {
		g := connectors.GroupRecord{System: System, ExternalID: id, Name: name, Kind: kind, Privileged: priv, Requestable: requestable}
		if desc != "" {
			g.Description = &desc
		}
		res.Groups = append(res.Groups, g)
	}

	// Which flags each profile or set enables; an owned set carries its profile's flags.
	enabled := map[string][]string{} // group id -> flag names
	privileged := map[string]bool{}
	for _, s := range sets {
		id := s.str("Id")
		if s.flag("IsOwnedByProfile") {
			id = s.str("ProfileId")
		}
		for _, f := range flags {
			if s.flag("Permissions" + f.Name) {
				enabled[id] = append(enabled[id], f.Name)
				privileged[id] = privileged[id] || f.Privileged
				known[f.Name] = true
			}
		}
	}

	profileIDs, roleIDs, setIDs, psgIDs := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, p := range profiles {
		profileIDs[p.str("Id")] = true
		group(p.str("Id"), p.str("Name"), KindProfile, p.str("Description"), privileged[p.str("Id")], false)
	}
	for _, r := range roles {
		roleIDs[r.str("Id")] = true
		group(r.str("Id"), r.str("Name"), KindRole, "", false, false)
	}
	for _, s := range sets {
		if s.flag("IsOwnedByProfile") || s.str("Type") == "Group" || s.str("Type") == "Session" {
			continue
		}
		name := s.str("Label")
		if name == "" {
			name = s.str("Name")
		}
		setIDs[s.str("Id")] = true
		group(s.str("Id"), name, KindPermSet, s.str("Description"), privileged[s.str("Id")], true)
	}
	for _, g := range groups {
		name := g.str("MasterLabel")
		if name == "" {
			name = g.str("DeveloperName")
		}
		psgIDs[g.str("Id")] = true
		group(g.str("Id"), name, KindPSG, g.str("Description"), false, true)
	}

	for _, f := range flags {
		if known[f.Name] {
			res.Permissions = append(res.Permissions, connectors.PermissionRecord{System: System, ExternalID: flagPerm(f.Name), Action: f.Name, ResourceExternalID: ResOrg, Privileged: f.Privileged})
		}
	}
	ids := make([]string, 0, len(enabled))
	for id := range enabled {
		if profileIDs[id] || setIDs[id] {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		for _, f := range enabled[id] {
			res.Edges = append(res.Edges, connectors.EdgeRecord{Src: ref(id), Dst: connectors.Ref{Kind: "perm", System: System, ExternalID: flagPerm(f)}, Relation: "grants"})
		}
	}
	// A group holds what its components grant, as a nested directory group does; its privilege follows.
	psgPriv := map[string]bool{}
	for _, cp := range comps {
		g, s := cp.str("PermissionSetGroupId"), cp.str("PermissionSetId")
		if psgIDs[g] && setIDs[s] {
			res.Edges = append(res.Edges, connectors.EdgeRecord{Src: ref(g), Dst: ref(s), Relation: "member_of"})
			psgPriv[g] = psgPriv[g] || privileged[s]
		}
	}
	for i := range res.Groups {
		if res.Groups[i].Kind == KindPSG && psgPriv[res.Groups[i].ExternalID] {
			res.Groups[i].Privileged = true
		}
	}

	frozen := map[string]bool{}
	for _, l := range logins {
		frozen[l.str("UserId")] = l.flag("IsFrozen")
	}
	now := c.now()
	for _, u := range users {
		id := u.str("Id")
		status := "active"
		if !u.flag("IsActive") || frozen[id] {
			status = "disabled"
		}
		kind := "user"
		if t := u.str("UserType"); t != "" && t != "Standard" {
			kind = "service"
		}
		acct := connectors.AccountRecord{System: System, ExternalID: id, Username: u.str("Username"), Kind: kind, Status: status,
			CreatedAt: u.time("CreatedDate"), LastLoginAt: u.time("LastLoginDate"),
			Attributes: map[string]string{"Id": id, "Username": u.str("Username"), "Email": u.str("Email"), "EmployeeNumber": u.str("EmployeeNumber"),
				"Title": u.str("Title"), "Department": u.str("Department"), "IsActive": fmt.Sprint(u.flag("IsActive")), "IsFrozen": fmt.Sprint(frozen[id])}}
		if e := strings.ToLower(strings.TrimSpace(u.str("Email"))); e != "" {
			acct.Identity = &connectors.IdentityRef{Email: e}
		}
		res.Accounts = append(res.Accounts, acct)
		from := connectors.Ref{Kind: "account", System: System, ExternalID: id}
		for _, g := range []struct {
			id string
			ok map[string]bool
		}{{u.str("ProfileId"), profileIDs}, {u.str("UserRoleId"), roleIDs}} {
			if g.ok[g.id] {
				res.Edges = append(res.Edges, connectors.EdgeRecord{Src: from, Dst: ref(g.id), Relation: "member_of"})
			}
		}
	}
	userIDs := map[string]bool{}
	for _, u := range users {
		userIDs[u.str("Id")] = true
	}
	seen := map[string]bool{}
	for _, a := range assigns {
		// A group assignment also lists each component set; the group is what was assigned.
		target := a.str("PermissionSetId")
		if g := a.str("PermissionSetGroupId"); g != "" {
			target = g
		}
		if exp := a.time("ExpirationDate"); exp != nil && !exp.After(now) {
			continue
		}
		key := a.str("AssigneeId") + ">" + target
		if !userIDs[a.str("AssigneeId")] || !(setIDs[target] || psgIDs[target]) || seen[key] {
			continue
		}
		seen[key] = true
		res.Edges = append(res.Edges, connectors.EdgeRecord{Src: connectors.Ref{Kind: "account", System: System, ExternalID: a.str("AssigneeId")}, Dst: ref(target), Relation: "member_of"})
	}
	return res, nil
}
