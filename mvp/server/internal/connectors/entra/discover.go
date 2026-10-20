package entra

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

const checkpointName = "discover"

const zeroGUID = "00000000-0000-0000-0000-000000000000"

const (
	userSelect  = "$select=id,displayName,userPrincipalName,mail,accountEnabled,createdDateTime,employeeId,department,jobTitle,userType"
	groupSelect = "$select=id,displayName,description,securityEnabled,mailEnabled,groupTypes,isAssignableToRole"
)

// eUser and eGroup hold the properties read from Graph. A delta response may
// carry only the changed properties of an object, so they are merged onto the
// stored copy (mergeInto) rather than replacing it.
type eUser struct {
	ID             string `json:"id"`
	DisplayName    string `json:"displayName"`
	UPN            string `json:"userPrincipalName"`
	Mail           string `json:"mail"`
	AccountEnabled *bool  `json:"accountEnabled"`
	Created        string `json:"createdDateTime"`
	EmployeeID     string `json:"employeeId"`
	Department     string `json:"department"`
	JobTitle       string `json:"jobTitle"`
	UserType       string `json:"userType"`
}

type eGroup struct {
	ID                 string   `json:"id"`
	DisplayName        string   `json:"displayName"`
	Description        string   `json:"description"`
	SecurityEnabled    *bool    `json:"securityEnabled"`
	MailEnabled        *bool    `json:"mailEnabled"`
	GroupTypes         []string `json:"groupTypes"`
	IsAssignableToRole *bool    `json:"isAssignableToRole"`
}

// member is a direct member of a group: K is "u", "g" or "s" (user, group,
// service principal).
type member struct{ K, ID string }

type groupState struct {
	G       eGroup
	Members []member
}

type state struct {
	Version int
	Users   map[string]*eUser
	Groups  map[string]*groupState
	// Apps maps a service principal's appId (the client id in sign-in logs) to
	// its object id. Refreshed on every sync.
	Apps map[string]string
}

const stateVersion = 1

func newState() *state {
	return &state{Version: stateVersion, Users: map[string]*eUser{}, Groups: map[string]*groupState{}, Apps: map[string]string{}}
}

// cursor is the checkpoint cursor: the two delta links.
type cursor struct {
	Users  string `json:"users"`
	Groups string `json:"groups"`
}

// mergeInto overlays the properties present in raw onto dst (a pointer to a
// struct with json tags).
func mergeInto(dst any, raw json.RawMessage) error {
	cur, err := json.Marshal(dst)
	if err != nil {
		return err
	}
	var m, patch map[string]json.RawMessage
	if err := json.Unmarshal(cur, &m); err != nil {
		return err
	}
	if err := json.Unmarshal(raw, &patch); err != nil {
		return err
	}
	for k, v := range patch {
		if strings.Contains(k, "@") { // @odata.*, @removed, members@delta
			continue
		}
		m[k] = v
	}
	merged, err := json.Marshal(m)
	if err != nil {
		return err
	}
	// Decode into a fresh value: decoding null into an existing field would
	// leave the old value, but Graph sends null to clear a property.
	fresh := reflect.New(reflect.TypeOf(dst).Elem())
	if err := json.Unmarshal(merged, fresh.Interface()); err != nil {
		return err
	}
	reflect.ValueOf(dst).Elem().Set(fresh.Elem())
	return nil
}

type deltaItem struct {
	ID      string          `json:"id"`
	Removed json.RawMessage `json:"@removed"`
}

// Discover implements connectors.Connector.
func (c *Connector) Discover(ctx context.Context) (*connectors.DiscoveryResult, error) {
	start := c.now()
	plan, err := connsync.Decide(ctx, System, checkpointName, start, c.cfg.MaxIncrementalAge)
	if err != nil {
		return nil, err
	}
	st, cur := newState(), cursor{}
	full := plan.Full
	if !full {
		if json.Unmarshal([]byte(plan.Prior.Cursor), &cur) != nil || cur.Users == "" || cur.Groups == "" ||
			connsync.DecodeState(plan.Prior.State, st) != nil || st.Version != stateVersion || st.Users == nil || st.Groups == nil ||
			!c.ownLink(cur.Users) || !c.ownLink(cur.Groups) {
			st, cur, full = newState(), cursor{}, true
		}
	}
	next, err := c.readDirectory(ctx, st, cur)
	if errors.Is(err, errDeltaExpired) {
		// The stored delta token is too old: start over.
		st, full = newState(), true
		next, err = c.readDirectory(ctx, st, cursor{})
	}
	if err != nil {
		return nil, err
	}
	apps, err := c.readServicePrincipals(ctx, st)
	if err != nil {
		return nil, err
	}
	roles, err := c.readDirectoryRoles(ctx)
	if err != nil {
		return nil, err
	}
	signIn := map[string]*time.Time{}
	if c.cfg.SignInActivity {
		signIn = c.readSignIns(ctx)
	}
	var agents []*eAgent
	agentsRead := false
	if c.cfg.DiscoverAgents {
		if agents, agentsRead, err = c.readAgents(ctx); err != nil {
			return nil, err
		}
		apps = c.markAgents(apps, agents)
	}
	res := c.build(st, apps, roles, signIn)
	res.AuthMethods, res.AuthSource = c.readAuthMethods(ctx, st)
	if agentsRead {
		c.applyAgents(res, agents)
	}
	c.save(ctx, st, next, start, full)
	return res, nil
}

// ownLink reports whether a stored delta link points at the configured Graph
// host: the bearer token is only ever sent there.
func (c *Connector) ownLink(link string) bool {
	_, err := connsync.SameOrigin(c.base, link)
	return err == nil
}

func (c *Connector) save(ctx context.Context, st *state, cur cursor, start time.Time, full bool) {
	store := connsync.StoreFrom(ctx)
	if store == nil {
		return
	}
	blob, err := connsync.EncodeState(st)
	curJSON, jerr := json.Marshal(cur)
	if err != nil || jerr != nil || cur.Users == "" || cur.Groups == "" {
		_ = store.Delete(ctx, System, checkpointName)
		return
	}
	cp := &connsync.Checkpoint{Cursor: string(curJSON), State: blob, UpdatedAt: start}
	if full {
		cp.FullSyncAt = &start
	} else if prior, err := store.Load(ctx, System, checkpointName); err == nil && prior != nil {
		cp.FullSyncAt = prior.FullSyncAt
	}
	_ = store.Save(ctx, System, checkpointName, cp)
}

var errDeltaExpired = errors.New("entra: delta token expired")

// deltaGone reports whether err means the delta token can no longer be used.
func deltaGone(err error) bool {
	s := connsync.Status(err)
	return s == 410 || s == 400 && strings.Contains(err.Error(), "syncStateNotFound")
}

// readDirectory reads users and groups through delta queries, starting from
// the links in cur (empty: a full enumeration), merges them into st and
// returns the new delta links.
func (c *Connector) readDirectory(ctx context.Context, st *state, cur cursor) (cursor, error) {
	var out cursor
	usersURL := cur.Users
	if usersURL == "" {
		usersURL = c.graph("/users/delta", userSelect)
	}
	var err error
	out.Users, err = listAll(ctx, c, usersURL, func(raw json.RawMessage) error {
		var it deltaItem
		if json.Unmarshal(raw, &it) != nil || !validID(it.ID) {
			return nil
		}
		if len(it.Removed) > 0 {
			delete(st.Users, it.ID)
			return nil
		}
		u := st.Users[it.ID]
		if u == nil {
			u = &eUser{}
			st.Users[it.ID] = u
		}
		if err := mergeInto(u, raw); err != nil {
			return fmt.Errorf("%w: user", connsync.ErrMalformed)
		}
		u.ID = it.ID
		return nil
	})
	if err != nil {
		if cur.Users != "" && deltaGone(err) {
			return out, errDeltaExpired
		}
		return out, fmt.Errorf("entra: users: %w", err)
	}
	groupsURL := cur.Groups
	if groupsURL == "" {
		groupsURL = c.graph("/groups/delta", groupSelect)
	}
	changed := map[string]bool{}
	out.Groups, err = listAll(ctx, c, groupsURL, func(raw json.RawMessage) error {
		var it deltaItem
		if json.Unmarshal(raw, &it) != nil || !validID(it.ID) {
			return nil
		}
		if len(it.Removed) > 0 {
			delete(st.Groups, it.ID)
			delete(changed, it.ID)
			return nil
		}
		g := st.Groups[it.ID]
		if g == nil {
			g = &groupState{}
			st.Groups[it.ID] = g
		}
		if err := mergeInto(&g.G, raw); err != nil {
			return fmt.Errorf("%w: group", connsync.ErrMalformed)
		}
		g.G.ID = it.ID
		changed[it.ID] = true
		return nil
	})
	if err != nil {
		if cur.Groups != "" && deltaGone(err) {
			return out, errDeltaExpired
		}
		return out, fmt.Errorf("entra: groups: %w", err)
	}
	if out.Users == "" || out.Groups == "" {
		return out, fmt.Errorf("%w: no delta link at the end of the delta query", connsync.ErrMalformed)
	}
	// Members of every group that changed (all of them on a full read).
	ids := make([]string, 0, len(changed))
	for id := range changed {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		ms, err := c.readMembers(ctx, id)
		if err != nil {
			return out, err
		}
		st.Groups[id].Members = ms
	}
	return out, nil
}

type directoryObject struct {
	Type string `json:"@odata.type"`
	ID   string `json:"id"`
}

func (c *Connector) readMembers(ctx context.Context, groupID string) ([]member, error) {
	var out []member
	seen := map[member]bool{}
	_, err := listAll(ctx, c, c.graph("/groups/"+url.PathEscape(groupID)+"/members", "$select=id&$top=999"), func(o directoryObject) error {
		if !validID(o.ID) {
			return nil
		}
		var m member
		switch strings.ToLower(o.Type) {
		case "#microsoft.graph.user":
			m = member{"u", o.ID}
		case "#microsoft.graph.group":
			m = member{"g", o.ID}
		case "#microsoft.graph.serviceprincipal":
			m = member{"s", o.ID}
		default:
			return nil // devices, contacts, organizational contacts
		}
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("entra: members of group: %w", err)
	}
	return out, nil
}

// readSignIns reads lastSignInDateTime for every user. Graph answers 403 when
// AuditLog.Read.All is not granted or the tenant has no Entra ID P1/P2: the
// result is then empty and the sync goes on without last sign-in. Any other
// failure is also non-fatal here, since the data is an enrichment.
func (c *Connector) readSignIns(ctx context.Context) map[string]*time.Time {
	out := map[string]*time.Time{}
	type u struct {
		ID     string `json:"id"`
		Signin struct {
			Last       string `json:"lastSignInDateTime"`
			Successful string `json:"lastSuccessfulSignInDateTime"`
		} `json:"signInActivity"`
	}
	_, err := listAll(ctx, c, c.graph("/users", "$select=id,signInActivity&$top=999"), func(x u) error {
		if !validID(x.ID) {
			return nil
		}
		t := parseTime(x.Signin.Successful)
		if t == nil {
			t = parseTime(x.Signin.Last)
		}
		if t != nil {
			out[x.ID] = t
		}
		return nil
	})
	if err != nil && connsync.Status(err) == 403 {
		return map[string]*time.Time{}
	}
	return out // after another failure, what was read so far
}

type appRole struct {
	ID          string `json:"id"`
	Value       string `json:"value"`
	DisplayName string `json:"displayName"`
	IsEnabled   *bool  `json:"isEnabled"`
}

type servicePrincipal struct {
	ID             string    `json:"id"`
	AppID          string    `json:"appId"`
	DisplayName    string    `json:"displayName"`
	OwnerTenant    string    `json:"appOwnerOrganizationId"`
	Type           string    `json:"servicePrincipalType"`
	AccountEnabled *bool     `json:"accountEnabled"`
	Tags           []string  `json:"tags"`
	AppRoles       []appRole `json:"appRoles"`
	assignments    []assignment
	owned          bool // owned by this tenant (not a Microsoft or third-party app)
}

type assignment struct {
	PrincipalID   string `json:"principalId"`
	PrincipalType string `json:"principalType"`
	AppRoleID     string `json:"appRoleId"`
}

// readServicePrincipals lists service principals and, for enterprise apps and
// apps this tenant owns, their app role assignments. It fills st.Apps.
func (c *Connector) readServicePrincipals(ctx context.Context, st *state) ([]*servicePrincipal, error) {
	var sps []*servicePrincipal
	sel := "$select=id,appId,displayName,appOwnerOrganizationId,servicePrincipalType,accountEnabled,tags,appRoles&$top=999"
	_, err := listAll(ctx, c, c.graph("/servicePrincipals", sel), func(sp servicePrincipal) error {
		if validID(sp.ID) {
			sp.owned = strings.EqualFold(sp.OwnerTenant, c.cfg.TenantID)
			sps = append(sps, &sp)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("entra: service principals: %w", err)
	}
	st.Apps = map[string]string{}
	for _, sp := range sps {
		if sp.AppID != "" {
			st.Apps[strings.ToLower(sp.AppID)] = sp.ID
		}
		if !(sp.owned || hasTag(sp.Tags, "WindowsAzureActiveDirectoryIntegratedApp")) {
			continue
		}
		_, err := listAll(ctx, c, c.graph("/servicePrincipals/"+url.PathEscape(sp.ID)+"/appRoleAssignedTo", "$top=999"), func(a assignment) error {
			if validID(a.PrincipalID) {
				sp.assignments = append(sp.assignments, a)
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("entra: app role assignments: %w", err)
		}
	}
	return sps, nil
}

func hasTag(tags []string, t string) bool {
	for _, x := range tags {
		if strings.EqualFold(x, t) {
			return true
		}
	}
	return false
}

type roleDef struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
}

type roleAssignment struct {
	PrincipalID      string `json:"principalId"`
	RoleDefinitionID string `json:"roleDefinitionId"`
}

type dirRoles struct {
	defs        map[string]string // role definition id -> name
	assignments []roleAssignment
}

// readDirectoryRoles reads role definitions and assignments. A 403 (the app
// lacks RoleManagement.Read.Directory) means no role data.
func (c *Connector) readDirectoryRoles(ctx context.Context) (*dirRoles, error) {
	out := &dirRoles{defs: map[string]string{}}
	_, err := listAll(ctx, c, c.graph("/roleManagement/directory/roleDefinitions", "$select=id,displayName"), func(d roleDef) error {
		if d.ID != "" && len(d.ID) <= 64 {
			out.defs[d.ID] = d.DisplayName
		}
		return nil
	})
	if err == nil {
		_, err = listAll(ctx, c, c.graph("/roleManagement/directory/roleAssignments", "$select=principalId,roleDefinitionId"), func(a roleAssignment) error {
			if validID(a.PrincipalID) && a.RoleDefinitionID != "" {
				out.assignments = append(out.assignments, a)
			}
			return nil
		})
	}
	if err != nil {
		if s := connsync.Status(err); s == 403 {
			return &dirRoles{defs: map[string]string{}}, nil
		}
		return nil, fmt.Errorf("entra: directory roles: %w", err)
	}
	return out, nil
}

func (c *Connector) build(st *state, sps []*servicePrincipal, roles *dirRoles, signIn map[string]*time.Time) *connectors.DiscoveryResult {
	res := &connectors.DiscoveryResult{}
	acctOf := map[string]bool{}
	seenIdent := map[string]bool{}
	for _, id := range sortedKeys(st.Users) {
		u := st.Users[id]
		email := u.Mail
		if email == "" && strings.Contains(u.UPN, "@") && !strings.Contains(u.UPN, "#EXT#") {
			email = u.UPN
		}
		xid := u.EmployeeID
		if xid == "" || len(xid) > 128 {
			xid = "entra:" + u.ID
		}
		name := u.DisplayName
		if name == "" {
			name = u.UPN
		}
		if name == "" {
			name = u.ID
		}
		username := u.UPN
		if username == "" {
			username = u.ID
		}
		status := "active"
		if u.AccountEnabled != nil && !*u.AccountEnabled {
			status = "disabled"
		}
		if c.cfg.EmitIdentities && !seenIdent[xid] {
			seenIdent[xid] = true
			res.Identities = append(res.Identities, connectors.IdentityRecord{ExternalID: xid, Name: name, Type: "human",
				Email: strp(email), Department: strp(u.Department), Title: strp(u.JobTitle), Status: "active"})
		}
		attrs := map[string]string{}
		for k, v := range map[string]string{"userPrincipalName": u.UPN, "mail": u.Mail, "employeeId": u.EmployeeID,
			"userType": u.UserType, "department": u.Department, "jobTitle": u.JobTitle} {
			if v != "" {
				attrs[k] = v
			}
		}
		acctOf[id] = true
		res.Accounts = append(res.Accounts, connectors.AccountRecord{System: System, ExternalID: id, Username: username,
			Identity: &connectors.IdentityRef{ExternalID: xid, Email: email}, Kind: "user", Status: status,
			CreatedAt: parseTime(u.Created), LastLoginAt: signIn[id], Attributes: attrs})
	}
	// Service principals owned by this tenant are machine accounts.
	sort.SliceStable(sps, func(i, j int) bool { return sps[i].ID < sps[j].ID })
	for _, sp := range sps {
		if !sp.owned {
			continue
		}
		xid := "entra-sp:" + sp.ID
		name := sp.DisplayName
		if name == "" {
			name = sp.ID
		}
		if c.cfg.EmitIdentities {
			res.Identities = append(res.Identities, connectors.IdentityRecord{ExternalID: xid, Name: name, Type: "service", Status: "active"})
		}
		status := "active"
		if sp.AccountEnabled != nil && !*sp.AccountEnabled {
			status = "disabled"
		}
		acctOf[sp.ID] = true
		res.Accounts = append(res.Accounts, connectors.AccountRecord{System: System, ExternalID: sp.ID, Username: name,
			Identity: &connectors.IdentityRef{ExternalID: xid}, Kind: "service", Status: status,
			Attributes: map[string]string{"appId": sp.AppID, "servicePrincipalType": sp.Type}})
	}
	groupRef := func(id string) connectors.Ref { return connectors.Ref{Kind: "group", System: System, ExternalID: id} }
	acctRef := func(id string) connectors.Ref { return connectors.Ref{Kind: "account", System: System, ExternalID: id} }
	// principal resolves a principal id to a graph reference that exists.
	principal := func(id string) (connectors.Ref, bool) {
		if acctOf[id] {
			return acctRef(id), true
		}
		if _, ok := st.Groups[id]; ok {
			return groupRef(id), true
		}
		return connectors.Ref{}, false
	}
	edges := map[[3]string]bool{}
	addEdge := func(src, dst connectors.Ref, rel string) {
		k := [3]string{src.Kind + ":" + src.ExternalID, dst.Kind + ":" + dst.ExternalID, rel}
		if !edges[k] {
			edges[k] = true
			res.Edges = append(res.Edges, connectors.EdgeRecord{Src: src, Dst: dst, Relation: rel})
		}
	}
	for _, id := range sortedKeys(st.Groups) {
		g := st.Groups[id]
		name := g.G.DisplayName
		if name == "" {
			name = id
		}
		kind := "group"
		switch {
		case g.G.SecurityEnabled != nil && *g.G.SecurityEnabled:
			kind = "security_group"
		case hasTag(g.G.GroupTypes, "Unified"):
			kind = "m365_group"
		}
		res.Groups = append(res.Groups, connectors.GroupRecord{System: System, ExternalID: id, Name: name, Kind: kind,
			Privileged: g.G.IsAssignableToRole != nil && *g.G.IsAssignableToRole, Description: strp(g.G.Description)})
		for _, m := range g.Members {
			switch m.K {
			case "u", "s":
				if acctOf[m.ID] {
					addEdge(acctRef(m.ID), groupRef(id), "member_of")
				}
			case "g":
				if _, ok := st.Groups[m.ID]; ok && m.ID != id {
					addEdge(groupRef(m.ID), groupRef(id), "member_of")
				}
			}
		}
	}
	// Directory roles that have at least one assignment.
	usedRole := map[string]bool{}
	for _, a := range roles.assignments {
		p, ok := principal(a.PrincipalID)
		if !ok {
			continue
		}
		if !usedRole[a.RoleDefinitionID] {
			usedRole[a.RoleDefinitionID] = true
			name := roles.defs[a.RoleDefinitionID]
			if name == "" {
				name = a.RoleDefinitionID
			}
			res.Groups = append(res.Groups, connectors.GroupRecord{System: System, ExternalID: "role:" + a.RoleDefinitionID,
				Name: name, Kind: "role", Privileged: !readerRole(name)})
		}
		addEdge(p, groupRef("role:"+a.RoleDefinitionID), "member_of")
	}
	// Apps and their assignments.
	for _, sp := range sps {
		if !(sp.owned || hasTag(sp.Tags, "WindowsAzureActiveDirectoryIntegratedApp")) {
			continue
		}
		name := sp.DisplayName
		if name == "" {
			name = sp.ID
		}
		rx := "app:" + sp.ID
		res.Resources = append(res.Resources, connectors.ResourceRecord{System: System, ExternalID: rx, Name: name, Kind: "app",
			Tags: nonEmpty(sp.Type)})
		perms := map[string]string{"access": "access"} // key -> action
		for _, r := range sp.AppRoles {
			if r.ID != "" && r.ID != zeroGUID && validID(r.ID) && (r.IsEnabled == nil || *r.IsEnabled) {
				act := r.Value
				if act == "" {
					act = r.DisplayName
				}
				if act == "" {
					act = "role:" + r.ID
				}
				perms[strings.ToLower(r.ID)] = act
			}
		}
		for _, a := range sp.assignments {
			if k := permKey(a.AppRoleID); k != "access" {
				if _, ok := perms[k]; !ok {
					perms[k] = "role:" + k
				}
			}
		}
		for _, k := range sortedKeys(perms) {
			res.Permissions = append(res.Permissions, connectors.PermissionRecord{System: System, ExternalID: rx + ":" + k,
				Action: perms[k], ResourceExternalID: rx})
		}
		for _, a := range sp.assignments {
			p, ok := principal(a.PrincipalID)
			if !ok {
				continue
			}
			perm := connectors.Ref{Kind: "perm", System: System, ExternalID: rx + ":" + permKey(a.AppRoleID)}
			if p.Kind == "group" {
				addEdge(p, perm, "grants")
			} else {
				addEdge(p, perm, "direct_grant")
			}
		}
	}
	return res
}

func permKey(roleID string) string {
	if roleID == "" || roleID == zeroGUID || !validID(roleID) {
		return "access"
	}
	return strings.ToLower(roleID)
}

// readerRole reports whether a directory role name is a read-only role.
func readerRole(name string) bool {
	n := strings.ToLower(name)
	return strings.HasSuffix(n, " reader") || strings.HasSuffix(n, " readers")
}

func nonEmpty(ss ...string) []string {
	out := []string{}
	for _, s := range ss {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
