package okta

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

const checkpointName = "discover"

// watermarkSkew is subtracted from the time a sync started to form the next
// watermark: Okta search is eventually consistent, and re-reading a few
// minutes of changes is harmless (the merge is idempotent).
const watermarkSkew = 5 * time.Minute

// Okta API shapes (only the fields read).
type apiUser struct {
	ID          string `json:"id"`
	Status      string `json:"status"`
	Created     string `json:"created"`
	LastLogin   string `json:"lastLogin"`
	LastUpdated string `json:"lastUpdated"`
	Profile     struct {
		Login          string `json:"login"`
		Email          string `json:"email"`
		FirstName      string `json:"firstName"`
		LastName       string `json:"lastName"`
		DisplayName    string `json:"displayName"`
		EmployeeNumber string `json:"employeeNumber"`
		Department     string `json:"department"`
		Title          string `json:"title"`
		ManagerID      string `json:"managerId"`
		UserType       string `json:"userType"`
	} `json:"profile"`
}

type apiGroup struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Profile struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	} `json:"profile"`
}

type apiApp struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	Name       string `json:"name"`
	Status     string `json:"status"`
	SignOnMode string `json:"signOnMode"`
	// The fields below are read only for agent discovery (agents.go).
	Created  string `json:"created"`
	Settings struct {
		OAuthClient struct {
			ApplicationType string `json:"application_type"`
		} `json:"oauthClient"`
	} `json:"settings"`
	Credentials struct {
		OAuthClient struct {
			ClientID string `json:"client_id"`
		} `json:"oauthClient"`
	} `json:"credentials"`
	Profile map[string]any `json:"profile"`
}

type apiAppUser struct {
	ID    string `json:"id"`
	Scope string `json:"scope"`
}

type apiRole struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Type   string `json:"type"`
	Status string `json:"status"`
}

type apiAssignee struct {
	ID string `json:"id"`
}

// Snapshot records. They are stored as the checkpoint state, so they hold only
// normalised data (no credentials, no raw profile).
type uRec struct {
	Ident     connectors.IdentityRecord
	Acct      connectors.AccountRecord
	ManagerID string
}

type gRec struct {
	Rec     connectors.GroupRecord
	Members []string // Okta user ids
	Roles   []string // role keys
}

type state struct {
	Version int
	Users   map[string]*uRec
	Groups  map[string]*gRec
	// RoleRecs are the administrator role groups seen on groups.
	RoleRecs map[string]connectors.GroupRecord
}

const stateVersion = 1

func newState() *state {
	return &state{Version: stateVersion, Users: map[string]*uRec{}, Groups: map[string]*gRec{}, RoleRecs: map[string]connectors.GroupRecord{}}
}

// Discover implements connectors.Connector.
func (c *Connector) Discover(ctx context.Context) (*connectors.DiscoveryResult, error) {
	start := c.now()
	plan, err := connsync.Decide(ctx, System, checkpointName, start, c.cfg.MaxIncrementalAge)
	if err != nil {
		return nil, err
	}
	st := newState()
	incremental := !plan.Full
	if incremental {
		if err := connsync.DecodeState(plan.Prior.State, st); err != nil || st.Version != stateVersion || st.Users == nil || st.Groups == nil {
			st, incremental = newState(), false // unreadable snapshot: read everything
		}
	}
	var since string
	if incremental {
		since = plan.Prior.Cursor
		if _, err := time.Parse(time.RFC3339, since); err != nil {
			st, incremental = newState(), false
		}
	}
	if err := c.readUsersAndGroups(ctx, st, incremental, since); err != nil {
		return nil, err
	}
	apps, err := c.readApps(ctx)
	if err != nil {
		return nil, err
	}
	userRoles, err := c.readUserRoles(ctx)
	if err != nil {
		return nil, err
	}
	res := c.build(st, apps, userRoles)
	if c.cfg.DiscoverAgents {
		if err := c.discoverAgents(ctx, apps, res); err != nil {
			return nil, err
		}
	}
	c.save(ctx, st, start, !incremental)
	return res, nil
}

// save stores the new checkpoint. A failure to snapshot (too large) only means
// the next sync reads everything; it never fails the sync.
func (c *Connector) save(ctx context.Context, st *state, start time.Time, full bool) {
	store := connsync.StoreFrom(ctx)
	if store == nil {
		return
	}
	blob, err := connsync.EncodeState(st)
	if err != nil {
		_ = store.Delete(ctx, System, checkpointName)
		return
	}
	cp := &connsync.Checkpoint{Cursor: start.Add(-watermarkSkew).UTC().Format(time.RFC3339), State: blob, UpdatedAt: start}
	if full {
		cp.FullSyncAt = &start
	} else if prior, err := store.Load(ctx, System, checkpointName); err == nil && prior != nil {
		cp.FullSyncAt = prior.FullSyncAt
	}
	_ = store.Save(ctx, System, checkpointName, cp)
}

func (c *Connector) readUsersAndGroups(ctx context.Context, st *state, incremental bool, since string) error {
	addUser := func(u apiUser) error {
		if !validID(u.ID) {
			return nil
		}
		st.Users[u.ID] = c.userRec(u)
		return nil
	}
	changedGroups := map[string]bool{}
	addGroup := func(g apiGroup) error {
		if !validID(g.ID) {
			return nil
		}
		prev := st.Groups[g.ID]
		rec := connectors.GroupRecord{System: System, ExternalID: "group:" + g.ID, Name: g.Profile.Name, Kind: "group",
			Description: strp(g.Profile.Description)}
		if rec.Name == "" {
			rec.Name = g.ID
		}
		if prev == nil {
			prev = &gRec{}
			st.Groups[g.ID] = prev
		}
		prev.Rec = rec
		changedGroups[g.ID] = true
		return nil
	}
	q := url.Values{"limit": {"200"}}
	if incremental {
		q.Set("search", fmt.Sprintf(`lastUpdated gt "%s"`, since))
		if err := list(ctx, c, c.path("/api/v1/users", q), addUser); err != nil {
			return fmt.Errorf("okta: users: %w", err)
		}
		gq := url.Values{"limit": {"200"}, "search": {fmt.Sprintf(`lastUpdated gt "%s" or lastMembershipUpdated gt "%s"`, since, since)}}
		if err := list(ctx, c, c.path("/api/v1/groups", gq), addGroup); err != nil {
			return fmt.Errorf("okta: groups: %w", err)
		}
	} else {
		if err := list(ctx, c, c.path("/api/v1/users", q), addUser); err != nil {
			return fmt.Errorf("okta: users: %w", err)
		}
		// Deprovisioned users are not in the default list.
		dq := url.Values{"limit": {"200"}, "search": {`status eq "DEPROVISIONED"`}}
		if err := list(ctx, c, c.path("/api/v1/users", dq), addUser); err != nil {
			return fmt.Errorf("okta: deprovisioned users: %w", err)
		}
		if err := list(ctx, c, c.path("/api/v1/groups", url.Values{"limit": {"200"}}), addGroup); err != nil {
			return fmt.Errorf("okta: groups: %w", err)
		}
	}
	// Members and role assignments of every group that was (re)read.
	ids := make([]string, 0, len(changedGroups))
	for id := range changedGroups {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, gid := range ids {
		g := st.Groups[gid]
		g.Members = g.Members[:0]
		seen := map[string]bool{}
		err := list(ctx, c, c.path("/api/v1/groups/"+url.PathEscape(gid)+"/users", url.Values{"limit": {"1000"}}), func(u apiUser) error {
			if validID(u.ID) && !seen[u.ID] {
				seen[u.ID] = true
				g.Members = append(g.Members, u.ID)
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("okta: members of group: %w", err)
		}
		g.Roles = g.Roles[:0]
		var roles []apiRole
		if _, err := c.api.GetJSON(ctx, c.path("/api/v1/groups/"+url.PathEscape(gid)+"/roles", nil), nil, &roles); err != nil {
			// A forbidden or unknown role listing is not fatal: no roles recorded.
			if s := connsync.Status(err); s != 403 && s != 404 {
				return fmt.Errorf("okta: roles of group: %w", err)
			}
			continue
		}
		for _, r := range roles {
			if key, rec, ok := roleRecord(r); ok {
				g.Roles = append(g.Roles, key)
				st.RoleRecs[key] = rec
			}
		}
	}
	return nil
}

func (c *Connector) userRec(u apiUser) *uRec {
	p := u.Profile
	email := p.Email
	if email == "" && strings.Contains(p.Login, "@") {
		email = p.Login
	}
	xid := p.EmployeeNumber
	if xid == "" || len(xid) > 128 {
		xid = "okta:" + u.ID
	}
	name := p.DisplayName
	if name == "" {
		name = strings.TrimSpace(p.FirstName + " " + p.LastName)
	}
	if name == "" {
		name = p.Login
	}
	if name == "" {
		name = u.ID
	}
	status := "active"
	switch u.Status {
	case "SUSPENDED", "DEPROVISIONED", "LOCKED_OUT":
		status = "disabled"
	}
	login := p.Login
	if login == "" {
		login = u.ID
	}
	attrs := map[string]string{}
	for k, v := range map[string]string{"login": p.Login, "email": p.Email, "employeeNumber": p.EmployeeNumber,
		"status": u.Status, "userType": p.UserType, "department": p.Department, "title": p.Title, "managerId": p.ManagerID} {
		if v != "" {
			attrs[k] = v
		}
	}
	ref := &connectors.IdentityRef{ExternalID: xid, Email: email}
	return &uRec{
		Ident: connectors.IdentityRecord{ExternalID: xid, Name: name, Type: "human", Email: strp(email), Department: strp(p.Department),
			Title: strp(p.Title), Status: "active"},
		Acct: connectors.AccountRecord{System: System, ExternalID: u.ID, Username: login, Identity: ref, Kind: "user", Status: status,
			CreatedAt: parseTime(u.Created), LastLoginAt: parseTime(u.LastLogin), Attributes: attrs},
		ManagerID: p.ManagerID,
	}
}

// readOnlyRoles are the Okta role types that grant no administrative change
// access; every other role is marked privileged.
var readOnlyRoles = map[string]bool{"READ_ONLY_ADMIN": true, "REPORT_ADMIN": true}

func roleRecord(r apiRole) (string, connectors.GroupRecord, bool) {
	t := strings.ToUpper(r.Type)
	if t == "" || len(t) > 64 || (r.Status != "" && r.Status != "ACTIVE") {
		return "", connectors.GroupRecord{}, false
	}
	key := t
	name := r.Label
	if t == "CUSTOM" || strings.HasPrefix(t, "CUSTOM") {
		if !validID(r.ID) {
			return "", connectors.GroupRecord{}, false
		}
		key = "CUSTOM:" + r.ID
	}
	if name == "" {
		name = t
	}
	return key, connectors.GroupRecord{System: System, ExternalID: "role:" + key, Name: name, Kind: "role",
		Privileged: !readOnlyRoles[t]}, true
}

type appAssign struct {
	app    apiApp
	users  []string
	groups []string
}

func (c *Connector) readApps(ctx context.Context) ([]*appAssign, error) {
	var apps []*appAssign
	q := url.Values{"limit": {"200"}, "filter": {`status eq "ACTIVE"`}}
	err := list(ctx, c, c.path("/api/v1/apps", q), func(a apiApp) error {
		if validID(a.ID) {
			apps = append(apps, &appAssign{app: a})
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("okta: apps: %w", err)
	}
	for _, a := range apps {
		id := url.PathEscape(a.app.ID)
		err := list(ctx, c, c.path("/api/v1/apps/"+id+"/users", url.Values{"limit": {"500"}}), func(u apiAppUser) error {
			// scope GROUP means the user got the app through a group; the group edge covers it.
			if validID(u.ID) && strings.EqualFold(u.Scope, "USER") {
				a.users = append(a.users, u.ID)
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("okta: app users: %w", err)
		}
		err = list(ctx, c, c.path("/api/v1/apps/"+id+"/groups", url.Values{"limit": {"200"}}), func(g apiGroup) error {
			if validID(g.ID) {
				a.groups = append(a.groups, g.ID)
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("okta: app groups: %w", err)
		}
	}
	return apps, nil
}

// readUserRoles reads the administrator roles of every user that has any.
// A 403 (the app lacks okta.roles.read) degrades to no role data.
func (c *Connector) readUserRoles(ctx context.Context) (map[string][]apiRole, error) {
	out := map[string][]apiRole{}
	var assignees []string
	var page struct {
		Value []apiAssignee `json:"value"`
	}
	err := connsync.Walk(ctx, c.base, c.path("/api/v1/iam/assignees/users", url.Values{"limit": {"200"}}),
		func(ctx context.Context, pageURL string) (string, error) {
			page.Value = nil
			h, err := c.api.GetJSON(ctx, pageURL, nil, &page)
			if err != nil {
				return "", err
			}
			for _, a := range page.Value {
				if validID(a.ID) {
					assignees = append(assignees, a.ID)
				}
			}
			return nextLink(h), nil
		})
	if err != nil {
		if s := connsync.Status(err); s == 403 || s == 404 {
			return out, nil
		}
		return nil, fmt.Errorf("okta: role assignees: %w", err)
	}
	for _, id := range assignees {
		var roles []apiRole
		if _, err := c.api.GetJSON(ctx, c.path("/api/v1/users/"+url.PathEscape(id)+"/roles", nil), nil, &roles); err != nil {
			if s := connsync.Status(err); s == 403 || s == 404 {
				continue
			}
			return nil, fmt.Errorf("okta: user roles: %w", err)
		}
		out[id] = roles
	}
	return out, nil
}

// build turns the snapshot, apps and roles into a full DiscoveryResult. Edges
// are produced only between objects that exist in the result.
func (c *Connector) build(st *state, apps []*appAssign, userRoles map[string][]apiRole) *connectors.DiscoveryResult {
	res := &connectors.DiscoveryResult{}
	uids := sortedKeys(st.Users)
	xidOf := map[string]string{}
	for _, id := range uids {
		xidOf[id] = st.Users[id].Ident.ExternalID
	}
	seenIdent := map[string]bool{}
	for _, id := range uids {
		u := st.Users[id]
		if c.cfg.EmitIdentities && !seenIdent[u.Ident.ExternalID] {
			seenIdent[u.Ident.ExternalID] = true
			rec := u.Ident
			if u.ManagerID != "" {
				mx := u.ManagerID
				if x, ok := xidOf[mx]; ok {
					mx = x
				}
				rec.Manager = &connectors.IdentityRef{ExternalID: mx}
			}
			res.Identities = append(res.Identities, rec)
		}
		res.Accounts = append(res.Accounts, u.Acct)
	}
	acct := func(id string) (connectors.Ref, bool) {
		_, ok := st.Users[id]
		return connectors.Ref{Kind: "account", System: System, ExternalID: id}, ok
	}
	roleGroups := map[string]connectors.GroupRecord{}
	for k, r := range st.RoleRecs {
		roleGroups[k] = r
	}
	for _, rs := range userRoles {
		for _, r := range rs {
			if key, rec, ok := roleRecord(r); ok {
				roleGroups[key] = rec
			}
		}
	}
	edges := map[[3]string]bool{}
	addEdge := func(src, dst connectors.Ref, rel string) {
		k := [3]string{src.Kind + ":" + src.ExternalID, dst.Kind + ":" + dst.ExternalID, rel}
		if !edges[k] {
			edges[k] = true
			res.Edges = append(res.Edges, connectors.EdgeRecord{Src: src, Dst: dst, Relation: rel})
		}
	}
	gids := sortedKeys(st.Groups)
	groupRef := func(id string) connectors.Ref {
		return connectors.Ref{Kind: "group", System: System, ExternalID: "group:" + id}
	}
	usedRoles := map[string]bool{}
	for _, id := range gids {
		g := st.Groups[id]
		res.Groups = append(res.Groups, g.Rec)
		for _, m := range g.Members {
			if a, ok := acct(m); ok {
				addEdge(a, groupRef(id), "member_of")
			}
		}
		for _, rk := range g.Roles {
			if _, ok := roleGroups[rk]; ok {
				usedRoles[rk] = true
				addEdge(groupRef(id), roleRef(rk), "member_of")
			}
		}
	}
	for _, id := range sortedKeys(userRoles) {
		a, ok := acct(id)
		if !ok {
			continue
		}
		for _, r := range userRoles[id] {
			if key, _, ok := roleRecord(r); ok {
				usedRoles[key] = true
				addEdge(a, roleRef(key), "member_of")
			}
		}
	}
	for _, k := range sortedKeys(roleGroups) {
		if usedRoles[k] {
			res.Groups = append(res.Groups, roleGroups[k])
		}
	}
	sort.SliceStable(apps, func(i, j int) bool { return apps[i].app.ID < apps[j].app.ID })
	for _, a := range apps {
		name := a.app.Label
		if name == "" {
			name = a.app.Name
		}
		rx := "app:" + a.app.ID
		res.Resources = append(res.Resources, connectors.ResourceRecord{System: System, ExternalID: rx, Name: name, Kind: "app",
			Tags: nonEmpty(a.app.Name, strings.ToLower(a.app.SignOnMode))})
		perm := connectors.Ref{Kind: "perm", System: System, ExternalID: rx + ":access"}
		res.Permissions = append(res.Permissions, connectors.PermissionRecord{System: System, ExternalID: perm.ExternalID,
			Action: "access", ResourceExternalID: rx})
		for _, u := range a.users {
			if ar, ok := acct(u); ok {
				addEdge(ar, perm, "direct_grant")
			}
		}
		for _, g := range a.groups {
			if _, ok := st.Groups[g]; ok {
				addEdge(groupRef(g), perm, "grants")
			}
		}
	}
	return res
}

func roleRef(key string) connectors.Ref {
	return connectors.Ref{Kind: "group", System: System, ExternalID: "role:" + key}
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
