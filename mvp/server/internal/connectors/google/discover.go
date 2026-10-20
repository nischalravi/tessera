package google

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

const checkpointName = "discover"

// watermarkOverlap is subtracted from the sync start when it is stored as the
// checkpoint cursor, so a clock difference with the source never hides a change.
const watermarkOverlap = 5 * time.Minute

const userFields = "nextPageToken,users(id,primaryEmail,name/fullName,suspended,archived,lastLoginTime,creationTime," +
	"isAdmin,isDelegatedAdmin,orgUnitPath,externalIds,organizations)"

type gUser struct {
	ID           string `json:"id"`
	PrimaryEmail string `json:"primaryEmail"`
	Name         struct {
		FullName string `json:"fullName"`
	} `json:"name"`
	Suspended        bool   `json:"suspended"`
	Archived         bool   `json:"archived"`
	LastLogin        string `json:"lastLoginTime"`
	Created          string `json:"creationTime"`
	IsAdmin          bool   `json:"isAdmin"`
	IsDelegatedAdmin bool   `json:"isDelegatedAdmin"`
	OrgUnitPath      string `json:"orgUnitPath"`
	ExternalIDs      []struct {
		Type       string `json:"type"`
		CustomType string `json:"customType"`
		Value      string `json:"value"`
	} `json:"externalIds"`
	Organizations []struct {
		Department string `json:"department"`
		Title      string `json:"title"`
		Primary    bool   `json:"primary"`
	} `json:"organizations"`
}

// employeeID is the HR employee id Workspace keeps in externalIds, which is
// what correlates the account to the HR identity.
func (u *gUser) employeeID() string {
	for _, e := range u.ExternalIDs {
		if e.Value == "" || len(e.Value) > 128 {
			continue
		}
		if e.Type == "organization" || e.Type == "custom" && strings.Contains(strings.ToLower(e.CustomType), "employee") {
			return e.Value
		}
	}
	return ""
}

// deptTitle is the primary organization's department and title.
func (u *gUser) deptTitle() (dept, title string) {
	for i, o := range u.Organizations {
		if i == 0 || o.Primary {
			dept, title = o.Department, o.Title
		}
		if o.Primary {
			break
		}
	}
	return dept, title
}

type gGroup struct {
	ID                 string `json:"id"`
	Email              string `json:"email"`
	Name               string `json:"name"`
	Description        string `json:"description"`
	Etag               string `json:"etag"`
	DirectMembersCount string `json:"directMembersCount"` // an int64 as a string
}

func (g *gGroup) fingerprint() string { return g.Etag + "|" + g.DirectMembersCount }

// member is a direct member of a group: K is "u" (user) or "g" (group).
type member struct{ K, ID string }

type groupState struct {
	Fingerprint string
	Members     []member
}

// state is the checkpoint snapshot: the members of every group, as of the
// fingerprint each was read at.
type state struct {
	Version int
	Groups  map[string]*groupState
}

const stateVersion = 1

func newState() *state { return &state{Version: stateVersion, Groups: map[string]*groupState{}} }

// Discover implements connectors.Connector.
func (c *Connector) Discover(ctx context.Context) (*connectors.DiscoveryResult, error) {
	start := c.now()
	plan, err := connsync.Decide(ctx, System, checkpointName, start, c.cfg.MaxIncrementalAge)
	if err != nil {
		return nil, err
	}
	prior, full := newState(), plan.Full
	if !full {
		// An unreadable, foreign or impossible checkpoint is not an error: read in full.
		wm, perr := time.Parse(time.RFC3339, plan.Prior.Cursor)
		if perr != nil || wm.After(start.Add(time.Hour)) ||
			connsync.DecodeState(plan.Prior.State, prior) != nil || prior.Version != stateVersion || prior.Groups == nil {
			prior, full = newState(), true
		}
	}
	users, err := c.readUsers(ctx)
	if err != nil {
		return nil, err
	}
	next := newState()
	var groups []*gGroup
	if c.cfg.Groups {
		if groups, err = c.readGroups(ctx); err != nil {
			return nil, err
		}
		for _, g := range groups {
			if old := prior.Groups[g.ID]; old != nil && !full && old.Fingerprint == g.fingerprint() {
				next.Groups[g.ID] = old
				continue
			}
			ms, err := c.readMembers(ctx, g.ID)
			if err != nil {
				return nil, err
			}
			next.Groups[g.ID] = &groupState{Fingerprint: g.fingerprint(), Members: ms}
		}
	}
	var roles *adminRoles
	if c.cfg.Roles {
		if roles, err = c.readRoles(ctx); err != nil {
			return nil, err
		}
	}
	res := c.build(users, groups, next, roles)
	c.save(ctx, next, start, full)
	return res, nil
}

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
	cp := &connsync.Checkpoint{Cursor: start.Add(-watermarkOverlap).UTC().Format(time.RFC3339), State: blob, UpdatedAt: start}
	if full {
		cp.FullSyncAt = &start
	} else if prior, err := store.Load(ctx, System, checkpointName); err == nil && prior != nil {
		cp.FullSyncAt = prior.FullSyncAt
	}
	_ = store.Save(ctx, System, checkpointName, cp)
}

func (c *Connector) listQuery(max int, fields string) url.Values {
	q := url.Values{"maxResults": {strconv.Itoa(max)}}
	if fields != "" {
		q.Set("fields", fields)
	}
	return q
}

func (c *Connector) readUsers(ctx context.Context) ([]*gUser, error) {
	q := c.listQuery(500, userFields)
	q.Set("orderBy", "email")
	if c.cfg.Domain != "" {
		q.Set("domain", c.cfg.Domain)
	} else {
		q.Set("customer", c.cfg.Customer)
	}
	type resp struct {
		Users []gUser `json:"users"`
		Next  string  `json:"nextPageToken"`
	}
	var out []*gUser
	seen := map[string]bool{}
	err := paged(ctx, c, c.dir("/users", q), func(r *resp) string { return r.Next }, func(r *resp) error {
		for i := range r.Users {
			u := &r.Users[i]
			if u.ID == "" || len(u.ID) > 64 || seen[u.ID] {
				continue
			}
			seen[u.ID] = true
			out = append(out, u)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("google: users: %w", err)
	}
	return out, nil
}

// readGroups lists the groups. A 403 means the delegation or the administrator
// lacks the group scope: the sync goes on without groups.
func (c *Connector) readGroups(ctx context.Context) ([]*gGroup, error) {
	q := c.listQuery(200, "nextPageToken,groups(id,email,name,description,etag,directMembersCount)")
	if c.cfg.Domain != "" {
		q.Set("domain", c.cfg.Domain)
	} else {
		q.Set("customer", c.cfg.Customer)
	}
	type resp struct {
		Groups []gGroup `json:"groups"`
		Next   string   `json:"nextPageToken"`
	}
	var out []*gGroup
	seen := map[string]bool{}
	err := paged(ctx, c, c.dir("/groups", q), func(r *resp) string { return r.Next }, func(r *resp) error {
		for i := range r.Groups {
			g := &r.Groups[i]
			if g.ID != "" && len(g.ID) <= 64 && !seen[g.ID] {
				seen[g.ID] = true
				out = append(out, g)
			}
		}
		return nil
	})
	if err != nil {
		if connsync.Status(err) == 403 && !errors.Is(err, connsync.ErrRateLimited) {
			return nil, nil
		}
		return nil, fmt.Errorf("google: groups: %w", err)
	}
	return out, nil
}

// readMembers lists the direct members of a group. A group deleted since it was
// listed (404) or one the administrator may not read (403) has no members here.
func (c *Connector) readMembers(ctx context.Context, groupID string) ([]member, error) {
	q := c.listQuery(200, "nextPageToken,members(id,type)")
	type resp struct {
		Members []struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		} `json:"members"`
		Next string `json:"nextPageToken"`
	}
	var out []member
	seen := map[member]bool{}
	err := paged(ctx, c, c.dir("/groups/"+url.PathEscape(groupID)+"/members", q), func(r *resp) string { return r.Next }, func(r *resp) error {
		for _, m := range r.Members {
			if m.ID == "" || len(m.ID) > 64 {
				continue
			}
			var x member
			switch strings.ToUpper(m.Type) {
			case "USER":
				x = member{"u", m.ID}
			case "GROUP":
				x = member{"g", m.ID}
			default:
				continue // CUSTOMER (everyone in the domain) and EXTERNAL have no account here
			}
			if !seen[x] {
				seen[x] = true
				out = append(out, x)
			}
		}
		return nil
	})
	if err != nil {
		if s := connsync.Status(err); (s == 403 && !errors.Is(err, connsync.ErrRateLimited)) || s == 404 {
			return nil, nil
		}
		return nil, fmt.Errorf("google: members of group: %w", err)
	}
	return out, nil
}

type adminRole struct {
	ID    string `json:"roleId"`
	Name  string `json:"roleName"`
	Desc  string `json:"roleDescription"`
	Super bool   `json:"isSuperAdminRole"`
}

type roleAssignment struct {
	RoleID       string `json:"roleId"`
	AssignedTo   string `json:"assignedTo"`
	AssigneeType string `json:"assigneeType"` // user or group
}

type adminRoles struct {
	defs        map[string]adminRole
	assignments []roleAssignment
}

// readRoles reads role definitions and assignments. A 403 (no
// rolemanagement.readonly, or an administrator who may not read roles) means
// no role data.
func (c *Connector) readRoles(ctx context.Context) (*adminRoles, error) {
	out := &adminRoles{defs: map[string]adminRole{}}
	type rolesResp struct {
		Items []adminRole `json:"items"`
		Next  string      `json:"nextPageToken"`
	}
	type assignResp struct {
		Items []roleAssignment `json:"items"`
		Next  string           `json:"nextPageToken"`
	}
	err := paged(ctx, c, c.dir("/customer/"+c.cfg.Customer+"/roles", c.listQuery(100, "")), func(r *rolesResp) string { return r.Next },
		func(r *rolesResp) error {
			for _, d := range r.Items {
				if d.ID != "" && len(d.ID) <= 64 {
					out.defs[d.ID] = d
				}
			}
			return nil
		})
	if err == nil {
		err = paged(ctx, c, c.dir("/customer/"+c.cfg.Customer+"/roleassignments", c.listQuery(200, "")), func(r *assignResp) string { return r.Next },
			func(r *assignResp) error {
				for _, a := range r.Items {
					if a.RoleID != "" && a.AssignedTo != "" && len(a.AssignedTo) <= 64 && len(a.RoleID) <= 64 {
						out.assignments = append(out.assignments, a)
					}
				}
				return nil
			})
	}
	if err != nil {
		if connsync.Status(err) == 403 && !errors.Is(err, connsync.ErrRateLimited) {
			return &adminRoles{defs: map[string]adminRole{}}, nil
		}
		return nil, fmt.Errorf("google: admin roles: %w", err)
	}
	return out, nil
}

func (c *Connector) build(users []*gUser, groups []*gGroup, st *state, roles *adminRoles) *connectors.DiscoveryResult {
	res := &connectors.DiscoveryResult{}
	acctOf := map[string]bool{}
	seenIdent := map[string]bool{}
	sort.Slice(users, func(i, j int) bool { return users[i].ID < users[j].ID })
	for _, u := range users {
		xid := u.employeeID()
		if xid == "" {
			xid = "google:" + u.ID
		}
		name := u.Name.FullName
		if name == "" {
			name = u.PrimaryEmail
		}
		if name == "" {
			name = u.ID
		}
		username := u.PrimaryEmail
		if username == "" {
			username = u.ID
		}
		status := "active"
		if u.Suspended || u.Archived {
			status = "disabled"
		}
		dept, title := u.deptTitle()
		if c.cfg.EmitIdentities && !seenIdent[xid] {
			seenIdent[xid] = true
			res.Identities = append(res.Identities, connectors.IdentityRecord{ExternalID: xid, Name: name, Type: "human",
				Email: strp(u.PrimaryEmail), Department: strp(dept), Title: strp(title), Status: "active"})
		}
		attrs := map[string]string{}
		for k, v := range map[string]string{"primaryEmail": u.PrimaryEmail, "employeeId": u.employeeID(), "orgUnitPath": u.OrgUnitPath,
			"department": dept, "title": title} {
			if v != "" {
				attrs[k] = v
			}
		}
		for k, v := range map[string]bool{"suspended": u.Suspended, "archived": u.Archived, "isAdmin": u.IsAdmin, "isDelegatedAdmin": u.IsDelegatedAdmin} {
			if v {
				attrs[k] = "true"
			}
		}
		acctOf[u.ID] = true
		res.Accounts = append(res.Accounts, connectors.AccountRecord{System: System, ExternalID: u.ID, Username: username,
			Identity: &connectors.IdentityRef{ExternalID: xid, Email: u.PrimaryEmail}, Kind: "user", Status: status,
			CreatedAt: parseTime(u.Created), LastLoginAt: parseTime(u.LastLogin), Attributes: attrs})
	}
	groupRef := func(id string) connectors.Ref { return connectors.Ref{Kind: "group", System: System, ExternalID: id} }
	acctRef := func(id string) connectors.Ref { return connectors.Ref{Kind: "account", System: System, ExternalID: id} }
	known := map[string]bool{}
	for _, g := range groups {
		known[g.ID] = true
	}
	edges := map[[3]string]bool{}
	addEdge := func(src, dst connectors.Ref, rel string) {
		k := [3]string{src.Kind + ":" + src.ExternalID, dst.Kind + ":" + dst.ExternalID, rel}
		if !edges[k] {
			edges[k] = true
			res.Edges = append(res.Edges, connectors.EdgeRecord{Src: src, Dst: dst, Relation: rel})
		}
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].ID < groups[j].ID })
	for _, g := range groups {
		name := g.Name
		if name == "" {
			name = g.Email
		}
		if name == "" {
			name = g.ID
		}
		res.Groups = append(res.Groups, connectors.GroupRecord{System: System, ExternalID: g.ID, Name: name, Kind: "group",
			Description: strp(g.Description)})
		gs := st.Groups[g.ID]
		if gs == nil {
			continue
		}
		for _, m := range gs.Members {
			switch m.K {
			case "u":
				if acctOf[m.ID] {
					addEdge(acctRef(m.ID), groupRef(g.ID), "member_of")
				}
			case "g":
				if known[m.ID] && m.ID != g.ID {
					addEdge(groupRef(m.ID), groupRef(g.ID), "member_of")
				}
			}
		}
	}
	if roles != nil {
		usedRole := map[string]bool{}
		for _, a := range roles.assignments {
			var p connectors.Ref
			switch {
			case strings.EqualFold(a.AssigneeType, "group") && known[a.AssignedTo]:
				p = groupRef(a.AssignedTo)
			case !strings.EqualFold(a.AssigneeType, "group") && acctOf[a.AssignedTo]:
				p = acctRef(a.AssignedTo)
			default:
				continue
			}
			if !usedRole[a.RoleID] {
				usedRole[a.RoleID] = true
				d := roles.defs[a.RoleID]
				name := d.Name
				if name == "" {
					name = a.RoleID
				}
				res.Groups = append(res.Groups, connectors.GroupRecord{System: System, ExternalID: "role:" + a.RoleID, Name: name,
					Kind: "role", Privileged: d.Super || !readerRole(name), Description: strp(d.Desc)})
			}
			addEdge(p, groupRef("role:"+a.RoleID), "member_of")
		}
	}
	return res
}

// readerRole reports whether a role name is a read-only role.
func readerRole(name string) bool {
	n := strings.ToLower(name)
	return strings.HasSuffix(n, " reader") || strings.HasSuffix(n, " readers") || strings.HasSuffix(n, "_reader_role")
}
