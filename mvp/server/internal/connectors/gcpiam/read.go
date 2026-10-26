package gcpiam

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors"
	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

// Resource is an organization, a folder or a project.
type Resource struct {
	Name        string // organizations/<id>, folders/<id> or projects/<project id>
	DisplayName string
	Parent      string
}

// Kind is gcp_organization, gcp_folder or gcp_project.
func (r Resource) Kind() string {
	switch {
	case strings.HasPrefix(r.Name, "organizations/"):
		return "gcp_organization"
	case strings.HasPrefix(r.Name, "folders/"):
		return "gcp_folder"
	}
	return "gcp_project"
}

// Binding is one binding of a policy.
type Binding struct {
	Role        string
	Members     []string
	Conditional bool
	// ConditionTitle and ConditionExpr identify the condition: two bindings of one role that differ
	// only by condition are different permissions.
	ConditionTitle, ConditionExpr string
}

// Role is what roles.get returned for a bound role.
type Role struct {
	Name, Title string
	Permissions []string
	Known       bool // false: the role could not be read; privilege is judged by the known-privileged list and its name
}

// Snapshot is what one read found.
type Snapshot struct {
	Resources []Resource
	Policies  map[string][]Binding // by resource name
	Roles     map[string]Role
	Accounts  map[string]ServiceAccount // service accounts of the projects, by email
	Partial   string
}

// ServiceAccount is a service account of a project.
type ServiceAccount struct {
	Email, DisplayName, Project string
	Disabled                    bool
}

func (c *Connector) u(base *url.URL, path string, q url.Values) string {
	x := *base
	x.Path = strings.TrimRight(base.Path, "/") + path
	x.RawQuery = q.Encode()
	return x.String()
}

func (c *Connector) get(ctx context.Context, base *url.URL, path string, q url.Values, v any) error {
	resp, err := c.api.Do(ctx, http.MethodGet, c.u(base, path, q), nil, nil)
	if err != nil {
		return err
	}
	return connsync.DecodeJSON(resp.Body, v)
}

// each calls fn for every page of a list operation that pages with pageToken and nextPageToken. The
// token goes in the query of the same URL, so a response cannot redirect the Authorization header.
func (c *Connector) each(ctx context.Context, base *url.URL, path string, q url.Values, fn func(raw json.RawMessage) (next string, err error)) error {
	seen := map[string]bool{}
	token := ""
	for n := 0; n < connsync.MaxPages; n++ {
		qq := url.Values{}
		for k, v := range q {
			qq[k] = v
		}
		if token != "" {
			qq.Set("pageToken", token)
		}
		resp, err := c.api.Do(ctx, http.MethodGet, c.u(base, path, qq), nil, nil)
		if err != nil {
			return err
		}
		if token, err = fn(json.RawMessage(resp.Body)); err != nil {
			return err
		}
		if token == "" {
			return nil
		}
		if seen[token] {
			return connsync.ErrPaging
		}
		seen[token] = true
	}
	return connsync.ErrPaging
}

func (c *Connector) listFolders(ctx context.Context, parent string) ([]Resource, error) {
	var out []Resource
	err := c.each(ctx, c.crm, "/v3/folders", url.Values{"parent": {parent}, "pageSize": {"1000"}}, func(raw json.RawMessage) (string, error) {
		var p struct {
			Folders []struct {
				Name, DisplayName, State string
			} `json:"folders"`
			Next string `json:"nextPageToken"`
		}
		if err := connsync.DecodeJSON(raw, &p); err != nil {
			return "", err
		}
		for _, f := range p.Folders {
			if (f.State == "" || f.State == "ACTIVE") && orgRE.MatchString(strings.TrimPrefix(f.Name, "folders/")) && strings.HasPrefix(f.Name, "folders/") {
				out = append(out, Resource{Name: f.Name, DisplayName: f.DisplayName, Parent: parent})
			}
		}
		return p.Next, nil
	})
	return out, err
}

func (c *Connector) listProjects(ctx context.Context, parent string) ([]Resource, error) {
	var out []Resource
	err := c.each(ctx, c.crm, "/v3/projects", url.Values{"parent": {parent}, "pageSize": {"1000"}}, func(raw json.RawMessage) (string, error) {
		var p struct {
			Projects []struct {
				ProjectID   string `json:"projectId"`
				DisplayName string `json:"displayName"`
				State       string `json:"state"`
			} `json:"projects"`
			Next string `json:"nextPageToken"`
		}
		if err := connsync.DecodeJSON(raw, &p); err != nil {
			return "", err
		}
		for _, pr := range p.Projects {
			if (pr.State == "" || pr.State == "ACTIVE") && projectRE.MatchString(pr.ProjectID) {
				out = append(out, Resource{Name: "projects/" + pr.ProjectID, DisplayName: pr.DisplayName, Parent: parent})
			}
		}
		return p.Next, nil
	})
	return out, err
}

// Resources returns the resources to read: the organization and every folder and project below it,
// the configured folders (walked) and projects.
func (c *Connector) Resources(ctx context.Context) ([]Resource, error) {
	var out []Resource
	seen := map[string]bool{}
	add := func(r Resource) bool {
		if seen[r.Name] {
			return false
		}
		seen[r.Name] = true
		out = append(out, r)
		return true
	}
	var walk func(parent string, depth int) error
	walk = func(parent string, depth int) error {
		if depth > 10 {
			return errors.New("gcpiam: folders nest deeper than 10 levels")
		}
		projects, err := c.listProjects(ctx, parent)
		if err != nil {
			return fmt.Errorf("projects of %s: %w", parent, err)
		}
		for _, p := range projects {
			add(p)
		}
		folders, err := c.listFolders(ctx, parent)
		if err != nil {
			return fmt.Errorf("folders of %s: %w", parent, err)
		}
		for _, f := range folders {
			if add(f) {
				if len(out) > maxResources {
					return errors.New("gcpiam: more than 20000 resources; narrow the organization, folders and projects")
				}
				if err := walk(f.Name, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if c.cfg.OrganizationID != "" {
		org := "organizations/" + c.cfg.OrganizationID
		add(Resource{Name: org, DisplayName: org})
		if err := walk(org, 0); err != nil {
			return nil, err
		}
	}
	for _, f := range c.cfg.FolderIDs {
		name := "folders/" + f
		if add(Resource{Name: name, DisplayName: name}) {
			if err := walk(name, 0); err != nil {
				return nil, err
			}
		}
	}
	for _, p := range c.cfg.ProjectIDs {
		add(Resource{Name: "projects/" + p, DisplayName: p})
	}
	return out, nil
}

// policy reads the IAM policy of one resource (version 3, so conditional bindings are returned).
func (c *Connector) policy(ctx context.Context, name string) ([]Binding, error) {
	body := []byte(`{"options":{"requestedPolicyVersion":3}}`)
	resp, err := c.api.Do(ctx, http.MethodPost, c.u(c.crm, "/v3/"+name+":getIamPolicy", nil), http.Header{"Content-Type": {"application/json"}}, body)
	if err != nil {
		return nil, err
	}
	var p struct {
		Bindings []struct {
			Role      string   `json:"role"`
			Members   []string `json:"members"`
			Condition *struct {
				Title      string `json:"title"`
				Expression string `json:"expression"`
			} `json:"condition"`
		} `json:"bindings"`
	}
	if err := connsync.DecodeJSON(resp.Body, &p); err != nil {
		return nil, err
	}
	var out []Binding
	for _, b := range p.Bindings {
		if b.Role == "" || len(b.Members) == 0 {
			continue
		}
		bd := Binding{Role: b.Role, Members: b.Members, Conditional: b.Condition != nil}
		if b.Condition != nil {
			bd.ConditionTitle, bd.ConditionExpr = b.Condition.Title, b.Condition.Expression
		}
		out = append(out, bd)
	}
	return out, nil
}

func (c *Connector) role(ctx context.Context, name string) Role {
	r := Role{Name: name}
	if !roleRE.MatchString(name) {
		return r
	}
	var v struct {
		Title       string   `json:"title"`
		Permissions []string `json:"includedPermissions"`
	}
	if c.get(ctx, c.iam, "/v1/"+name, nil, &v) != nil {
		return r
	}
	r.Title, r.Permissions, r.Known = v.Title, v.Permissions, true
	return r
}

func (c *Connector) serviceAccounts(ctx context.Context, project string, into map[string]ServiceAccount) error {
	return c.each(ctx, c.iam, "/v1/projects/"+project+"/serviceAccounts", url.Values{"pageSize": {"100"}}, func(raw json.RawMessage) (string, error) {
		var p struct {
			Accounts []struct {
				Email       string `json:"email"`
				DisplayName string `json:"displayName"`
				Disabled    bool   `json:"disabled"`
			} `json:"accounts"`
			Next string `json:"nextPageToken"`
		}
		if err := connsync.DecodeJSON(raw, &p); err != nil {
			return "", err
		}
		for _, a := range p.Accounts {
			if emailRE.MatchString(a.Email) {
				into[strings.ToLower(a.Email)] = ServiceAccount{Email: strings.ToLower(a.Email), DisplayName: a.DisplayName, Project: project, Disabled: a.Disabled}
			}
		}
		return p.Next, nil
	})
}

func unreadable(err error) bool {
	s := connsync.Status(err)
	return s == http.StatusForbidden || s == http.StatusNotFound
}

// Read lists the resources, reads each policy, the bound roles and the service accounts of the
// projects. A resource whose policy cannot be read (403, 404) is skipped and the snapshot is flagged
// Partial (the ingest deletion guard holds back removal of identities and account status, and edge
// pruning, issue #577, leaves the edges of the unread resources alone); none readable is an error. A project whose service accounts
// cannot be listed (IAM API off, no permission) keeps the service accounts its policies name.
func (c *Connector) Read(ctx context.Context) (*Snapshot, error) {
	res, err := c.Resources(ctx)
	if err != nil {
		return nil, err
	}
	snap := &Snapshot{Resources: res, Policies: map[string][]Binding{}, Roles: map[string]Role{}, Accounts: map[string]ServiceAccount{}}
	var skipped []string
	var lastErr error
	for _, r := range res {
		b, err := c.policy(ctx, r.Name)
		if err != nil {
			if !unreadable(err) {
				return nil, fmt.Errorf("policy of %s: %w", r.Name, err)
			}
			skipped, lastErr = append(skipped, r.Name), err
			continue
		}
		snap.Policies[r.Name] = b
		if r.Kind() == "gcp_project" {
			if err := c.serviceAccounts(ctx, strings.TrimPrefix(r.Name, "projects/"), snap.Accounts); err != nil && !unreadable(err) {
				return nil, fmt.Errorf("service accounts of %s: %w", r.Name, err)
			}
		}
	}
	if len(res) > 0 && len(snap.Policies) == 0 {
		return nil, fmt.Errorf("no policy could be read: %w", lastErr)
	}
	if len(skipped) > 0 {
		if len(skipped) > 3 {
			skipped = append(skipped[:3:3], "...")
		}
		snap.Partial = fmt.Sprintf("%d of %d resources could not be read (%s)", len(res)-len(snap.Policies), len(res), strings.Join(skipped, ", "))
	}
	var roles []string
	seen := map[string]bool{}
	for _, bs := range snap.Policies {
		for _, b := range bs {
			if !seen[b.Role] {
				seen[b.Role] = true
				roles = append(roles, b.Role)
			}
		}
	}
	sort.Strings(roles)
	var unread []string
	for i, name := range roles {
		if i >= maxRoles {
			unread = append(unread, roles[i:]...)
			break
		}
		r := c.role(ctx, name)
		snap.Roles[name] = r
		if !r.Known {
			unread = append(unread, name)
		}
	}
	if len(unread) > 0 {
		// a role whose permissions are unknown is judged by name, which can miss (a custom role
		// that can set policy), so the result says it is not the whole picture
		if len(unread) > 3 {
			unread = append(unread[:3:3], "...")
		}
		reason := fmt.Sprintf("bound roles could not be read (%s); their privilege is judged by name", strings.Join(unread, ", "))
		if snap.Partial != "" {
			reason = snap.Partial + "; " + reason
		}
		snap.Partial = reason
	}
	return snap, nil
}

// Probe is what a readiness probe learns with a few reads.
type Probe struct {
	Identity  string
	Resources int
	Bindings  int
}

// Probe signs in, lists the resources and reads the policies of the first few; nothing is kept.
func (c *Connector) Probe(ctx context.Context) (Probe, error) {
	res, err := c.Resources(ctx)
	if err != nil {
		return Probe{}, err
	}
	p := Probe{Identity: c.email, Resources: len(res)}
	for i, r := range res {
		if i >= 3 {
			break
		}
		b, err := c.policy(ctx, r.Name)
		if err != nil && !unreadable(err) {
			return p, err
		}
		p.Bindings += len(b)
	}
	return p, nil
}

// Discover reads the estate and maps it.
func (c *Connector) Discover(ctx context.Context) (*connectors.DiscoveryResult, error) {
	snap, err := c.Read(ctx)
	if err != nil {
		return nil, err
	}
	return build(snap), nil
}

var setIAM = map[string]bool{"iam.serviceaccounts.actas": true, "iam.serviceaccounts.getaccesstoken": true,
	"iam.serviceaccounts.implicitdelegation": true, "iam.serviceaccounts.signblob": true, "iam.serviceaccounts.signjwt": true,
	"iam.serviceaccountkeys.create": true, "iam.roles.update": true, "resourcemanager.projects.setiampolicy": true}

// knownPrivileged are predefined roles that can change who has access or act as another identity. They
// are privileged even when roles.get fails.
var knownPrivileged = map[string]bool{
	"roles/owner": true, "roles/editor": true,
	"roles/iam.securityadmin": true, "roles/iam.serviceaccounttokencreator": true, "roles/iam.serviceaccountuser": true,
	"roles/iam.serviceaccountkeyadmin": true, "roles/iam.serviceaccountadmin": true, "roles/iam.serviceaccountopenidtokencreator": true,
	"roles/iam.workloadidentityuser": true, "roles/iam.workloadidentitypooladmin": true, "roles/iam.roleadmin": true,
	"roles/iam.organizationroleadmin": true, "roles/resourcemanager.organizationadmin": true, "roles/resourcemanager.folderadmin": true,
	"roles/resourcemanager.projectiamadmin": true, "roles/resourcemanager.folderiamadmin": true, "roles/orgpolicy.policyadmin": true,
	"roles/iam.denyadmin": true,
}

// privilegedRole reports whether a role can change who has access or act as another identity: the
// basic Owner and Editor roles, a role holding a setIamPolicy permission or a service account
// impersonation permission. A role that could not be read is judged by its name.
func privilegedRole(r Role) bool {
	l := strings.ToLower(r.Name)
	if knownPrivileged[l] {
		return true // whatever roles.get said or failed to say
	}
	if !r.Known {
		return strings.HasSuffix(l, "admin")
	}
	for _, p := range r.Permissions {
		lp := strings.ToLower(p)
		if strings.HasSuffix(lp, ".setiampolicy") || setIAM[lp] {
			return true
		}
	}
	return false
}

// member classifies an IAM policy member.
type member struct {
	id, name, username, email string
	kind                      string // user, service (accounts); the group kind otherwise
	account                   bool
	privileged                bool
}

// parseMember maps a member string. ok is false for a deleted principal (it holds nothing).
func parseMember(m string) (member, bool) {
	switch {
	case strings.HasPrefix(m, "deleted:"):
		return member{}, false
	case m == "allUsers" || m == "allAuthenticatedUsers":
		return member{id: m, name: m, kind: "public", privileged: true}, true
	}
	typ, rest, found := strings.Cut(m, ":")
	if !found {
		return member{id: m, name: m, kind: "gcp_principal"}, true
	}
	switch typ {
	case "user":
		return member{id: "user:" + strings.ToLower(rest), username: strings.ToLower(rest), email: strings.ToLower(rest), kind: "user", account: true}, true
	case "serviceAccount":
		return member{id: "serviceAccount:" + strings.ToLower(rest), username: strings.ToLower(rest), kind: "service", account: true}, true
	case "group":
		return member{id: m, name: rest, kind: "google_group"}, true
	case "domain":
		return member{id: m, name: rest, kind: "google_domain"}, true
	case "projectOwner", "projectEditor", "projectViewer":
		return member{id: m, name: m, kind: "gcp_convenience", privileged: typ != "projectViewer"}, true
	}
	return member{id: m, name: m, kind: "gcp_principal"}, true // federated principal:// and principalSet://
}

func build(s *Snapshot) *connectors.DiscoveryResult {
	res := &connectors.DiscoveryResult{System: System, Partial: s.Partial, EdgeSnapshotOf: []string{System}}
	for n := range s.Policies { // a resource whose policy was read has all its bindings
		res.EdgeScopesRead = append(res.EdgeScopesRead, n)
	}
	sort.Strings(res.EdgeScopesRead)
	for _, r := range s.Resources {
		name := r.DisplayName
		if name == "" {
			name = r.Name
		}
		tags := []string{"gcp", strings.TrimPrefix(r.Kind(), "gcp_")}
		if r.Parent != "" {
			tags = append(tags, "parent:"+r.Parent)
		}
		res.Resources = append(res.Resources, connectors.ResourceRecord{System: System, ExternalID: r.Name, Name: name, Kind: r.Kind(), Tags: tags})
	}
	acctSeen, groupSeen := map[string]bool{}, map[string]bool{}
	addAccount := func(a connectors.AccountRecord) {
		if !acctSeen[a.ExternalID] {
			acctSeen[a.ExternalID] = true
			res.Accounts = append(res.Accounts, a)
		}
	}
	emails := make([]string, 0, len(s.Accounts))
	for e := range s.Accounts {
		emails = append(emails, e)
	}
	sort.Strings(emails)
	for _, e := range emails {
		a := s.Accounts[e]
		st := "active"
		if a.Disabled {
			st = "disabled"
		}
		addAccount(connectors.AccountRecord{System: System, ExternalID: "serviceAccount:" + a.Email, Username: a.Email, Kind: "service", Status: st})
	}
	names := make([]string, 0, len(s.Policies))
	for n := range s.Policies {
		names = append(names, n)
	}
	sort.Strings(names)
	permSeen, edgeSeen := map[string]bool{}, map[[2]string]bool{}
	for _, rn := range names {
		for _, b := range s.Policies[rn] {
			role := s.Roles[b.Role]
			if role.Name == "" {
				role = Role{Name: b.Role}
			}
			id, action := rn+"|"+b.Role, b.Role
			if b.Conditional {
				sum := sha256.Sum256([]byte(b.ConditionTitle + "\x00" + b.ConditionExpr))
				id += "|c" + hex.EncodeToString(sum[:4])
				action += " (conditional)"
			}
			if !permSeen[id] {
				permSeen[id] = true
				res.Permissions = append(res.Permissions, connectors.PermissionRecord{System: System, ExternalID: id, Action: action,
					ResourceExternalID: rn, Privileged: privilegedRole(role)})
			}
			perm := connectors.Ref{Kind: "perm", System: System, ExternalID: id}
			for _, m := range b.Members {
				pm, ok := parseMember(m)
				if !ok {
					continue
				}
				var src connectors.Ref
				rel := "direct_grant"
				if pm.account {
					a := connectors.AccountRecord{System: System, ExternalID: pm.id, Username: pm.username, Kind: pm.kind, Status: "active"}
					if pm.email != "" {
						a.Identity = &connectors.IdentityRef{Email: pm.email}
					}
					addAccount(a)
					src = connectors.Ref{Kind: "account", System: System, ExternalID: pm.id}
				} else {
					if !groupSeen[pm.id] {
						groupSeen[pm.id] = true
						res.Groups = append(res.Groups, connectors.GroupRecord{System: System, ExternalID: pm.id, Name: pm.name, Kind: pm.kind, Privileged: pm.privileged})
					}
					src, rel = connectors.Ref{Kind: "group", System: System, ExternalID: pm.id}, "grants"
				}
				if k := [2]string{src.Kind + ":" + src.ExternalID, id}; !edgeSeen[k] {
					edgeSeen[k] = true
					res.Edges = append(res.Edges, connectors.EdgeRecord{Src: src, Dst: perm, Relation: rel})
				}
			}
		}
	}
	return res
}

// PrivilegedRole is privilegedRole for a role named name with the given permissions (known: roles.get answered).
func PrivilegedRole(name string, permissions []string, known bool) bool {
	return privilegedRole(Role{Name: name, Permissions: permissions, Known: known})
}
