package azurerbac

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/connectors/connsync"
)

const mgPrefix = "/providers/Microsoft.Management/managementGroups/"

func (c *Connector) u(path string, q url.Values) string {
	x := *c.arm
	x.Path = path
	x.RawQuery = q.Encode()
	return x.String()
}

// page is the paging envelope of every list operation (managementGroups spells the link @nextLink).
type page struct {
	Value  []json.RawMessage `json:"value"`
	Next   string            `json:"nextLink"`
	AtNext string            `json:"@nextLink"`
}

// list walks a list operation, calling each for every item. Next links must stay on the ARM host:
// the Authorization header goes wherever a link points.
func (c *Connector) list(ctx context.Context, path string, q url.Values, each func(json.RawMessage) error) error {
	return connsync.Walk(ctx, c.arm, c.u(path, q), func(ctx context.Context, pageURL string) (string, error) {
		resp, err := c.api.Do(ctx, http.MethodGet, pageURL, nil, nil)
		if err != nil {
			return "", err
		}
		var p page
		if err := connsync.DecodeJSON(resp.Body, &p); err != nil {
			return "", err
		}
		for _, raw := range p.Value {
			if err := each(raw); err != nil {
				return "", err
			}
		}
		if p.Next != "" {
			return p.Next, nil
		}
		return p.AtNext, nil
	})
}

// Scopes returns the scopes to read: the configured subscriptions and management groups, or every
// one the application can list.
func (c *Connector) Scopes(ctx context.Context) ([]Scope, error) {
	var out []Scope
	if len(c.cfg.SubscriptionIDs)+len(c.cfg.ManagementGroupIDs) > 0 {
		for _, m := range c.cfg.ManagementGroupIDs {
			out = append(out, Scope{ID: mgPrefix + m, Name: m})
		}
		for _, s := range c.cfg.SubscriptionIDs {
			out = append(out, Scope{ID: "/subscriptions/" + lower(s), Name: s})
		}
		return out, nil
	}
	err := c.list(ctx, "/subscriptions", url.Values{"api-version": {apiSubscriptions}}, func(raw json.RawMessage) error {
		var s struct {
			SubscriptionID string `json:"subscriptionId"`
			DisplayName    string `json:"displayName"`
			State          string `json:"state"`
		}
		if err := json.Unmarshal(raw, &s); err != nil || !guidRE.MatchString(s.SubscriptionID) {
			return nil
		}
		switch s.State {
		case "", "Enabled", "Warned", "PastDue": // a disabled or deleted subscription has nothing to read
			out = append(out, Scope{ID: "/subscriptions/" + lower(s.SubscriptionID), Name: nonEmpty(s.DisplayName, s.SubscriptionID)})
		}
		if len(out) > maxScopes {
			return errors.New("azurerbac: more than 5000 scopes; narrow the subscription and management group lists")
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("subscriptions: %w", err)
	}
	err = c.list(ctx, "/providers/Microsoft.Management/managementGroups", url.Values{"api-version": {apiMgmtGroups}}, func(raw json.RawMessage) error {
		var m struct {
			Name       string `json:"name"`
			Properties struct {
				DisplayName string `json:"displayName"`
			} `json:"properties"`
		}
		if err := json.Unmarshal(raw, &m); err != nil || !mgRE.MatchString(m.Name) {
			return nil
		}
		out = append(out, Scope{ID: mgPrefix + m.Name, Name: nonEmpty(m.Properties.DisplayName, m.Name)})
		return nil
	})
	if err != nil && connsync.Status(err) != http.StatusForbidden && connsync.Status(err) != http.StatusNotFound {
		return nil, fmt.Errorf("management groups: %w", err)
	}
	return out, nil // management groups are optional: a reader on subscriptions only cannot list them
}

func nonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

type roleDefJSON struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Properties struct {
		RoleName    string `json:"roleName"`
		Type        string `json:"type"`
		Permissions []struct {
			Actions    []string `json:"actions"`
			NotActions []string `json:"notActions"`
		} `json:"permissions"`
	} `json:"properties"`
}

func (r roleDefJSON) def() RoleDef {
	d := RoleDef{ID: r.ID, Name: nonEmpty(r.Properties.RoleName, r.Name), Type: r.Properties.Type}
	for _, p := range r.Properties.Permissions {
		d.Actions = append(d.Actions, p.Actions...)
		d.NotActions = append(d.NotActions, p.NotActions...)
	}
	d.Privileged = privilegedRole(d.Actions)
	return d
}

// privilegedRole reports whether a role can change anything and everything (an action of "*") or
// manage access itself (Microsoft.Authorization). Owner, Contributor and User Access Administrator
// are privileged; Reader ("*/read") is not.
func privilegedRole(actions []string) bool {
	for _, a := range actions {
		switch l := lower(strings.TrimSpace(a)); {
		case l == "*", l == "microsoft.authorization/*", l == "microsoft.authorization/*/write",
			l == "microsoft.authorization/roleassignments/write", l == "microsoft.authorization/roledefinitions/write",
			l == "microsoft.authorization/elevateaccess/action":
			return true
		}
	}
	return false
}

func (c *Connector) roleDefinitions(ctx context.Context, scope string, into map[string]RoleDef) error {
	return c.list(ctx, scope+"/providers/Microsoft.Authorization/roleDefinitions", url.Values{"api-version": {apiRBAC}}, func(raw json.RawMessage) error {
		var r roleDefJSON
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil
		}
		if k := roleKey(r.ID); k != "" {
			into[k] = r.def()
		}
		return nil
	})
}

type assignmentJSON struct {
	ID         string `json:"id"`
	Properties struct {
		PrincipalID      string `json:"principalId"`
		PrincipalType    string `json:"principalType"`
		RoleDefinitionID string `json:"roleDefinitionId"`
		Scope            string `json:"scope"`
		Condition        string `json:"condition"`
		EndDateTime      string `json:"endDateTime"`
		Status           string `json:"status"`
	} `json:"properties"`
}

func (c *Connector) assignments(ctx context.Context, scope string, eligible bool, into map[string]Assignment) error {
	path, q := scope+"/providers/Microsoft.Authorization/roleAssignments", url.Values{"api-version": {apiRBAC}}
	if eligible {
		path, q = scope+"/providers/Microsoft.Authorization/roleEligibilityScheduleInstances", url.Values{"api-version": {apiEligibility}}
	}
	if eligible || strings.HasPrefix(scope, mgPrefix) {
		q.Set("$filter", "atScope()") // at and above the scope; what is below is read from its own scope
	}
	return c.list(ctx, path, q, func(raw json.RawMessage) error {
		var a assignmentJSON
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil
		}
		p := a.Properties
		if !guidRE.MatchString(p.PrincipalID) || p.RoleDefinitionID == "" || !armIDRE.MatchString(p.Scope) {
			return nil
		}
		var end *time.Time
		if eligible {
			if p.Status != "" && p.Status != "Provisioned" && p.Status != "Granted" {
				return nil // an assignment that is not in force is not eligibility either
			}
			if t, err := time.Parse(time.RFC3339, p.EndDateTime); err == nil {
				end = &t
			}
		}
		key := lower(a.ID)
		if key == "" || eligible {
			key = lower(p.Scope + "|" + p.RoleDefinitionID + "|" + p.PrincipalID)
		}
		if eligible {
			key += "|eligible"
		}
		if len(into) >= maxAssignments {
			return errors.New("azurerbac: more than 500000 role assignments; stopping")
		}
		into[key] = Assignment{ID: nonEmpty(a.ID, key), Scope: p.Scope, PrincipalID: lower(p.PrincipalID), PrincipalType: p.PrincipalType,
			RoleDefinitionID: p.RoleDefinitionID, Conditional: p.Condition != "", Eligible: eligible, End: end}
		return nil
	})
}

// unreadable reports whether err is the source refusing or not having a scope: that scope is left
// out and the read goes on, flagged partial.
func unreadable(err error) bool {
	s := connsync.Status(err)
	return s == http.StatusForbidden || s == http.StatusNotFound || s == http.StatusBadRequest
}

// Read lists the scopes, then the role definitions and assignments (and eligible assignments) of
// each. A scope the application cannot read is skipped and the snapshot is flagged Partial, which
// holds back deletions; no readable scope at all is an error.
func (c *Connector) Read(ctx context.Context) (*Snapshot, error) {
	scopes, err := c.Scopes(ctx)
	if err != nil {
		return nil, err
	}
	snap := &Snapshot{Scopes: scopes, Roles: map[string]RoleDef{}}
	byID := map[string]Assignment{}
	var skipped []string
	var lastErr error
	read := 0
	for _, sc := range scopes {
		if err := c.roleDefinitions(ctx, sc.ID, snap.Roles); err != nil {
			if !unreadable(err) {
				return nil, fmt.Errorf("role definitions of %s: %w", sc.Name, err)
			}
			lastErr = err
		}
		if err := c.assignments(ctx, sc.ID, false, byID); err != nil {
			if !unreadable(err) {
				return nil, fmt.Errorf("role assignments of %s: %w", sc.Name, err)
			}
			skipped, lastErr = append(skipped, sc.Name), err
			continue
		}
		read++
		if c.cfg.IncludeEligible {
			if err := c.assignments(ctx, sc.ID, true, byID); err != nil {
				if !unreadable(err) {
					return nil, fmt.Errorf("eligible assignments of %s: %w", sc.Name, err)
				}
				snap.Partial = "eligible (PIM) assignments could not be read at " + sc.Name
			}
		}
	}
	if len(scopes) > 0 && read == 0 {
		return nil, fmt.Errorf("no scope could be read: %w", lastErr)
	}
	if len(skipped) > 0 {
		snap.Partial = fmt.Sprintf("%d of %d scopes could not be read (%s)", len(skipped), len(scopes), strings.Join(first(skipped, 3), ", "))
	}
	for _, a := range byID {
		snap.Assignments = append(snap.Assignments, a)
	}
	c.fillRoles(ctx, snap)
	return snap, nil
}

func first(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// fillRoles reads the definition of each assigned role no listing returned (a custom role defined
// at a scope that was not read), by its id. A role that cannot be read keeps its GUID as its name.
func (c *Connector) fillRoles(ctx context.Context, snap *Snapshot) {
	tried := map[string]bool{}
	for _, a := range snap.Assignments {
		k := roleKey(a.RoleDefinitionID)
		if _, ok := snap.Roles[k]; ok || tried[k] {
			continue
		}
		tried[k] = true
		id := a.RoleDefinitionID
		if !armIDRE.MatchString(id) || !strings.Contains(lower(id), "/providers/microsoft.authorization/roledefinitions/") || len(tried) > 500 {
			continue
		}
		resp, err := c.api.Do(ctx, http.MethodGet, c.u(id, url.Values{"api-version": {apiRBAC}}), nil, nil)
		if err != nil {
			continue
		}
		var r roleDefJSON
		if connsync.DecodeJSON(resp.Body, &r) == nil {
			snap.Roles[k] = r.def()
		}
	}
}

// Probe is what a readiness probe learns with a few reads.
type Probe struct {
	Mode        string
	Scopes      int
	Assignments int
	Roles       int
}

// Probe acquires a token, lists the scopes and reads the assignments and role definitions of the
// first few; nothing is kept.
func (c *Connector) Probe(ctx context.Context) (Probe, error) {
	scopes, err := c.Scopes(ctx)
	if err != nil {
		return Probe{}, err
	}
	p := Probe{Mode: c.mode, Scopes: len(scopes)}
	roles := map[string]RoleDef{}
	as := map[string]Assignment{}
	for i, sc := range scopes {
		if i >= 3 {
			break
		}
		if err := c.assignments(ctx, sc.ID, false, as); err != nil && !unreadable(err) {
			return p, err
		}
		if i == 0 {
			if err := c.roleDefinitions(ctx, sc.ID, roles); err != nil && !unreadable(err) {
				return p, err
			}
		}
	}
	p.Assignments, p.Roles = len(as), len(roles)
	return p, nil
}
