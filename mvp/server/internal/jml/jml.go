// Package jml automates joiner / mover / leaver changes driven by the HRIS feed.
package jml

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/containment"
	"github.com/nischalravi/tessera/mvp/server/internal/flatfile"
	"github.com/nischalravi/tessera/mvp/server/internal/graph"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/policy"
	"github.com/nischalravi/tessera/mvp/server/internal/provision"
	"github.com/nischalravi/tessera/mvp/server/internal/provision/target"
	"github.com/nischalravi/tessera/mvp/server/internal/simulate"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
	"github.com/nischalravi/tessera/mvp/server/internal/timeutil"
)

// Error is a caller error ("unknown identity", "event already executed").
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

// The two ExecuteEvent refusals the API maps apart from other caller errors:
// an unknown event is a 404, an event that is already executed a 409.
var (
	ErrEventNotFound = &Error{"event not found"}
	ErrEventExecuted = &Error{"event already executed"}
)

type sysXID struct{ system, xid string }

var eng = []sysXID{{"okta", "everyone"}, {"okta", "engineering"}, {"github", "team/all-engineers"}}

func with(base []sysXID, more ...sysXID) []sysXID {
	return append(append([]sysXID{}, base...), more...)
}

// Birthright is the access every member of a team gets: (system, group external id).
var Birthright = map[string][]sysXID{
	"backend":  with(eng, sysXID{"okta", "eng-backend"}, sysXID{"github", "team/backend"}),
	"frontend": with(eng, sysXID{"okta", "eng-frontend"}, sysXID{"github", "team/frontend"}),
	"platform": with(eng, sysXID{"okta", "eng-platform"}, sysXID{"github", "team/platform"}),
	"data": {{"okta", "everyone"}, {"okta", "data-team"}, {"github", "team/all-engineers"}, {"github", "team/data"},
		{"snowflake", "role/ANALYST"}},
	"security": {{"okta", "everyone"}, {"okta", "security-team"}, {"github", "team/security"}},
	"finance":  {{"okta", "everyone"}, {"okta", "finance"}, {"snowflake", "role/FINANCE_ANALYST"}},
	"sales":    {{"okta", "everyone"}, {"okta", "sales"}, {"snowflake", "role/ANALYST"}},
	"support":  {{"okta", "everyone"}, {"okta", "support"}},
	"people":   {{"okta", "everyone"}, {"okta", "people-ops"}, {"workday", "sg-hr-partner"}},
	"exec":     {{"okta", "everyone"}, {"okta", "executives"}},
}

// TeamByOktaGroup infers a team from Okta group membership.
var TeamByOktaGroup = map[string]string{"eng-backend": "backend", "eng-frontend": "frontend", "eng-platform": "platform",
	"data-team": "data", "security-team": "security", "finance": "finance", "sales": "sales",
	"support": "support", "people-ops": "people", "executives": "exec"}

// Step is one plan step, an ordered JSON object.
type Step = ojson.Object

func stepGet(s Step, k string) any { v, _ := s.Get(k); return v }

func stepStr(s Step, k string) string { v, _ := stepGet(s, k).(string); return v }

func stepInt(s Step, k string) (int64, bool) {
	switch v := stepGet(s, k).(type) {
	case int64:
		return v, true
	case *int64:
		if v != nil {
			return *v, true
		}
	}
	return 0, false
}

func getOrNil[T any](v *T, err error) (*T, error) {
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	return v, err
}

// InferTeam derives a team from the identity's Okta group memberships.
func InferTeam(c *store.TenantTx, identityID int64) (*string, error) {
	accts, err := c.IdentityAccounts(identityID)
	if err != nil {
		return nil, err
	}
	for _, a := range accts {
		if a.System != "okta" {
			continue
		}
		edges, err := c.EdgesFrom(graph.Key("account", a.ID))
		if err != nil {
			return nil, err
		}
		for _, e := range edges {
			if !strings.HasPrefix(e.Dst, "group:") {
				continue
			}
			_, gid, err := graph.ParseKey(e.Dst)
			if err != nil {
				continue
			}
			g, err := getOrNil(c.Group(gid))
			if err != nil {
				return nil, err
			}
			if g != nil {
				if t, ok := TeamByOktaGroup[g.ExternalID]; ok {
					return &t, nil
				}
			}
		}
	}
	return nil, nil
}

// Label renders a node key from the database.
func Label(c *store.TenantTx, key string) (string, error) {
	kind, raw, _ := strings.Cut(key, ":")
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return key, nil
	}
	switch kind {
	case "group":
		g, err := getOrNil(c.Group(id))
		if err != nil || g == nil {
			return key, err
		}
		return g.System + ":" + g.Name, nil
	case "account":
		a, err := getOrNil(c.Account(id))
		if err != nil || a == nil {
			return key, err
		}
		return a.System + ":" + a.Username, nil
	case "perm":
		p, err := getOrNil(c.Permission(id))
		if err != nil || p == nil {
			return key, err
		}
		name, err := c.ResourceName(p.ResourceID)
		if err != nil {
			return key, err
		}
		return p.Action + " on " + name, nil
	}
	return key, nil
}

// ------------------------------------------------------------------ leaver

// Plan is a JML plan (an ordered JSON object).
type Plan = ojson.Object

// LeaverPlan lists everything to do when an identity leaves. withImpact adds a
// simulation of disabling the identity's active accounts.
func LeaverPlan(c *store.TenantTx, now time.Time, identityID int64, withImpact bool, policies []*policy.Policy) (Plan, error) {
	ident, err := getOrNil(c.Identity(identityID))
	if err != nil {
		return nil, err
	}
	if ident == nil {
		return nil, &Error{"unknown identity"}
	}
	var manager *store.Identity
	if ident.ManagerID != nil {
		if manager, err = getOrNil(c.Identity(*ident.ManagerID)); err != nil {
			return nil, err
		}
	}
	accounts, err := c.IdentityAccounts(identityID)
	if err != nil {
		return nil, err
	}
	steps := []Step{}
	var active []*store.Account
	for _, a := range accounts {
		if a.Status == "active" {
			active = append(active, a)
			steps = append(steps, Step{{Key: "action", Value: "disable_account"}, {Key: "system", Value: a.System},
				{Key: "target", Value: a.Username}, {Key: "account_id", Value: a.ID},
				{Key: "detail", Value: fmt.Sprintf("Disable %s account %s", a.System, a.Username)}})
		}
	}
	// Kill switch (issue #106): sessions, refresh tokens and OAuth grants live
	// at the IdP and outlast a disabled account. Only accounts on a system with
	// a live connection get the steps.
	specs, err := containment.Steps(c, identityID, true)
	if err != nil {
		return nil, err
	}
	for _, sp := range specs {
		a, err := c.Account(sp.AccountID)
		if err != nil {
			return nil, err
		}
		what := "Revoke sessions and refresh tokens of %s account %s"
		if sp.Action == containment.ActionRevokeGrants {
			what = "Revoke OAuth consents and credentials of %s account %s"
		}
		steps = append(steps, Step{{Key: "action", Value: sp.Action}, {Key: "system", Value: a.System},
			{Key: "target", Value: a.Username}, {Key: "account_id", Value: a.ID},
			{Key: "detail", Value: fmt.Sprintf(what, a.System, a.Username)}})
	}
	for _, a := range accounts {
		edges, err := c.EdgesFrom(graph.Key("account", a.ID))
		if err != nil {
			return nil, err
		}
		for _, e := range edges {
			lbl, err := Label(c, e.Dst)
			if err != nil {
				return nil, err
			}
			suffix := ""
			if e.Source == "jit" {
				suffix = " (JIT)"
			}
			steps = append(steps, Step{{Key: "action", Value: "remove_grant"}, {Key: "system", Value: a.System},
				{Key: "edge_id", Value: e.ID}, {Key: "target", Value: lbl},
				{Key: "detail", Value: fmt.Sprintf("Remove %s:%s from %s%s", a.System, a.Username, lbl, suffix)}})
		}
	}
	reqs, err := c.OpenRequestsFor(identityID)
	if err != nil {
		return nil, err
	}
	for _, r := range reqs {
		lbl, err := Label(c, graph.Key("group", r.GroupID))
		if err != nil {
			return nil, err
		}
		steps = append(steps, Step{{Key: "action", Value: "cancel_jit"}, {Key: "request_id", Value: r.ID},
			{Key: "system", Value: "tessera"}, {Key: "target", Value: lbl},
			{Key: "detail", Value: fmt.Sprintf("Cancel %s JIT request #%d", r.Status, r.ID)}})
	}
	owned, err := activeOnly(c.IdentitiesOwnedBy(identityID))
	if err != nil {
		return nil, err
	}
	var newOwner any
	newOwnerName := "security team"
	if manager != nil {
		newOwner, newOwnerName = manager.ID, manager.Name
	}
	handover, err := ownershipHandover(c, identityID, newOwner, newOwnerName)
	if err != nil {
		return nil, err
	}
	for _, n := range owned {
		to, toName := newOwner, newOwnerName
		if h, ok := handover[store.OwnedIdentity+"/"+strconv.FormatInt(n.ID, 10)]; ok {
			to, toName = h.primary, h.primaryName
		}
		steps = append(steps, Step{{Key: "action", Value: "reassign_owner"}, {Key: "identity_id", Value: n.ID},
			{Key: "system", Value: "tessera"}, {Key: "target", Value: n.Name}, {Key: "new_owner_id", Value: to},
			{Key: "detail", Value: fmt.Sprintf("Transfer ownership of %s (%s) to %s", n.Name, n.Type, toName)}})
		nAccts, err := c.IdentityAccounts(n.ID)
		if err != nil {
			return nil, err
		}
		for _, a := range nAccts {
			secs, err := c.AccountSecrets(a.ID)
			if err != nil {
				return nil, err
			}
			for _, s := range secs {
				if s.Status != "active" {
					continue
				}
				steps = append(steps, Step{{Key: "action", Value: "rotate_secret"}, {Key: "secret_id", Value: s.ID},
					{Key: "system", Value: s.System}, {Key: "target", Value: s.Name},
					{Key: "detail", Value: fmt.Sprintf("Rotate %s '%s' on %s (leaver had custody)", s.Kind, s.Name, n.Name)}})
			}
		}
	}
	steps = append(steps, handoverSteps(handover)...)
	dels, err := c.Delegations()
	if err != nil {
		return nil, err
	}
	for _, d := range dels {
		if d.PrincipalID != identityID {
			continue
		}
		agent, err := getOrNil(c.Identity(d.AgentID))
		if err != nil {
			return nil, err
		}
		target := strconv.FormatInt(d.AgentID, 10)
		if agent != nil {
			target = agent.Name
		}
		steps = append(steps, Step{{Key: "action", Value: "revoke_delegation"}, {Key: "delegation_id", Value: d.ID},
			{Key: "system", Value: "tessera"}, {Key: "target", Value: target},
			{Key: "detail", Value: fmt.Sprintf("Revoke delegation: %s acting on behalf of %s (%s)", target, ident.Name,
				strings.Join(d.Scopes, ", "))}})
	}
	reports, err := activeOnly(c.IdentitiesManagedBy(identityID))
	if err != nil {
		return nil, err
	}
	if len(reports) > 0 {
		ids := make([]int64, len(reports))
		for i, r := range reports {
			ids[i] = r.ID
		}
		mgrName := "TBD"
		if manager != nil {
			mgrName = manager.Name
		}
		steps = append(steps, Step{{Key: "action", Value: "reassign_reports"}, {Key: "system", Value: "workday"},
			{Key: "target", Value: fmt.Sprintf("%d direct reports", len(reports))}, {Key: "report_ids", Value: ids},
			{Key: "new_manager_id", Value: newOwner},
			{Key: "detail", Value: fmt.Sprintf("Move %d direct reports to %s", len(reports), mgrName)}})
	}
	plan := Plan{{Key: "type", Value: "leaver"}, {Key: "identity", Value: ojson.Object{{Key: "id", Value: ident.ID},
		{Key: "name", Value: ident.Name}, {Key: "status", Value: ident.Status}, {Key: "department", Value: ident.Department},
		{Key: "title", Value: ident.Title}}}, {Key: "steps", Value: steps}}
	if withImpact {
		ids := make([]int64, len(active))
		sysSet := map[string]bool{}
		for i, a := range active {
			ids[i] = a.ID
			sysSet[a.System] = true
		}
		sim, err := simulate.Run(c, simulate.Request{DisableAccountIDs: ids}, simulate.Inputs{Now: now, Policies: policies})
		if err != nil {
			return nil, err
		}
		removed, privRemoved := 0, 0
		for _, x := range sim.Identities {
			if x.IdentityID == identityID {
				removed = len(x.Removed)
				for _, p := range x.Removed {
					if p.Privileged {
						privRemoved++
					}
				}
				break
			}
		}
		systems := make([]string, 0, len(sysSet))
		for s := range sysSet {
			systems = append(systems, s)
		}
		sort.Strings(systems)
		plan = append(plan, ojson.KV{Key: "impact", Value: ojson.Object{{Key: "permissions_removed", Value: removed},
			{Key: "privileged_removed", Value: privRemoved}, {Key: "systems", Value: systems},
			{Key: "owned_nhis", Value: len(owned)}, {Key: "violations_resolved", Value: sim.Summary.ViolationsResolved}}})
	}
	return plan, nil
}

// ------------------------------------------------------------------- mover

type birthGroup struct {
	key string
	g   *store.Group
}

func birthrightGroups(c *store.TenantTx, team *string) ([]birthGroup, error) {
	var out []birthGroup
	seen := map[string]int{}
	if team == nil {
		return out, nil
	}
	for _, sx := range Birthright[*team] {
		g, err := getOrNil(c.GroupByXID(sx.system, sx.xid))
		if err != nil {
			return nil, err
		}
		if g == nil {
			continue
		}
		k := graph.Key("group", g.ID)
		if i, ok := seen[k]; ok {
			out[i].g = g
			continue
		}
		seen[k] = len(out)
		out = append(out, birthGroup{k, g})
	}
	return out, nil
}

func hasKey(gs []birthGroup, k string) bool {
	for _, g := range gs {
		if g.key == k {
			return true
		}
	}
	return false
}

func pyStr(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case string:
		return x
	case *string:
		if x == nil {
			return "None"
		}
		return *x
	case bool:
		if x {
			return "True"
		}
		return "False"
	case json.Number:
		return x.String()
	}
	return fmt.Sprint(v)
}

// MoverPlan computes access changes for a team move.
func MoverPlan(c *store.TenantTx, identityID int64, toTeam string, fromTeam *string, newTitle, toDepartment any) (Plan, error) {
	ident, err := getOrNil(c.Identity(identityID))
	if err != nil {
		return nil, err
	}
	if ident == nil {
		return nil, fmt.Errorf("jml: mover for unknown identity %d", identityID)
	}
	if fromTeam == nil {
		if fromTeam, err = InferTeam(c, identityID); err != nil {
			return nil, err
		}
	}
	old, err := birthrightGroups(c, fromTeam)
	if err != nil {
		return nil, err
	}
	nw, err := birthrightGroups(c, &toTeam)
	if err != nil {
		return nil, err
	}
	accounts, err := c.IdentityAccounts(identityID)
	if err != nil {
		return nil, err
	}
	accts := map[string]*store.Account{}
	for _, a := range accounts {
		if a.Status == "active" {
			accts[a.System] = a
		}
	}
	target := ident.Name
	if ident.Email != nil && *ident.Email != "" {
		target = *ident.Email
	}
	steps := []Step{}
	for _, bg := range nw {
		if hasKey(old, bg.key) {
			continue
		}
		g := bg.g
		a := accts[g.System]
		if a == nil {
			steps = append(steps, Step{{Key: "action", Value: "create_account"}, {Key: "system", Value: g.System},
				{Key: "target", Value: target}, {Key: "detail", Value: fmt.Sprintf("Create %s account for %s", g.System, ident.Name)}})
		} else if e, err := getOrNil(c.EdgeBetween(graph.Key("account", a.ID), bg.key)); err != nil {
			return nil, err
		} else if e != nil {
			continue
		}
		steps = append(steps, Step{{Key: "action", Value: "add_grant"}, {Key: "system", Value: g.System},
			{Key: "group_id", Value: g.ID}, {Key: "target", Value: g.System + ":" + g.Name},
			{Key: "detail", Value: fmt.Sprintf("Add to %s:%s (birthright for %s)", g.System, g.Name, toTeam)}})
	}
	for _, a := range accounts {
		edges, err := c.EdgesFrom(graph.Key("account", a.ID))
		if err != nil {
			return nil, err
		}
		for _, e := range edges {
			inOld, inNew := hasKey(old, e.Dst), hasKey(nw, e.Dst)
			if inNew {
				continue
			}
			lbl, err := Label(c, e.Dst)
			if err != nil {
				return nil, err
			}
			if inOld {
				steps = append(steps, Step{{Key: "action", Value: "remove_grant"}, {Key: "system", Value: a.System},
					{Key: "edge_id", Value: e.ID}, {Key: "target", Value: lbl},
					{Key: "detail", Value: fmt.Sprintf("Remove %s (birthright of previous team %s)", lbl, pyStr(fromTeam))}})
			} else {
				steps = append(steps, Step{{Key: "action", Value: "review_grant"}, {Key: "system", Value: a.System},
					{Key: "edge_id", Value: e.ID}, {Key: "target", Value: lbl},
					{Key: "detail", Value: fmt.Sprintf("Flag %s for manager review within 30 days (not birthright for %s)", lbl, toTeam)}})
			}
		}
	}
	var from any
	if fromTeam != nil {
		from = *fromTeam
	}
	return Plan{{Key: "type", Value: "mover"}, {Key: "identity", Value: ojson.Object{{Key: "id", Value: ident.ID},
		{Key: "name", Value: ident.Name}, {Key: "department", Value: ident.Department}, {Key: "title", Value: ident.Title}}},
		{Key: "from_team", Value: from}, {Key: "to_team", Value: toTeam}, {Key: "new_title", Value: newTitle},
		{Key: "to_department", Value: toDepartment}, {Key: "steps", Value: steps}}, nil
}

// ------------------------------------------------------------------ joiner

// JoinerPlan lists the accounts and birthright access for a new hire.
func JoinerPlan(c *store.TenantTx, payload ojson.Object) (Plan, error) {
	teamV, _ := payload.Get("team")
	var team *string
	if s, ok := teamV.(string); ok {
		team = &s
	}
	name, _ := payload.Get("name")
	title, _ := payload.Get("title")
	dept, _ := payload.Get("department")
	email, _ := payload.Get("email")
	steps := []Step{{{Key: "action", Value: "create_identity"}, {Key: "system", Value: "tessera"}, {Key: "target", Value: name},
		{Key: "detail", Value: fmt.Sprintf("Create identity %s (%s, %s)", pyStr(name), pyStr(title), pyStr(dept))}}}
	var groups []birthGroup
	if team != nil {
		var err error
		if groups, err = birthrightGroups(c, team); err != nil {
			return nil, err
		}
	}
	sysSet := map[string]bool{}
	for _, g := range groups {
		sysSet[g.g.System] = true
	}
	systems := []string{"workday"}
	for _, s := range sortedKeys(sysSet) {
		systems = append(systems, s)
	}
	for _, s := range systems {
		steps = append(steps, Step{{Key: "action", Value: "create_account"}, {Key: "system", Value: s},
			{Key: "target", Value: email}, {Key: "detail", Value: fmt.Sprintf("Create %s account", s)}})
	}
	for _, bg := range groups {
		g := bg.g
		steps = append(steps, Step{{Key: "action", Value: "add_grant"}, {Key: "system", Value: g.System},
			{Key: "group_id", Value: g.ID}, {Key: "target", Value: g.System + ":" + g.Name},
			{Key: "detail", Value: fmt.Sprintf("Add to %s:%s (birthright for %s)", g.System, g.Name, pyStr(teamV))}})
	}
	return Plan{{Key: "type", Value: "joiner"}, {Key: "identity", Value: ojson.Object{{Key: "name", Value: name},
		{Key: "department", Value: dept}, {Key: "title", Value: title}}}, {Key: "team", Value: teamV},
		{Key: "steps", Value: steps}}, nil
}

// ExistsError says a joiner matches an identity that is already active. The
// operator should use the mover or rehire flow, or the account-match and
// merge tools, instead of creating a second identity.
type ExistsError struct {
	ExistingID int64
	MatchedOn  string // "email" or "hr_id"
}

func (e *ExistsError) Error() string {
	return fmt.Sprintf("an active identity %d already has this %s", e.ExistingID, strings.Replace(e.MatchedOn, "_", " ", 1))
}

// joinerKeys is the joiner payload's email and HR employee id ("" if absent).
func joinerKeys(payload ojson.Object) (email, hrID string) {
	if s := optStr(payload, "email"); s != nil {
		email = strings.TrimSpace(*s)
	}
	if s := optStr(payload, "employee_id"); s != nil {
		hrID = strings.TrimSpace(*s)
	}
	return email, hrID
}

// CheckJoiner returns an *ExistsError if the joiner's email (case-insensitive,
// trimmed) or HR employee id belongs to an active identity. A terminated
// identity does not count: that person is a rehire. ExecuteEvent runs it
// inside its write transaction, which makes the check authoritative.
func CheckJoiner(c *store.TenantTx, payload ojson.Object) error {
	email, hrID := joinerKeys(payload)
	m, err := getOrNil(c.ActiveIdentityMatching(email, hrID))
	if err != nil || m == nil {
		return err
	}
	on := "hr_id"
	if m.Email != nil && email != "" && strings.EqualFold(strings.TrimSpace(*m.Email), email) {
		on = "email"
	}
	return &ExistsError{ExistingID: m.ID, MatchedOn: on}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// --------------------------------------------------------------- execute

func optStr(payload ojson.Object, k string) *string {
	v, _ := payload.Get(k)
	if s, ok := v.(string); ok {
		return &s
	}
	return nil
}

func getAny(payload ojson.Object, k string) any { v, _ := payload.Get(k); return v }

// PlanForEvent builds the plan for an HRIS event.
func PlanForEvent(c *store.TenantTx, now time.Time, ev *store.HrisEvent, withImpact bool, policies []*policy.Policy) (Plan, error) {
	switch ev.Type {
	case "leaver":
		if ev.IdentityID == nil {
			return nil, &Error{"unknown identity"}
		}
		return LeaverPlan(c, now, *ev.IdentityID, withImpact, policies)
	case "mover":
		if ev.IdentityID == nil {
			return nil, fmt.Errorf("jml: mover event %d has no identity", ev.ID)
		}
		toTeam := pyStr(getAny(ev.Payload, "to_team"))
		return MoverPlan(c, *ev.IdentityID, toTeam, optStr(ev.Payload, "from_team"), getAny(ev.Payload, "new_title"),
			getAny(ev.Payload, "to_department"))
	}
	return JoinerPlan(c, ev.Payload)
}

// accountSpec is the username and external id a new account of ident in
// system gets.
func accountSpec(ident *store.Identity, system string) (uname, extID string, err error) {
	switch system {
	case "okta":
		if ident.Email == nil {
			return "", "", fmt.Errorf("jml: %s has no email for an okta account", ident.Name)
		}
		uname = *ident.Email
	case "workday":
		uname = ident.ExternalID
	default:
		base := ident.Name
		if ident.Email != nil && *ident.Email != "" {
			base = *ident.Email
		}
		uname = strings.ReplaceAll(strings.SplitN(base, "@", 2)[0], ".", "-")
	}
	return uname, "tessera-" + system + "-" + ident.ExternalID, nil
}

func ensureAccount(c *store.TenantTx, now time.Time, ident *store.Identity, system string) (*store.Account, error) {
	accts, err := c.IdentityAccounts(ident.ID)
	if err != nil {
		return nil, err
	}
	for _, a := range accts {
		if a.System == system && a.Status == "active" {
			return a, nil
		}
	}
	uname, extID, err := accountSpec(ident, system)
	if err != nil {
		return nil, err
	}
	iid := ident.ID
	id, err := c.InsertAccount(&store.Account{System: system, ExternalID: extID,
		IdentityID: &iid, Username: uname, Kind: "user", Status: "active", CreatedAt: &now})
	if err != nil {
		return nil, err
	}
	return c.Account(id)
}

func addGrant(c *store.TenantTx, now time.Time, ident *store.Identity, st Step) error {
	gid, _ := stepInt(st, "group_id")
	return addGrantTo(c, now, ident, gid)
}

func addGrantTo(c *store.TenantTx, now time.Time, ident *store.Identity, gid int64) error {
	g, err := c.Group(gid)
	if err != nil {
		return err
	}
	a, err := ensureAccount(c, now, ident, g.System)
	if err != nil {
		return err
	}
	src, dst := graph.Key("account", a.ID), graph.Key("group", g.ID)
	existing, err := getOrNil(c.EdgeBetween(src, dst))
	if err != nil || existing != nil {
		return err
	}
	_, err = c.InsertEdge(&store.GrantEdge{Src: src, Dst: dst, Relation: "member_of", Source: "manual", CreatedAt: now})
	return err
}

// ContainmentSpecs lists the plan's containment steps. They call providers,
// so the caller runs them (internal/containment) before ExecuteEvent, with no
// transaction open.
func ContainmentSpecs(plan Plan) []containment.Spec {
	var out []containment.Spec
	steps, _ := getAny(plan, "steps").([]Step)
	for _, st := range steps {
		if a := stepStr(st, "action"); isContainment(a) {
			id, _ := stepInt(st, "account_id")
			out = append(out, containment.Spec{Action: a, AccountID: id})
		}
	}
	return out
}

func isContainment(action string) bool {
	return action == containment.ActionRevokeSessions || action == containment.ActionRevokeGrants
}

// Completions the provisioning engine runs once the target confirms a step.
const (
	completeEnsureAccount = "jml.ensure_account"
	completeAddGrant      = "jml.add_grant"
)

type identitySystem struct {
	IdentityID int64  `json:"identity_id"`
	System     string `json:"system"`
}

type identityGroup struct {
	IdentityID int64 `json:"identity_id"`
	GroupID    int64 `json:"group_id"`
}

func init() {
	provision.RegisterCompletion(completeEnsureAccount, func(c *store.TenantTx, now time.Time, raw json.RawMessage) error {
		var d identitySystem
		if err := json.Unmarshal(raw, &d); err != nil {
			return err
		}
		ident, err := c.Identity(d.IdentityID)
		if err != nil {
			return err
		}
		_, err = ensureAccount(c, now, ident, d.System)
		return err
	})
	provision.RegisterCompletion(completeAddGrant, func(c *store.TenantTx, now time.Time, raw json.RawMessage) error {
		var d identityGroup
		if err := json.Unmarshal(raw, &d); err != nil {
			return err
		}
		ident, err := c.Identity(d.IdentityID)
		if err != nil {
			return err
		}
		return addGrantTo(c, now, ident, d.GroupID)
	})
}

// route sends a step's change to the provisioning engine when the system's
// connection has write-back on. It reports whether it did; the caller then
// leaves the graph alone (the engine edits it once the target confirms).
func route(c *store.TenantTx, now time.Time, ch provision.Change) (bool, error) {
	_, routed, err := provision.Submit(c, now, ch)
	return routed, err
}

func stepKey(eventID int64, idx int, action string) string {
	return fmt.Sprintf("jml:%d:%d:%s", eventID, idx, action)
}

func applyStep(c *store.TenantTx, now time.Time, by string, ident *store.Identity, st Step, eventID int64, idx int) error {
	var err error
	switch stepStr(st, "action") {
	case containment.ActionRevokeSessions, containment.ActionRevokeGrants:
		// run by the caller before ExecuteEvent; failures become retry tasks
	case "disable_account":
		id, _ := stepInt(st, "account_id")
		var routed bool
		if routed, err = routeDisable(c, now, id, stepKey(eventID, idx, "disable_account")); err == nil && !routed {
			if err = c.DisableAccount(id); err == nil {
				// an app with no connector cannot be disabled from here: a manual task (issue #105)
				err = flatfile.AccountDisabled(c, now, by, id, "leaver")
			}
		}
	case "remove_grant":
		id, _ := stepInt(st, "edge_id")
		var routed bool
		if routed, err = routeRemoveGrant(c, now, id, stepKey(eventID, idx, "remove_grant")); err == nil && !routed {
			if err = flatfile.GrantRevoked(c, now, by, id, "leaver"); err == nil {
				err = c.RevokeEdge(id, now, "jml")
			}
		}
	case "add_grant":
		var routed bool
		if routed, err = routeAddGrant(c, now, ident, st, stepKey(eventID, idx, "add_grant")); err == nil && !routed {
			err = addGrant(c, now, ident, st)
		}
	case "cancel_jit":
		id, _ := stepInt(st, "request_id")
		err = c.CancelRequest(id, now)
	case "reassign_owner":
		id, _ := stepInt(st, "identity_id")
		err = c.SetIdentityOwner(id, optInt(stepGet(st, "new_owner_id")))
	case "reassign_ownership":
		err = reassignOwnership(c, now, st)
	case "rotate_secret":
		id, _ := stepInt(st, "secret_id")
		err = c.SetSecretRotated(id, now)
	case "revoke_delegation":
		id, _ := stepInt(st, "delegation_id")
		err = c.DeleteDelegation(id)
	case "reassign_reports":
		ids, _ := stepGet(st, "report_ids").([]int64)
		for _, rid := range ids {
			if err = c.SetIdentityManager(rid, optInt(stepGet(st, "new_manager_id"))); err != nil {
				return err
			}
		}
	}
	// create_account / review_grant / create_identity are informational for existing identities
	return err
}

func routeDisable(c *store.TenantTx, now time.Time, accountID int64, key string) (bool, error) {
	a, err := getOrNil(c.Account(accountID))
	if err != nil || a == nil {
		return false, err
	}
	return route(c, now, provision.Change{System: a.System, Kind: target.DisableAccount,
		Account: target.Account{Username: a.Username, ExternalID: a.ExternalID}, Source: provision.SourceJML, Key: key,
		Completion: provision.CompleteAccountDisable, Data: provision.AccountData{AccountID: accountID}})
}

// routeRemoveGrant routes the removal of a group membership. Edges to
// permissions have no counterpart in a target and are never routed.
func routeRemoveGrant(c *store.TenantTx, now time.Time, edgeID int64, key string) (bool, error) {
	e, err := getOrNil(c.Edge(edgeID))
	if err != nil || e == nil {
		return false, err
	}
	kind, aid, err := graph.ParseKey(e.Src)
	if err != nil || kind != "account" {
		return false, nil
	}
	kind, gid, err := graph.ParseKey(e.Dst)
	if err != nil || kind != "group" {
		return false, nil
	}
	a, err := getOrNil(c.Account(aid))
	if err != nil || a == nil {
		return false, err
	}
	g, err := getOrNil(c.Group(gid))
	if err != nil || g == nil {
		return false, err
	}
	return route(c, now, provision.Change{System: g.System, Kind: target.RemoveEntitlement,
		Account: target.Account{Username: a.Username, ExternalID: a.ExternalID},
		Group:   target.Group{ExternalID: g.ExternalID, Name: g.Name}, Source: provision.SourceJML, Key: key,
		Completion: provision.CompleteEdgeRemove, Data: provision.EdgeData{EdgeID: edgeID}})
}

func routeAddGrant(c *store.TenantTx, now time.Time, ident *store.Identity, st Step, key string) (bool, error) {
	gid, _ := stepInt(st, "group_id")
	g, err := getOrNil(c.Group(gid))
	if err != nil || g == nil {
		return false, err
	}
	if t, err := provision.Route(c, g.System); err != nil || t == nil {
		return false, err
	}
	uname, extID, err := accountSpec(ident, g.System)
	if err != nil {
		return false, err
	}
	accts, err := c.IdentityAccounts(ident.ID)
	if err != nil {
		return false, err
	}
	have := false
	for _, a := range accts {
		if a.System == g.System && a.Status == "active" {
			uname, extID, have = a.Username, a.ExternalID, true
		}
	}
	if !have { // the identity has no account there yet: create it first
		if err := routeEnsureAccount(c, now, ident, g.System, key+":account"); err != nil {
			return false, err
		}
	}
	return route(c, now, provision.Change{System: g.System, Kind: target.AddEntitlement,
		Account: target.Account{Username: uname, ExternalID: extID},
		Group:   target.Group{ExternalID: g.ExternalID, Name: g.Name}, Source: provision.SourceJML, Key: key,
		Completion: completeAddGrant, Data: identityGroup{IdentityID: ident.ID, GroupID: gid}})
}

// routeEnsureAccount creates the joiner's account in the target when the
// system's connection has write-back on. Without a target (or when the
// account exists) it is a plain ensureAccount.
func routeEnsureAccount(c *store.TenantTx, now time.Time, ident *store.Identity, system, key string) error {
	if t, err := provision.Route(c, system); err != nil {
		return err
	} else if t != nil {
		accts, err := c.IdentityAccounts(ident.ID)
		if err != nil {
			return err
		}
		for _, a := range accts {
			if a.System == system && a.Status == "active" {
				return nil // already there
			}
		}
		uname, extID, err := accountSpec(ident, system)
		if err != nil {
			return err
		}
		acct := target.Account{Username: uname, ExternalID: extID, DisplayName: ident.Name}
		if ident.Email != nil {
			acct.Email = *ident.Email
		}
		_, err = route(c, now, provision.Change{System: system, Kind: target.CreateAccount, Account: acct,
			Source: provision.SourceJML, Key: key, Completion: completeEnsureAccount,
			Data: identitySystem{IdentityID: ident.ID, System: system}})
		return err
	}
	_, err := ensureAccount(c, now, ident, system)
	return err
}

// ExecuteEvent applies an HRIS event's plan and marks it executed.
// by is the platform user who executes it (the request's principal). The
// containment steps (revoke_sessions, revoke_grants) are not applied here:
// the caller runs them before, and a failed one is a retry task, not a
// reason to stop the leaver.
func ExecuteEvent(c *store.TenantTx, now time.Time, eventID int64, by store.UserRef, policies []*policy.Policy) (Plan, error) {
	ev, err := getOrNil(c.HrisEvent(eventID))
	if err != nil {
		return nil, err
	}
	if ev == nil {
		return nil, ErrEventNotFound
	}
	if ev.Status == "executed" {
		return nil, ErrEventExecuted
	}
	if ev.Type == "joiner" {
		if err := CheckJoiner(c, ev.Payload); err != nil {
			return nil, err
		}
	}
	plan, err := PlanForEvent(c, now, ev, false, policies)
	if err != nil {
		return nil, err
	}
	steps, _ := getAny(plan, "steps").([]Step)
	var identityName any
	if ident, ok := getAny(plan, "identity").(ojson.Object); ok {
		identityName = getAny(ident, "name")
	}
	if ev.Type == "joiner" {
		p := ev.Payload
		var mgr *int64
		if xid, ok := getAny(p, "manager_external_id").(string); ok {
			if m, err := getOrNil(c.IdentityByExternalID(xid)); err != nil {
				return nil, err
			} else if m != nil {
				mgr = &m.ID
			}
		}
		source, hired := "workday", ev.EffectiveAt
		// The HR employee id, when the event carries one, is the external id so a later
		// duplicate is caught. A rehire's old (terminated) row still holds it, and the
		// column is unique, so that case keeps the event-derived id.
		xid := fmt.Sprintf("emp-new-%d", ev.ID)
		if _, hrID := joinerKeys(p); hrID != "" {
			if old, err := getOrNil(c.IdentityByExternalID(hrID)); err != nil {
				return nil, err
			} else if old == nil {
				xid = hrID
			}
		}
		id, err := c.InsertIdentity(&store.Identity{ExternalID: xid,
			Name: pyStr(getAny(p, "name")), Email: optStr(p, "email"), Type: "human", Department: optStr(p, "department"),
			Title: optStr(p, "title"), Status: "active", ManagerID: mgr, Source: &source, HiredAt: &hired, CreatedAt: now})
		if err != nil {
			return nil, err
		}
		if err := c.SetHrisEventIdentity(ev.ID, id); err != nil {
			return nil, err
		}
		if err := joinerLifecycle(c, now, id, mgr, p); err != nil {
			return nil, err
		}
		ident, err := c.Identity(id)
		if err != nil {
			return nil, err
		}
		sysSet := map[string]bool{}
		for _, st := range steps {
			if stepStr(st, "action") == "add_grant" {
				sysSet[stepStr(st, "system")] = true
			}
		}
		for _, s := range append([]string{"workday"}, sortedKeys(sysSet)...) {
			if err := routeEnsureAccount(c, now, ident, s, fmt.Sprintf("jml:%d:account:%s", ev.ID, s)); err != nil {
				return nil, err
			}
		}
		for i, st := range steps {
			if stepStr(st, "action") == "add_grant" {
				if err := applyStep(c, now, by.Display, ident, st, ev.ID, i); err != nil {
					return nil, err
				}
			}
		}
	} else {
		ident, err := c.Identity(*ev.IdentityID)
		if err != nil {
			return nil, err
		}
		for i, st := range steps {
			if err := applyStep(c, now, by.Display, ident, st, ev.ID, i); err != nil {
				return nil, err
			}
		}
		switch ev.Type {
		case "leaver":
			err = c.TerminateIdentity(ident.ID, now)
		case "mover":
			dept, title := ident.Department, ident.Title
			if v, ok := ev.Payload.Get("to_department"); ok {
				dept = dbValue(v)
			}
			if v, ok := ev.Payload.Get("new_title"); ok {
				title = dbValue(v)
			}
			err = c.SetIdentityDepartmentTitle(ident.ID, dept, title)
		}
		if err != nil {
			return nil, err
		}
	}
	if err := c.MarkHrisEventExecuted(ev.ID, now, by); err != nil {
		return nil, err
	}
	err = c.Audit(now, by.Display, "jml."+ev.Type, ojson.Object{{Key: "event_id", Value: ev.ID},
		{Key: "identity", Value: identityName}, {Key: "steps", Value: len(steps)}})
	return plan, err
}

func dbValue(v any) *string {
	switch x := v.(type) {
	case nil:
		return nil
	case string:
		return &x
	}
	s := pyStr(v)
	return &s
}

// optInt is a plan step's optional integer id (nil stores NULL).
func optInt(v any) *int64 {
	switch x := v.(type) {
	case int64:
		return &x
	case *int64:
		return x
	}
	return nil
}

// activeOnly keeps the active identities, preserving order.
func activeOnly(in []*store.Identity, err error) ([]*store.Identity, error) {
	if err != nil {
		return nil, err
	}
	out := in[:0:0]
	for _, i := range in {
		if i.Status == "active" {
			out = append(out, i)
		}
	}
	return out, nil
}

// IdentityRef is a brief identity in an event view.
type IdentityRef struct {
	ID         int64   `json:"id"`
	Name       string  `json:"name"`
	Department *string `json:"department"`
}

// EventView is the API rendering of an HRIS event.
type EventView struct {
	ID          int64        `json:"id"`
	ExternalID  string       `json:"external_id"`
	Type        string       `json:"type"`
	Status      string       `json:"status"`
	EffectiveAt string       `json:"effective_at"`
	ExecutedAt  *string      `json:"executed_at"`
	Identity    *IdentityRef `json:"identity"`
	Payload     ojson.Object `json:"payload"`
}

// ViewEvent renders an event.
func ViewEvent(c *store.TenantTx, ev *store.HrisEvent) (EventView, error) {
	v := EventView{ID: ev.ID, ExternalID: ev.ExternalID, Type: ev.Type, Status: ev.Status,
		EffectiveAt: timeutil.ISO(ev.EffectiveAt), ExecutedAt: timeutil.ISOPtr(ev.ExecutedAt), Payload: ev.Payload}
	if v.Payload == nil {
		v.Payload = ojson.Object{}
	}
	if ev.IdentityID != nil {
		i, err := getOrNil(c.Identity(*ev.IdentityID))
		if err != nil {
			return v, err
		}
		if i != nil {
			v.Identity = &IdentityRef{i.ID, i.Name, i.Department}
		}
	}
	return v, nil
}

// ExecuteLeaver runs an identity's leaver plan outside an HRIS event (an
// identity reaching its end date, issue #159): every step of LeaverPlan is
// applied and the identity is terminated, in the caller's transaction. The
// caller writes the audit event.
func ExecuteLeaver(c *store.TenantTx, now time.Time, identityID int64) (Plan, error) {
	plan, err := LeaverPlan(c, now, identityID, false, nil)
	if err != nil {
		return nil, err
	}
	ident, err := c.Identity(identityID)
	if err != nil {
		return nil, err
	}
	steps, _ := getAny(plan, "steps").([]Step)
	for i, st := range steps {
		// No HRIS event: a negative id keeps the provisioning keys of this
		// identity's end-date leaver apart from every event's.
		if err := applyStep(c, now, "system", ident, st, -identityID, i); err != nil {
			return nil, err
		}
	}
	return plan, c.TerminateIdentity(identityID, now)
}

// joinerLifecycle records a non-employee joiner's worker type, end date and
// sponsor from the HRIS payload (worker_type, end_date, and
// sponsor_external_id, else the manager), issue #159. An employee joiner
// writes nothing.
func joinerLifecycle(c *store.TenantTx, now time.Time, id int64, mgr *int64, p ojson.Object) error {
	wt, _ := getAny(p, "worker_type").(string)
	if wt == "" || wt == store.WorkerEmployee {
		return nil
	}
	l := &store.Lifecycle{IdentityID: id, WorkerType: wt, SponsorID: mgr, Source: "hris", UpdatedAt: now}
	if xid, ok := getAny(p, "sponsor_external_id").(string); ok {
		sp, err := getOrNil(c.IdentityByExternalID(xid))
		if err != nil {
			return err
		}
		if sp != nil {
			l.SponsorID = &sp.ID
		}
	}
	end, _ := getAny(p, "end_date").(string)
	t, err := timeutil.ParseISO(end)
	if err != nil {
		return &Error{fmt.Sprintf("a %s joiner needs an end_date", wt)}
	}
	l.EndsAt = &t
	if err := c.PutLifecycle(l); err != nil {
		return err
	}
	w := wt
	return c.AddLifecycleEvent(&store.LifecycleEvent{IdentityID: id, Event: "set", WorkerType: &w, EndsAt: l.EndsAt,
		Actor: "hris", At: now})
}
