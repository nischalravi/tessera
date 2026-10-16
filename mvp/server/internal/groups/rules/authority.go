package rules

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/groups/privs"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Authority (design §10.3): a rule needs admin (stem_admin on a folder) on its
// owner and on every object its action touches. Objects it only looks at (a
// group a condition or a membership require names, a group that is to hold an
// assigned privilege) need less, because naming them is not changing them but
// would otherwise tell the author who is in a group they cannot see: read on a
// group whose members it tests, view on a group it names as a holder.

type need struct {
	obj  privs.Object
	priv privs.Privilege
}

// needs lists what the author must hold for the rule, owner first.
func (s *Spec) needs() []need {
	var out []need
	if s.OwnerType == store.RuleOwnerFolder {
		out = append(out, need{privs.Object{Type: privs.Folder, ID: s.OwnerID}, privs.StemAdmin})
	} else {
		out = append(out, need{privs.Object{Type: privs.Group, ID: s.OwnerID}, privs.Admin})
	}
	group := func(id string, p privs.Privilege) {
		out = append(out, need{privs.Object{Type: privs.Group, ID: id}, p})
	}
	switch s.Action {
	case ActAddToGroup, ActRemoveFromGroup:
		group(s.Params.Group, privs.Admin) // the rule changes this group's members
	case ActRequireMemberOf:
		group(s.Params.Group, privs.Read)
	case ActAssignPrivilege:
		if s.Params.HolderType == store.HolderGroup {
			group(s.Params.HolderGroup, privs.View)
		}
	}
	for _, c := range s.Conditions {
		if c.Group != "" {
			group(c.Group, privs.Read)
		}
	}
	return out
}

// Authorize returns a *privs.DeniedError for the first privilege the checker's
// subject lacks for the rule.
func Authorize(ck *privs.Checker, s *Spec) error {
	for _, n := range s.needs() {
		if err := ck.Require(n.obj, n.priv); err != nil {
			return err
		}
	}
	return nil
}

// Compiled is a stored rule with its conditions and params decoded.
type Compiled struct {
	Rule *store.GrpRule
	Spec Spec
}

// Compile decodes a stored rule. A row that does not decode (damaged by hand)
// is an error: the caller fails closed.
func Compile(r *store.GrpRule) (*Compiled, error) {
	s := Spec{OwnerType: r.OwnerType, OwnerID: r.OwnerID, Scope: r.Scope, Name: r.Name, Trigger: r.Trigger,
		Action: r.Action, Enabled: r.Enabled}
	if err := json.Unmarshal([]byte(r.Conditions), &s.Conditions); err != nil {
		return nil, fmt.Errorf("rule %s: conditions: %w", r.ID, err)
	}
	if err := json.Unmarshal([]byte(r.Params), &s.Params); err != nil {
		return nil, fmt.Errorf("rule %s: params: %w", r.ID, err)
	}
	return &Compiled{Rule: r, Spec: s}, nil
}

// errNoAuthor is the reason a rule cannot act: its author no longer exists or
// can no longer sign in.
var errNoAuthor = errors.New("the rule's author is no longer an active user")

// SubjectOf is the privilege subject of a platform user at now, for a rule
// that acts in the background: the identity the user is linked to, and
// tenant_admin when the user holds that role (assigned and unexpired: there is
// no session whose step-up could activate it).
func SubjectOf(tx *store.TenantTx, userID string, now time.Time) (privs.Subject, error) {
	id, err := uuid.Parse(userID)
	if err != nil {
		return privs.Subject{}, errNoAuthor
	}
	u, err := tx.PlatformUser(id)
	if errors.Is(err, store.ErrNotFound) {
		return privs.Subject{}, errNoAuthor
	}
	if err != nil {
		return privs.Subject{}, err
	}
	if u.Status != "active" {
		return privs.Subject{}, errNoAuthor
	}
	as, err := tx.RoleAssignments(u.ID)
	if err != nil {
		return privs.Subject{}, err
	}
	return privs.Subject{Identity: u.IdentityID, TenantAdmin: auth.AssignedRoles(as, now).Has(auth.RoleTenantAdmin)}, nil
}

// authority is the answer to "may this rule act now": the subject it acts as
// and, when it may not, why.
type authority struct {
	Subject privs.Subject
	Denied  string // "" when the rule may act
}

// authorize checks the rule's author, with the privileges they hold now.
func (rt *Runtime) authorize(tx *store.TenantTx, now time.Time, c *Compiled) (authority, error) {
	sub, err := SubjectOf(tx, c.Rule.UpdatedBy, now)
	if errors.Is(err, errNoAuthor) {
		return authority{Denied: "author_unavailable"}, nil
	}
	if err != nil {
		return authority{}, err
	}
	err = Authorize(privs.NewChecker(tx, now, rt.engine(), sub), &c.Spec)
	var d *privs.DeniedError
	switch {
	case errors.As(err, &d):
		return authority{Subject: sub, Denied: fmt.Sprintf("privilege_required: %s on %s %s", d.Privilege, d.Object.Type, d.Object.ID)}, nil
	case err != nil:
		return authority{}, err
	}
	return authority{Subject: sub}, nil
}
