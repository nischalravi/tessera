// Package stepup is the tenant's step-up policy per action (issue #298).
//
// The code declares a step-up requirement on each sensitive route
// (auth.StepUpPolicy, auth.StepUpAdmin); those are the floor. A tenant policy
// maps a permission to a requirement, and the requirement a state-changing
// route of that permission is held to is the stricter of the floor and the
// tenant's entry (auth.AuthnRequirement.Merge): an admin can add step-up to an
// action that has none, or tighten one, and can never remove or weaken what the
// code requires. Validate refuses an entry below the floor, and Effective keeps
// the floor even if one got stored.
//
// The only way below the floor is the deployment's own TESSERA_STEPUP_ALLOW_WEAKER
// switch, which the production configuration refuses.
package stepup

import (
	"slices"
	"sort"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/auth"
	"github.com/nischalravi/tessera/mvp/server/internal/cfgerr"
	"github.com/nischalravi/tessera/mvp/server/internal/ojson"
	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

// Bounds of an entry's maximum authentication age.
const (
	MinMaxAge = 60 * time.Second
	MaxMaxAge = 3600 * time.Second
)

// ACRs an entry may name, weakest first. A plain sign-in (aal1) needs no step-up.
var ACRs = []auth.ACR{auth.ACRAAL2, auth.ACRPhr, auth.ACRPhrh}

// Entry is one action's requirement.
type Entry struct {
	ACR    auth.ACR
	MaxAge time.Duration
}

// Req is the entry as an authentication requirement.
func (e Entry) Req() auth.AuthnRequirement {
	return auth.AuthnRequirement{ACR: e.ACR, MaxAge: e.MaxAge}
}

// Policy is the tenant's entries by permission (the action).
type Policy map[auth.Permission]Entry

// Floor is what the code requires of one permission's state-changing routes.
type Floor struct {
	// Req is the weakest requirement among the permission's routes that have
	// one; nil when no route of the permission has a step-up (an entry then adds).
	Req *auth.AuthnRequirement
	// Unguarded is true when some state-changing route of the permission has
	// no step-up in code, so an entry adds step-up there.
	Unguarded bool
	Routes    int
}

// Catalog is the actions a policy may name: every permission that has a
// state-changing route that takes the tenant policy.
type Catalog map[auth.Permission]*Floor

// RouteDecl is what the catalog needs of a registered route.
type RouteDecl struct {
	Method string
	Perm   auth.Permission
	Authn  *auth.AuthnRequirement
	// Exempt: the route never takes the tenant policy (the policy's own routes,
	// so a policy cannot lock its admins out of fixing it).
	Exempt bool
}

// Applies reports whether the tenant policy covers a route: it is
// state-changing, has a real permission and is not exempt.
func Applies(method string, perm auth.Permission, exempt bool) bool {
	return !exempt && !auth.SafeMethod(method) && perm != "" && perm != auth.PermAuthenticated
}

// weaker is the weaker of two requirements: the lower ACR and the longer age
// (no limit is the longest).
func weaker(a, b auth.AuthnRequirement) auth.AuthnRequirement {
	out := a
	if b.ACR.Rank() < out.ACR.Rank() {
		out.ACR = b.ACR
	}
	if a.MaxAge <= 0 || b.MaxAge <= 0 {
		out.MaxAge = 0
	} else if b.MaxAge > out.MaxAge {
		out.MaxAge = b.MaxAge
	}
	return out
}

// BuildCatalog derives the actions, and the floor of each, from the routes.
func BuildCatalog(routes []RouteDecl) Catalog {
	c := Catalog{}
	for _, r := range routes {
		if !Applies(r.Method, r.Perm, r.Exempt) {
			continue
		}
		f := c[r.Perm]
		if f == nil {
			f = &Floor{}
			c[r.Perm] = f
		}
		f.Routes++
		if r.Authn == nil {
			f.Unguarded = true
			continue
		}
		if f.Req == nil {
			req := *r.Authn
			f.Req = &req
		} else {
			w := weaker(*f.Req, *r.Authn)
			f.Req = &w
		}
	}
	return c
}

// Actions lists the catalog's permissions, sorted.
func (c Catalog) Actions() []auth.Permission {
	out := make([]auth.Permission, 0, len(c))
	for p := range c {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Validate checks a policy from the API against the catalog. Unless
// allowWeaker, an entry weaker than the floor of its action is refused.
func (c Catalog) Validate(p Policy, allowWeaker bool) error {
	for perm, e := range p {
		f := c[perm]
		switch {
		case f == nil:
			return cfgerr.Refuse(422, "unknown_action", "%q is not an action with a step-up setting", perm)
		case !slices.Contains(ACRs, e.ACR):
			return cfgerr.Refuse(422, "invalid_acr", "%s: the assurance level is %s, %s or %s", perm, ACRs[0], ACRs[1], ACRs[2])
		case e.MaxAge < MinMaxAge || e.MaxAge > MaxMaxAge:
			return cfgerr.Refuse(422, "invalid_max_age", "%s: the sign-in may be %d to %d seconds old", perm,
				int(MinMaxAge/time.Second), int(MaxMaxAge/time.Second))
		}
		// an action with an unguarded route may be given an entry below the weakest guarded one: on the guarded
		// routes Effective keeps the code's requirement, and the entry only adds step-up to the rest
		if f.Req != nil && !f.Unguarded && !allowWeaker {
			req := e.Req()
			if req.ACR.Rank() < f.Req.ACR.Rank() || (f.Req.MaxAge > 0 && req.MaxAge > f.Req.MaxAge) {
				return cfgerr.Refuse(422, "weaker_than_required", "%s already requires %s within %d seconds; a policy can add step-up or make it stricter, not weaker",
					perm, f.Req.ACR, int(f.Req.MaxAge/time.Second))
			}
		}
	}
	return nil
}

// Effective is the requirement a state-changing route of perm is held to: the
// route's own (floor, nil for none) made at least as strict as the tenant's
// entry. allowWeaker (dev only) lets the entry replace the floor instead.
func (p Policy) Effective(perm auth.Permission, floor *auth.AuthnRequirement, allowWeaker bool) *auth.AuthnRequirement {
	e, ok := p[perm]
	if !ok {
		return floor
	}
	req := e.Req()
	if floor == nil || allowWeaker {
		return &req
	}
	m := floor.Merge(req)
	return &m
}

// Load returns the tenant's policy and the version it was saved at (0: none saved).
func Load(tx *store.TenantTx) (Policy, int, error) {
	row, err := tx.StepUpPolicy()
	if store.ErrNoSettings(err) {
		return Policy{}, 0, nil
	} else if err != nil {
		return nil, 0, err
	}
	p := Policy{}
	for perm, e := range row.Entries {
		p[auth.Permission(perm)] = Entry{ACR: auth.ACR(e.ACR), MaxAge: time.Duration(e.MaxAgeS) * time.Second}
	}
	return p, row.Version, nil
}

func detail(p Policy) ojson.Object {
	perms := make([]string, 0, len(p))
	for perm := range p {
		perms = append(perms, string(perm))
	}
	sort.Strings(perms)
	d := ojson.Object{}
	for _, perm := range perms {
		e := p[auth.Permission(perm)]
		d = append(d, ojson.KV{Key: perm, Value: ojson.Object{{Key: "acr", Value: string(e.ACR)}, {Key: "max_age_s", Value: int(e.MaxAge / time.Second)}}})
	}
	return d
}

// Save replaces the tenant's policy. ver is the version the caller read (0 if
// it read none); a different current version is a conflict. The change is
// audited in the same transaction, with the old entries.
func Save(tx *store.TenantTx, c Catalog, p Policy, ver int, allowWeaker bool, by string, now time.Time) (Policy, int, error) {
	if err := c.Validate(p, allowWeaker); err != nil {
		return nil, 0, err
	}
	old, cur, err := Load(tx)
	if err != nil {
		return nil, 0, err
	}
	if ver != cur {
		return nil, 0, cfgerr.Conflict(ver, cur)
	}
	row := &store.StepUpPolicyRow{Entries: map[string]store.StepUpEntry{}, UpdatedBy: by}
	for perm, e := range p {
		row.Entries[string(perm)] = store.StepUpEntry{ACR: string(e.ACR), MaxAgeS: int(e.MaxAge / time.Second)}
	}
	if err := tx.PutStepUpPolicy(row, now); err != nil {
		return nil, 0, err
	}
	d := ojson.Object{{Key: "entries", Value: detail(p)}, {Key: "previous", Value: detail(old)}, {Key: "version", Value: cur + 1}}
	if err := tx.Audit(now, by, "stepup.policy.update", d); err != nil {
		return nil, 0, err
	}
	return p, cur + 1, nil
}
