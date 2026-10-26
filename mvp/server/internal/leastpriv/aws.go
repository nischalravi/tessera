package leastpriv

import (
	"context"
	"fmt"
	"sort"

	"github.com/nischalravi/tessera/mvp/server/internal/authz"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/index"
	awsq "github.com/nischalravi/tessera/mvp/server/internal/aws/query"
)

// Least privilege on AWS (design §11.5, issue #30). A recommendation is a
// candidate change; the evaluator decides whether it is safe:
//
//  1. every (action, resource) pair the principal used over the observation
//     window is still ALLOW under the candidate, and
//  2. the candidate's effective permissions are a subset of the current ones
//     (the candidate takes away, and gives nothing).
//
// Both are evaluator queries, so the statement "this change removes N
// permissions, none used in 90 days, and keeps all 41 observed calls" has an
// exact basis. A change is applied without a human only when the permissions
// it touches are EXACT and unconditional (spec R2): an APPROXIMATE, UNSUPPORTED
// or CONDITIONAL basis is advice, never an action.

// UsedCall is one (action, resource) pair a principal was seen to use.
type UsedCall struct {
	Action   string `json:"action"`
	Resource string `json:"resource"`
}

// Verification is the evaluator's check of a candidate change for one principal.
type Verification struct {
	// Kept are the used calls still allowed; Broken are those that no longer
	// are, with the decision they now get.
	Kept   []UsedCall   `json:"kept"`
	Broken []BrokenCall `json:"broken"`
	// Inexact are the kept calls whose decision after the change is allowed
	// but not EXACT: a right-size that rests on them is refused (LP-3).
	Inexact []UsedCall `json:"inexact"`
	// Added counts the permissions the candidate gives that the principal did
	// not have; Removed those it takes away.
	Added   int `json:"added"`
	Removed int `json:"removed"`
	// OK: no used call broke and nothing was added. The candidate is a safe
	// narrowing, whatever the fidelity of its basis.
	OK bool `json:"ok"`
	// AutoApplicable: OK, and every used call and every permission removed
	// rests on an EXACT, unconditional ALLOW. Only then may it be applied
	// without a person deciding.
	AutoApplicable bool     `json:"auto_applicable"`
	Reasons        []string `json:"reasons"`
}

// BrokenCall is a used call the candidate would stop allowing.
type BrokenCall struct {
	UsedCall
	Outcome  string `json:"outcome"`
	Fidelity string `json:"fidelity"`
}

// maxVerifiedCells bounds the permissions compared for one principal.
const maxVerifiedCells = 200000

type cellKey struct{ action, resource string }

// grantCells lists the (action, resource) cells a principal can use, with their
// decisions: the cells that are not a clean deny.
func grantCells(ctx context.Context, q *awsq.Querier, principal string) (map[cellKey]*index.Cell, error) {
	p, err := q.EffectivePermissions(ctx, principal)
	if err != nil {
		return nil, err
	}
	n := 0
	for _, row := range p.Rows {
		n += len(q.Idx.Actions.Atoms[row.Action].Members) * len(q.Idx.Resources.Atoms[row.Resource].Members)
		if n > maxVerifiedCells {
			return nil, fmt.Errorf("leastpriv: %s holds more than %d permissions to compare", principal, maxVerifiedCells)
		}
	}
	out := map[cellKey]*index.Cell{}
	for _, c := range p.Expand() {
		if c.Cell.Outcome == authz.Allow || c.Cell.Outcome == authz.Conditional {
			out[cellKey{c.Action, c.Resource}] = c.Cell
		}
	}
	return out, nil
}

// VerifyAWS checks a candidate change (the head querier's snapshot) against
// the current estate (base) for one principal and the calls it used. Both
// queriers must use the same options.
func VerifyAWS(ctx context.Context, base, head *awsq.Querier, principal string, used []UsedCall) (*Verification, error) {
	before, err := grantCells(ctx, base, principal)
	if err != nil {
		return nil, err
	}
	after, err := grantCells(ctx, head, principal)
	if err != nil {
		return nil, err
	}
	v := &Verification{Kept: []UsedCall{}, Broken: []BrokenCall{}, Inexact: []UsedCall{}, Reasons: []string{}}
	exact := func(c *index.Cell) bool { return c != nil && c.Outcome == authz.Allow && c.Fidelity == authz.Exact }
	auto := true
	for _, u := range used {
		res := u.Resource
		d, err := head.Can(ctx, principal, u.Action, res)
		if err != nil {
			return nil, err
		}
		if d.Outcome == authz.Allow {
			v.Kept = append(v.Kept, u)
			if d.Fidelity != authz.Exact {
				auto = false
				v.Inexact = append(v.Inexact, u)
				v.Reasons = append(v.Reasons, fmt.Sprintf("%s on %s is %s after the change", u.Action, u.Resource, d.Fidelity))
			}
			continue
		}
		v.Broken = append(v.Broken, BrokenCall{u, d.Outcome.String(), d.Fidelity.String()})
	}
	for k, c := range before {
		if _, kept := after[k]; !kept {
			v.Removed++
			if !exact(c) {
				auto = false
			}
		}
	}
	for k := range after {
		if _, had := before[k]; !had {
			v.Added++
		}
	}
	if len(v.Broken) > 0 {
		v.Reasons = append(v.Reasons, fmt.Sprintf("%d used call(s) would no longer be allowed", len(v.Broken)))
	}
	if v.Added > 0 {
		v.Reasons = append(v.Reasons, fmt.Sprintf("the change gives %d permission(s) the principal did not have", v.Added))
	}
	v.OK = len(v.Broken) == 0 && v.Added == 0
	if v.Removed > 0 && !auto {
		v.Reasons = append(v.Reasons, "some permission removed rests on a conditional or approximate evaluation: review it by hand")
	}
	v.AutoApplicable = v.OK && auto
	sort.Slice(v.Kept, func(i, j int) bool { return v.Kept[i].Action+v.Kept[i].Resource < v.Kept[j].Action+v.Kept[j].Resource })
	return v, nil
}
