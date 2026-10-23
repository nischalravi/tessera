package perms

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Policy renders the permission assignments as Cedar policy text: one permit (or
// forbid, for a disallow) per assignment, with its limits as a `when` condition
// over `context`. The role is the principal group, a (role, identity) pair adds
// the identity, and resource and action inheritance are Cedar's `in` over the
// entity hierarchy the implication closures describe:
//
//	permit (principal in Tessera::Group::"app:roles:payroll",
//	        action in Tessera::Action::"read",
//	        resource in Tessera::Resource::"app:perms:ledger")
//	when { context has amount && context.amount < 1000 };
//
// Cedar lets a forbid override any permit, while the heuristics (Decide) let a
// more specific allow beat a broader disallow: the text is exact when no
// allow overrides a disallow, and the decision point (Decide) is the authority
// otherwise. An assignment outside its dates at now, or with a limit that does
// not compile, is left out and named in a comment (a forbid with such a limit stays, unconditional).
func (s *Set) Policy(now time.Time) string {
	var b strings.Builder
	as := slices.Clone(s.Assignments)
	slices.SortFunc(as, func(x, y *Assignment) int { return strings.Compare(x.ID, y.ID) })
	for _, a := range as {
		if !a.InDates(now) {
			fmt.Fprintf(&b, "// assignment %s is outside its dates\n", a.ID)
			continue
		}
		cond, err := CompileLimits(a.Limits)
		if err != nil {
			if !a.Disallowed {
				fmt.Fprintf(&b, "// assignment %s is left out: %s\n", a.ID, oneLine(err.Error()))
				continue
			}
			// fail closed: a deny whose limit cannot be read stays, unconditional
			fmt.Fprintf(&b, "// assignment %s has a limit that does not compile (%s): its forbid is unconditional\n", a.ID, oneLine(err.Error()))
			cond = nil
		}
		effect := "permit"
		if a.Disallowed {
			effect = "forbid"
		}
		principal := fmt.Sprintf("principal in Tessera::Group::%s", strconv.Quote(a.RoleName))
		if a.Subject != nil {
			principal = fmt.Sprintf("principal == Tessera::Identity::\"%d\"", *a.Subject)
		}
		fmt.Fprintf(&b, "// assignment %s\n%s (\n  %s,\n  action in Tessera::Action::%s,\n  resource in Tessera::Resource::%s\n)",
			a.ID, effect, principal, strconv.Quote(a.Action), strconv.Quote(a.Resource))
		if a.Subject != nil {
			// the pair also needs the role: the identity holds it only while a member
			fmt.Fprintf(&b, "\nwhen { principal in Tessera::Group::%s", strconv.Quote(a.RoleName))
			if cond != nil {
				fmt.Fprintf(&b, " && (%s)", cond.Cedar())
			}
			b.WriteString(" }")
		} else if cond != nil {
			fmt.Fprintf(&b, "\nwhen { %s }", cond.Cedar())
		}
		b.WriteString(";\n\n")
	}
	return b.String()
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }
