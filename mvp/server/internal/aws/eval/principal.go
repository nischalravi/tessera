package eval

import (
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/authz"

	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
)

// MatchKind says how a resource-policy principal matched a requester (§8.4.2).
// The engine treats the kinds differently (§7.4): ACCOUNT delegates to identity
// policies, PARENT stays capped by the boundary and session policy, SELF does
// not.
type MatchKind uint8

const (
	MatchSelf                 MatchKind = iota + 1 // the requester's own user or session ARN (or federated provider)
	MatchParent                                    // the role (or IAM user) a session was issued from
	MatchAccount                                   // an account principal that holds the requester's account
	MatchWildcard                                  // "*"
	MatchWildcardPrincipalARN                      // "*" in a statement that also conditions on aws:PrincipalArn
	MatchService                                   // a service principal
)

var matchKindNames = []string{"", "SELF", "PARENT", "ACCOUNT", "WILDCARD", "WILDCARD_PRINCIPALARN", "SERVICE"}

func (k MatchKind) String() string {
	if int(k) < len(matchKindNames) {
		return matchKindNames[k]
	}
	return "UNKNOWN"
}

// MatchKinds is the set of kinds a statement's principal list matched with.
// A list can match in several ways at once (an account and a role ARN); the
// engine picks, so the result does not depend on list order.
type MatchKinds uint8

// Has reports whether k is in the set.
func (s MatchKinds) Has(k MatchKind) bool { return k != 0 && s&(1<<k) != 0 }

// Empty reports whether nothing matched.
func (s MatchKinds) Empty() bool { return s == 0 }

func (s *MatchKinds) add(k MatchKind) { *s |= 1 << k }

// String lists the kinds in a fixed order, e.g. "SELF|ACCOUNT".
func (s MatchKinds) String() string {
	var parts []string
	for k := MatchSelf; k <= MatchService; k++ {
		if s.Has(k) {
			parts = append(parts, k.String())
		}
	}
	return strings.Join(parts, "|")
}

// ConditionsOnPrincipalARN reports whether any condition atom tests
// aws:PrincipalArn, under any operator (§8.4.1).
func ConditionsOnPrincipalARN(cond []authz.Atom) bool {
	for _, a := range cond {
		if a.Key == "aws:principalarn" {
			return true
		}
	}
	return false
}

// MatchStatementPrincipal matches a statement's Principal against requester p.
// canonicalIDs is snapshot.canonical_ids (S3 canonical user id to account id).
// A statement without Principal matches nothing (identity-based statements
// have none; implied principals are the engine's concern).
func MatchStatementPrincipal(st *model.Statement, p *model.Principal, canonicalIDs map[string]string) MatchKinds {
	return MatchPrincipal(st.Principals, ConditionsOnPrincipalARN(st.Condition), p, canonicalIDs)
}

// MatchPrincipal reports how the Principal element ps matches requester p
// (§8.4.2). wildcardPrincipalARN says the statement also conditions on
// aws:PrincipalArn, which turns a WILDCARD match into WILDCARD_PRINCIPALARN.
// ARNs and ids are compared case-sensitively (§8.1).
func MatchPrincipal(ps *model.PrincipalSet, wildcardPrincipalARN bool, p *model.Principal, canonicalIDs map[string]string) MatchKinds {
	var out MatchKinds
	if ps == nil || p == nil {
		return out
	}
	for _, e := range ps.Entries {
		switch e.Kind {
		case model.PrincipalWildcard:
			if wildcardPrincipalARN {
				out.add(MatchWildcardPrincipalARN)
			} else {
				out.add(MatchWildcard)
			}
		case model.PrincipalIAMUser:
			switch p.Kind {
			case model.IAMUser:
				if e.Value == p.ARN {
					out.add(MatchSelf)
				}
			case model.FederatedUserSession:
				if e.Value == p.EntityARN {
					out.add(MatchParent)
				}
			}
		case model.PrincipalAssumedRole, model.PrincipalFederatedUser:
			if (p.Kind == model.RoleSession || p.Kind == model.FederatedUserSession) && e.Value == p.ARN {
				out.add(MatchSelf)
			}
		case model.PrincipalIAMRole:
			switch p.Kind {
			case model.RoleSession:
				if e.Value == p.EntityARN {
					out.add(MatchParent)
				}
			case model.IAMRole:
				if e.Value == p.ARN {
					out.add(MatchSelf)
				}
			}
		case model.PrincipalUniqueID:
			if p.UniqueID == "" || e.Value != p.UniqueID {
				break
			}
			switch p.Kind {
			case model.RoleSession:
				out.add(MatchParent)
			case model.IAMUser, model.IAMRole:
				out.add(MatchSelf)
			}
		case model.PrincipalAccount:
			matchAccount(&out, e.AccountID, p)
		case model.PrincipalCanonicalUser:
			if acct, ok := canonicalIDs[e.Value]; ok {
				matchAccount(&out, acct, p)
			}
		case model.PrincipalService:
			if p.Kind == model.Service && e.Value == p.ARN {
				out.add(MatchService)
			}
		case model.PrincipalFederated:
			if p.FederatedProvider != "" && e.Value == p.FederatedProvider {
				out.add(MatchSelf)
			}
		}
	}
	return out
}

// matchAccount adds ACCOUNT when the requester is an IAM principal of the
// account; for the account's root user it adds SELF instead, because root
// holds every permission of its account (§8.4.2).
func matchAccount(out *MatchKinds, account string, p *model.Principal) {
	if account == "" || p.AccountID != account {
		return
	}
	switch p.Kind {
	case model.Root:
		out.add(MatchSelf)
	case model.IAMUser, model.IAMRole, model.RoleSession, model.FederatedUserSession:
		out.add(MatchAccount)
	}
}

// NotPrincipalDenyApplies reports whether a Deny with NotPrincipal list np
// applies to requester p (§8.4.3). It is true unless p is exempt: its account
// is listed and, for a user, its ARN; for a session, its role (or user) ARN or
// its session ARN (ambiguity A4); root needs only the account.
//
// A requester with a permissions boundary is never exempt, whatever is listed
// (documented AWS behaviour). NotPrincipal with Allow is invalid and is
// dropped at ingest, so this has no Allow counterpart.
//
// ambiguousA4 is true when the answer rests on the A4 default for sessions
// (the account is listed and exactly one of the role and session ARNs is; with
// neither listed the Deny applies by every reading, and with both listed the
// requester is exempt by every reading): the caller adds AMBIGUITY:A4 to the decision's fidelity reasons.
func NotPrincipalDenyApplies(np *model.PrincipalSet, p *model.Principal) (applies, ambiguousA4 bool) {
	if np == nil || p == nil {
		return false, false
	}
	if p.BoundaryPolicyID != "" {
		return true, false
	}
	var acctListed, arnListed, entityListed, serviceListed bool
	for _, e := range np.Entries {
		switch e.Kind {
		case model.PrincipalAccount:
			if e.AccountID != "" && e.AccountID == p.AccountID {
				acctListed = true
			}
		case model.PrincipalIAMUser, model.PrincipalAssumedRole, model.PrincipalFederatedUser, model.PrincipalIAMRole:
			if e.Value == p.ARN {
				arnListed = true
			}
			if p.EntityARN != "" && e.Value == p.EntityARN {
				entityListed = true
			}
		case model.PrincipalService:
			if e.Value == p.ARN {
				serviceListed = true
			}
		}
	}
	switch p.Kind {
	case model.Root:
		return !acctListed, false
	case model.IAMUser:
		return !(acctListed && arnListed), false
	case model.RoleSession, model.FederatedUserSession:
		exempt := acctListed && (entityListed || arnListed)
		// Only one of the two spellings listed is the case the probe settles.
		return !exempt, acctListed && (entityListed != arnListed)
	case model.Service:
		return !serviceListed, false
	}
	return true, false
}
