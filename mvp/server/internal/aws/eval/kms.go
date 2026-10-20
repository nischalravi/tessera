package eval

import (
	"strings"

	"github.com/nischalravi/tessera/mvp/server/internal/authz"
)

// This file is the KMS part of §7.6.1: grants (SPECIAL.kms_grant_*) and the
// cross-account operation allowlist (a guardrail). The key policy itself is an
// ordinary resource policy with requires_explicit_allow, handled by the grant
// matrix in grant.go.

const ecKeyPrefix = "kms:encryptioncontext:"

// kmsRelation says how a grant's grantee (or retiring principal) relates to the
// requester.
type kmsRelation uint8

const (
	kmsNone   kmsRelation = iota
	kmsSelf               // the requester's own ARN: a user, session or service
	kmsParent             // the requester's role (or the IAM user a federated session came from)
	kmsRoot               // the requester's account root: a delegation
)

func (r kmsRelation) String() string {
	switch r {
	case kmsSelf:
		return "self"
	case kmsParent:
		return "parent"
	case kmsRoot:
		return "account_root"
	}
	return "none"
}

// kmsRelationOf classifies one principal string against the requester.
func (e *evaluator) kmsRelationOf(arn string) kmsRelation {
	if arn == "" {
		return kmsNone
	}
	if e.class == classService {
		if asciiLower(arn) == asciiLower(e.p.ARN) {
			return kmsSelf
		}
		return kmsNone
	}
	if e.class != classIAM {
		return kmsNone
	}
	switch {
	case arn == e.p.ARN:
		return kmsSelf
	case e.p.EntityARN != "" && arn == e.p.EntityARN:
		return kmsParent
	}
	if parts, ok := splitARN(arn); ok && parts[2] == "iam" && parts[5] == "root" && parts[4] != "" && parts[4] == e.p.AccountID {
		return kmsRoot
	}
	return kmsNone
}

// kmsTerms computes SPECIAL.kms_grant_self, _parent and the root-delegation
// term for the request. A grant counts only if the requested operation is one
// it lists and every constraint holds against the request context.
func (e *evaluator) kmsTerms() {
	s := &e.spec
	s.kmsSelf, s.kmsParent, s.kmsRoot = authz.F, authz.F, authz.F
	if e.prefix != "kms" || e.res.none {
		return
	}
	_, op, _ := strings.Cut(e.action, ":")
	for _, g := range e.snap.KMSGrants[e.res.arn] {
		rel := kmsNone
		var match authz.Tri
		if r := e.kmsRelationOf(g.GranteePrincipal); r != kmsNone {
			rel, match = r, e.grantMatches(g.Operations, op, g.ConstraintsECEquals, g.ConstraintsECSubset, g.ConstraintSourceARN)
		} else if r := e.kmsRelationOf(g.GranteeServicePrincipal); r != kmsNone {
			rel, match = r, e.grantMatches(g.Operations, op, g.ConstraintsECEquals, g.ConstraintsECSubset, g.ConstraintSourceARN)
		}
		// The retiring principal may retire the grant on the grant's own
		// authority, with no operation or constraint check (§7.6.1).
		if asciiLower(e.action) == "kms:retiregrant" {
			if r := e.kmsRelationOf(g.RetiringPrincipal); r == kmsSelf || r == kmsParent {
				rel, match = r, authz.T
			}
		}
		if rel == kmsNone {
			continue
		}
		switch rel {
		case kmsSelf:
			s.kmsSelf = s.kmsSelf.Or(match)
		case kmsParent:
			s.kmsParent = s.kmsParent.Or(match)
		case kmsRoot:
			s.kmsRoot = s.kmsRoot.Or(match)
		}
		step := authz.ExplanationStep{
			Stage:     authz.StageKMSGrant,
			MatchedOn: map[string]string{"grant_id": g.GrantID, "grantee": rel.String()},
		}
		switch {
		case match.IsTrue():
			step.Result, step.Note = authz.ResultAllow, "grant "+g.GrantID+" allows "+e.action
		case match.IsFalse():
			step.Result, step.Note = authz.ResultNoMatch, "grant "+g.GrantID+" does not cover "+e.action+" under this request context"
		default:
			step.Result, step.Residual, step.Note = authz.ResultConditional, match.Residual(), "grant "+g.GrantID+" depends on the request context"
		}
		s.kmsSteps = append(s.kmsSteps, step)
	}
}

// grantMatches is the operation and constraint test of §7.6.1.
func (e *evaluator) grantMatches(ops []string, op string, ecEquals, ecSubset map[string]string, sourceARN string) authz.Tri {
	found := false
	for _, o := range ops {
		lo := asciiLower(o)
		if lo == asciiLower(op) || (strings.HasSuffix(lo, "*") && strings.HasPrefix(asciiLower(op), strings.TrimSuffix(lo, "*"))) {
			found = true
			break
		}
	}
	if !found {
		return authz.F
	}
	t := authz.T
	if ecEquals != nil {
		t = t.And(e.ecSubset(ecEquals))
		// EncryptionContextEquals: the request's map must equal the grant's
		// map exactly, so a request key the grant does not name fails it. In
		// symbolic mode a key that is not in the profile is unknown and the
		// check cannot see it; the residual then names only the grant's keys.
		want := map[string]bool{}
		for k := range ecEquals {
			want[ecKeyPrefix+asciiLower(k)] = true
		}
		for k, v := range e.ctx.Values {
			if strings.HasPrefix(k, ecKeyPrefix) && v.State == Present && !want[k] {
				return authz.F
			}
		}
	}
	if ecSubset != nil {
		t = t.And(e.ecSubset(ecSubset))
	}
	if sourceARN != "" {
		t = t.And(e.ctxAtom("StringEquals", "aws:SourceArn", sourceARN))
	}
	return t
}

// ecSubset holds when every pair of m is in the request's encryption context.
// Keys are compared case-insensitively because the context keys are folded.
func (e *evaluator) ecSubset(m map[string]string) authz.Tri {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sortStrings(keys)
	t := authz.T
	for _, k := range keys {
		t = t.And(e.ctxAtom("StringEquals", "kms:EncryptionContext:"+k, m[k]))
	}
	return t
}

// ctxAtom evaluates one positive, literal condition atom against the context;
// several values are alternatives.
func (e *evaluator) ctxAtom(op, rawKey string, values ...string) authz.Tri {
	a := authz.Atom{Op: op, Key: asciiLower(rawKey), RawKey: rawKey, Values: values}
	return EvalAtom(a, e.ctx, false).Result
}

// kmsCrossAccountGate is the §7.6.1 allowlist: a kms: action on a key of
// another account that is not a cryptographic operation (or one of the few
// others) is a guardrail deny whatever the policies say.
func (e *evaluator) kmsCrossAccountGate(cross bool) authz.Tri {
	if e.prefix != "kms" || e.res.none || !cross || e.cat.KMSCrossAccountOp(e.action) {
		return authz.T
	}
	return authz.F
}
