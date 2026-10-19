package eval

import (
	"testing"

	"github.com/nischalravi/tessera/mvp/server/internal/authz"
	"github.com/nischalravi/tessera/mvp/server/internal/aws/model"
)

const (
	acct   = "111111111111"
	other  = "222222222222"
	user   = "arn:aws:iam::111111111111:user/alice"
	role   = "arn:aws:iam::111111111111:role/app"
	sess   = "arn:aws:sts::111111111111:assumed-role/app/s1"
	fedUsr = "arn:aws:sts::111111111111:federated-user/bob"
	rootA  = "arn:aws:iam::111111111111:root"
	uidAR  = "AROAEXAMPLEEXAMPLE01"
	uidAI  = "AIDAEXAMPLEEXAMPLE01"
)

var (
	pUser = &model.Principal{ARN: user, Kind: model.IAMUser, AccountID: acct, UniqueID: uidAI}
	pSess = &model.Principal{ARN: sess, Kind: model.RoleSession, AccountID: acct, EntityARN: role, UniqueID: uidAR}
	pFed  = &model.Principal{ARN: fedUsr, Kind: model.FederatedUserSession, AccountID: acct, EntityARN: user}
	pRoot = &model.Principal{ARN: rootA, Kind: model.Root, AccountID: acct}
	pSvc  = &model.Principal{ARN: "s3.amazonaws.com", Kind: model.Service}
	pAnon = &model.Principal{Kind: model.Anonymous}
	pWeb  = &model.Principal{ARN: "arn:aws:sts::222222222222:assumed-role/x/s", Kind: model.RoleSession, AccountID: other,
		EntityARN: "arn:aws:iam::222222222222:role/x", FederatedProvider: "arn:aws:iam::222222222222:oidc-provider/idp"}
)

// set builds a normalized PrincipalSet from the raw entries.
func set(entries ...model.PrincipalEntry) *model.PrincipalSet {
	return &model.PrincipalSet{Entries: entries}
}

func e(k model.PrincipalEntryKind, value, account string) model.PrincipalEntry {
	return model.PrincipalEntry{Kind: k, Value: value, AccountID: account}
}

func TestMatchPrincipal(t *testing.T) {
	wild := e(model.PrincipalWildcard, "*", "")
	tests := []struct {
		name string
		set  *model.PrincipalSet
		pa   bool
		p    *model.Principal
		want MatchKinds
		has  []MatchKind
	}{
		{name: "wildcard, user", set: set(wild), p: pUser, has: []MatchKind{MatchWildcard}},
		{name: "wildcard, anonymous", set: set(wild), p: pAnon, has: []MatchKind{MatchWildcard}},
		{name: "wildcard with PrincipalArn condition", set: set(wild), pa: true, p: pUser, has: []MatchKind{MatchWildcardPrincipalARN}},
		{name: "user ARN, user is SELF", set: set(e(model.PrincipalIAMUser, user, acct)), p: pUser, has: []MatchKind{MatchSelf}},
		{name: "user ARN, other user", set: set(e(model.PrincipalIAMUser, "arn:aws:iam::111111111111:user/Alice", acct)), p: pUser},
		{name: "user ARN, federated session is PARENT", set: set(e(model.PrincipalIAMUser, user, acct)), p: pFed, has: []MatchKind{MatchParent}},
		{name: "role ARN, session is PARENT", set: set(e(model.PrincipalIAMRole, role, acct)), p: pSess, has: []MatchKind{MatchParent}},
		{name: "role ARN does not match a user", set: set(e(model.PrincipalIAMRole, role, acct)), p: pUser},
		{name: "role ARN is case sensitive", set: set(e(model.PrincipalIAMRole, "arn:aws:iam::111111111111:role/App", acct)), p: pSess},
		{name: "session ARN is SELF", set: set(e(model.PrincipalAssumedRole, sess, acct)), p: pSess, has: []MatchKind{MatchSelf}},
		{name: "other session ARN", set: set(e(model.PrincipalAssumedRole, "arn:aws:sts::111111111111:assumed-role/app/s2", acct)), p: pSess},
		{name: "federated-user ARN is SELF", set: set(e(model.PrincipalFederatedUser, fedUsr, acct)), p: pFed, has: []MatchKind{MatchSelf}},
		{name: "role unique id is PARENT", set: set(e(model.PrincipalUniqueID, uidAR, "")), p: pSess, has: []MatchKind{MatchParent}},
		{name: "user unique id is SELF", set: set(e(model.PrincipalUniqueID, uidAI, "")), p: pUser, has: []MatchKind{MatchSelf}},
		{name: "unique id mismatch", set: set(e(model.PrincipalUniqueID, "AROAOTHEROTHEROTHER1", "")), p: pSess},
		{name: "account id, user is ACCOUNT", set: set(e(model.PrincipalAccount, acct, acct)), p: pUser, has: []MatchKind{MatchAccount}},
		{name: "account root ARN, session is ACCOUNT", set: set(e(model.PrincipalAccount, rootA, acct)), p: pSess, has: []MatchKind{MatchAccount}},
		{name: "account, root behaves as SELF", set: set(e(model.PrincipalAccount, acct, acct)), p: pRoot, has: []MatchKind{MatchSelf}},
		{name: "account, other account", set: set(e(model.PrincipalAccount, other, other)), p: pUser},
		{name: "account, service does not match", set: set(e(model.PrincipalAccount, acct, acct)), p: pSvc},
		{name: "account, anonymous does not match", set: set(e(model.PrincipalAccount, acct, acct)), p: pAnon},
		{name: "service", set: set(e(model.PrincipalService, "s3.amazonaws.com", "")), p: pSvc, has: []MatchKind{MatchService}},
		{name: "service name is case sensitive", set: set(e(model.PrincipalService, "S3.amazonaws.com", "")), p: pSvc},
		{name: "service does not match a user", set: set(e(model.PrincipalService, "s3.amazonaws.com", "")), p: pUser},
		{name: "federated provider is SELF", set: set(e(model.PrincipalFederated, "arn:aws:iam::222222222222:oidc-provider/idp", "")), p: pWeb, has: []MatchKind{MatchSelf}},
		{name: "federated provider, no provider in request", set: set(e(model.PrincipalFederated, "arn:aws:iam::222222222222:oidc-provider/idp", "")), p: pUser},
		{name: "unrecognized value never matches", set: set(e(model.PrincipalUnrecognized, user, "")), p: pUser},
		{name: "several kinds at once", set: set(e(model.PrincipalAccount, acct, acct), e(model.PrincipalIAMRole, role, acct)), p: pSess, has: []MatchKind{MatchAccount, MatchParent}},
		{name: "nil set", set: nil, p: pUser},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := MatchPrincipal(tc.set, tc.pa, tc.p, nil)
			var want MatchKinds
			for _, k := range tc.has {
				want.add(k)
			}
			if got != want {
				t.Errorf("got %q, want %q", got, want)
			}
		})
	}
}

func TestMatchPrincipalIsOrderIndependent(t *testing.T) {
	a := set(e(model.PrincipalAccount, acct, acct), e(model.PrincipalIAMRole, role, acct))
	b := set(e(model.PrincipalIAMRole, role, acct), e(model.PrincipalAccount, acct, acct))
	if MatchPrincipal(a, false, pSess, nil) != MatchPrincipal(b, false, pSess, nil) {
		t.Error("entry order changed the result")
	}
}

func TestMatchCanonicalUser(t *testing.T) {
	ids := map[string]string{"canon1": acct}
	s := set(e(model.PrincipalCanonicalUser, "canon1", ""))
	if got := MatchPrincipal(s, false, pUser, ids); !got.Has(MatchAccount) {
		t.Errorf("canonical user of the account: %q", got)
	}
	if got := MatchPrincipal(s, false, pUser, nil); !got.Empty() {
		t.Errorf("unknown canonical id must not match: %q", got)
	}
	if got := MatchPrincipal(set(e(model.PrincipalCanonicalUser, "canon1", "")), false, &model.Principal{Kind: model.IAMUser, AccountID: other}, ids); !got.Empty() {
		t.Errorf("canonical user of another account: %q", got)
	}
}

func TestMatchStatementPrincipal(t *testing.T) {
	st := &model.Statement{
		Principals: set(e(model.PrincipalWildcard, "*", "")),
		Condition:  []authz.Atom{{Op: "ArnLike", Key: "aws:principalarn", Values: []string{"arn:aws:iam::*:role/x"}}},
	}
	if got := MatchStatementPrincipal(st, pUser, nil); !got.Has(MatchWildcardPrincipalARN) || got.Has(MatchWildcard) {
		t.Errorf("got %q", got)
	}
	st.Condition = []authz.Atom{{Op: "StringEquals", Key: "aws:sourceip"}}
	if got := MatchStatementPrincipal(st, pUser, nil); !got.Has(MatchWildcard) {
		t.Errorf("got %q", got)
	}
	if got := MatchStatementPrincipal(&model.Statement{}, pUser, nil); !got.Empty() {
		t.Errorf("statement without Principal matched: %q", got)
	}
}

func TestMatchKindStrings(t *testing.T) {
	var s MatchKinds
	s.add(MatchAccount)
	s.add(MatchSelf)
	if s.String() != "SELF|ACCOUNT" {
		t.Errorf("String() = %q", s.String())
	}
	if MatchWildcardPrincipalARN.String() != "WILDCARD_PRINCIPALARN" || MatchKind(99).String() != "UNKNOWN" {
		t.Error("MatchKind.String")
	}
	if MatchKinds(0).Has(0) {
		t.Error("Has(0)")
	}
}

func TestNotPrincipalDenyApplies(t *testing.T) {
	acctE := e(model.PrincipalAccount, rootA, acct)
	userE := e(model.PrincipalIAMUser, user, acct)
	roleE := e(model.PrincipalIAMRole, role, acct)
	sessE := e(model.PrincipalAssumedRole, sess, acct)
	withBoundary := func(p *model.Principal) *model.Principal {
		c := *p
		c.BoundaryPolicyID = "pol-boundary"
		return &c
	}
	tests := []struct {
		name      string
		np        *model.PrincipalSet
		p         *model.Principal
		applies   bool
		ambiguous bool
	}{
		{"user: account and user listed is exempt", set(acctE, userE), pUser, false, false},
		{"user: only user listed, Deny applies", set(userE), pUser, true, false},
		{"user: only account listed, Deny applies", set(acctE), pUser, true, false},
		{"user: other user listed, Deny applies", set(acctE, e(model.PrincipalIAMUser, "arn:aws:iam::111111111111:user/bob", acct)), pUser, true, false},
		{"user: other account's account listed", set(e(model.PrincipalAccount, other, other), userE), pUser, true, false},
		{"user with boundary: always denied", set(acctE, userE), withBoundary(pUser), true, false},
		{"session A4: account listed, role and session both listed", set(acctE, roleE, sessE), pSess, false, false},
		{"session A4: account listed, role only (flagged)", set(acctE, roleE), pSess, false, true},
		{"session A4: account listed, session only (flagged)", set(acctE, sessE), pSess, false, true},
		{"session A4: account listed, neither role nor session (not flagged)", set(acctE), pSess, true, false},
		{"session: role and session, no account", set(roleE, sessE), pSess, true, false},
		{"session: only account listed", set(acctE), pSess, true, false},
		{"session: only role listed", set(roleE), pSess, true, false},
		{"session with boundary: always denied", set(acctE, roleE, sessE), withBoundary(pSess), true, false},
		{"federated session: account and user listed", set(acctE, userE), pFed, false, true},
		{"federated session: account and session listed", set(acctE, e(model.PrincipalFederatedUser, fedUsr, acct)), pFed, false, true},
		{"root: account listed is exempt", set(acctE), pRoot, false, false},
		{"root: other account listed", set(e(model.PrincipalAccount, other, other)), pRoot, true, false},
		{"service: listed is exempt", set(e(model.PrincipalService, "s3.amazonaws.com", "")), pSvc, false, false},
		{"service: not listed", set(acctE), pSvc, true, false},
		{"anonymous: Deny applies", set(acctE, userE), pAnon, true, false},
		{"nil list matches nobody", nil, pUser, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			applies, amb := NotPrincipalDenyApplies(tc.np, tc.p)
			if applies != tc.applies || amb != tc.ambiguous {
				t.Errorf("got applies=%v ambiguousA4=%v, want %v %v", applies, amb, tc.applies, tc.ambiguous)
			}
		})
	}
}
