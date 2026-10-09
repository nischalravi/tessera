package model

import (
	"encoding"
	"testing"
)

type textEnum interface {
	encoding.TextMarshaler
	String() string
}

func TestEnumText(t *testing.T) {
	for _, tc := range []struct {
		v    textEnum
		text string
		back func([]byte) (textEnum, error)
	}{
		{IAMUser, "iam_user", func(b []byte) (textEnum, error) { var v PrincipalKind; err := v.UnmarshalText(b); return v, err }},
		{FederatedUserSession, "federated_user_session", func(b []byte) (textEnum, error) { var v PrincipalKind; err := v.UnmarshalText(b); return v, err }},
		{PolicyKMSKey, "kms_key_policy", func(b []byte) (textEnum, error) { var v PolicyKind; err := v.UnmarshalText(b); return v, err }},
		{PolicyRAM, "ram_synthetic", func(b []byte) (textEnum, error) { var v PolicyKind; err := v.UnmarshalText(b); return v, err }},
		{PolicyVPCE, "vpc_endpoint", func(b []byte) (textEnum, error) { var v PolicyKind; err := v.UnmarshalText(b); return v, err }},
		{EffectDeny, "deny", func(b []byte) (textEnum, error) { var v Effect; err := v.UnmarshalText(b); return v, err }},
		{AttachTrust, "trust", func(b []byte) (textEnum, error) { var v AttachmentType; err := v.UnmarshalText(b); return v, err }},
		{OrgOU, "ou", func(b []byte) (textEnum, error) { var v OrgNodeKind; err := v.UnmarshalText(b); return v, err }},
		{AssumeRoleWithSAML, "assume_role_with_saml", func(b []byte) (textEnum, error) { var v TrustMechanism; err := v.UnmarshalText(b); return v, err }},
		{KeyIP, "ip", func(b []byte) (textEnum, error) { var v KeyType; err := v.UnmarshalText(b); return v, err }},
		{PrincipalAssumedRole, "assumed_role", func(b []byte) (textEnum, error) { var v PrincipalEntryKind; err := v.UnmarshalText(b); return v, err }},
	} {
		b, err := tc.v.MarshalText()
		if err != nil || string(b) != tc.text || tc.v.String() != tc.text {
			t.Errorf("%v: text %q, %v", tc.v, b, err)
			continue
		}
		got, err := tc.back(b)
		if err != nil || got != tc.v {
			t.Errorf("round trip %q = %v, %v", b, got, err)
		}
	}
	if _, err := PolicyKind(200).MarshalText(); err == nil {
		t.Error("out-of-range enum must not marshal")
	}
	// Every enum refuses an out-of-range value with the same error.
	for _, v := range []encoding.TextMarshaler{PrincipalKind(200), PolicyKind(200), Effect(200), AttachmentType(200),
		OrgNodeKind(200), TrustMechanism(200), KeyType(200), PrincipalEntryKind(200)} {
		_, err := v.MarshalText()
		if err == nil || err.Error() != "model: enum value out of range" {
			t.Errorf("%T(200).MarshalText() error = %v", v, err)
		}
	}
	var k PolicyKind
	if err := k.UnmarshalText([]byte("Identity")); err == nil {
		t.Error("enum text is case-sensitive")
	}
	if EffectAllow.PolicyElement() != "Allow" || EffectDeny.PolicyElement() != "Deny" || Effect(0).PolicyElement() != "" {
		t.Error("PolicyElement spelling is wrong")
	}
}

func TestPatternSetMatchPatterns(t *testing.T) {
	var nilSet *PatternSet
	if nilSet.MatchPatterns() != nil {
		t.Error("nil set")
	}
	raw := &PatternSet{Patterns: []string{"arn:aws:sqs"}}
	if got := raw.MatchPatterns(); len(got) != 1 || got[0] != "arn:aws:sqs" {
		t.Errorf("raw = %q", got)
	}
	done := &PatternSet{Patterns: []string{"arn:aws:sqs"}, Completed: []string{"arn:aws:sqs:*:*:*"}}
	if got := done.MatchPatterns(); len(got) != 1 || got[0] != "arn:aws:sqs:*:*:*" {
		t.Errorf("completed = %q", got)
	}
}

func TestPolicyKindClasses(t *testing.T) {
	for k := PolicyIdentity; k <= PolicyRAM; k++ {
		rb := k == PolicyResource || k == PolicyTrust || k == PolicyKMSKey || k == PolicyVPCE || k == PolicyS3AccessPoint
		ib := k == PolicyIdentity || k == PolicyBoundary || k == PolicySession
		if k.IsResourceBased() != rb || k.IsIdentityBased() != ib {
			t.Errorf("%v: resource-based %v identity-based %v", k, k.IsResourceBased(), k.IsIdentityBased())
		}
	}
}

func TestOrganizationPathTo(t *testing.T) {
	o := &Organization{Nodes: map[string]*OrgNode{
		"r-1":          {ID: "r-1", Kind: OrgRoot},
		"ou-prod":      {ID: "ou-prod", Kind: OrgOU, ParentID: "r-1"},
		"111111111111": {ID: "111111111111", Kind: OrgAccount, ParentID: "ou-prod"},
		"999999999999": {ID: "999999999999", Kind: OrgAccount, ParentID: "r-1"},
		"ou-a":         {ID: "ou-a", Kind: OrgOU, ParentID: "ou-b"},
		"ou-b":         {ID: "ou-b", Kind: OrgOU, ParentID: "ou-a"},
		"222222222222": {ID: "222222222222", Kind: OrgAccount, ParentID: "ou-a"},
		"333333333333": {ID: "333333333333", Kind: OrgAccount, ParentID: "ou-missing"},
	}}
	ids := func(ns []*OrgNode) (out []string) {
		for _, n := range ns {
			out = append(out, n.ID)
		}
		return out
	}
	if got := ids(o.PathTo("111111111111")); len(got) != 3 || got[0] != "r-1" || got[1] != "ou-prod" || got[2] != "111111111111" {
		t.Errorf("path = %v", got)
	}
	if got := ids(o.PathTo("999999999999")); len(got) != 2 {
		t.Errorf("mgmt path = %v", got)
	}
	for _, acct := range []string{"222222222222", "333333333333", "444444444444", "ou-prod"} {
		if o.PathTo(acct) != nil {
			t.Errorf("PathTo(%s) must be nil", acct)
		}
	}
	var nilOrg *Organization
	if nilOrg.PathTo("x") != nil {
		t.Error("nil org")
	}
}

func TestHasWildcardAndVariables(t *testing.T) {
	var p *PrincipalSet
	if p.HasWildcard() {
		t.Error("nil set")
	}
	p = &PrincipalSet{Entries: []PrincipalEntry{{Kind: PrincipalAccount}, {Kind: PrincipalWildcard}}}
	if !p.HasWildcard() {
		t.Error("wildcard entry")
	}
	for v, want := range map[string]bool{"2012-10-17": true, "2008-10-17": false, "": false} {
		if (&PolicyDoc{LanguageVersion: v}).VariablesEnabled() != want {
			t.Errorf("VariablesEnabled(%q)", v)
		}
	}
}
