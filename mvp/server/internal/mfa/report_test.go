package mfa

import (
	"reflect"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

var t0 = time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)

func sp(s string) *string { return &s }
func ip(i int64) *int64   { return &i }
func bp(b bool) *bool     { return &b }

func person(id int64, name, dept string) *store.Identity {
	return &store.Identity{ID: id, Name: name, Type: "human", Status: "active", Department: sp(dept)}
}

func acct(id, ident int64, system, user string) *store.Account {
	return &store.Account{ID: id, IdentityID: ip(ident), System: system, Username: user, Kind: "user", Status: "active"}
}

func method(acct int64, id, strength, kind string) *store.AuthMethod {
	return &store.AuthMethod{AccountID: acct, ExternalID: id, Strength: strength, Kind: kind}
}

func edge(src, dst, rel string) *store.GrantEdge {
	return &store.GrantEdge{Src: src, Dst: dst, Relation: rel, Source: "connector"}
}

func okSource(system string) *store.AuthMethodSource {
	return &store.AuthMethodSource{System: system, Status: SourceOK}
}

// One identity per best class, plus the two ways of having no class.
func TestBestMethodPerIdentity(t *testing.T) {
	in := Input{Now: t0,
		Identities: []*store.Identity{person(1, "Pat", "Eng"), person(2, "Quinn", "Eng"), person(3, "Rae", "Eng"), person(4, "Sam", "Eng"),
			person(5, "Tess", "Eng"), person(6, "Uma", "Eng"), person(7, "Vic", "Eng"), person(8, "Wes", "Eng")},
		Accounts: []*store.Account{acct(11, 1, "okta", "pat"), acct(12, 2, "okta", "quinn"), acct(13, 3, "okta", "rae"),
			acct(14, 4, "okta", "sam"), acct(15, 5, "okta", "tess"), acct(16, 6, "okta", "uma"),
			acct(17, 7, "github", "vic"), // no IdP account: unknown
			{ID: 18, IdentityID: ip(8), System: "okta", Username: "wes", Kind: "user", Status: "disabled"}},
		Methods: []*store.AuthMethod{
			method(11, "a", "otp", "totp"), method(11, "b", "phishing_resistant", "passkey"), method(11, "c", "sms_voice", "sms"), // strongest wins
			method(12, "a", "push_number_match", "app_push"), method(12, "b", "otp", "totp"),
			method(13, "a", "push", "app_push"),
			method(14, "a", "otp", "totp"),
			method(15, "a", "sms_voice", "sms"),
			method(18, "a", "phishing_resistant", "passkey"), // a disabled account's methods do not count
		},
		Sources: []*store.AuthMethodSource{okSource("okta")},
	}
	got := map[string]Strength{}
	passkey := map[string]bool{}
	for _, v := range Compute(in).Identities {
		got[v.Name] = v.Best
		passkey[v.Name] = v.Passkey
	}
	want := map[string]Strength{"Pat": PhishingResistant, "Quinn": PushNumberMatch, "Rae": Push, "Sam": OTP, "Tess": SMSVoice,
		"Uma": None, "Vic": Unknown, "Wes": Unknown} // Wes has only a disabled account: not covered
	if !reflect.DeepEqual(got, want) {
		t.Errorf("best = %v, want %v", got, want)
	}
	if !passkey["Pat"] || passkey["Quinn"] {
		t.Errorf("passkey flags = %v", passkey)
	}
}

// An IdP whose methods could not be read covers nobody: its people are unknown, never "no MFA".
func TestUnavailableSourceIsUnknownNotNone(t *testing.T) {
	in := Input{Now: t0, Identities: []*store.Identity{person(1, "Pat", "Eng")},
		Accounts: []*store.Account{acct(11, 1, "entra", "pat")},
		Sources:  []*store.AuthMethodSource{{System: "entra", Status: SourceUnavailable, Detail: "scope"}}}
	d := Compute(in)
	if d.Identities[0].Best != Unknown || Summarize(d.Identities).Totals.Unknown != 1 || Summarize(d.Identities).Totals.NoMFA != 0 {
		t.Errorf("best = %s, summary = %+v", d.Identities[0].Best, Summarize(d.Identities).Totals)
	}
	if len(d.Sources) != 1 || d.Sources[0].Status != SourceUnavailable {
		t.Errorf("sources = %+v", d.Sources)
	}
}

func TestPrivilegedViaGroupsNestingAndGrants(t *testing.T) {
	soon, past := t0.Add(time.Hour), t0.Add(-time.Hour)
	jitPast := edge("account:14", "group:2", "member_of")
	jitPast.ExpiresAt = &past
	jitSoon := edge("account:15", "group:2", "member_of")
	jitSoon.ExpiresAt = &soon
	in := Input{Now: t0,
		Identities: []*store.Identity{person(1, "Direct", "Eng"), person(2, "Nested", "Eng"), person(3, "Mapped", "Eng"), person(4, "Expired", "Eng"),
			person(5, "Active JIT", "Eng"), person(6, "Plain", "Eng"), person(7, "Perm", "Eng")},
		Accounts: []*store.Account{acct(11, 1, "okta", "d"), acct(12, 2, "okta", "n"), acct(13, 3, "okta", "m"), acct(14, 4, "okta", "e"),
			acct(15, 5, "okta", "j"), acct(16, 6, "okta", "p"), acct(17, 7, "okta", "x")},
		Groups: []*store.Group{
			{ID: 1, System: "aws", Name: "Admins", Privileged: true}, {ID: 2, System: "aws", Name: "Root", Privileged: true},
			{ID: 3, System: "okta", Name: "Inner"}, {ID: 4, System: "okta", Name: "Outer"}, {ID: 5, System: "okta", Name: "Staff"}, {ID: 6, System: "okta", Name: "Readers"}},
		Perms: []*store.Permission{{ID: 1, System: "aws", Action: "iam:*", Privileged: true}, {ID: 2, System: "aws", Action: "s3:Get"}},
		Edges: []*store.GrantEdge{
			edge("account:11", "group:1", "member_of"),
			edge("account:12", "group:4", "member_of"), edge("group:4", "group:3", "member_of"), edge("group:3", "group:1", "member_of"),
			edge("account:13", "group:5", "member_of"), edge("group:5", "group:1", "maps_to"),
			jitPast, jitSoon,
			edge("account:16", "group:6", "member_of"), edge("group:6", "perm:2", "grants"),
			edge("account:17", "perm:1", "direct_grant"),
		},
		Sources: []*store.AuthMethodSource{okSource("okta")},
	}
	d := Compute(in)
	got := map[string][]string{}
	priv := map[string]bool{}
	for _, v := range d.Identities {
		got[v.Name], priv[v.Name] = v.PrivilegedGroups, v.Privileged
	}
	for name, want := range map[string]bool{"Direct": true, "Nested": true, "Mapped": true, "Expired": false, "Active JIT": true,
		"Plain": false, "Perm": true} {
		if priv[name] != want {
			t.Errorf("%s privileged = %v, want %v", name, priv[name], want)
		}
	}
	if !reflect.DeepEqual(got["Nested"], []string{"aws: Admins"}) || !reflect.DeepEqual(got["Active JIT"], []string{"aws: Root"}) ||
		len(got["Perm"]) != 0 {
		t.Errorf("privileged groups = %v", got)
	}
}

func TestSummarizeByDepartmentAndPrivilegedGroup(t *testing.T) {
	in := Input{Now: t0,
		Identities: []*store.Identity{person(1, "A", "Eng"), person(2, "B", "Eng"), person(3, "C", "Fin"),
			{ID: 4, Name: "D", Type: "human", Status: "active"}, // no department
			{ID: 5, Name: "bot", Type: "service", Status: "active"}, {ID: 6, Name: "gone", Type: "human", Status: "terminated"}},
		Accounts: []*store.Account{acct(11, 1, "okta", "a"), acct(12, 2, "okta", "b"), acct(13, 3, "okta", "c"), acct(14, 4, "okta", "d")},
		Groups:   []*store.Group{{ID: 1, System: "okta", Name: "SuperAdmins", Privileged: true}},
		Edges:    []*store.GrantEdge{edge("account:11", "group:1", "member_of"), edge("account:13", "group:1", "member_of")},
		Methods: []*store.AuthMethod{method(11, "a", "phishing_resistant", "passkey"), method(12, "a", "otp", "totp"),
			method(13, "a", "sms_voice", "sms")},
		Sources: []*store.AuthMethodSource{okSource("okta")},
	}
	s := Summarize(Compute(in).Identities)
	if want := (Counts{Total: 4, PhishingResistant: 1, OTP: 1, SMSVoice: 1, NoMFA: 1, PasskeyEnrolled: 1}); s.Totals != want {
		t.Errorf("totals = %+v, want %+v", s.Totals, want)
	}
	wantDept := []Group{
		{NoDepartment, Counts{Total: 1, NoMFA: 1}},
		{"Eng", Counts{Total: 2, PhishingResistant: 1, OTP: 1, PasskeyEnrolled: 1}},
		{"Fin", Counts{Total: 1, SMSVoice: 1}},
	}
	if !reflect.DeepEqual(s.ByDepartment, wantDept) {
		t.Errorf("by department = %+v", s.ByDepartment)
	}
	wantGrp := []Group{{"okta: SuperAdmins", Counts{Total: 2, PhishingResistant: 1, SMSVoice: 1, PasskeyEnrolled: 1}}}
	if !reflect.DeepEqual(s.ByPrivilegedGrp, wantGrp) {
		t.Errorf("by privileged group = %+v", s.ByPrivilegedGrp)
	}
	if s.PrivilegedTotals.Total != 2 {
		t.Errorf("privileged totals = %+v", s.PrivilegedTotals)
	}
	rows := Compute(in).SnapshotRows("2026-10-08")
	if len(rows) != 1+3+1 || rows[0].Dimension != DimAll || rows[0].Total != 4 || rows[0].PasskeyEnrolled != 1 ||
		rows[len(rows)-1].Dimension != DimPrivilegedGroup {
		t.Errorf("snapshot rows = %+v", rows)
	}
}

// Apps and data platforms: only what a connector reported is judged, and a
// system that reports nothing is listed as a gap.
func TestAppFindings(t *testing.T) {
	in := Input{Now: t0,
		Identities: []*store.Identity{person(1, "Pat", "Eng"), person(2, "Quinn", "Eng")},
		Accounts: []*store.Account{acct(11, 1, "okta", "pat"), acct(21, 1, "snowflake", "PAT"), acct(22, 2, "snowflake", "QUINN"),
			acct(31, 1, "github", "pat-gh"), acct(32, 2, "github", "quinn-gh"), acct(41, 2, "aws", "quinn-iam"),
			{ID: 23, IdentityID: ip(2), System: "snowflake", Username: "OLD", Kind: "user", Status: "disabled"},
			{ID: 24, System: "snowflake", Username: "SVC", Kind: "service", Status: "active"}},
		Sources: []*store.AuthMethodSource{okSource("okta")},
		Signals: []*store.AccountAuthSignals{
			{AccountID: 21, HasLocalPassword: bp(true), MFAEnabled: bp(false)},                        // password and no MFA
			{AccountID: 22, HasLocalPassword: bp(false), MFAEnabled: bp(true), SSOEnforced: bp(true)}, // clean
			{AccountID: 23, HasLocalPassword: bp(true)},                                               // disabled: ignored
			{AccountID: 31, SSOEnforced: bp(false)},                                                   // SSO not enforced
			{AccountID: 32},                                                                           // nothing reported
		},
	}
	d := Compute(in)
	if len(d.Findings) != 2 {
		t.Fatalf("findings = %+v", d.Findings)
	}
	if f := d.Findings[0]; f.System != "snowflake" || f.Username != "PAT" || f.IdentityName != "Pat" ||
		!reflect.DeepEqual(f.Issues, []string{IssueLocalPassword, IssueNoMFA}) {
		t.Errorf("first finding = %+v (the one with more issues comes first)", f)
	}
	if f := d.Findings[1]; f.System != "github" || !reflect.DeepEqual(f.Issues, []string{IssueSSONotEnforced}) {
		t.Errorf("second finding = %+v", f)
	}
	wantApps := []AppSystem{{"aws", 1, 0, 0}, {"github", 2, 1, 1}, {"snowflake", 2, 2, 1}} // okta is an IdP; service accounts are not people
	if !reflect.DeepEqual(d.Apps, wantApps) {
		t.Errorf("apps = %+v, want %+v", d.Apps, wantApps)
	}
}
