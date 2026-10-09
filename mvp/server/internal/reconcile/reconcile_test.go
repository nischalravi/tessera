package reconcile

import (
	"strings"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

var now = time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)

func acct(xid, kind string, attrs map[string]string) *store.StagedAccount {
	return &store.StagedAccount{System: "dir", ExternalID: xid, Username: xid, Kind: kind, Status: "active", Attributes: attrs}
}

func people() []Person {
	return []Person{
		{ID: 1, ExternalID: "emp-1", Name: "Ada", Email: "ada@x.example", Status: "active"},
		{ID: 2, ExternalID: "emp-2", Name: "Bo", Email: "bo@x.example", Status: "active"},
		{ID: 3, ExternalID: "emp-3", Name: "Cy", Email: "shared@x.example", Status: "active"},
		{ID: 4, ExternalID: "emp-4", Name: "Di", Email: "shared@x.example", Status: "active"},
	}
}

func outcome(rs []Result, xid string) Result {
	for _, r := range rs {
		if r.ExternalID == xid {
			return r
		}
	}
	return Result{}
}

func TestCorrelation_Tiers(t *testing.T) {
	accts := []*store.StagedAccount{
		acct("a1", "user", map[string]string{"employeeID": " EMP-1 ", "mail": "bo@x.example"}), // tier 1 wins over email
		acct("a2", "user", map[string]string{"immutable_link": "entra:guid-2"}),                // tier 2
		acct("a3", "user", map[string]string{"mail": "BO@x.example"}),                          // tier 3: proposed only
		acct("a4", "service", map[string]string{"employeeID": "emp-2"}),                        // service, never a person
		acct("a5", "user", map[string]string{"mail": "nobody@x.example"}),                      // uncorrelated
		acct("a6", "user", map[string]string{"employeeID": "emp-999"}),                         // unknown HR id
	}
	links := []LiveLink{{System: "entra", ExternalID: "guid-2", IdentityID: 2}}
	rs := Correlate(accts, "employeeID", "account_source", people(), links)
	want := map[string]struct {
		outcome string
		tier    int
		linked  bool
	}{
		"a1": {Correlated, 1, true}, "a2": {Correlated, 2, true}, "a3": {Proposed, 3, false},
		"a4": {Service, 0, false}, "a5": {Uncorrelated, 0, false}, "a6": {Uncorrelated, 0, false},
	}
	for xid, w := range want {
		r := outcome(rs, xid)
		if r.Outcome != w.outcome || r.Tier != w.tier || (r.IdentityID != nil) != w.linked {
			t.Errorf("%s: got %s tier %d linked %v, want %+v", xid, r.Outcome, r.Tier, r.IdentityID != nil, w)
		}
	}
	// Tier 3 never links: the proposal names the person but IdentityID stays empty.
	if r := outcome(rs, "a3"); r.ProposedID == nil || *r.ProposedID != 2 || r.IdentityID != nil {
		t.Errorf("tier 3 must only propose: %+v", r)
	}
	// The authoritative source is not correlated against itself.
	for _, r := range Correlate(accts, "employeeID", "authoritative", people(), nil) {
		if r.Outcome != Authoritative {
			t.Errorf("authoritative: %+v", r)
		}
	}
}

func TestCorrelation_Ambiguous(t *testing.T) {
	accts := []*store.StagedAccount{
		acct("s1", "user", map[string]string{"mail": "shared@x.example"}), // two people share the email
		acct("d1", "user", map[string]string{"employeeID": "emp-1"}),      // two accounts for one person
		acct("d2", "user", map[string]string{"employeeID": "emp-1"}),
		acct("d3", "admin", map[string]string{"employeeID": "emp-1"}), // a non-user kind is a non-human account
		acct("ok", "user", map[string]string{"employeeID": "emp-2"}),
	}
	rs := Correlate(accts, "employeeID", "account_source", people(), nil)
	for _, xid := range []string{"s1", "d1", "d2"} {
		if r := outcome(rs, xid); r.Outcome != Ambiguous || r.IdentityID != nil {
			t.Errorf("%s: %+v (want ambiguous, never auto-resolved)", xid, r)
		}
	}
	if r := outcome(rs, "ok"); r.Outcome != Correlated {
		t.Errorf("ok: %+v", r)
	}
	if r := outcome(rs, "d3"); r.Outcome != Service {
		t.Errorf("d3: %+v", r)
	}
}

func snapshotWith(accts []*store.StagedAccount) *Snapshot {
	s := &Snapshot{ID: "run", Meta: Meta{System: "dir", SystemName: "Directory", TemplateID: "ad", Role: "account_source",
		HRAttribute: "employeeID", HRItem: "ad.key.employeeid", Now: now}, Accounts: accts}
	s.index()
	return s
}

func TestCause_UnmappedKey(t *testing.T) {
	var accts []*store.StagedAccount
	for i := range 10 {
		attrs := map[string]string{}
		if i == 0 {
			attrs["employeeID"] = "emp-x" // matches no one
		}
		a := acct(string(rune('a'+i)), "user", attrs)
		a.Correlation = Uncorrelated
		if i >= 6 {
			a.Correlation = Proposed
		}
		accts = append(accts, a)
	}
	matched := acct("m", "user", map[string]string{"employeeID": "emp-1"})
	matched.Correlation = Correlated
	accts = append(accts, matched)
	fs, err := Analyze(Input{Snap: snapshotWith(accts), People: map[int64]Person{}})
	if err != nil {
		t.Fatal(err)
	}
	var rf01 *Finding
	for i := range fs {
		if fs[i].Code == "RF-01" {
			rf01 = &fs[i]
		}
	}
	if rf01 == nil || rf01.Count != 10 || rf01.Cause == nil {
		t.Fatalf("RF-01: %+v", rf01)
	}
	c := rf01.Cause
	if c.Analyser != "unmapped_key+email_would_match" || !strings.Contains(c.Sentence, "employeeID is empty on 90% of them") ||
		!strings.Contains(c.Sentence, "4 of them match a person by email") || c.FixItem != "ad.key.employeeid" || !c.Probable {
		t.Errorf("cause: %+v", c)
	}
	if c.Numbers["unmatched_without_key"] != 9 {
		t.Errorf("numbers: %v", c.Numbers)
	}
	// When most unmatched accounts do carry the key, the key is not the cause.
	for _, a := range accts {
		a.Attributes["employeeID"] = "emp-unknown"
	}
	fs, _ = Analyze(Input{Snap: snapshotWith(accts), People: map[int64]Person{}})
	for _, f := range fs {
		if f.Code == "RF-01" && f.Cause != nil {
			t.Errorf("unexpected cause: %+v", f.Cause)
		}
	}
}

func TestRules_Load(t *testing.T) {
	r, err := LoadRules()
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range []string{"RF-01", "RF-02", "RF-03", "RF-04", "RF-05", "RF-06a", "RF-06b", "RF-07", "RF-08", "RF-09", "RF-10", "RF-11", "RF-12"} {
		if r.Rules[code].Severity == "" || r.Rules[code].Title == "" {
			t.Errorf("rule %s missing", code)
		}
	}
	if r.Rules["RF-08"].Severity != "critical" || r.Rules["RF-01"].Privileged != "critical" {
		t.Error("default severities differ from the design")
	}
}

func TestExpired(t *testing.T) {
	past := acct("p", "user", map[string]string{"accountExpires": "133000000000000000"}) // 2022
	never := acct("n", "user", map[string]string{"accountExpires": "9223372036854775807"})
	zero := acct("z", "user", map[string]string{"accountExpires": "0"})
	if !Expired(past, now) || Expired(never, now) || Expired(zero, now) || !Enabled(never, now) || Enabled(past, now) {
		t.Error("accountExpires parsing")
	}
}
