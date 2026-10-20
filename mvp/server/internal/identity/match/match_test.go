package match

import (
	"math"
	"strings"
	"testing"
)

func TestJaroWinkler_ReferenceValues(t *testing.T) {
	// the published reference values for the algorithm (Winkler 1990)
	for _, c := range []struct {
		a, b   string
		jaro   float64
		winkle float64
	}{
		{"MARTHA", "MARHTA", 0.9444, 0.9611},
		{"DWAYNE", "DUANE", 0.8222, 0.84},
		{"DIXON", "DICKSONX", 0.7667, 0.8133},
		{"JELLYFISH", "SMELLYFISH", 0.8963, 0.8963},
		{"", "", 1, 1},
		{"abc", "", 0, 0},
		{"abc", "xyz", 0, 0},
		{"same", "same", 1, 1},
	} {
		if got := Jaro(c.a, c.b); math.Abs(got-c.jaro) > 0.0005 {
			t.Errorf("Jaro(%q,%q) = %.4f, want %.4f", c.a, c.b, got, c.jaro)
		}
		if got := JaroWinkler(c.a, c.b); math.Abs(got-c.winkle) > 0.0005 {
			t.Errorf("JaroWinkler(%q,%q) = %.4f, want %.4f", c.a, c.b, got, c.winkle)
		}
	}
	// runes, not bytes
	if got := JaroWinkler("josé", "josé"); got != 1 {
		t.Errorf("accented equal = %v", got)
	}
}

func TestFold(t *testing.T) {
	for in, want := range map[string]string{
		"José  GARCÍA-López": "jose garcia lopez",
		"  Zoë O'Brien ":     "zoe o brien",
		"ＡＬＩＣＥ":              "alice", // NFKC: full-width letters
		"Straße":             "strasse",
		"Søren Łukasz":       "soren lukasz",
		"":                   "",
		"---":                "",
	} {
		if got := Fold(in); got != want {
			t.Errorf("Fold(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNameScore_OrderAndPreferred(t *testing.T) {
	legal := []Name{{Given: "Robert", Family: "García"}}
	for _, c := range []struct {
		name string
		b    []Name
		min  float64
	}{
		{"same", []Name{{Given: "robert", Family: "GARCIA"}}, 1},
		{"family first", []Name{{Given: "García", Family: "Robert"}}, 1},
		{"preferred", []Name{{Given: "Roberto", Family: "Garcia", Preferred: "Robert"}}, 1},
		{"typo", []Name{{Given: "Robert", Family: "Garsia"}}, 0.92},
	} {
		if got := NameScore(legal, c.b); got < c.min {
			t.Errorf("%s: score %.3f, want at least %.2f", c.name, got, c.min)
		}
	}
	if got := NameScore(legal, []Name{{Given: "Wei", Family: "Zhang"}}); got > 0.7 {
		t.Errorf("different people score %.3f", got)
	}
	if NameScore(nil, legal) != 0 {
		t.Error("no names must score 0")
	}
}

func contact(s string, v bool) []Contact { return []Contact{{Norm: s, Verified: v}} }

var alice = Candidate{ID: 7, Names: []Name{{Given: "Alice", Family: "Smith"}}, Emails: contact("alice@gmail.com", true),
	DOBKey: "dob-1990-04-12", Sources: []Source{{"hris", "W1"}}, Authoritative: true,
	Identifiers: []Ident{{Type: "employee_id", Issuer: "univ", HMAC: "h-emp", Authoritative: true}, {Type: "oidc_sub", Issuer: "https://idp", HMAC: "h-sub"}}}

func firedRules(r Result) string {
	var out []string
	for _, f := range r.Fired {
		out = append(out, f.Rule)
	}
	return strings.Join(out, ",")
}

func TestMatch_SelfAssertedNeverAutoLinks(t *testing.T) {
	// every kind of match, including exact ones, only ever flags a self-asserted intake
	for name, in := range map[string]Intake{
		"email_dob_name":   {Names: []Name{{Given: "Alice", Family: "Smith"}}, Emails: contact("alice@gmail.com", false), DOB: DOB{Exact: "dob-1990-04-12"}},
		"email_only":       {Names: []Name{{Given: "Someone", Family: "Else"}}, Emails: contact("alice@gmail.com", false)},
		"name_dob":         {Names: []Name{{Given: "Alice", Family: "Smyth"}}, DOB: DOB{Exact: "dob-1990-04-12"}},
		"source_linked":    {Source: Source{"hris", "W1"}},
		"authoritative_id": {Identifiers: []Ident{{Type: "employee_id", Issuer: "univ", HMAC: "h-emp", Authoritative: true}}},
	} {
		in.Mode = SelfAsserted
		for _, cfg := range []Config{{}, {AutoLinkTierB: true}} {
			v := Evaluate(in, []Candidate{alice}, cfg)
			if len(v.Results) != 1 || v.Outcome != OutcomeSuspected || v.Results[0].Outcome != OutcomeSuspected {
				t.Errorf("%s (cfg %+v): outcome %q, results %+v", name, cfg, v.Outcome, v.Results)
			}
		}
	}
	// no rule fires: a new person
	v := Evaluate(Intake{Mode: SelfAsserted, Names: []Name{{Given: "Wei", Family: "Zhang"}}}, []Candidate{alice}, Config{})
	if v.Tier != TierD || v.Outcome != OutcomeNew || len(v.Results) != 0 {
		t.Errorf("no match: %+v", v)
	}
	// proof of possession is the one thing that links a self-asserted intake
	v = Evaluate(Intake{Mode: SelfAsserted, SignedInAs: 7}, []Candidate{alice}, Config{})
	if v.Outcome != OutcomeAutoLink || v.Tier != TierA || firedRules(v.Results[0]) != RuleSignedIn {
		t.Errorf("link by sign-in: %+v", v)
	}
	// ... and only as the right person
	if v = Evaluate(Intake{Mode: SelfAsserted, SignedInAs: 8}, []Candidate{alice}, Config{}); v.Outcome != OutcomeNew {
		t.Errorf("signed in as someone else: %+v", v)
	}
}

func TestMatch_TierExplanations(t *testing.T) {
	type want struct {
		tier    Tier
		rules   string
		outcome Outcome
	}
	for name, c := range map[string]struct {
		in   Intake
		cfg  Config
		want want
	}{
		"A source re-sent": {Intake{Mode: Authoritative, Source: Source{"hris", "W1"}}, Config{}, want{TierA, RuleSourceLinked, OutcomeAutoLink}},
		"A shared authoritative id": {Intake{Mode: Authoritative, Identifiers: []Ident{{Type: "employee_id", Issuer: "univ", HMAC: "h-emp", Authoritative: true}}},
			Config{}, want{TierA, RuleAuthIdent, OutcomeAutoLink}},
		"A not authoritative on the intake side": {Intake{Mode: Authoritative, Identifiers: []Ident{{Type: "employee_id", Issuer: "univ", HMAC: "h-emp"}}},
			Config{}, want{TierD, "", OutcomeNew}},
		"A federated binding": {Intake{Mode: Federated, Identifiers: []Ident{{Type: "oidc_sub", Issuer: "https://idp", HMAC: "h-sub"}}},
			Config{}, want{TierA, RuleFederated, OutcomeAutoLink}},
		"A federated, tenant requires review": {Intake{Mode: Federated, Identifiers: []Ident{{Type: "oidc_sub", Issuer: "https://idp", HMAC: "h-sub"}}},
			Config{RequireReviewTierA: true}, want{TierA, RuleFederated, OutcomeSuspected}},
		"A another issuer": {Intake{Mode: Federated, Identifiers: []Ident{{Type: "oidc_sub", Issuer: "https://other", HMAC: "h-sub"}}},
			Config{}, want{TierD, "", OutcomeNew}},
		"B authoritative, tier B off": {Intake{Mode: Authoritative, Names: []Name{{Given: "Alice", Family: "Smith"}}, Emails: contact("Alice@gmail.com", true), DOB: DOB{Exact: "dob-1990-04-12"}},
			Config{}, want{TierB, RuleEmailDOBName + "," + RuleNameDOB + "," + RuleEmailOnly, OutcomeReview}},
		"B authoritative, tier B on": {Intake{Mode: Authoritative, Names: []Name{{Given: "Alice", Family: "Smith"}}, Emails: contact("alice@gmail.com", true), DOB: DOB{Exact: "dob-1990-04-12"}},
			Config{AutoLinkTierB: true}, want{TierB, RuleEmailDOBName + "," + RuleNameDOB + "," + RuleEmailOnly, OutcomeAutoLink}},
		"B transposed date of birth": {Intake{Mode: Authoritative, Names: []Name{{Given: "Smith", Family: "Alice"}}, Emails: contact("alice@gmail.com", true), DOB: DOB{Exact: "dob-1990-12-04", Swapped: "dob-1990-04-12"}},
			Config{}, want{TierB, RuleEmailDOBName + "," + RuleNameDOB + "," + RuleEmailOnly, OutcomeReview}},
		"C unverified email on an authoritative intake": {Intake{Mode: Authoritative, Emails: contact("alice@gmail.com", false)},
			Config{}, want{TierD, "", OutcomeNew}},
		"C name and dob": {Intake{Mode: Authoritative, Names: []Name{{Given: "Alyce", Family: "Smith"}}, DOB: DOB{Exact: "dob-1990-04-12"}},
			Config{}, want{TierC, RuleNameDOB, OutcomeReview}},
		"C phone": {Intake{Mode: Authoritative, Phones: contact("+15550100", true)},
			Config{}, want{TierD, "", OutcomeNew}}, // alice holds no phone
		"C email only, self-asserted": {Intake{Mode: SelfAsserted, Emails: contact("alice@gmail.com", false)},
			Config{}, want{TierC, RuleEmailOnly, OutcomeSuspected}},
		"D different dob": {Intake{Mode: Authoritative, Names: []Name{{Given: "Alice", Family: "Smith"}}, DOB: DOB{Exact: "dob-2001-01-01"}},
			Config{}, want{TierD, "", OutcomeNew}},
	} {
		v := Evaluate(c.in, []Candidate{alice}, c.cfg)
		if v.Tier != c.want.tier || v.Outcome != c.want.outcome {
			t.Errorf("%s: tier %s outcome %s, want %s %s (%+v)", name, v.Tier, v.Outcome, c.want.tier, c.want.outcome, v.Results)
			continue
		}
		if c.want.rules == "" {
			continue
		}
		if got := firedRules(v.Results[0]); got != c.want.rules {
			t.Errorf("%s: rules %q, want %q", name, got, c.want.rules)
		}
		// every fired rule explains itself, and nothing in the explanation is a raw value
		for _, f := range v.Results[0].Fired {
			if f.Why == "" || f.Score <= 0 {
				t.Errorf("%s: rule %s has no explanation or score: %+v", name, f.Rule, f)
			}
			for k, val := range f.Compared {
				if strings.Contains(val, "alice@gmail.com") || strings.Contains(val, "Alice Smith") || strings.Contains(val, "dob-") {
					t.Errorf("%s: %s.%s leaks %q", name, f.Rule, k, val)
				}
			}
		}
	}
}

func TestMatch_AmbiguousNeverAutoLinks(t *testing.T) {
	twin := alice
	twin.ID = 8
	twin.Sources = nil
	twin.Identifiers = []Ident{{Type: "employee_id", Issuer: "univ", HMAC: "h-emp", Authoritative: true}}
	in := Intake{Mode: Authoritative, Identifiers: []Ident{{Type: "employee_id", Issuer: "univ", HMAC: "h-emp", Authoritative: true}}}
	v := Evaluate(in, []Candidate{alice, twin}, Config{})
	if len(v.Results) != 2 || v.Outcome != OutcomeReview {
		t.Errorf("two exact candidates: %+v", v)
	}
	// link by sign-in resolves the tie by proof
	in.SignedInAs = 8
	if v = Evaluate(in, []Candidate{alice, twin}, Config{}); v.Results[0].CandidateID != 8 || v.Outcome != OutcomeAutoLink {
		t.Errorf("signed in: %+v", v)
	}
}

func TestMask(t *testing.T) {
	for got, want := range map[string]string{
		MaskName("Alice Smith"):      "A**** S****",
		MaskEmail("alice@gmail.com"): "a***@gmail.com",
		MaskPhone("+15550100"):       "***0100",
		MaskPhone("123"):             "***",
		MaskID("W000123"):            "W0***23",
		MaskName("Jo"):               "J*",
	} {
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}
