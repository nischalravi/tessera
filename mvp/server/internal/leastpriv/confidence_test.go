package leastpriv

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/nischalravi/tessera/mvp/server/internal/store"
)

var confNow = time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)

func day(daysAgo int) string { return dayOf(confNow).AddDate(0, 0, -daysAgo).Format("2006-01-02") }

func ctState(coveredFromAgo, coveredToAgo int, s3 string) *store.AWSUsageState {
	return &store.AWSUsageState{Source: store.AWSUsageCloudTrail, CoveredFrom: day(coveredFromAgo), CoveredTo: day(coveredToAgo), S3DataEvents: s3}
}

// steadyDays is activity on every 3rd day of the last n days.
func steadyDays(n int) []string {
	var out []string
	for i := 0; i < n; i += 3 {
		out = append(out, day(i))
	}
	return out
}

func created(daysAgo int) *time.Time {
	t := confNow.AddDate(0, 0, -daysAgo)
	return &t
}

func goodFacts() PrincipalFacts {
	return PrincipalFacts{ARN: "arn:aws:iam::1:role/r", Created: created(400), ActiveDays: steadyDays(60)}
}

func TestAssess(t *testing.T) {
	arn := "arn:aws:iam::1:role/r"
	cases := []struct {
		name   string
		action string
		used   bool
		ev     AWSEvidence
		p      PrincipalFacts
		want   string
	}{
		{"complete evidence is high", "iam:ListRoles", false, AWSEvidence{States: []*store.AWSUsageState{ctState(120, 0, "disabled")}}, goodFacts(), ConfHigh},
		{"used is not an unused finding", "iam:ListRoles", true, AWSEvidence{States: []*store.AWSUsageState{ctState(120, 0, "enabled")}}, goodFacts(), ConfLow},
		{"no ingest is unknown", "iam:ListRoles", false, AWSEvidence{}, goodFacts(), ConfUnknown},
		{"access advisor alone is unknown", "iam:ListRoles", false,
			AWSEvidence{States: []*store.AWSUsageState{{Source: store.AWSUsageAccessAdvisor, CoveredFrom: day(90), CoveredTo: day(0)}}}, goodFacts(), ConfUnknown},
		{"s3 object action, data events off", "s3:GetObject", false, AWSEvidence{States: []*store.AWSUsageState{ctState(120, 0, "disabled")}}, goodFacts(), ConfUnknown},
		{"s3 object action, data events unknown", "s3:PutObject", false, AWSEvidence{States: []*store.AWSUsageState{ctState(120, 0, "unknown")}}, goodFacts(), ConfUnknown},
		{"s3 object action, data events on", "s3:GetObject", false, AWSEvidence{States: []*store.AWSUsageState{ctState(120, 0, "enabled")}}, goodFacts(), ConfHigh},
		{"s3 bucket action is a management event", "s3:ListBucket", false, AWSEvidence{States: []*store.AWSUsageState{ctState(120, 0, "disabled")}}, goodFacts(), ConfHigh},
		{"logs cover most of the window", "iam:ListRoles", false, AWSEvidence{States: []*store.AWSUsageState{ctState(45, 0, "enabled")}}, goodFacts(), ConfMedium},
		{"logs cover under half", "iam:ListRoles", false, AWSEvidence{States: []*store.AWSUsageState{ctState(20, 0, "enabled")}}, goodFacts(), ConfLow},
		{"logs end days ago", "iam:ListRoles", false, AWSEvidence{States: []*store.AWSUsageState{ctState(120, 6, "enabled")}}, goodFacts(), ConfMedium},
		{"ingest gap", "iam:ListRoles", false, AWSEvidence{States: []*store.AWSUsageState{ctState(120, 0, "enabled")},
			Gaps: []*store.AWSUsageGap{{Source: "cloudtrail", Code: "too_large", Day: day(5)}}}, goodFacts(), ConfMedium},
		{"gap outside the window is ignored", "iam:ListRoles", false, AWSEvidence{States: []*store.AWSUsageState{ctState(120, 0, "enabled")},
			Gaps: []*store.AWSUsageGap{{Source: "cloudtrail", Code: "too_large", Day: day(80)}}}, goodFacts(), ConfHigh},
		{"unmapped actions gap is ignored", "iam:ListRoles", false, AWSEvidence{States: []*store.AWSUsageState{ctState(120, 0, "enabled")},
			Gaps: []*store.AWSUsageGap{{Source: "cloudtrail", Code: "unmapped_actions"}}}, goodFacts(), ConfHigh},
		{"future digest gap is low", "iam:ListRoles", false, AWSEvidence{States: []*store.AWSUsageState{ctState(120, 0, "enabled")},
			Gaps: []*store.AWSUsageGap{{Source: "cloudtrail", Code: "digest_missing", Day: day(3)}}}, goodFacts(), ConfLow},
		{"future digest gap with no day is low", "iam:ListRoles", false, AWSEvidence{States: []*store.AWSUsageState{ctState(120, 0, "enabled")},
			Gaps: []*store.AWSUsageGap{{Source: "cloudtrail", Code: "digest_invalid"}}}, goodFacts(), ConfLow},
		{"advisor gap for this principal", "iam:ListRoles", false, AWSEvidence{States: []*store.AWSUsageState{ctState(120, 0, "enabled")},
			Gaps: []*store.AWSUsageGap{{Source: "access_advisor", Ref: arn, Code: "rate_limited"}}}, goodFacts(), ConfMedium},
		{"advisor gap for another principal", "iam:ListRoles", false, AWSEvidence{States: []*store.AWSUsageState{ctState(120, 0, "enabled")},
			Gaps: []*store.AWSUsageGap{{Source: "access_advisor", Ref: "arn:aws:iam::1:role/other", Code: "rate_limited"}}}, goodFacts(), ConfHigh},
		{"identity younger than a week", "iam:ListRoles", false, AWSEvidence{States: []*store.AWSUsageState{ctState(120, 0, "enabled")}},
			PrincipalFacts{ARN: arn, Created: created(5), ActiveDays: steadyDays(5)}, ConfLow},
		{"identity younger than the window", "iam:ListRoles", false, AWSEvidence{States: []*store.AWSUsageState{ctState(120, 0, "enabled")}},
			PrincipalFacts{ARN: arn, Created: created(30), ActiveDays: steadyDays(30)}, ConfMedium},
		{"creation date unknown", "iam:ListRoles", false, AWSEvidence{States: []*store.AWSUsageState{ctState(120, 0, "enabled")}},
			PrincipalFacts{ARN: arn, ActiveDays: steadyDays(60)}, ConfMedium},
		{"dormant principal", "iam:ListRoles", false, AWSEvidence{States: []*store.AWSUsageState{ctState(120, 0, "enabled")}},
			PrincipalFacts{ARN: arn, Created: created(400)}, ConfMedium},
		{"monthly job pattern", "iam:ListRoles", false, AWSEvidence{States: []*store.AWSUsageState{ctState(120, 0, "enabled")}},
			PrincipalFacts{ARN: arn, Created: created(400), ActiveDays: []string{day(2), day(58)}}, ConfMedium},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Assess(confNow, 60, tc.action, tc.used, tc.ev, tc.p)
			if got.Level != tc.want {
				t.Fatalf("level = %s (%v), want %s", got.Level, got.Reasons, tc.want)
			}
			if len(got.Reasons) == 0 {
				t.Fatal("no reasons")
			}
		})
	}
}

func TestIsDataEventAction(t *testing.T) {
	for a, want := range map[string]bool{
		"s3:GetObject": true, "S3:getobject": true, "s3:GetObjectVersion": true, "s3:PutObjectAcl": true, "s3:DeleteObject": true,
		"s3:ListBucket": false, "s3:GetBucketPolicy": false, "iam:GetObject": false, "s3": false, "": false,
	} {
		if got := IsDataEventAction(a); got != want {
			t.Errorf("IsDataEventAction(%q) = %v, want %v", a, got, want)
		}
	}
}

// randomEvidence builds evidence and facts from the generator.
func randomEvidence(r *rand.Rand) (AWSEvidence, PrincipalFacts) {
	s3 := []string{"enabled", "disabled", "unknown"}[r.Intn(3)]
	ev := AWSEvidence{}
	if r.Intn(8) != 0 {
		ev.States = append(ev.States, ctState(r.Intn(150)+r.Intn(60), r.Intn(10), s3))
		if ev.States[0].CoveredTo < ev.States[0].CoveredFrom {
			ev.States[0].CoveredFrom, ev.States[0].CoveredTo = ev.States[0].CoveredTo, ev.States[0].CoveredFrom
		}
	}
	codes := []string{"too_large", "too_many_prefixes", "rate_limited", "not_ready", "digest_missing", "digest_invalid", "unmapped_actions", "data_events_unknown", "novel"}
	for i := r.Intn(4); i > 0; i-- {
		src := []string{"cloudtrail", "access_advisor"}[r.Intn(2)]
		d := ""
		if r.Intn(2) == 0 {
			d = day(r.Intn(100))
		}
		ev.Gaps = append(ev.Gaps, &store.AWSUsageGap{Source: src, Ref: []string{"p", "q"}[r.Intn(2)], Code: codes[r.Intn(len(codes))], Day: d})
	}
	p := PrincipalFacts{ARN: "p"}
	if r.Intn(5) != 0 {
		p.Created = created(r.Intn(500))
	}
	for i := r.Intn(30); i > 0; i-- {
		p.ActiveDays = append(p.ActiveDays, day(r.Intn(90)))
	}
	return ev, p
}

var actions = []string{"s3:GetObject", "s3:PutObject", "s3:DeleteObjectVersion", "s3:ListBucket", "iam:ListRoles", "ec2:DescribeInstances"}

func TestAssessProperties(t *testing.T) {
	r := rand.New(rand.NewSource(645))
	levels := map[string]bool{}
	for i := 0; i < 1500; i++ {
		ev, p := randomEvidence(r)
		window := []int{1, 7, 30, 60, 90}[r.Intn(5)]
		action := actions[r.Intn(len(actions))]
		got := Assess(confNow, window, action, false, ev, p)
		levels[got.Level] = true
		name := fmt.Sprintf("case %d (%s, %d days)", i, action, window)

		if rank(got.Level) == 0 && got.Level != ConfUnknown {
			t.Fatalf("%s: invalid level %q", name, got.Level)
		}
		if len(got.Reasons) == 0 {
			t.Fatalf("%s: no reasons", name)
		}
		// S3 object actions are never high unless data events are enabled
		if IsDataEventAction(action) && got.Level == ConfHigh {
			if len(ev.States) == 0 || ev.States[0].S3DataEvents != store.AWSDataEventsEnabled {
				t.Fatalf("%s: data event action is high without data events", name)
			}
		}
		// determinism
		if again := Assess(confNow, window, action, false, ev, p); again.Level != got.Level {
			t.Fatalf("%s: not deterministic", name)
		}
		// a gap never raises the level
		more := AWSEvidence{States: ev.States, Gaps: append(append([]*store.AWSUsageGap{}, ev.Gaps...),
			&store.AWSUsageGap{Source: "cloudtrail", Code: "digest_invalid"})}
		if got2 := Assess(confNow, window, action, false, more, p); got.Level != ConfUnknown && rank(got2.Level) > rank(got.Level) {
			t.Fatalf("%s: a gap raised %s to %s", name, got.Level, got2.Level)
		}
		// a digest gap inside the window caps at low when the answer is not unknown
		if got.Level != ConfUnknown {
			if got2 := Assess(confNow, window, action, false, more, p); got2.Level != ConfLow && got2.Level != ConfUnknown {
				t.Fatalf("%s: digest gap left %s", name, got2.Level)
			}
		}
		// shorter coverage never raises the level
		if len(ev.States) > 0 && got.Level != ConfUnknown {
			st := *ev.States[0]
			to, _ := parseDay(st.CoveredTo)
			from, _ := parseDay(st.CoveredFrom)
			if to.After(from) {
				st.CoveredFrom = from.AddDate(0, 0, 1+r.Intn(int(to.Sub(from).Hours()/24))).Format("2006-01-02")
				if got3 := Assess(confNow, window, action, false, AWSEvidence{States: []*store.AWSUsageState{&st}, Gaps: ev.Gaps}, p); rank(got3.Level) > rank(got.Level) && got3.Level != ConfUnknown {
					t.Fatalf("%s: shrinking coverage raised %s to %s", name, got.Level, got3.Level)
				}
			}
		}
		// an identity that is younger never rates higher
		if p.Created != nil && got.Level != ConfUnknown {
			younger := p
			younger.Created = created(int(confNow.Sub(*p.Created).Hours()/24) / 2)
			if got4 := Assess(confNow, window, action, false, ev, younger); rank(got4.Level) > rank(got.Level) && got4.Level != ConfUnknown {
				t.Fatalf("%s: a younger identity raised %s to %s", name, got.Level, got4.Level)
			}
		}
	}
	for _, l := range []string{ConfHigh, ConfMedium, ConfLow, ConfUnknown} {
		if !levels[l] {
			t.Errorf("generator never produced %s: the properties are not exercising it", l)
		}
	}
}
